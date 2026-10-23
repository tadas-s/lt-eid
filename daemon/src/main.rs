//! lt-eidd: owns the one connection to the Lithuanian eID card.
//!
//! It loads a private OpenSC PKCS#11 module and serves lt-eid PKCS#11
//! clients over a unix socket, one thread per connection. All card access
//! goes through a single mutex, so requests from different clients never
//! interleave on the card.
//!
//! OpenSC is driven through raw `C_*` calls: attribute values and `CK_RV`
//! codes pass through to clients unchanged.

use std::collections::HashMap;
use std::ffi::c_void;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::thread;

use cryptoki_sys::*;
use lt_eid_proto::{
    Attr, AttrValue, PROTO_VERSION, Request, Response, Token, read_frame, write_frame,
};

const DEFAULT_MODULE: &str = "/opt/opensc/lib/opensc-pkcs11.so";

fn check(rv: CK_RV) -> Result<(), CK_RV> {
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// PKCS#11 strings are fixed-size and blank-padded.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches([' ', '\0']).to_owned()
}

struct Card {
    p11: Pkcs11,
    /// One read-only session per slot, shared by all clients and opened on
    /// first use. Login state is per token anyway, so per-client sessions
    /// would not isolate anything.
    sessions: HashMap<CK_SLOT_ID, CK_SESSION_HANDLE>,
}

impl Card {
    fn open(module: &Path) -> Result<Self, String> {
        let p11 = unsafe { Pkcs11::new(module) }.map_err(|e| e.to_string())?;
        let mut args = CK_C_INITIALIZE_ARGS {
            CreateMutex: None,
            DestroyMutex: None,
            LockMutex: None,
            UnlockMutex: None,
            flags: CKF_OS_LOCKING_OK,
            pReserved: null_mut(),
        };
        check(unsafe { p11.C_Initialize(&mut args as *mut _ as *mut c_void) })
            .map_err(|rv| format!("C_Initialize: {rv:#x}"))?;
        Ok(Card { p11, sessions: HashMap::new() })
    }

    fn tokens(&mut self) -> Result<Vec<Token>, CK_RV> {
        let mut count: CK_ULONG = 0;
        check(unsafe { self.p11.C_GetSlotList(CK_TRUE, null_mut(), &mut count) })?;
        let mut slots = vec![0; count as usize];
        check(unsafe { self.p11.C_GetSlotList(CK_TRUE, slots.as_mut_ptr(), &mut count) })?;
        slots.truncate(count as usize);
        // A session on a slot whose token is gone is dead.
        self.sessions.retain(|slot, _| slots.contains(slot));

        let mut tokens = Vec::new();
        for slot in slots {
            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            match unsafe { self.p11.C_GetTokenInfo(slot, &mut info) } {
                CKR_OK => {}
                // Removed between the two calls.
                CKR_TOKEN_NOT_PRESENT => continue,
                rv => return Err(rv),
            }
            tokens.push(Token {
                slot,
                label: text(&info.label),
                manufacturer: text(&info.manufacturerID),
                model: text(&info.model),
                serial: text(&info.serialNumber),
                flags: info.flags,
                min_pin_len: info.ulMinPinLen,
                max_pin_len: info.ulMaxPinLen,
            });
        }
        Ok(tokens)
    }

    /// Run `f` with the shared session for `slot`. If the session turns out
    /// to be stale (the card was reinserted), reopen it and try once more.
    fn with_session<T>(
        &mut self,
        slot: CK_SLOT_ID,
        mut f: impl FnMut(&Pkcs11, CK_SESSION_HANDLE) -> Result<T, CK_RV>,
    ) -> Result<T, CK_RV> {
        for _ in 0..2 {
            let session = match self.sessions.get(&slot) {
                Some(&session) => session,
                None => {
                    let mut session = 0;
                    check(unsafe {
                        self.p11.C_OpenSession(slot, CKF_SERIAL_SESSION, null_mut(), None, &mut session)
                    })?;
                    self.sessions.insert(slot, session);
                    session
                }
            };
            match f(&self.p11, session) {
                Err(CKR_SESSION_HANDLE_INVALID | CKR_SESSION_CLOSED) => {
                    self.sessions.remove(&slot);
                }
                result => return result,
            }
        }
        Err(CKR_SESSION_HANDLE_INVALID)
    }

    fn find(&mut self, slot: CK_SLOT_ID, template: &[Attr]) -> Result<Vec<u64>, CK_RV> {
        // OpenSC only reads the template, the `*mut` is a C API wart.
        let mut raw: Vec<CK_ATTRIBUTE> = template
            .iter()
            .map(|a| CK_ATTRIBUTE {
                type_: a.ty,
                pValue: a.value.as_ptr() as *mut c_void,
                ulValueLen: a.value.len() as CK_ULONG,
            })
            .collect();
        self.with_session(slot, |p11, session| unsafe {
            check(p11.C_FindObjectsInit(session, raw.as_mut_ptr(), raw.len() as CK_ULONG))?;
            let mut found = Vec::new();
            let mut batch = [0; 32];
            let rv = loop {
                let mut n = 0;
                let rv = p11.C_FindObjects(session, batch.as_mut_ptr(), batch.len() as CK_ULONG, &mut n);
                if rv != CKR_OK || n == 0 {
                    break rv;
                }
                found.extend_from_slice(&batch[..n as usize]);
            };
            // Always end the search: the session is shared.
            p11.C_FindObjectsFinal(session);
            check(rv)?;
            Ok(found)
        })
    }

    fn get_attrs(&mut self, slot: CK_SLOT_ID, object: CK_OBJECT_HANDLE, types: &[u64]) -> Result<Vec<AttrValue>, CK_RV> {
        self.with_session(slot, |p11, session| {
            types.iter().map(|&ty| get_attr(p11, session, object, ty)).collect()
        })
    }
}

/// Read one attribute. Asking for them one at a time gives each its own
/// status instead of one `CK_RV` for the whole template.
fn get_attr(p11: &Pkcs11, session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE, ty: u64) -> Result<AttrValue, CK_RV> {
    let mut attr = CK_ATTRIBUTE { type_: ty, pValue: null_mut(), ulValueLen: 0 };
    match unsafe { p11.C_GetAttributeValue(session, object, &mut attr, 1) } {
        CKR_OK => {}
        CKR_ATTRIBUTE_SENSITIVE => return Ok(AttrValue::Sensitive),
        CKR_ATTRIBUTE_TYPE_INVALID => return Ok(AttrValue::Invalid),
        rv => return Err(rv),
    }
    let mut value = vec![0u8; attr.ulValueLen as usize];
    attr.pValue = value.as_mut_ptr().cast();
    check(unsafe { p11.C_GetAttributeValue(session, object, &mut attr, 1) })?;
    value.truncate(attr.ulValueLen as usize);
    Ok(AttrValue::Value(value))
}

fn handle(card: &Mutex<Card>, req: Request) -> Response {
    let mut card = card.lock().unwrap_or_else(|e| e.into_inner());
    let result = match req {
        // Only valid as the first request; see `serve`.
        Request::Hello { .. } => Err(CKR_GENERAL_ERROR),
        Request::Tokens => card.tokens().map(Response::Tokens),
        Request::Find { slot, template } => card.find(slot, &template).map(Response::Objects),
        Request::GetAttrs { slot, object, types } => {
            card.get_attrs(slot, object, &types).map(Response::Attrs)
        }
    };
    result.unwrap_or_else(Response::Rv)
}

fn serve(card: &Mutex<Card>, mut stream: UnixStream) -> io::Result<()> {
    match read_frame(&mut stream)? {
        Request::Hello { proto: PROTO_VERSION } => {
            write_frame(&mut stream, &Response::Hello { proto: PROTO_VERSION })?;
        }
        other => {
            eprintln!("bad handshake: {other:?}");
            return Ok(());
        }
    }
    loop {
        let req = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        write_frame(&mut stream, &handle(card, req))?;
    }
}

/// Bind the socket in a private directory, replacing a stale socket file.
fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => fs::remove_file(path)?,
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(_) => {}
    }
    UnixListener::bind(path)
}

fn main() {
    let module: PathBuf = std::env::args_os()
        .nth(1)
        .map(Into::into)
        .unwrap_or_else(|| DEFAULT_MODULE.into());
    let Some(socket) = lt_eid_proto::socket_path() else {
        eprintln!("neither LT_EID_SOCKET nor XDG_RUNTIME_DIR is set");
        std::process::exit(1);
    };

    let card = match Card::open(&module) {
        Ok(card) => Arc::new(Mutex::new(card)),
        Err(e) => {
            eprintln!("loading {}: {e}", module.display());
            std::process::exit(1);
        }
    };
    let listener = match bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("binding {}: {e}", socket.display());
            std::process::exit(1);
        }
    };
    eprintln!("using {}, listening on {}", module.display(), socket.display());

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(stream) => stream,
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let card = Arc::clone(&card);
        thread::spawn(move || {
            if let Err(e) = serve(&card, stream) {
                eprintln!("client: {e}");
            }
        });
    }
}
