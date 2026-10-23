//! lt-eidd: owns the one connection to the Lithuanian eID card.
//!
//! It loads a private OpenSC PKCS#11 module and serves lt-eid PKCS#11
//! clients over a unix socket, one thread per connection. All card access
//! goes through a single mutex, so requests from different clients never
//! interleave on the card.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki_sys::*;
use lt_eid_proto::{PROTO_VERSION, Request, Response, Token, read_frame, write_frame};

const DEFAULT_MODULE: &str = "/opt/opensc/lib/opensc-pkcs11.so";

struct Card {
    p11: Pkcs11,
}

impl Card {
    fn open(module: &Path) -> cryptoki::error::Result<Self> {
        let p11 = Pkcs11::new(module)?;
        p11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
        Ok(Card { p11 })
    }

    fn tokens(&self) -> cryptoki::error::Result<Vec<Token>> {
        let mut tokens = Vec::new();
        for slot in self.p11.get_slots_with_token()? {
            let info = self.p11.get_token_info(slot)?;
            tokens.push(Token {
                slot: slot.id(),
                label: info.label().to_owned(),
                manufacturer: info.manufacturer_id().to_owned(),
                model: info.model().to_owned(),
                serial: info.serial_number().to_owned(),
                min_pin_len: info.min_pin_length() as u64,
                max_pin_len: info.max_pin_length() as u64,
                pin_count_low: info.user_pin_count_low(),
                pin_final_try: info.user_pin_final_try(),
                pin_locked: info.user_pin_locked(),
            });
        }
        Ok(tokens)
    }
}

fn handle(card: &Mutex<Card>, req: Request) -> Response {
    let card = card.lock().unwrap_or_else(|e| e.into_inner());
    match req {
        // Only valid as the first request; see `serve`.
        Request::Hello { .. } => Response::Rv(CKR_GENERAL_ERROR),
        Request::Tokens => match card.tokens() {
            Ok(tokens) => Response::Tokens(tokens),
            Err(e) => {
                eprintln!("listing tokens: {e}");
                Response::Rv(CKR_DEVICE_ERROR)
            }
        },
    }
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
