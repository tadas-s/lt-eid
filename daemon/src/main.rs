//! lt-eidd: owns the one connection to the Lithuanian eID card.
//!
//! It loads a private OpenSC PKCS#11 module and serves lt-eid PKCS#11
//! clients over a unix socket, one thread per connection. All card access
//! goes through a single mutex, so requests from different clients never
//! interleave on the card.
//!
//! Clients never see a PIN. The first client to log in to a token makes the
//! daemon ask for the PIN; later clients only need the user's approval.

mod card;
mod dialog;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use cryptoki_sys::*;
use lt_eid_proto::{Attr, PROTO_VERSION, Request, Response, Token, read_frame, write_frame};
use secrecy::ExposeSecret;

use card::Card;
use dialog::Dialogs;

const DEFAULT_MODULE: &str = "/opt/opensc/lib/opensc-pkcs11.so";

struct Daemon {
    card: Mutex<Card>,
    /// Held for a whole login, dialogs included, so only one dialog shows at
    /// a time. A client waiting here finds the token logged in by the one
    /// before it and only needs approval.
    login: Mutex<()>,
    dialogs: Dialogs,
}

/// One connected application.
struct Client {
    app: String,
    /// Tokens this client may use, keyed by slot, with the login they
    /// approved (see `Card::login_id`).
    grants: HashMap<CK_SLOT_ID, u64>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Daemon {
    fn granted(&self, client: &Client, slot: CK_SLOT_ID) -> Result<bool, CK_RV> {
        let current = lock(&self.card).login_id(slot)?;
        Ok(current.is_some() && client.grants.get(&slot).copied() == current)
    }

    fn login(&self, client: &mut Client, slot: CK_SLOT_ID) -> Result<(), CK_RV> {
        let _login = lock(&self.login);
        let (token, current) = {
            let mut card = lock(&self.card);
            (card.token(slot)?, card.login_id(slot)?)
        };
        // Card access stays unlocked while a dialog is open.
        let login = match current {
            Some(id) if client.grants.get(&slot) == Some(&id) => id,
            Some(id) => {
                self.dialogs.approve(&client.app, &token)?;
                id
            }
            None => self.enter_pin(&client.app, token)?,
        };
        client.grants.insert(slot, login);
        Ok(())
    }

    /// Ask for the PIN until the card accepts it or the user gives up.
    fn enter_pin(&self, app: &str, mut token: Token) -> Result<u64, CK_RV> {
        let mut error = None;
        loop {
            if token.flags & CKF_USER_PIN_LOCKED != 0 {
                return Err(CKR_PIN_LOCKED);
            }
            let pin = self.dialogs.pin(app, &token, error.as_deref())?;
            let pin = pin.expose_secret().as_bytes();
            // Don't spend a card attempt on a PIN that can't be right.
            let len = pin.len() as u64;
            if len < token.min_pin_len || len > token.max_pin_len {
                error = Some(format!("The PIN has {} to {} digits.", token.min_pin_len, token.max_pin_len));
                continue;
            }
            let mut card = lock(&self.card);
            match card.login(token.slot, pin) {
                Err(CKR_PIN_INCORRECT) => {
                    error = Some("Wrong PIN.".to_owned());
                    // Refresh the retry-counter flags for the next dialog.
                    token = card.token(token.slot)?;
                }
                result => return result,
            }
        }
    }

    fn handle(&self, client: &mut Client, req: Request) -> Result<Response, CK_RV> {
        match req {
            // Only valid as the first request; see `serve`.
            Request::Hello { .. } => Err(CKR_GENERAL_ERROR),
            Request::Tokens => lock(&self.card).tokens().map(Response::Tokens),
            Request::Find { slot, mut template } => {
                // Private objects are visible once anyone logged in to the
                // token; hide them from clients that haven't.
                if !self.granted(client, slot)? {
                    template.push(Attr { ty: CKA_PRIVATE, value: vec![CK_FALSE] });
                }
                lock(&self.card).find(slot, &template).map(Response::Objects)
            }
            Request::GetAttrs { slot, object, types } => {
                lock(&self.card).get_attrs(slot, object, &types).map(Response::Attrs)
            }
            Request::Login { slot } => self.login(client, slot).map(|()| Response::Ok),
            Request::Logout { slot } => {
                client.grants.remove(&slot);
                Ok(Response::Ok)
            }
        }
    }
}

fn serve(daemon: &Daemon, mut stream: UnixStream) -> io::Result<()> {
    let hello = match read_frame(&mut stream) {
        Ok(hello) => hello,
        // Connected and left, e.g. a check whether we are up.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
        Err(e) => return Err(e),
    };
    let mut client = match hello {
        Request::Hello { proto: PROTO_VERSION, app } => {
            write_frame(&mut stream, &Response::Hello { proto: PROTO_VERSION })?;
            Client { app, grants: HashMap::new() }
        }
        other => {
            eprintln!("bad handshake: {other:?}");
            return Ok(());
        }
    };
    loop {
        let req = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        };
        let resp = daemon.handle(&mut client, req).unwrap_or_else(Response::Rv);
        write_frame(&mut stream, &resp)?;
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
        Ok(card) => card,
        Err(e) => {
            eprintln!("loading {}: {e}", module.display());
            std::process::exit(1);
        }
    };
    let daemon = Arc::new(Daemon {
        card: Mutex::new(card),
        login: Mutex::new(()),
        dialogs: Dialogs::new(),
    });
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
        let daemon = Arc::clone(&daemon);
        thread::spawn(move || {
            if let Err(e) = serve(&daemon, stream) {
                eprintln!("client: {e}");
            }
        });
    }
}
