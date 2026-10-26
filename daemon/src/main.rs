// SPDX-License-Identifier: LGPL-2.1-or-later
//! lt-eidd: owns the one connection to the Lithuanian eID card.
//!
//! It loads a private OpenSC PKCS#11 module and serves lt-eid PKCS#11
//! clients over a unix socket, one thread per connection. All card access
//! goes through a single mutex, so requests from different clients never
//! interleave on the card.
//!
//! Clients never see a PIN. The first client to log in to a token makes the
//! daemon ask for the PIN; later clients only need the user's approval.
//! Signing with the authentication key needs nothing more. A qualified
//! signature always needs the user: PIN.QES if the card wants it for every
//! signature, otherwise an approval.
//!
//! A card can only be opened with its card access number (CAN), which the
//! lteid driver keeps in a cache. When a card is inserted that the cached
//! CAN doesn't open, the daemon asks for its CAN.

mod card;
mod dialog;
mod monitor;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::fd::FromRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use cryptoki_sys::*;
use lt_eid_proto::{Attr, PROTO_VERSION, Request, Response, Role, Token, read_frame, write_frame};
use secrecy::ExposeSecret;

use card::{Card, CanError};
use dialog::{Dialogs, Purpose};

/// The private OpenSC build packaged with lt-eid.
const DEFAULT_MODULE: &str = "/opt/lt-eid/lib/opensc-pkcs11.so";

struct Daemon {
    card: Mutex<Card>,
    /// Held for a whole login or signature that shows a dialog, so only one
    /// dialog shows at a time. A client waiting here to log in finds the
    /// token logged in by the one before it and only needs approval.
    dialog: Mutex<()>,
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
    fn granted(&self, client: &Client, slot: CK_SLOT_ID) -> bool {
        let current = lock(&self.card).login_id(slot);
        current.is_some() && client.grants.get(&slot).copied() == current
    }

    fn login(&self, client: &mut Client, slot: CK_SLOT_ID) -> Result<(), CK_RV> {
        let _dialog = lock(&self.dialog);
        let (token, current) = {
            let mut card = lock(&self.card);
            (card.token(slot)?, card.login_id(slot))
        };
        // Card access stays unlocked while a dialog is open.
        let login = match current {
            Some(id) if client.grants.get(&slot) == Some(&id) => id,
            Some(id) => {
                self.dialogs.approve(&client.app, &token, Purpose::Login)?;
                id
            }
            None => self.with_pin(&client.app, token, Purpose::Login, |card, pin| card.login(slot, pin))?,
        };
        client.grants.insert(slot, login);
        Ok(())
    }

    fn sign(&self, client: &Client, slot: CK_SLOT_ID, key: u64, mechanism: u64, data: &[u8]) -> Result<Vec<u8>, CK_RV> {
        if !self.granted(client, slot) {
            return Err(CKR_USER_NOT_LOGGED_IN);
        }
        let (token, always_authenticate) = {
            let mut card = lock(&self.card);
            (card.token(slot)?, card.always_authenticate(slot, key)?)
        };
        // TLS client authentication: the login was enough.
        if token.role == Role::Auth && !always_authenticate {
            return lock(&self.card).sign(slot, key, mechanism, data, None);
        }
        let _dialog = lock(&self.dialog);
        if always_authenticate {
            return self.with_pin(&client.app, token, Purpose::Sign, |card, pin| {
                card.sign(slot, key, mechanism, data, Some(pin))
            });
        }
        // The card doesn't want PIN.QES again; still, no qualified signature
        // without the user saying so.
        self.dialogs.approve(&client.app, &token, Purpose::Sign)?;
        lock(&self.card).sign(slot, key, mechanism, data, None)
    }

    /// Ask for the PIN and run `attempt` with it, until the card accepts it
    /// or the user gives up.
    fn with_pin<T>(
        &self,
        app: &str,
        mut token: Token,
        purpose: Purpose,
        mut attempt: impl FnMut(&mut Card, &[u8]) -> Result<T, CK_RV>,
    ) -> Result<T, CK_RV> {
        let mut error = None;
        loop {
            if token.flags & CKF_USER_PIN_LOCKED != 0 {
                return Err(CKR_PIN_LOCKED);
            }
            let pin = self.dialogs.pin(app, &token, purpose, error.as_deref())?;
            let pin = pin.expose_secret().as_bytes();
            // Don't spend a card attempt on a PIN that can't be right.
            let len = pin.len() as u64;
            if len < token.min_pin_len || len > token.max_pin_len {
                error = Some(format!("The PIN has {} to {} digits.", token.min_pin_len, token.max_pin_len));
                continue;
            }
            let mut card = lock(&self.card);
            match attempt(&mut card, pin) {
                Err(CKR_PIN_INCORRECT) => {
                    error = Some("Wrong PIN.".to_owned());
                    // Refresh the retry-counter flags for the next dialog.
                    token = card.token(token.slot)?;
                }
                result => return result,
            }
        }
    }

    /// A Lithuanian eID was inserted into `reader`. If the cached CAN
    /// doesn't open it, ask for the card's CAN until it works or the user
    /// gives up; the next try is when the card is inserted again.
    fn card_inserted(&self, reader: &str) {
        let _dialog = lock(&self.dialog);
        // OpenSC opens the card with the cached CAN, if it has one that works.
        let has_tokens = |card: &mut Card| card.tokens().is_ok_and(|tokens| !tokens.is_empty());
        {
            let mut card = lock(&self.card);
            if has_tokens(&mut card) {
                return;
            }
            // No tokens also when another program has the card open: then
            // the CAN is not the problem. To tell, OpenSC must let go of it.
            card.release();
            if monitor::held_by_another(reader) {
                eprintln!("{reader}: card in use by another program, not asking for its CAN");
                return;
            }
        }
        eprintln!("{reader}: card needs its CAN");
        let mut error = None;
        loop {
            let Ok(can) = self.dialogs.can(error.as_deref()) else {
                eprintln!("{reader}: no CAN entered");
                return;
            };
            let can = can.expose_secret();
            if can.len() != 6 || !can.bytes().all(|b| b.is_ascii_digit()) {
                error = Some("The CAN has 6 digits.".to_owned());
                continue;
            }
            let mut card = lock(&self.card);
            match card.store_can(can) {
                Ok(()) if has_tokens(&mut card) => {
                    eprintln!("{reader}: CAN stored, card ready");
                    return;
                }
                Ok(()) => {
                    eprintln!("{reader}: CAN stored, but OpenSC still can't open the card");
                    return;
                }
                Err(CanError::Wrong) => error = Some("Wrong CAN. Check the number on the card.".to_owned()),
                Err(CanError::Failed(why)) => {
                    eprintln!("{reader}: storing the CAN failed: {why}");
                    return;
                }
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
                if !self.granted(client, slot) {
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
            Request::Mechanisms { slot } => lock(&self.card).mechanisms(slot).map(Response::Mechanisms),
            Request::Sign { slot, key, mechanism, data } => self
                .sign(client, slot, key, mechanism, &data)
                .map(Response::Signature)
                // The spec's code for "the user rejected the signature".
                .map_err(|rv| if rv == CKR_FUNCTION_CANCELED { CKR_FUNCTION_REJECTED } else { rv }),
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

/// The listening socket systemd passed us (socket activation), if any.
///
/// Must run before any thread starts: it edits the environment.
fn activated_listener() -> Option<UnixListener> {
    let pid = std::env::var("LISTEN_PID").ok();
    let fds = std::env::var("LISTEN_FDS").ok();
    // Meant for us only: pinentry must not see them.
    for name in ["LISTEN_PID", "LISTEN_PIDFDID", "LISTEN_FDS", "LISTEN_FDNAMES"] {
        unsafe { std::env::remove_var(name) };
    }
    if pid?.parse::<u32>().ok()? != std::process::id() {
        return None;
    }
    if fds?.parse::<u32>().ok()? != 1 {
        eprintln!("expected one socket from systemd");
        return None;
    }
    // The first passed descriptor is 3 (SD_LISTEN_FDS_START). It comes
    // without close-on-exec; a clone has it, so pinentry won't inherit it.
    let passed = unsafe { UnixListener::from_raw_fd(3) };
    passed.try_clone().ok()
}

/// Bind the socket in a private directory, replacing a stale socket file.
fn bind(path: &Path) -> io::Result<UnixListener> {
    if let Some(dir) = path.parent() {
        fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    match fs::symlink_metadata(path) {
        // Someone still answers there: another lt-eidd, or systemd's socket.
        Ok(meta) if meta.file_type().is_socket() && UnixStream::connect(path).is_ok() => {
            return Err(io::Error::new(io::ErrorKind::AddrInUse, "in use by another lt-eidd or its systemd socket"));
        }
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
    let activated = activated_listener();
    let module: PathBuf = std::env::args_os()
        .nth(1)
        .map(Into::into)
        .unwrap_or_else(|| DEFAULT_MODULE.into());
    let card = match Card::open(&module) {
        Ok(card) => card,
        Err(e) => {
            eprintln!("loading {}: {e}", module.display());
            std::process::exit(1);
        }
    };
    let daemon = Arc::new(Daemon {
        card: Mutex::new(card),
        dialog: Mutex::new(()),
        dialogs: Dialogs::new(),
    });
    let watched = Arc::clone(&daemon);
    thread::spawn(move || {
        monitor::watch(|reader| {
            let daemon = Arc::clone(&watched);
            let reader = reader.to_owned();
            // Off the monitor thread: the CAN dialog can take minutes.
            thread::spawn(move || daemon.card_inserted(&reader));
        })
    });

    let listener = match activated {
        Some(listener) => {
            eprintln!("using {}, listening on the socket from systemd", module.display());
            listener
        }
        None => {
            let Some(socket) = lt_eid_proto::socket_path() else {
                eprintln!("neither LT_EID_SOCKET nor XDG_RUNTIME_DIR is set");
                std::process::exit(1);
            };
            let listener = match bind(&socket) {
                Ok(listener) => listener,
                Err(e) => {
                    eprintln!("binding {}: {e}", socket.display());
                    std::process::exit(1);
                }
            };
            eprintln!("using {}, listening on {}", module.display(), socket.display());
            listener
        }
    };

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
