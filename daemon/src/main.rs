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
//! CAN doesn't open, the daemon asks for its CAN. The CAN also resumes the
//! eID PIN after two wrong tries suspended it, as part of the next login.

mod card;
mod dialog;
mod monitor;

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::Instant;

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
    peer: Peer,
    app: String,
    /// Tokens this client may use, keyed by slot, with the login they
    /// approved (see `Card::login_id`).
    grants: HashMap<CK_SLOT_ID, u64>,
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // The module's name for the program differs for Java programs.
        if self.app == self.peer.comm {
            write!(f, "{}", self.peer)
        } else {
            write!(f, "{} {:?}", self.peer, self.app)
        }
    }
}

/// The process at the other end of a connection, for the log.
struct Peer {
    /// Numbers connections in the order they came, to tell apart log lines
    /// of several connections from one process.
    id: u64,
    pid: Option<libc::pid_t>,
    /// The process's own idea of its name (`/proc/<pid>/comm`).
    comm: String,
}

impl Peer {
    fn of(stream: &UnixStream) -> Self {
        static LAST: AtomicU64 = AtomicU64::new(0);
        let id = LAST.fetch_add(1, Ordering::Relaxed) + 1;
        let pid = peer_pid(stream);
        let comm = pid
            .and_then(|pid| fs::read_to_string(format!("/proc/{pid}/comm")).ok())
            .map(|comm| comm.trim_end().to_owned())
            .unwrap_or_else(|| "?".to_owned());
        Peer { id, pid, comm }
    }
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "#{} {}[{pid}]", self.id, self.comm),
            None => write!(f, "#{} pid unknown", self.id),
        }
    }
}

/// The PID of the process that connected, as the kernel recorded it.
fn peer_pid(stream: &UnixStream) -> Option<libc::pid_t> {
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    let rv = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len)
    };
    (rv == 0 && cred.pid > 0).then_some(cred.pid)
}

/// How a dialog ended, for the log. A cancel right at the timeout most
/// likely means the user never saw the dialog.
fn outcome<T>(result: &Result<T, CK_RV>, shown: Instant) -> String {
    let secs = shown.elapsed().as_secs_f32();
    match result {
        Ok(_) => format!("answered after {secs:.1}s"),
        Err(CKR_FUNCTION_CANCELED) => format!("cancelled or timed out after {secs:.1}s"),
        Err(rv) => format!("failed after {secs:.1}s: {}", rv_name(*rv)),
    }
}

/// A `CK_RV` for the log.
fn rv_name(rv: CK_RV) -> String {
    let name = match rv {
        CKR_OK => "CKR_OK",
        CKR_FUNCTION_CANCELED => "CKR_FUNCTION_CANCELED",
        CKR_FUNCTION_REJECTED => "CKR_FUNCTION_REJECTED",
        CKR_FUNCTION_FAILED => "CKR_FUNCTION_FAILED",
        CKR_GENERAL_ERROR => "CKR_GENERAL_ERROR",
        CKR_DEVICE_ERROR => "CKR_DEVICE_ERROR",
        CKR_DEVICE_REMOVED => "CKR_DEVICE_REMOVED",
        CKR_TOKEN_NOT_PRESENT => "CKR_TOKEN_NOT_PRESENT",
        CKR_TOKEN_NOT_RECOGNIZED => "CKR_TOKEN_NOT_RECOGNIZED",
        CKR_PIN_INCORRECT => "CKR_PIN_INCORRECT",
        CKR_PIN_LOCKED => "CKR_PIN_LOCKED",
        CKR_USER_NOT_LOGGED_IN => "CKR_USER_NOT_LOGGED_IN",
        CKR_SESSION_HANDLE_INVALID => "CKR_SESSION_HANDLE_INVALID",
        CKR_KEY_HANDLE_INVALID => "CKR_KEY_HANDLE_INVALID",
        CKR_MECHANISM_INVALID => "CKR_MECHANISM_INVALID",
        _ => return format!("{rv:#x}"),
    };
    name.to_owned()
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
                eprintln!("{client}: asking to approve login to {:?}", token.label);
                let shown = Instant::now();
                let approved = self.dialogs.approve(&client.app, &token, Purpose::Login);
                eprintln!("{client}: login approval {}", outcome(&approved, shown));
                approved?;
                id
            }
            None => {
                let result = self.with_pin(client, token, Purpose::Login, |card, pin| card.login(slot, pin));
                match &result {
                    Ok(_) => eprintln!("{client}: logged in to slot {slot}"),
                    Err(rv) => eprintln!("{client}: login to slot {slot} failed: {}", rv_name(*rv)),
                }
                result?
            }
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
        let result = if always_authenticate {
            self.with_pin(client, token, Purpose::Sign, |card, pin| card.sign(slot, key, mechanism, data, Some(pin)))
        } else {
            // The card doesn't want PIN.QES again; still, no qualified
            // signature without the user saying so.
            eprintln!("{client}: asking to approve a signature with {:?}", token.label);
            let shown = Instant::now();
            let approved = self.dialogs.approve(&client.app, &token, Purpose::Sign);
            eprintln!("{client}: signature approval {}", outcome(&approved, shown));
            approved.and_then(|()| lock(&self.card).sign(slot, key, mechanism, data, None))
        };
        match &result {
            Ok(_) => eprintln!("{client}: signed with slot {slot}"),
            Err(rv) => eprintln!("{client}: signing with slot {slot} failed: {}", rv_name(*rv)),
        }
        result
    }

    /// Ask for the PIN and run `attempt` with it, until the card accepts it
    /// or the user gives up.
    fn with_pin<T>(
        &self,
        client: &Client,
        mut token: Token,
        purpose: Purpose,
        mut attempt: impl FnMut(&mut Card, &[u8]) -> Result<T, CK_RV>,
    ) -> Result<T, CK_RV> {
        let mut error = None;
        loop {
            if token.flags & CKF_USER_PIN_LOCKED != 0 {
                eprintln!("{client}: PIN of {:?} is blocked", token.label);
                return Err(CKR_PIN_LOCKED);
            }
            let retries = match token.flags {
                f if f & CKF_USER_PIN_FINAL_TRY != 0 => ", final try",
                f if f & CKF_USER_PIN_COUNT_LOW != 0 => ", earlier attempt wrong",
                _ => "",
            };
            eprintln!("{client}: asking for the PIN of {:?}{retries}", token.label);
            let shown = Instant::now();
            let pin = self.dialogs.pin(&client.app, &token, purpose, error.as_deref());
            eprintln!("{client}: PIN dialog {}", outcome(&pin, shown));
            let pin = pin?;
            let pin = pin.expose_secret();
            // Don't spend a card attempt on a PIN that can't be right.
            let len = pin.len() as u64;
            if len < token.min_pin_len || len > token.max_pin_len {
                eprintln!("{client}: PIN of the wrong length, not trying it on the card");
                error = Some(format!("The PIN has {} to {} digits.", token.min_pin_len, token.max_pin_len));
                continue;
            }
            let mut card = lock(&self.card);
            // Two wrong eID PINs suspend it: its last try must be resumed
            // with the CAN first. That ends every login (OpenSC restarts),
            // then `attempt` logs in again with the PIN now known right.
            let suspended = token.role == Role::Auth && token.flags & CKF_USER_PIN_FINAL_TRY != 0;
            let result = if suspended {
                eprintln!("{client}: PIN of {:?} is suspended, resuming it with the CAN", token.label);
                card.resume_pin(pin).and_then(|()| {
                    eprintln!("{client}: PIN of {:?} resumed", token.label);
                    attempt(&mut card, pin.as_bytes())
                })
            } else {
                attempt(&mut card, pin.as_bytes())
            };
            match result {
                Err(CKR_PIN_INCORRECT) => {
                    eprintln!("{client}: wrong PIN");
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
            let shown = Instant::now();
            let can = self.dialogs.can(error.as_deref());
            eprintln!("{reader}: CAN dialog {}", outcome(&can, shown));
            let Ok(can) = can else {
                return;
            };
            let can = can.expose_secret();
            if can.len() != 6 || !can.bytes().all(|b| b.is_ascii_digit()) {
                eprintln!("{reader}: CAN is not 6 digits");
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
                Err(CanError::Wrong) => {
                    eprintln!("{reader}: wrong CAN");
                    error = Some("Wrong CAN. Check the number on the card.".to_owned());
                }
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
                if client.grants.remove(&slot).is_some() {
                    eprintln!("{client}: logged out of slot {slot}");
                }
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

fn serve(daemon: &Daemon, mut stream: UnixStream) {
    let peer = Peer::of(&stream);
    let hello = match read_frame(&mut stream) {
        Ok(hello) => hello,
        // Connected and left, e.g. a check whether we are up.
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return,
        Err(e) => {
            eprintln!("{peer}: handshake: {e}");
            return;
        }
    };
    let mut client = match hello {
        Request::Hello { proto: PROTO_VERSION, app } => Client { peer, app, grants: HashMap::new() },
        Request::Hello { proto, app } => {
            eprintln!("{peer} {app:?}: protocol version {proto}, we speak {PROTO_VERSION}; module and daemon don't match");
            return;
        }
        other => {
            eprintln!("{peer}: bad handshake: {other:?}");
            return;
        }
    };
    if let Err(e) = write_frame(&mut stream, &Response::Hello { proto: PROTO_VERSION }) {
        eprintln!("{client}: handshake: {e}");
        return;
    }
    eprintln!("{client}: connected");
    let connected = Instant::now();
    let ended = loop {
        let req = match read_frame(&mut stream) {
            Ok(req) => req,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break "disconnected".to_owned(),
            Err(e) => break format!("connection failed: {e}"),
        };
        let resp = daemon.handle(&mut client, req).unwrap_or_else(Response::Rv);
        if let Err(e) = write_frame(&mut stream, &resp) {
            break format!("connection failed: {e}");
        }
    };
    eprintln!("{client}: {ended} after {:.0}s", connected.elapsed().as_secs_f32());
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
        monitor::watch(
            || lock(&watched.card).forget_tokens(),
            |reader| {
                let daemon = Arc::clone(&watched);
                let reader = reader.to_owned();
                // Off the monitor thread: the CAN dialog can take minutes.
                thread::spawn(move || daemon.card_inserted(&reader));
            },
        )
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
        thread::spawn(move || serve(&daemon, stream));
    }
}
