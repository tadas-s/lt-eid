// SPDX-License-Identifier: LGPL-2.1-or-later
//! The lt-eid PKCS#11 module.
//!
//! It never talks to the card itself. It forwards to the lt-eid daemon over
//! a unix socket, and the daemon owns the one connection to the card.
//!
//! There are two fixed slots: 0 for the authentication token and 1 for the
//! qualified signature token. Slot and token information, object search,
//! attribute reads, login and signing go to the daemon. Sessions are local:
//! each one remembers which daemon token it belongs to.
//!
//! Signing offers `CKM_ECDSA` and `CKM_ECDSA_SHA256/384/512`. The hashing is
//! done here, so the card only ever sees `CKM_ECDSA`. Everything else
//! returns `CKR_FUNCTION_NOT_SUPPORTED`.
//!
//! Tokens advertise a protected authentication path: applications call
//! `C_Login` without a PIN, and the daemon asks the user for it.
//!
//! Applications load the shared library, call `C_GetFunctionList` and from
//! then on go through the returned table of function pointers.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};

use cryptoki_sys::*;
use sha2::{Digest, Sha256, Sha384, Sha512};
use lt_eid_proto::{
    Attr, AttrValue, PROTO_VERSION, Request, Response, Role, Token, read_frame, write_frame,
};

/// Our fixed slots. The token behind each comes and goes with the card.
const SLOTS: [(CK_SLOT_ID, Role); 2] = [(0, Role::Auth), (1, Role::Qes)];

fn slot_role(slot: CK_SLOT_ID) -> Option<Role> {
    SLOTS.iter().find(|(id, _)| *id == slot).map(|(_, role)| *role)
}
const PKCS11_VERSION: CK_VERSION = CK_VERSION { major: 2, minor: 40 };

// ---------------------------------------------------------------------------
// Global module state
// ---------------------------------------------------------------------------

struct Session {
    flags: CK_FLAGS,
    /// Our slot.
    slot: CK_SLOT_ID,
    /// The daemon's slot for the token, fixed when the session opens.
    token_slot: u64,
    /// The token's generation when the session opened. When the daemon's
    /// is another, the token was replaced (to applications) and the session
    /// is gone, as with a card swap.
    generation: u64,
    /// Results of the active search and how many were handed out.
    find: Option<(Vec<CK_OBJECT_HANDLE>, usize)>,
    sign: Option<SignOp>,
}

/// An active signing operation. The daemon signs in one go, so the message
/// is collected here until the application asks for the signature.
struct SignOp {
    mechanism: CK_MECHANISM_TYPE,
    key: CK_OBJECT_HANDLE,
    message: Vec<u8>,
    /// Kept after a size query or a too-small buffer, so the next call
    /// returns the same signature instead of signing again.
    signature: Option<Vec<u8>>,
}

struct State {
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    next_handle: CK_SESSION_HANDLE,
    /// Our slots this application is logged in to, with the token
    /// generation logged in to.
    logged_in: HashMap<CK_SLOT_ID, u64>,
    /// Connection to the daemon, opened on first use.
    conn: Option<UnixStream>,
    /// Process that owns `conn`. A forked child must not share it.
    pid: u32,
}

/// `None` until `C_Initialize` is called, and again after `C_Finalize`.
static STATE: Mutex<Option<State>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<State>> {
    // A poisoned mutex can only come from a panic, which aborts anyway.
    STATE.lock().unwrap_or_else(|e| e.into_inner())
}

/// Run `f` with the module state, or fail if the library isn't initialized.
fn with_state(f: impl FnOnce(&mut State) -> CK_RV) -> CK_RV {
    match lock().as_mut() {
        Some(state) => f(state),
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

/// Run `f` with a session looked up by handle.
fn with_session(h: CK_SESSION_HANDLE, f: impl FnOnce(&mut Session) -> CK_RV) -> CK_RV {
    with_state(|state| match state.sessions.get_mut(&h) {
        Some(session) => f(session),
        None => CKR_SESSION_HANDLE_INVALID,
    })
}

/// How the daemon's dialogs refer to us: the program's file name, or for a
/// `java -jar` application, the jar's.
fn app_name() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.file_name().map(|name| name.to_string_lossy().into_owned()));
    match exe.as_deref() {
        Some("java") => jar_name(&std::env::args().collect::<Vec<_>>()).unwrap_or_else(|| "A Java application".to_owned()),
        Some(exe) => exe.to_owned(),
        None => "An application".to_owned(),
    }
}

/// The jar in a `java ... -jar <file>` command line, without directory,
/// extension or version: "autogram" for "target/autogram-2.6.92.jar".
fn jar_name(args: &[String]) -> Option<String> {
    let jar = args.iter().skip_while(|arg| *arg != "-jar").nth(1)?;
    let stem = std::path::Path::new(jar).file_stem()?.to_str()?;
    let name = match stem.rsplit_once('-') {
        Some((name, version)) if version.starts_with(|c: char| c.is_ascii_digit()) => name,
        _ => stem,
    };
    Some(name.to_owned())
}

fn connect() -> std::io::Result<UnixStream> {
    let path = lt_eid_proto::socket_path()
        .ok_or_else(|| std::io::Error::other("no socket path"))?;
    let mut conn = UnixStream::connect(path)?;
    write_frame(&mut conn, &Request::Hello { proto: PROTO_VERSION, app: app_name() })?;
    match read_frame(&mut conn)? {
        Response::Hello { proto: PROTO_VERSION } => Ok(conn),
        _ => Err(std::io::Error::other("daemon speaks another protocol")),
    }
}

/// Send one request to the daemon, connecting first if needed.
///
/// `None` means the daemon is unreachable. Callers report that as "no
/// token" rather than an error, so applications keep the module loaded.
fn call(state: &mut State, req: &Request) -> Option<Response> {
    let pid = std::process::id();
    if state.pid != pid {
        state.conn = None;
        state.pid = pid;
    }
    // A connection that worked before may have died with a daemon restart:
    // then retry once on a fresh one.
    for _ in 0..2 {
        let reused = state.conn.is_some();
        if !reused {
            state.conn = Some(connect().ok()?);
            // Logins are held per connection; none carry over to this one.
            state.logged_in.clear();
        }
        let conn = state.conn.as_mut()?;
        match write_frame(conn, req).and_then(|()| read_frame(conn)) {
            Ok(resp) => return Some(resp),
            Err(_) => {
                state.conn = None;
                if !reused {
                    return None;
                }
            }
        }
    }
    None
}

/// Like `call`, for operations that need the daemon: an unreachable daemon
/// or an error reply becomes a `CK_RV`.
fn request(state: &mut State, req: &Request) -> Result<Response, CK_RV> {
    match call(state, req) {
        None => Err(CKR_DEVICE_REMOVED),
        Some(Response::Rv(rv)) => Err(rv),
        Some(resp) => Ok(resp),
    }
}

/// The tokens behind our slots, as `(our slot, token)`. Empty if the daemon
/// is down or no card is inserted.
fn tokens(state: &mut State) -> Vec<(CK_SLOT_ID, Token)> {
    let Some(Response::Tokens(tokens)) = call(state, &Request::Tokens) else {
        return Vec::new();
    };
    SLOTS
        .iter()
        .filter_map(|&(slot, role)| {
            let token = tokens.iter().find(|t| t.role == role)?;
            Some((slot, token.clone()))
        })
        .collect()
}

/// The token behind one of our slots.
fn token(state: &mut State, slot: CK_SLOT_ID) -> Option<Token> {
    tokens(state).into_iter().find(|(s, _)| *s == slot).map(|(_, token)| token)
}

/// Whether this application is logged in to the token of `session`.
fn logged_in(state: &State, session: &Session) -> bool {
    state.logged_in.get(&session.slot) == Some(&session.generation)
}

/// Forget this application's login to `slot`, here and in the daemon.
fn log_out(state: &mut State, slot: CK_SLOT_ID, token_slot: u64) {
    if state.logged_in.remove(&slot).is_some() {
        // If the daemon is gone, so is its record of our login.
        let _ = call(state, &Request::Logout { slot: token_slot });
    }
}

/// The token in `slot` of `generation` is gone: end its sessions and the
/// login to it, as OpenSC does when the card is swapped. The daemon knows
/// already; applications notice by `CKR_SESSION_HANDLE_INVALID` and set
/// the token up afresh (NSS asks `C_GetSessionInfo`).
fn expire(state: &mut State, slot: CK_SLOT_ID, generation: u64) {
    state.sessions.retain(|_, s| s.slot != slot || s.generation != generation);
    if state.logged_in.get(&slot) == Some(&generation) {
        state.logged_in.remove(&slot);
    }
}

/// `request` for one that names the token of session `h` by its
/// generation. If the daemon says it's not the current one, expire the
/// session (see `expire`).
fn session_request(state: &mut State, h: CK_SESSION_HANDLE, req: &Request) -> Result<Response, CK_RV> {
    let result = request(state, req);
    if result.as_ref().is_err_and(|&rv| rv == CKR_SESSION_HANDLE_INVALID) {
        if let Some(session) = state.sessions.get(&h) {
            expire(state, session.slot, session.generation);
        }
    }
    result
}

/// PKCS#11 strings are fixed-size, blank-padded and not NUL-terminated.
fn padded<const N: usize>(s: &str) -> [u8; N] {
    let mut buf = [b' '; N];
    let len = s.len().min(N);
    buf[..len].copy_from_slice(&s.as_bytes()[..len]);
    buf
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: PKCS11_VERSION,
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: Some(C_InitToken),
    C_InitPIN: Some(C_InitPIN),
    C_SetPIN: Some(C_SetPIN),
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: Some(C_GetOperationState),
    C_SetOperationState: Some(C_SetOperationState),
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: Some(C_CreateObject),
    C_CopyObject: Some(C_CopyObject),
    C_DestroyObject: Some(C_DestroyObject),
    C_GetObjectSize: Some(C_GetObjectSize),
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: Some(C_SetAttributeValue),
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: Some(C_EncryptInit),
    C_Encrypt: Some(C_Encrypt),
    C_EncryptUpdate: Some(C_EncryptUpdate),
    C_EncryptFinal: Some(C_EncryptFinal),
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: Some(C_DecryptUpdate),
    C_DecryptFinal: Some(C_DecryptFinal),
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: Some(C_DigestKey),
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: Some(C_SignRecoverInit),
    C_SignRecover: Some(C_SignRecover),
    C_VerifyInit: Some(C_VerifyInit),
    C_Verify: Some(C_Verify),
    C_VerifyUpdate: Some(C_VerifyUpdate),
    C_VerifyFinal: Some(C_VerifyFinal),
    C_VerifyRecoverInit: Some(C_VerifyRecoverInit),
    C_VerifyRecover: Some(C_VerifyRecover),
    C_DigestEncryptUpdate: Some(C_DigestEncryptUpdate),
    C_DecryptDigestUpdate: Some(C_DecryptDigestUpdate),
    C_SignEncryptUpdate: Some(C_SignEncryptUpdate),
    C_DecryptVerifyUpdate: Some(C_DecryptVerifyUpdate),
    C_GenerateKey: Some(C_GenerateKey),
    C_GenerateKeyPair: Some(C_GenerateKeyPair),
    C_WrapKey: Some(C_WrapKey),
    C_UnwrapKey: Some(C_UnwrapKey),
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: Some(C_GetFunctionStatus),
    C_CancelFunction: Some(C_CancelFunction),
    C_WaitForSlotEvent: Some(C_WaitForSlotEvent),
};

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    if ppFunctionList.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    // The table is read-only; the `*mut` in the signature is a C API wart.
    unsafe { *ppFunctionList = &FUNCTION_LIST as *const _ as *mut _ };
    CKR_OK
}

// ---------------------------------------------------------------------------
// General-purpose functions
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(pInitArgs: *mut c_void) -> CK_RV {
    if !pInitArgs.is_null() {
        let args = unsafe { &*(pInitArgs as *const CK_C_INITIALIZE_ARGS) };
        if !args.pReserved.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // We always use OS locking (std::sync::Mutex), which is acceptable
        // whether or not the caller passed CKF_OS_LOCKING_OK.
    }

    let mut guard = lock();
    if guard.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    *guard = Some(State {
        sessions: HashMap::new(),
        next_handle: 1,
        logged_in: HashMap::new(),
        conn: None,
        pid: std::process::id(),
    });
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(pReserved: *mut c_void) -> CK_RV {
    if !pReserved.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    match lock().take() {
        Some(_) => CKR_OK,
        None => CKR_CRYPTOKI_NOT_INITIALIZED,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetInfo(pInfo: *mut CK_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|_| {
        let info = CK_INFO {
            cryptokiVersion: PKCS11_VERSION,
            manufacturerID: padded("lt-eid"),
            flags: 0,
            libraryDescription: padded("Lithuanian eID (via lt-eidd)"),
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        unsafe { *pInfo = info };
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Slot and token management
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotList(
    tokenPresent: CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| unsafe {
        // The slots always exist; only their tokens come and go.
        let slots: Vec<CK_SLOT_ID> = if tokenPresent == CK_FALSE {
            SLOTS.iter().map(|(slot, _)| *slot).collect()
        } else {
            tokens(state).into_iter().map(|(slot, _)| slot).collect()
        };
        let count = slots.len() as CK_ULONG;
        // Standard PKCS#11 two-call pattern: a NULL list asks for the size.
        if pSlotList.is_null() {
            *pulCount = count;
            return CKR_OK;
        }
        if *pulCount < count {
            *pulCount = count;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(slots.as_ptr(), pSlotList, slots.len());
        *pulCount = count;
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSlotInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_SLOT_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(role) = slot_role(slotID) else {
            return CKR_SLOT_ID_INVALID;
        };
        let present = if token(state, slotID).is_some() { CKF_TOKEN_PRESENT } else { 0 };
        let description = match role {
            Role::Auth => "Lithuanian eID: authentication",
            Role::Qes => "Lithuanian eID: qualified signature",
        };
        let info = CK_SLOT_INFO {
            slotDescription: padded(description),
            manufacturerID: padded("lt-eid"),
            flags: CKF_REMOVABLE_DEVICE | CKF_HW_SLOT | present,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
        };
        unsafe { *pInfo = info };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetTokenInfo(slotID: CK_SLOT_ID, pInfo: *mut CK_TOKEN_INFO) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        if slot_role(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        let Some(token) = token(state, slotID) else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        let sessions: Vec<&Session> = state.sessions.values().filter(|s| s.slot == slotID).collect();
        let rw_count = sessions.iter().filter(|s| s.flags & CKF_RW_SESSION != 0).count();
        // Only the PIN status comes from the card; the rest describes us.
        // The daemon asks for the PIN, hence the protected authentication path.
        let pin_status = CKF_USER_PIN_COUNT_LOW | CKF_USER_PIN_FINAL_TRY | CKF_USER_PIN_LOCKED;
        let flags = CKF_TOKEN_INITIALIZED
            | CKF_USER_PIN_INITIALIZED
            | CKF_LOGIN_REQUIRED
            | CKF_PROTECTED_AUTHENTICATION_PATH
            | CKF_WRITE_PROTECTED
            | (token.flags & pin_status);
        let info = CK_TOKEN_INFO {
            label: padded(&token.label),
            manufacturerID: padded(&token.manufacturer),
            model: padded(&token.model),
            serialNumber: padded(&token.serial),
            flags,
            ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
            ulSessionCount: sessions.len() as CK_ULONG,
            ulMaxRwSessionCount: CK_EFFECTIVELY_INFINITE,
            ulRwSessionCount: rw_count as CK_ULONG,
            ulMaxPinLen: token.max_pin_len as CK_ULONG,
            ulMinPinLen: token.min_pin_len as CK_ULONG,
            ulTotalPublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePublicMemory: CK_UNAVAILABLE_INFORMATION,
            ulTotalPrivateMemory: CK_UNAVAILABLE_INFORMATION,
            ulFreePrivateMemory: CK_UNAVAILABLE_INFORMATION,
            hardwareVersion: CK_VERSION { major: 0, minor: 1 },
            firmwareVersion: CK_VERSION { major: 0, minor: 1 },
            utcTime: padded(""),
        };
        unsafe { *pInfo = info };
        CKR_OK
    })
}

/// The mechanisms we offer. Only `CKM_ECDSA` reaches the card; for the
/// others we hash the message first.
const MECHANISMS: [CK_MECHANISM_TYPE; 4] = [CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512];

/// The card's `CKM_ECDSA` info, limited to signing. `None` if the token
/// can't sign with it, in which case we offer no mechanisms at all.
fn ecdsa_info(state: &mut State, slot: CK_SLOT_ID) -> Result<Option<CK_MECHANISM_INFO>, CK_RV> {
    let token = token(state, slot).ok_or(CKR_TOKEN_NOT_PRESENT)?;
    let mechanisms = match request(state, &Request::Mechanisms { slot: token.slot })? {
        Response::Mechanisms(mechanisms) => mechanisms,
        _ => return Err(CKR_DEVICE_ERROR),
    };
    let ec_flags = CKF_EC_F_P | CKF_EC_ECPARAMETERS | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS;
    Ok(mechanisms
        .iter()
        .find(|m| m.ty == CKM_ECDSA && m.flags & CKF_SIGN != 0)
        .map(|m| CK_MECHANISM_INFO {
            ulMinKeySize: m.min_key_size,
            ulMaxKeySize: m.max_key_size,
            flags: m.flags & (CKF_HW | CKF_SIGN | ec_flags),
        }))
}

/// What the card signs for `message` under `mechanism`.
fn to_be_signed(mechanism: CK_MECHANISM_TYPE, message: &[u8]) -> Vec<u8> {
    match mechanism {
        CKM_ECDSA_SHA256 => Sha256::digest(message).to_vec(),
        CKM_ECDSA_SHA384 => Sha384::digest(message).to_vec(),
        CKM_ECDSA_SHA512 => Sha512::digest(message).to_vec(),
        // CKM_ECDSA: the application already hashed it.
        _ => message.to_vec(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| unsafe {
        if slot_role(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        let mechanisms: &[CK_MECHANISM_TYPE] = match ecdsa_info(state, slotID) {
            Ok(Some(_)) => &MECHANISMS,
            Ok(None) => &[],
            Err(rv) => return rv,
        };
        let count = mechanisms.len() as CK_ULONG;
        // Standard PKCS#11 two-call pattern: a NULL list asks for the size.
        if pMechanismList.is_null() {
            *pulCount = count;
            return CKR_OK;
        }
        if *pulCount < count {
            *pulCount = count;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(mechanisms.as_ptr(), pMechanismList, mechanisms.len());
        *pulCount = count;
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    type_: CK_MECHANISM_TYPE,
    pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        if slot_role(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        if !MECHANISMS.contains(&type_) {
            return CKR_MECHANISM_INVALID;
        }
        match ecdsa_info(state, slotID) {
            Ok(Some(info)) => {
                unsafe { *pInfo = info };
                CKR_OK
            }
            Ok(None) => CKR_MECHANISM_INVALID,
            Err(rv) => rv,
        }
    })
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: *mut c_void,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    if phSession.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        if slot_role(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        // Required by the spec for legacy reasons.
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        let Some(token) = token(state, slotID) else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        let handle = state.next_handle;
        state.next_handle += 1;
        let session =
            Session { flags, slot: slotID, token_slot: token.slot, generation: token.generation, find: None, sign: None };
        state.sessions.insert(handle, session);
        unsafe { *phSession = handle };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(closed) = state.sessions.remove(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        // Login state is per token and ends with its last session.
        if !state.sessions.values().any(|s| s.slot == closed.slot) {
            log_out(state, closed.slot, closed.token_slot);
        }
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    with_state(|state| {
        if slot_role(slotID).is_none() {
            return CKR_SLOT_ID_INVALID;
        }
        let mut token_slot = None;
        state.sessions.retain(|_, s| {
            if s.slot != slotID {
                return true;
            }
            token_slot = Some(s.token_slot);
            false
        });
        if let Some(token_slot) = token_slot {
            log_out(state, slotID, token_slot);
        }
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut CK_SESSION_INFO,
) -> CK_RV {
    if pInfo.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| {
        let Some(session) = state.sessions.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        // Applications ask this to learn whether the token is still the one
        // they set up (NSS does, every so often): a removed or replaced
        // token ends the session.
        let (slot, generation) = (session.slot, session.generation);
        if token(state, slot).is_none_or(|token| token.generation != generation) {
            expire(state, slot, generation);
            return CKR_SESSION_HANDLE_INVALID;
        }
        let session = &state.sessions[&hSession];
        let rw = session.flags & CKF_RW_SESSION != 0;
        let info = CK_SESSION_INFO {
            slotID: session.slot,
            state: match (rw, logged_in(state, session)) {
                (false, false) => CKS_RO_PUBLIC_SESSION,
                (false, true) => CKS_RO_USER_FUNCTIONS,
                (true, false) => CKS_RW_PUBLIC_SESSION,
                (true, true) => CKS_RW_USER_FUNCTIONS,
            },
            flags: session.flags,
            ulDeviceError: 0,
        };
        unsafe { *pInfo = info };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    userType: CK_USER_TYPE,
    _pPin: *mut CK_UTF8CHAR,
    _ulPinLen: CK_ULONG,
) -> CK_RV {
    with_state(|state| {
        let Some(session) = state.sessions.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let (slot, token_slot, generation) = (session.slot, session.token_slot, session.generation);
        match userType {
            CKU_USER => {}
            // Re-authentication for the signature being made. The daemon
            // asks for the PIN itself when the signature is due.
            CKU_CONTEXT_SPECIFIC if session.sign.is_some() => return CKR_OK,
            CKU_CONTEXT_SPECIFIC => return CKR_OPERATION_NOT_INITIALIZED,
            _ => return CKR_USER_TYPE_INVALID,
        }
        if logged_in(state, session) {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        // A PIN passed in anyway is ignored: PINs go to the card only
        // through the daemon's own dialog. This blocks until the user
        // answers it.
        match request(state, &Request::Login { slot: token_slot }) {
            Ok(Response::Ok) => {}
            Ok(_) => return CKR_DEVICE_ERROR,
            Err(rv) => return rv,
        }
        state.logged_in.insert(slot, generation);
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        let Some(session) = state.sessions.get(&hSession) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        if !logged_in(state, session) {
            return CKR_USER_NOT_LOGGED_IN;
        }
        let (slot, token_slot) = (session.slot, session.token_slot);
        log_out(state, slot, token_slot);
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Objects
//
// The daemon returns all matches at once; we hand them out page by page.
// ---------------------------------------------------------------------------

/// The C template as owned attributes, for sending to the daemon.
unsafe fn read_template(pTemplate: *const CK_ATTRIBUTE, ulCount: CK_ULONG) -> Result<Vec<Attr>, CK_RV> {
    if ulCount == 0 {
        return Ok(Vec::new());
    }
    let template = unsafe { std::slice::from_raw_parts(pTemplate, ulCount as usize) };
    template
        .iter()
        .map(|a| {
            let value = match (a.pValue.is_null(), a.ulValueLen) {
                (_, 0) => Vec::new(),
                (true, _) => return Err(CKR_ATTRIBUTE_VALUE_INVALID),
                (false, len) => unsafe { std::slice::from_raw_parts(a.pValue as *const u8, len as usize) }.to_vec(),
            };
            Ok(Attr { ty: a.type_, value })
        })
        .collect()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() && ulCount > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let template = match unsafe { read_template(pTemplate, ulCount) } {
        Ok(template) => template,
        Err(rv) => return rv,
    };
    with_state(|state| {
        let (slot, generation) = match state.sessions.get(&hSession) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(session) if session.find.is_some() => return CKR_OPERATION_ACTIVE,
            Some(session) => (session.token_slot, session.generation),
        };
        let found = match session_request(state, hSession, &Request::Find { slot, generation, template }) {
            Ok(Response::Objects(found)) => found,
            Ok(_) => return CKR_DEVICE_ERROR,
            Err(rv) => return rv,
        };
        if let Some(session) = state.sessions.get_mut(&hSession) {
            session.find = Some((found, 0));
        }
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_session(hSession, |session| {
        let Some((found, next)) = session.find.as_mut() else {
            return CKR_OPERATION_NOT_INITIALIZED;
        };
        let page = &found[*next..];
        let page = &page[..page.len().min(ulMaxObjectCount as usize)];
        unsafe {
            std::ptr::copy_nonoverlapping(page.as_ptr(), phObject, page.len());
            *pulObjectCount = page.len() as CK_ULONG;
        }
        *next += page.len();
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_session(hSession, |session| {
        if session.find.take().is_none() {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() && ulCount > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let template: &mut [CK_ATTRIBUTE] = if ulCount == 0 {
        &mut []
    } else {
        unsafe { std::slice::from_raw_parts_mut(pTemplate, ulCount as usize) }
    };
    with_state(|state| {
        let Some((slot, generation)) = state.sessions.get(&hSession).map(|s| (s.token_slot, s.generation)) else {
            return CKR_SESSION_HANDLE_INVALID;
        };
        let types = template.iter().map(|a| a.type_).collect();
        let req = Request::GetAttrs { slot, generation, object: hObject, types };
        let values = match session_request(state, hSession, &req) {
            Ok(Response::Attrs(values)) if values.len() == template.len() => values,
            Ok(_) => return CKR_DEVICE_ERROR,
            Err(rv) => return rv,
        };

        // Every attribute is filled in even after one fails; the spec then
        // lets us return any of the per-attribute errors.
        let mut rv = CKR_OK;
        for (attr, value) in template.iter_mut().zip(values) {
            let error = match value {
                AttrValue::Sensitive => CKR_ATTRIBUTE_SENSITIVE,
                AttrValue::Invalid => CKR_ATTRIBUTE_TYPE_INVALID,
                // Two-call pattern: a NULL buffer asks for the size.
                AttrValue::Value(v) if attr.pValue.is_null() => {
                    attr.ulValueLen = v.len() as CK_ULONG;
                    continue;
                }
                AttrValue::Value(v) if attr.ulValueLen >= v.len() as CK_ULONG => {
                    unsafe { std::ptr::copy_nonoverlapping(v.as_ptr(), attr.pValue.cast(), v.len()) };
                    attr.ulValueLen = v.len() as CK_ULONG;
                    continue;
                }
                AttrValue::Value(_) => CKR_BUFFER_TOO_SMALL,
            };
            attr.ulValueLen = CK_UNAVAILABLE_INFORMATION;
            rv = error;
        }
        rv
    })
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// A `CK_ULONG` or `CK_BBOOL` attribute value, as the daemon sent it.
fn ulong(value: &AttrValue) -> Option<CK_ULONG> {
    match value {
        AttrValue::Value(v) => Some(CK_ULONG::from_ne_bytes(v.as_slice().try_into().ok()?)),
        _ => None,
    }
}

fn bbool(value: &AttrValue) -> bool {
    matches!(value, AttrValue::Value(v) if v.first().is_some_and(|&b| b != CK_FALSE))
}

unsafe fn bytes<'a>(p: *const CK_BYTE, len: CK_ULONG) -> &'a [u8] {
    if len == 0 { &[] } else { unsafe { std::slice::from_raw_parts(p, len as usize) } }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: *mut CK_MECHANISM,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    if pMechanism.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mechanism = unsafe { &*pMechanism };
    with_state(|state| {
        let (token_slot, generation) = match state.sessions.get(&hSession) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(session) if session.sign.is_some() => return CKR_OPERATION_ACTIVE,
            Some(session) if !logged_in(state, session) => return CKR_USER_NOT_LOGGED_IN,
            Some(session) => (session.token_slot, session.generation),
        };
        if !MECHANISMS.contains(&mechanism.mechanism) {
            return CKR_MECHANISM_INVALID;
        }
        if !mechanism.pParameter.is_null() || mechanism.ulParameterLen != 0 {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        // Check the key now, so a bad one fails here and not at C_Sign.
        let types = vec![CKA_CLASS, CKA_KEY_TYPE, CKA_SIGN];
        let req = Request::GetAttrs { slot: token_slot, generation, object: hKey, types };
        let attrs = match session_request(state, hSession, &req) {
            Ok(Response::Attrs(attrs)) if attrs.len() == 3 => attrs,
            Ok(_) => return CKR_DEVICE_ERROR,
            Err(CKR_OBJECT_HANDLE_INVALID) => return CKR_KEY_HANDLE_INVALID,
            Err(rv) => return rv,
        };
        if ulong(&attrs[0]) != Some(CKO_PRIVATE_KEY) {
            return CKR_KEY_HANDLE_INVALID;
        }
        if ulong(&attrs[1]) != Some(CKK_EC) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if !bbool(&attrs[2]) {
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
        }
        if let Some(session) = state.sessions.get_mut(&hSession) {
            session.sign = Some(SignOp { mechanism: mechanism.mechanism, key: hKey, message: Vec::new(), signature: None });
        }
        CKR_OK
    })
}

/// Finish the session's signing operation, optionally with a last piece of
/// the message, and hand out the signature. Per the spec, a size query or a
/// too-small buffer keeps the operation going; anything else ends it.
fn finish_sign(
    state: &mut State,
    hSession: CK_SESSION_HANDLE,
    last: &[u8],
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    let Some(session) = state.sessions.get_mut(&hSession) else {
        return CKR_SESSION_HANDLE_INVALID;
    };
    let Some(op) = session.sign.as_mut() else {
        return CKR_OPERATION_NOT_INITIALIZED;
    };
    let signature = match &op.signature {
        Some(signature) => signature.clone(),
        None => {
            op.message.extend_from_slice(last);
            let req = Request::Sign {
                slot: session.token_slot,
                generation: session.generation,
                key: op.key,
                mechanism: CKM_ECDSA,
                data: to_be_signed(op.mechanism, &op.message),
            };
            let slot = session.slot;
            let result = session_request(state, hSession, &req);
            // Gone if the token was replaced (see `session_request`).
            let Some(session) = state.sessions.get_mut(&hSession) else {
                return CKR_SESSION_HANDLE_INVALID;
            };
            match result {
                Ok(Response::Signature(signature)) => {
                    session.sign.as_mut().expect("sign op").signature = Some(signature.clone());
                    signature
                }
                result => {
                    session.sign = None;
                    let rv = match result {
                        Err(rv) => rv,
                        _ => CKR_DEVICE_ERROR,
                    };
                    // The daemon lost our login (card reset, removed): let
                    // the application log in again.
                    if rv == CKR_USER_NOT_LOGGED_IN {
                        state.logged_in.remove(&slot);
                    }
                    return rv;
                }
            }
        }
    };

    let len = signature.len() as CK_ULONG;
    unsafe {
        if pSignature.is_null() {
            *pulSignatureLen = len;
            return CKR_OK;
        }
        if *pulSignatureLen < len {
            *pulSignatureLen = len;
            return CKR_BUFFER_TOO_SMALL;
        }
        std::ptr::copy_nonoverlapping(signature.as_ptr(), pSignature, signature.len());
        *pulSignatureLen = len;
    }
    if let Some(session) = state.sessions.get_mut(&hSession) {
        session.sign = None;
    }
    CKR_OK
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: *mut CK_BYTE,
    ulDataLen: CK_ULONG,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    if pulSignatureLen.is_null() || (pData.is_null() && ulDataLen > 0) {
        return CKR_ARGUMENTS_BAD;
    }
    let data = unsafe { bytes(pData, ulDataLen) };
    with_state(|state| finish_sign(state, hSession, data, pSignature, pulSignatureLen))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignUpdate(hSession: CK_SESSION_HANDLE, pPart: *mut CK_BYTE, ulPartLen: CK_ULONG) -> CK_RV {
    if pPart.is_null() && ulPartLen > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    let part = unsafe { bytes(pPart, ulPartLen) };
    with_session(hSession, |session| match session.sign.as_mut() {
        Some(op) if op.signature.is_none() => {
            op.message.extend_from_slice(part);
            CKR_OK
        }
        _ => CKR_OPERATION_NOT_INITIALIZED,
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: *mut CK_BYTE,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    if pulSignatureLen.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|state| finish_sign(state, hSession, &[], pSignature, pulSignatureLen))
}

// ---------------------------------------------------------------------------
// Everything else is unsupported.
//
// Each stub still needs its exact C signature: the compiler checks it against
// the corresponding `CK_C_*` field type in FUNCTION_LIST above.
// ---------------------------------------------------------------------------

macro_rules! not_supported {
    ($(fn $name:ident($($arg:ty),* $(,)?);)*) => {$(
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $name($(_: $arg),*) -> CK_RV {
            CKR_FUNCTION_NOT_SUPPORTED
        }
    )*};
}

type H = CK_SESSION_HANDLE;
type OBJ = CK_OBJECT_HANDLE;
type BYTES = *mut CK_BYTE;
type LEN = CK_ULONG;
type PLEN = *mut CK_ULONG;
type MECH = *mut CK_MECHANISM;
type ATTRS = *mut CK_ATTRIBUTE;
type POBJ = *mut CK_OBJECT_HANDLE;

not_supported! {
    fn C_InitToken(CK_SLOT_ID, *mut CK_UTF8CHAR, LEN, *mut CK_UTF8CHAR);
    fn C_InitPIN(H, *mut CK_UTF8CHAR, LEN);
    fn C_SetPIN(H, *mut CK_UTF8CHAR, LEN, *mut CK_UTF8CHAR, LEN);
    fn C_GetOperationState(H, BYTES, PLEN);
    fn C_SetOperationState(H, BYTES, LEN, OBJ, OBJ);

    fn C_CreateObject(H, ATTRS, LEN, POBJ);
    fn C_CopyObject(H, OBJ, ATTRS, LEN, POBJ);
    fn C_DestroyObject(H, OBJ);
    fn C_GetObjectSize(H, OBJ, PLEN);
    fn C_SetAttributeValue(H, OBJ, ATTRS, LEN);

    fn C_EncryptInit(H, MECH, OBJ);
    fn C_Encrypt(H, BYTES, LEN, BYTES, PLEN);
    fn C_EncryptUpdate(H, BYTES, LEN, BYTES, PLEN);
    fn C_EncryptFinal(H, BYTES, PLEN);
    fn C_DecryptInit(H, MECH, OBJ);
    fn C_Decrypt(H, BYTES, LEN, BYTES, PLEN);
    fn C_DecryptUpdate(H, BYTES, LEN, BYTES, PLEN);
    fn C_DecryptFinal(H, BYTES, PLEN);

    fn C_DigestInit(H, MECH);
    fn C_Digest(H, BYTES, LEN, BYTES, PLEN);
    fn C_DigestUpdate(H, BYTES, LEN);
    fn C_DigestKey(H, OBJ);
    fn C_DigestFinal(H, BYTES, PLEN);

    fn C_SignRecoverInit(H, MECH, OBJ);
    fn C_SignRecover(H, BYTES, LEN, BYTES, PLEN);
    fn C_VerifyInit(H, MECH, OBJ);
    fn C_Verify(H, BYTES, LEN, BYTES, LEN);
    fn C_VerifyUpdate(H, BYTES, LEN);
    fn C_VerifyFinal(H, BYTES, LEN);
    fn C_VerifyRecoverInit(H, MECH, OBJ);
    fn C_VerifyRecover(H, BYTES, LEN, BYTES, PLEN);

    fn C_DigestEncryptUpdate(H, BYTES, LEN, BYTES, PLEN);
    fn C_DecryptDigestUpdate(H, BYTES, LEN, BYTES, PLEN);
    fn C_SignEncryptUpdate(H, BYTES, LEN, BYTES, PLEN);
    fn C_DecryptVerifyUpdate(H, BYTES, LEN, BYTES, PLEN);

    fn C_GenerateKey(H, MECH, ATTRS, LEN, POBJ);
    fn C_GenerateKeyPair(H, MECH, ATTRS, LEN, ATTRS, LEN, POBJ, POBJ);
    fn C_WrapKey(H, MECH, OBJ, OBJ, BYTES, PLEN);
    fn C_UnwrapKey(H, MECH, OBJ, BYTES, LEN, ATTRS, LEN, POBJ);
    fn C_DeriveKey(H, MECH, OBJ, ATTRS, LEN, POBJ);

    fn C_SeedRandom(H, BYTES, LEN);
    fn C_GenerateRandom(H, BYTES, LEN);

    fn C_GetFunctionStatus(H);
    fn C_CancelFunction(H);
    fn C_WaitForSlotEvent(CK_FLAGS, *mut CK_SLOT_ID, *mut c_void);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split(' ').map(str::to_owned).collect()
    }

    #[test]
    fn jar_names() {
        assert_eq!(jar_name(&args("/usr/bin/java -jar target/autogram-2.6.92.jar --cli")).as_deref(), Some("autogram"));
        assert_eq!(jar_name(&args("java -Xmx1g -jar /opt/tool.jar")).as_deref(), Some("tool"));
        assert_eq!(jar_name(&args("java -jar my-tool.jar")).as_deref(), Some("my-tool"));
        assert_eq!(jar_name(&args("java -cp x.jar Main")), None);
        assert_eq!(jar_name(&args("java -jar")), None);
    }
}
