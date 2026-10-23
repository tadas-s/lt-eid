//! The lt-eid PKCS#11 module.
//!
//! It never talks to the card itself. It forwards to the lt-eid daemon over
//! a unix socket, and the daemon owns the one connection to the card.
//!
//! So far only slot and token information come from the daemon. Sessions,
//! login and object search are still local stand-ins (any PIN is accepted,
//! searches find nothing); every cryptographic operation returns
//! `CKR_FUNCTION_NOT_SUPPORTED`.
//!
//! Applications load the shared library, call `C_GetFunctionList` and from
//! then on go through the returned table of function pointers.

#![allow(non_snake_case)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, MutexGuard};

use cryptoki_sys::*;
use lt_eid_proto::{PROTO_VERSION, Request, Response, Token, read_frame, write_frame};

const SLOT_ID: CK_SLOT_ID = 0;
const PKCS11_VERSION: CK_VERSION = CK_VERSION { major: 2, minor: 40 };

// ---------------------------------------------------------------------------
// Global module state
// ---------------------------------------------------------------------------

struct Session {
    flags: CK_FLAGS,
    find_active: bool,
}

struct State {
    sessions: HashMap<CK_SESSION_HANDLE, Session>,
    next_handle: CK_SESSION_HANDLE,
    logged_in: bool,
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

fn connect() -> std::io::Result<UnixStream> {
    let path = lt_eid_proto::socket_path()
        .ok_or_else(|| std::io::Error::other("no socket path"))?;
    let mut conn = UnixStream::connect(path)?;
    write_frame(&mut conn, &Request::Hello { proto: PROTO_VERSION })?;
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
    if state.conn.is_none() {
        state.conn = connect().ok();
    }
    let conn = state.conn.as_mut()?;
    let resp = write_frame(conn, req).and_then(|()| read_frame(conn));
    if resp.is_err() {
        state.conn = None;
    }
    resp.ok()
}

/// The token behind our slot, if the daemon is up and a card is inserted.
fn token(state: &mut State) -> Option<Token> {
    match call(state, &Request::Tokens)? {
        // OpenSC shows one token per PIN; the first is the authentication one.
        Response::Tokens(tokens) => tokens.into_iter().next(),
        _ => None,
    }
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
        logged_in: false,
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
        // The slot always exists; only its token comes and goes.
        let count = if tokenPresent == CK_FALSE || token(state).is_some() { 1 } else { 0 };
        // Standard PKCS#11 two-call pattern: a NULL list asks for the size.
        if pSlotList.is_null() {
            *pulCount = count;
            return CKR_OK;
        }
        if *pulCount < count {
            *pulCount = count;
            return CKR_BUFFER_TOO_SMALL;
        }
        if count == 1 {
            *pSlotList = SLOT_ID;
        }
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
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        let present = if token(state).is_some() { CKF_TOKEN_PRESENT } else { 0 };
        let info = CK_SLOT_INFO {
            slotDescription: padded("Lithuanian eID"),
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
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        let Some(token) = token(state) else {
            return CKR_TOKEN_NOT_PRESENT;
        };
        let rw_count = state
            .sessions
            .values()
            .filter(|s| s.flags & CKF_RW_SESSION != 0)
            .count();
        let mut flags = CKF_TOKEN_INITIALIZED | CKF_USER_PIN_INITIALIZED;
        for (set, flag) in [
            (token.pin_count_low, CKF_USER_PIN_COUNT_LOW),
            (token.pin_final_try, CKF_USER_PIN_FINAL_TRY),
            (token.pin_locked, CKF_USER_PIN_LOCKED),
        ] {
            if set {
                flags |= flag;
            }
        }
        let info = CK_TOKEN_INFO {
            label: padded(&token.label),
            manufacturerID: padded(&token.manufacturer),
            model: padded(&token.model),
            serialNumber: padded(&token.serial),
            flags,
            ulMaxSessionCount: CK_EFFECTIVELY_INFINITE,
            ulSessionCount: state.sessions.len() as CK_ULONG,
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    _pMechanismList: *mut CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    if pulCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_state(|_| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        // We support no mechanisms at all.
        unsafe { *pulCount = 0 };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    _type: CK_MECHANISM_TYPE,
    _pInfo: *mut CK_MECHANISM_INFO,
) -> CK_RV {
    with_state(|_| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        CKR_MECHANISM_INVALID
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
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        // Required by the spec for legacy reasons.
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
        }
        if token(state).is_none() {
            return CKR_TOKEN_NOT_PRESENT;
        }
        let handle = state.next_handle;
        state.next_handle += 1;
        state.sessions.insert(handle, Session { flags, find_active: false });
        unsafe { *phSession = handle };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if state.sessions.remove(&hSession).is_none() {
            return CKR_SESSION_HANDLE_INVALID;
        }
        // Login state is per-token and ends with its last session.
        if state.sessions.is_empty() {
            state.logged_in = false;
        }
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    with_state(|state| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        state.sessions.clear();
        state.logged_in = false;
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
        let rw = session.flags & CKF_RW_SESSION != 0;
        let info = CK_SESSION_INFO {
            slotID: SLOT_ID,
            state: match (rw, state.logged_in) {
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
        if !state.sessions.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if userType != CKU_USER {
            return CKR_USER_TYPE_INVALID;
        }
        if state.logged_in {
            return CKR_USER_ALREADY_LOGGED_IN;
        }
        // Any PIN is accepted.
        state.logged_in = true;
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_state(|state| {
        if !state.sessions.contains_key(&hSession) {
            return CKR_SESSION_HANDLE_INVALID;
        }
        if !state.logged_in {
            return CKR_USER_NOT_LOGGED_IN;
        }
        state.logged_in = false;
        CKR_OK
    })
}

// ---------------------------------------------------------------------------
// Object search -- the token is empty, so every search finds nothing.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    if pTemplate.is_null() && ulCount > 0 {
        return CKR_ARGUMENTS_BAD;
    }
    with_session(hSession, |session| {
        if session.find_active {
            return CKR_OPERATION_ACTIVE;
        }
        session.find_active = true;
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    _ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    if phObject.is_null() || pulObjectCount.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    with_session(hSession, |session| {
        if !session.find_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        unsafe { *pulObjectCount = 0 };
        CKR_OK
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    with_session(hSession, |session| {
        if !session.find_active {
            return CKR_OPERATION_NOT_INITIALIZED;
        }
        session.find_active = false;
        CKR_OK
    })
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
    fn C_GetAttributeValue(H, OBJ, ATTRS, LEN);
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

    fn C_SignInit(H, MECH, OBJ);
    fn C_Sign(H, BYTES, LEN, BYTES, PLEN);
    fn C_SignUpdate(H, BYTES, LEN);
    fn C_SignFinal(H, BYTES, PLEN);
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
