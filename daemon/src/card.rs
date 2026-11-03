// SPDX-License-Identifier: LGPL-2.1-or-later
//! The card, as seen through OpenSC's PKCS#11 module.
//!
//! OpenSC is driven through raw `C_*` calls: attribute values and `CK_RV`
//! codes pass through to clients unchanged.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::ptr::null_mut;

use cryptoki_sys::*;
use lt_eid_proto::{Attr, AttrValue, Mechanism, Role, Token};

fn check(rv: CK_RV) -> Result<(), CK_RV> {
    if rv == CKR_OK { Ok(()) } else { Err(rv) }
}

/// PKCS#11 strings are fixed-size and blank-padded.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim_end_matches([' ', '\0']).to_owned()
}

/// OpenSC labels each token "<holder name> (<PIN name>)".
fn role(label: &str) -> Role {
    if label.ends_with("(PIN.QES)") { Role::Qes } else { Role::Auth }
}

/// Why storing a CAN failed.
pub enum CanError {
    /// The card refused it.
    Wrong,
    /// Anything else, with lteid-tool's explanation.
    Failed(String),
}

fn initialize(p11: &Pkcs11) -> Result<(), CK_RV> {
    let mut args = CK_C_INITIALIZE_ARGS {
        CreateMutex: None,
        DestroyMutex: None,
        LockMutex: None,
        UnlockMutex: None,
        flags: CKF_OS_LOCKING_OK,
        pReserved: null_mut(),
    };
    check(unsafe { p11.C_Initialize(&mut args as *mut _ as *mut c_void) })
}

pub struct Card {
    p11: Pkcs11,
    /// False after a failed restart of OpenSC (see `store_can`); the next
    /// use tries again.
    initialized: bool,
    /// The lteid-tool of the same OpenSC build: `<prefix>/bin/lteid-tool`
    /// for `<prefix>/lib/opensc-pkcs11.so`.
    lteid_tool: PathBuf,
    /// One read-only session per slot, shared by all clients and opened on
    /// first use. Login state is per token anyway, so per-client sessions
    /// would not isolate anything.
    sessions: HashMap<CK_SLOT_ID, CK_SESSION_HANDLE>,
    /// Slots we logged in to, each with a fresh number per login. Approvals
    /// are tied to it, so they don't outlive a card reset or swap.
    ///
    /// This is our own record, kept instead of asking OpenSC: its
    /// `C_GetSessionInfo` asks the card, and the card reports PIN.QES as not
    /// verified even right after a successful login.
    logins: HashMap<CK_SLOT_ID, u64>,
    last_login: u64,
    /// The tokens as last read, while a card is in. OpenSC asks the card for
    /// the PIN retry counters on every `C_GetTokenInfo`, which takes tens of
    /// milliseconds per token, and clients ask for the tokens all the time.
    /// The card is read-only, and we hold it exclusively, so the tokens only
    /// change when the card goes or comes (see `forget_tokens`), or with a
    /// PIN attempt.
    tokens: Option<Vec<Token>>,
}

impl Card {
    pub fn open(module: &Path) -> Result<Self, String> {
        let p11 = unsafe { Pkcs11::new(module) }.map_err(|e| e.to_string())?;
        initialize(&p11).map_err(|rv| format!("C_Initialize: {rv:#x}"))?;
        let prefix = module.parent().and_then(Path::parent).unwrap_or(Path::new("/"));
        Ok(Card {
            p11,
            initialized: true,
            lteid_tool: prefix.join("bin/lteid-tool"),
            sessions: HashMap::new(),
            logins: HashMap::new(),
            last_login: 0,
            tokens: None,
        })
    }

    fn ready(&mut self) -> Result<(), CK_RV> {
        if !self.initialized {
            initialize(&self.p11)?;
            self.initialized = true;
        }
        Ok(())
    }

    /// Finalize OpenSC, which lets go of the card. Every session and login
    /// ends; the next use starts OpenSC again.
    pub fn release(&mut self) {
        if self.initialized {
            unsafe { self.p11.C_Finalize(null_mut()) };
            self.initialized = false;
        }
        self.sessions.clear();
        self.logins.clear();
        self.tokens = None;
    }

    /// Read the tokens from the card again next time: a card was inserted
    /// or removed, or a reader came or went.
    pub fn forget_tokens(&mut self) {
        self.tokens = None;
    }

    /// Run lteid-tool with `args`, passing it the secret `value` in the
    /// environment variable `var` (so it doesn't show up in ps). OpenSC is
    /// restarted around it: it must let go of the card for lteid-tool, and
    /// it would not retry a card it failed to open until the card is
    /// reinserted. Every session and login ends.
    fn run_lteid_tool(&mut self, args: &[&str], (var, value): (&str, &str)) -> Result<Output, String> {
        self.release();
        let output = Command::new(&self.lteid_tool).args(args).env(var, value).stdin(Stdio::null()).output();
        if let Err(rv) = self.ready() {
            eprintln!("restarting OpenSC: C_Initialize: {rv:#x}");
        }
        output.map_err(|e| format!("{}: {e}", self.lteid_tool.display()))
    }

    /// Check `can` on the card and store it for the lteid driver, using
    /// lteid-tool (see `run_lteid_tool`).
    pub fn store_can(&mut self, can: &str) -> Result<(), CanError> {
        let output = self
            .run_lteid_tool(&["--verify-can", "--can", "env:LT_EID_CAN"], ("LT_EID_CAN", can))
            .map_err(CanError::Failed)?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("CAN number verification failed") {
            Err(CanError::Wrong)
        } else {
            Err(CanError::Failed(stderr.trim().to_owned()))
        }
    }

    /// Resume the eID PIN after two wrong tries suspended it, using
    /// lteid-tool (see `run_lteid_tool`): the card takes a third try only
    /// through PACE with the CAN (the driver's cached one) first, and PACE
    /// with the PIN inside that channel, which the lteid driver can't do on
    /// its own. Right resets the retry counter; wrong blocks the PIN.
    pub fn resume_pin(&mut self, pin: &str) -> Result<(), CK_RV> {
        let output = self
            .run_lteid_tool(&["--resume", "--pin", "env:LT_EID_PIN"], ("LT_EID_PIN", pin))
            .map_err(|e| {
                eprintln!("{e}");
                CKR_FUNCTION_FAILED
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        // "Not blocked": the PIN was not suspended after all, nothing to do.
        if output.status.success() || stderr.contains("is not blocked") {
            // OpenSC looks for the card again when asked for the slots.
            self.tokens()?;
            Ok(())
        } else if stderr.contains("PIN code verification failed") {
            Err(CKR_PIN_INCORRECT)
        } else if stderr.contains("fully blocked") {
            Err(CKR_PIN_LOCKED)
        } else {
            eprintln!("lteid-tool --resume: {}", stderr.trim());
            Err(CKR_FUNCTION_FAILED)
        }
    }

    pub fn tokens(&mut self) -> Result<Vec<Token>, CK_RV> {
        if let Some(tokens) = &self.tokens {
            return Ok(tokens.clone());
        }
        self.ready()?;
        let mut count: CK_ULONG = 0;
        check(unsafe { self.p11.C_GetSlotList(CK_TRUE, null_mut(), &mut count) })?;
        let mut slots = vec![0; count as usize];
        check(unsafe { self.p11.C_GetSlotList(CK_TRUE, slots.as_mut_ptr(), &mut count) })?;
        slots.truncate(count as usize);
        // A session or login on a slot whose token is gone is dead.
        self.sessions.retain(|slot, _| slots.contains(slot));
        self.logins.retain(|slot, _| slots.contains(slot));

        let mut tokens = Vec::new();
        for slot in slots {
            let mut info: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
            match unsafe { self.p11.C_GetTokenInfo(slot, &mut info) } {
                CKR_OK => {}
                // Removed between the two calls, or a card OpenSC can't
                // read: no lteid card, or one without a working CAN.
                CKR_TOKEN_NOT_PRESENT | CKR_TOKEN_NOT_RECOGNIZED => continue,
                rv => return Err(rv),
            }
            // OpenSC adds an empty slot for card-initialization tools.
            if info.flags & CKF_TOKEN_INITIALIZED == 0 {
                continue;
            }
            let label = text(&info.label);
            tokens.push(Token {
                slot,
                role: role(&label),
                label,
                manufacturer: text(&info.manufacturerID),
                model: text(&info.model),
                serial: text(&info.serialNumber),
                flags: info.flags,
                min_pin_len: info.ulMinPinLen,
                max_pin_len: info.ulMaxPinLen,
            });
        }
        // Not without tokens: then the card may only be waiting for its CAN,
        // or for another program to let go of it, and no event tells us.
        if !tokens.is_empty() {
            self.tokens = Some(tokens.clone());
        }
        Ok(tokens)
    }

    pub fn token(&mut self, slot: CK_SLOT_ID) -> Result<Token, CK_RV> {
        self.tokens()?.into_iter().find(|t| t.slot == slot).ok_or(CKR_TOKEN_NOT_PRESENT)
    }

    /// Run `f` with the shared session for `slot`. If the session turns out
    /// to be stale (the card was reinserted), reopen it and try once more.
    fn with_session<T>(
        &mut self,
        slot: CK_SLOT_ID,
        mut f: impl FnMut(&Pkcs11, CK_SESSION_HANDLE) -> Result<T, CK_RV>,
    ) -> Result<T, CK_RV> {
        self.ready()?;
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
                // The card was reinserted: the session and login are gone.
                Err(CKR_SESSION_HANDLE_INVALID | CKR_SESSION_CLOSED) => {
                    self.sessions.remove(&slot);
                    self.logins.remove(&slot);
                    self.tokens = None;
                }
                result => {
                    if let Err(CKR_USER_NOT_LOGGED_IN | CKR_DEVICE_REMOVED | CKR_TOKEN_NOT_PRESENT) = result {
                        self.logins.remove(&slot);
                    }
                    if let Err(CKR_DEVICE_REMOVED | CKR_TOKEN_NOT_PRESENT) = result {
                        self.tokens = None;
                    }
                    return result;
                }
            }
        }
        Err(CKR_SESSION_HANDLE_INVALID)
    }

    /// Swap the shared session for a fresh one, dropping whatever operation
    /// the old one was in the middle of. The new session opens first:
    /// closing a token's last session would log it out.
    fn replace_session(&mut self, slot: CK_SLOT_ID) {
        let Some(old) = self.sessions.remove(&slot) else {
            return;
        };
        let mut new = 0;
        let rv = unsafe { self.p11.C_OpenSession(slot, CKF_SERIAL_SESSION, null_mut(), None, &mut new) };
        // If none opens, the token is gone and the old session with it.
        if rv == CKR_OK {
            self.sessions.insert(slot, new);
            unsafe { self.p11.C_CloseSession(old) };
        }
    }

    /// The number of the current login on `slot`, or `None` if the token is
    /// logged out.
    pub fn login_id(&self, slot: CK_SLOT_ID) -> Option<u64> {
        self.logins.get(&slot).copied()
    }

    /// Log the token in `slot` in and return the new login's number.
    ///
    /// There is deliberately no logout: the lteid driver tears down the PACE
    /// channel on logout, which would log out every token on the card.
    pub fn login(&mut self, slot: CK_SLOT_ID, pin: &[u8]) -> Result<u64, CK_RV> {
        // Right or wrong, the PIN changes the retry counters.
        self.tokens = None;
        self.with_session(slot, |p11, session| {
            // OpenSC only reads the PIN, the `*mut` is a C API wart.
            let (pin, len) = (pin.as_ptr() as *mut _, pin.len() as CK_ULONG);
            match unsafe { p11.C_Login(session, CKU_USER, pin, len) } {
                // OpenSC still counts an earlier login that we no longer
                // trust (the card lost it), and returns without checking the
                // PIN. A context-specific login makes the card check it.
                CKR_USER_ALREADY_LOGGED_IN => check(unsafe { p11.C_Login(session, CKU_CONTEXT_SPECIFIC, pin, len) }),
                rv => check(rv),
            }
        })?;
        self.last_login += 1;
        self.logins.insert(slot, self.last_login);
        Ok(self.last_login)
    }

    pub fn mechanisms(&mut self, slot: CK_SLOT_ID) -> Result<Vec<Mechanism>, CK_RV> {
        self.ready()?;
        let mut count: CK_ULONG = 0;
        check(unsafe { self.p11.C_GetMechanismList(slot, null_mut(), &mut count) })?;
        let mut types = vec![0; count as usize];
        check(unsafe { self.p11.C_GetMechanismList(slot, types.as_mut_ptr(), &mut count) })?;
        types.truncate(count as usize);
        types
            .into_iter()
            .map(|ty| {
                let mut info: CK_MECHANISM_INFO = unsafe { std::mem::zeroed() };
                check(unsafe { self.p11.C_GetMechanismInfo(slot, ty, &mut info) })?;
                Ok(Mechanism {
                    ty,
                    min_key_size: info.ulMinKeySize,
                    max_key_size: info.ulMaxKeySize,
                    flags: info.flags,
                })
            })
            .collect()
    }

    /// Whether `key` needs the PIN again for every signature.
    pub fn always_authenticate(&mut self, slot: CK_SLOT_ID, key: CK_OBJECT_HANDLE) -> Result<bool, CK_RV> {
        let values = self.get_attrs(slot, key, &[CKA_ALWAYS_AUTHENTICATE])?;
        Ok(matches!(values.first(), Some(AttrValue::Value(v)) if v.first().is_some_and(|&b| b != CK_FALSE)))
    }

    /// Sign `data` with `key`. With `pin`, log in for this one signature
    /// first (`CKU_CONTEXT_SPECIFIC`), as keys with `CKA_ALWAYS_AUTHENTICATE`
    /// require.
    pub fn sign(
        &mut self,
        slot: CK_SLOT_ID,
        key: CK_OBJECT_HANDLE,
        mechanism: CK_MECHANISM_TYPE,
        data: &[u8],
        pin: Option<&[u8]>,
    ) -> Result<Vec<u8>, CK_RV> {
        if pin.is_some() {
            // Right or wrong, the PIN changes the retry counters.
            self.tokens = None;
        }
        let mut started = false;
        let result = self.with_session(slot, |p11, session| unsafe {
            let mut mechanism = CK_MECHANISM { mechanism, pParameter: null_mut(), ulParameterLen: 0 };
            check(p11.C_SignInit(session, &mut mechanism, key))?;
            started = true;
            if let Some(pin) = pin {
                // OpenSC only reads the PIN, the `*mut` is a C API wart.
                check(p11.C_Login(session, CKU_CONTEXT_SPECIFIC, pin.as_ptr() as *mut _, pin.len() as CK_ULONG))?;
            }
            // Big enough for any EC or RSA signature, so no size query.
            let mut signature = vec![0u8; 1024];
            let mut len = signature.len() as CK_ULONG;
            check(p11.C_Sign(session, data.as_ptr() as *mut _, data.len() as CK_ULONG, signature.as_mut_ptr(), &mut len))?;
            signature.truncate(len as usize);
            Ok(signature)
        });
        // After a failure the operation may still be active, and PKCS#11
        // 2.40 has no way to cancel it.
        if result.is_err() && started {
            self.replace_session(slot);
        }
        result
    }

    pub fn find(&mut self, slot: CK_SLOT_ID, template: &[Attr]) -> Result<Vec<u64>, CK_RV> {
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

    pub fn get_attrs(&mut self, slot: CK_SLOT_ID, object: CK_OBJECT_HANDLE, types: &[u64]) -> Result<Vec<AttrValue>, CK_RV> {
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
