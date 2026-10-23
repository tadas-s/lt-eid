//! The card, as seen through OpenSC's PKCS#11 module.
//!
//! OpenSC is driven through raw `C_*` calls: attribute values and `CK_RV`
//! codes pass through to clients unchanged.

use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::ptr::null_mut;

use cryptoki_sys::*;
use lt_eid_proto::{Attr, AttrValue, Role, Token};

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

pub struct Card {
    p11: Pkcs11,
    /// One read-only session per slot, shared by all clients and opened on
    /// first use. Login state is per token anyway, so per-client sessions
    /// would not isolate anything.
    sessions: HashMap<CK_SLOT_ID, CK_SESSION_HANDLE>,
    /// A fresh number for every login we perform. Approvals are tied to it,
    /// so they don't outlive a card reset or swap.
    logins: HashMap<CK_SLOT_ID, u64>,
    last_login: u64,
}

impl Card {
    pub fn open(module: &Path) -> Result<Self, String> {
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
        Ok(Card { p11, sessions: HashMap::new(), logins: HashMap::new(), last_login: 0 })
    }

    pub fn tokens(&mut self) -> Result<Vec<Token>, CK_RV> {
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

    /// The number of the current login on `slot`, or `None` if the token is
    /// logged out.
    pub fn login_id(&mut self, slot: CK_SLOT_ID) -> Result<Option<u64>, CK_RV> {
        let state = self.with_session(slot, |p11, session| {
            let mut info: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
            check(unsafe { p11.C_GetSessionInfo(session, &mut info) })?;
            Ok(info.state)
        })?;
        let logged_in = matches!(state, CKS_RO_USER_FUNCTIONS | CKS_RW_USER_FUNCTIONS);
        Ok(logged_in.then(|| self.logins.get(&slot).copied().unwrap_or(0)))
    }

    /// Log the token in `slot` in and return the new login's number.
    ///
    /// There is deliberately no logout: the lteid driver tears down the PACE
    /// channel on logout, which would log out every token on the card.
    pub fn login(&mut self, slot: CK_SLOT_ID, pin: &[u8]) -> Result<u64, CK_RV> {
        let rv = self.with_session(slot, |p11, session| {
            // OpenSC only reads the PIN, the `*mut` is a C API wart.
            check(unsafe { p11.C_Login(session, CKU_USER, pin.as_ptr() as *mut _, pin.len() as CK_ULONG) })
        });
        match rv {
            Ok(()) | Err(CKR_USER_ALREADY_LOGGED_IN) => {}
            Err(rv) => return Err(rv),
        }
        self.last_login += 1;
        self.logins.insert(slot, self.last_login);
        Ok(self.last_login)
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
