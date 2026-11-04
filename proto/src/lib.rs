// SPDX-License-Identifier: LGPL-2.1-or-later
//! Wire protocol between the lt-eid PKCS#11 module and the lt-eid daemon.
//!
//! The module connects to a unix stream socket and sends `Request`s; the
//! daemon answers each one with exactly one `Response`. Every message is a
//! frame: a little-endian `u32` length followed by that many bytes of
//! postcard-encoded data.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Bumped on any incompatible change to `Request` or `Response`.
pub const PROTO_VERSION: u32 = 5;

/// Upper bound for a single frame. Certificates are the largest payload.
pub const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Must be the first request on a connection. `app` names the client
    /// in the daemon's dialogs.
    Hello { proto: u32, app: String },
    /// List the tokens currently present.
    Tokens,
    /// Find all objects on the token in `slot` matching `template`.
    ///
    /// Requests that take or return object handles carry the `generation`
    /// of the token they belong to (see `Token::generation`). For another
    /// one the daemon answers `CKR_SESSION_HANDLE_INVALID`.
    Find { slot: u64, generation: u64, template: Vec<Attr> },
    /// Read attributes of one object, in the order given.
    GetAttrs { slot: u64, generation: u64, object: u64, types: Vec<u64> },
    /// Log this client in to the token in `slot`. The daemon asks the user
    /// for the PIN, or only for approval if the token is already logged in.
    /// Blocks until the user answers.
    Login { slot: u64 },
    /// Log this client out. The card itself stays logged in for others.
    Logout { slot: u64 },
    /// The token's mechanisms, as OpenSC reports them.
    Mechanisms { slot: u64 },
    /// Sign `data` with a mechanism that takes no parameters, in one go.
    /// May show a dialog (PIN or approval) and block until it is answered.
    Sign { slot: u64, generation: u64, key: u64, mechanism: u64, data: Vec<u8> },
    /// Change the card's PIN: the eID PIN and PIN.QES together. The daemon
    /// asks for the current and new PIN and shows the outcome itself.
    /// Blocks until done.
    ChangePin,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Hello { proto: u32 },
    Ok,
    Tokens(Vec<Token>),
    Objects(Vec<u64>),
    /// One entry per requested type.
    Attrs(Vec<AttrValue>),
    Mechanisms(Vec<Mechanism>),
    Signature(Vec<u8>),
    /// The request failed with this `CK_RV`.
    Rv(u64),
}

/// A token as reported by the daemon's OpenSC, one per PIN on the card.
/// Strings have their blank padding removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub slot: u64,
    pub label: String,
    pub manufacturer: String,
    pub model: String,
    pub serial: String,
    pub role: Role,
    /// `CK_TOKEN_INFO.flags`, unmodified.
    pub flags: u64,
    pub min_pin_len: u64,
    pub max_pin_len: u64,
    /// Changes whenever the daemon's object handles and logins become
    /// invalid: the card was removed or inserted, or the daemon restarted
    /// OpenSC (to change the PIN, store a CAN, or resume the PIN). The
    /// token is a new one to applications then.
    pub generation: u64,
}

/// A `CK_MECHANISM_INFO` with its mechanism type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mechanism {
    pub ty: u64,
    pub min_key_size: u64,
    pub max_key_size: u64,
    pub flags: u64,
}

/// What a token is for. OpenSC shows one token per PIN on the card.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    /// The PACE PIN token: authentication key, used for TLS client login.
    Auth,
    /// The PIN.QES token: qualified signature key.
    Qes,
}

/// A `CK_ATTRIBUTE` with its value as raw bytes. Both ends run on the same
/// machine, so native-endian `CK_ULONG` values need no conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attr {
    pub ty: u64,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttrValue {
    Value(Vec<u8>),
    /// `CKR_ATTRIBUTE_SENSITIVE`
    Sensitive,
    /// `CKR_ATTRIBUTE_TYPE_INVALID`
    Invalid,
}

/// `$LT_EID_SOCKET`, or `$XDG_RUNTIME_DIR/lt-eid/sock`.
pub fn socket_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("LT_EID_SOCKET") {
        return Some(path.into());
    }
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")?;
    Some(PathBuf::from(runtime).join("lt-eid").join("sock"))
}

pub fn write_frame<T: Serialize>(w: &mut impl Write, msg: &T) -> io::Result<()> {
    let body = postcard::to_stdvec(msg).map_err(io::Error::other)?;
    if body.len() > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    // One write, so a frame is never split across two syscalls by us.
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
    buf.extend_from_slice(&body);
    w.write_all(&buf)
}

pub fn read_frame<T: DeserializeOwned>(r: &mut impl Read) -> io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    postcard::from_bytes(&body).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &Request::Hello { proto: PROTO_VERSION, app: "test".into() }).unwrap();
        write_frame(&mut buf, &Request::Tokens).unwrap();

        let mut r = buf.as_slice();
        assert!(matches!(read_frame(&mut r).unwrap(), Request::Hello { proto: PROTO_VERSION, .. }));
        assert!(matches!(read_frame(&mut r).unwrap(), Request::Tokens));
        assert!(r.is_empty());
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut buf = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
        buf.resize(4 + MAX_FRAME + 1, 0);
        let err = read_frame::<Request>(&mut buf.as_slice()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
