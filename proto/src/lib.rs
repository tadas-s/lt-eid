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
pub const PROTO_VERSION: u32 = 2;

/// Upper bound for a single frame. Certificates are the largest payload.
pub const MAX_FRAME: usize = 64 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub enum Request {
    /// Must be the first request on a connection.
    Hello { proto: u32 },
    /// List the tokens currently present.
    Tokens,
    /// Find all objects on the token in `slot` matching `template`.
    Find { slot: u64, template: Vec<Attr> },
    /// Read attributes of one object, in the order given.
    GetAttrs { slot: u64, object: u64, types: Vec<u64> },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Response {
    Hello { proto: u32 },
    Tokens(Vec<Token>),
    Objects(Vec<u64>),
    /// One entry per requested type.
    Attrs(Vec<AttrValue>),
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
    /// `CK_TOKEN_INFO.flags`, unmodified.
    pub flags: u64,
    pub min_pin_len: u64,
    pub max_pin_len: u64,
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
        write_frame(&mut buf, &Request::Hello { proto: PROTO_VERSION }).unwrap();
        write_frame(&mut buf, &Request::Tokens).unwrap();

        let mut r = buf.as_slice();
        assert!(matches!(read_frame(&mut r).unwrap(), Request::Hello { proto: PROTO_VERSION }));
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
