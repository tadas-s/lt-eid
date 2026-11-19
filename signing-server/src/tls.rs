// SPDX-License-Identifier: LGPL-2.1-or-later
//! The HTTPS certificate for 127.0.0.1, one per user.
//!
//! Elpako's clients call https://127.0.0.1:38888, so the service needs a
//! certificate, and the user accepts it once in the browser. It is made on
//! the first start and kept in the service's state directory: a key that
//! only this user has means that another program or user taking the port
//! gets a browser warning rather than the accepted certificate.
//!
//! It is deliberately not a CA: if someone adds it to their trusted
//! authorities to get rid of the warning, it vouches for 127.0.0.1 and
//! nothing else.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use openssl::asn1::{Asn1Integer, Asn1Time};
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier};
use openssl::x509::{X509, X509Builder, X509NameBuilder};

const KEY_FILE: &str = "tls-key.pem";
const CERT_FILE: &str = "tls-cert.pem";
const VALID_DAYS: u32 = 10 * 365;

/// The certificate and key, PEM encoded, as tiny_http takes them.
pub struct Identity {
    pub certificate: Vec<u8>,
    pub private_key: Vec<u8>,
    pub cert_path: PathBuf,
    pub fingerprint: String,
    pub created: bool,
}

/// Where the certificate lives: systemd's StateDirectory= when run as the
/// user service, otherwise $XDG_STATE_HOME/lt-eid (~/.local/state/lt-eid).
pub fn state_dir() -> Option<PathBuf> {
    if let Some(dirs) = std::env::var_os("STATE_DIRECTORY") {
        // A colon-separated list when a unit names several; ours names one.
        let first = dirs.to_str()?.split(':').next()?.to_owned();
        return Some(first.into());
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".local/state")))?;
    Some(base.join("lt-eid"))
}

/// Loads the certificate in `dir`, or makes a new one if there is none or
/// it has expired. A certificate put there by hand is used as it is.
pub fn load_or_create(dir: &Path) -> io::Result<Identity> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);

    if let Some(certificate) = read_if_exists(&cert_path)? {
        let cert = X509::from_pem(&certificate).map_err(|e| bad(&cert_path, e))?;
        if !expired(&cert).map_err(|e| bad(&cert_path, e))? {
            let private_key = fs::read(&key_path).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", key_path.display())))?;
            let key = PKey::private_key_from_pem(&private_key).map_err(|e| bad(&key_path, e))?;
            let pubkey = cert.public_key().map_err(|e| bad(&cert_path, e))?;
            if !pubkey.public_eq(&key) {
                return Err(io::Error::other(format!("{} does not belong to {}", key_path.display(), cert_path.display())));
            }
            let fingerprint = fingerprint(&cert).map_err(|e| bad(&cert_path, e))?;
            return Ok(Identity { certificate, private_key, cert_path, fingerprint, created: false });
        }
        eprintln!("{} has expired, making a new one", cert_path.display());
    }

    let (cert, private_key) = generate().map_err(io::Error::other)?;
    let certificate = cert.to_pem().map_err(io::Error::other)?;
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    write_atomically(&key_path, &private_key, 0o600)?;
    write_atomically(&cert_path, &certificate, 0o644)?;
    let fingerprint = fingerprint(&cert).map_err(io::Error::other)?;
    Ok(Identity { certificate, private_key, cert_path, fingerprint, created: true })
}

fn generate() -> Result<(X509, Vec<u8>), ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;

    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "lt-eid")?;
    name.append_entry_by_nid(Nid::COMMONNAME, "127.0.0.1")?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(127, MsbOption::MAYBE_ZERO, false)?;

    let serial = Asn1Integer::from_bn(&serial)?;
    let not_before = Asn1Time::days_from_now(0)?;
    let not_after = Asn1Time::days_from_now(VALID_DAYS)?;

    let mut builder = X509Builder::new()?;
    builder.set_version(2)?;
    builder.set_serial_number(&serial)?;
    builder.set_subject_name(&name)?;
    builder.set_issuer_name(&name)?;
    builder.set_pubkey(&key)?;
    builder.set_not_before(&not_before)?;
    builder.set_not_after(&not_after)?;
    builder.append_extension(BasicConstraints::new().critical().build()?)?;
    builder.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    builder.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let san = SubjectAlternativeName::new().ip("127.0.0.1").build(&builder.x509v3_context(None, None))?;
    builder.append_extension(san)?;
    let ski = SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?;
    builder.append_extension(ski)?;
    builder.sign(&key, MessageDigest::sha256())?;

    Ok((builder.build(), key.private_key_to_pem_pkcs8()?))
}

fn expired(cert: &X509) -> Result<bool, ErrorStack> {
    Ok(cert.not_after() < Asn1Time::days_from_now(0)?)
}

fn fingerprint(cert: &X509) -> Result<String, ErrorStack> {
    let digest = cert.digest(MessageDigest::sha256())?;
    Ok(digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":"))
}

fn read_if_exists(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
    }
}

fn write_atomically(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
    let tmp = path.with_file_name(format!(".{name}.tmp"));
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&tmp, path)
}

fn bad(path: &Path, e: ErrorStack) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("{}: {e}", path.display()))
}
