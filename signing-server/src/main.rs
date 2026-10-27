// SPDX-License-Identifier: LGPL-2.1-or-later
//! lt-eid-signing-server: logs in to Elpako-based sites (epaslaugos.lt) with
//! the Lithuanian eID.
//!
//! Such sites talk to "Elpako Signer", a local web service, from the
//! browser. This implements the part of its protocol used for
//! authentication, over HTTPS on 127.0.0.1:38888.
//!
//! The card is used through the lt-eid PKCS#11 module like any other
//! application does, so lt-eidd asks for the PIN or approval: each
//! signature logs in and out again, which makes the daemon ask every time.

use std::io::Read;
use std::net::TcpListener;
use std::os::fd::FromRawFd;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use cryptoki::context::{CInitializeArgs, CInitializeFlags, Pkcs11};
use cryptoki::error::{Error as P11Error, RvError};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::slot::Slot;
use serde_json::{Value, json};
use tiny_http::{Header, Method, Request, Response, Server, SslConfig};
use x509_parser::prelude::*;

/// The lt-eid PKCS#11 module.
const DEFAULT_MODULE: &str = "/opt/lt-eid/lib/lt-eid-pkcs11.so";
/// Where Elpako Signer listens.
const LISTEN: &str = "127.0.0.1:38888";
/// The only web origin allowed to use the service.
const ALLOWED_ORIGIN: &str = "https://api.elpako.lt";
/// Requests are small: a certificate and the data to sign.
const MAX_BODY: usize = 1 << 20;

/// Self-signed certificate for 127.0.0.1, the same as the Python server's,
/// so that browsers that already accept it keep doing so.
const TLS_CERT: &[u8] = include_bytes!("../ssl/cert.pem");
const TLS_KEY: &[u8] = include_bytes!("../ssl/key.pem");

/// An error answer: Elpako's clients show `exception` to the user.
struct Failure {
    code: &'static str,
    message: String,
}

fn fail(code: &'static str, message: impl Into<String>) -> Failure {
    Failure { code, message: message.into() }
}

impl From<P11Error> for Failure {
    fn from(e: P11Error) -> Self {
        eprintln!("pkcs11: {e}");
        fail("error", format!("Klaida: {e}"))
    }
}

/// A certificate found on a token, with the id of its private key.
struct Found {
    slot: Slot,
    id: Vec<u8>,
    der: Vec<u8>,
}

/// Every certificate on every token. Certificates are public: no login.
fn certificates(p11: &Pkcs11) -> Result<Vec<Found>, P11Error> {
    let mut found = Vec::new();
    for slot in p11.get_slots_with_token()? {
        let session = p11.open_ro_session(slot)?;
        for cert in session.find_objects(&[Attribute::Class(ObjectClass::CERTIFICATE)])? {
            let (mut id, mut der) = (Vec::new(), Vec::new());
            for attr in session.get_attributes(cert, &[AttributeType::Id, AttributeType::Value])? {
                match attr {
                    Attribute::Id(v) => id = v,
                    Attribute::Value(v) => der = v,
                    _ => {}
                }
            }
            found.push(Found { slot, id, der });
        }
    }
    Ok(found)
}

/// Whether a certificate is meant for logging in: digital signature key
/// usage and the TLS client authentication extended key usage.
fn for_authentication(cert: &X509Certificate) -> bool {
    let signs = matches!(cert.key_usage(), Ok(Some(ku)) if ku.value.digital_signature());
    let client_auth = matches!(cert.extended_key_usage(), Ok(Some(eku)) if eku.value.client_auth);
    signs && client_auth
}

/// The authentication certificate on the card, if any.
fn authentication_certificate(p11: &Pkcs11) -> Result<Option<Found>, P11Error> {
    Ok(certificates(p11)?.into_iter().find(|found| {
        X509Certificate::from_der(&found.der).is_ok_and(|(_, cert)| for_authentication(&cert))
    }))
}

fn first(mut values: impl Iterator<Item = String>) -> String {
    values.next().unwrap_or_default()
}

/// GET /Signing/SelectCertificate?purpose=authentication&...
fn select_certificate(p11: &Pkcs11, purpose: Option<&str>) -> Result<Value, Failure> {
    if purpose != Some("authentication") {
        return Err(fail("only_authentication", "Galima tik autentifikacija."));
    }
    let Some(found) = authentication_certificate(p11)? else {
        return Err(fail(
            "no_certificate",
            "Nerastas tinkamas autentifikacijos sertifikatas. Patikrinkite ar kortelė skaitytuve ir paruošta darbui.",
        ));
    };
    let (_, cert) = X509Certificate::from_der(&found.der).map_err(|e| fail("no_certificate", e.to_string()))?;
    let as_string = |attr: &AttributeTypeAndValue| attr.as_str().ok().map(str::to_owned);
    Ok(json!({
        "certificate": BASE64.encode(&found.der),
        "name": first(cert.subject().iter_common_name().filter_map(as_string)),
        "issuer": first(cert.issuer().iter_organization().filter_map(as_string)),
        "validTo": cert.validity().not_after.to_datetime().date().to_string(),
    }))
}

/// POST /Signing/Sign {"certificate": <base64 DER>, "dtbs": <base64 data>}
///
/// Signs the data with ECDSA over SHA-256 (the module hashes it) and returns
/// the raw r || s signature.
fn sign(p11: &Pkcs11, body: &[u8]) -> Result<Value, Failure> {
    let params: Value = serde_json::from_slice(body).map_err(|e| fail("bad_request", e.to_string()))?;
    let decode = |name: &str| {
        params[name]
            .as_str()
            .and_then(|s| BASE64.decode(s).ok())
            .ok_or_else(|| fail("bad_request", format!("Trūksta „{name}“")))
    };
    let (wanted, data) = (decode("certificate")?, decode("dtbs")?);

    let bad_cert = || fail("bad_cert", "Nerastas tinkamas sertifikatas");
    // Only the authentication certificate: this is for logging in, not for
    // qualified signatures.
    let found = authentication_certificate(p11)?.filter(|found| found.der == wanted).ok_or_else(bad_cert)?;

    let session = p11.open_ro_session(found.slot)?;
    // No PIN: the token has a protected authentication path, and lt-eidd
    // asks for the PIN, or only for approval if the card is logged in.
    match session.login(UserType::User, None) {
        Ok(()) | Err(P11Error::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => {}
        Err(P11Error::Pkcs11(RvError::FunctionCanceled, _)) => return Err(fail("bad_pin", "Atšaukta")),
        Err(P11Error::Pkcs11(RvError::PinLocked, _)) => return Err(fail("bad_pin", "PIN užblokuotas")),
        Err(e) => return Err(e.into()),
    }
    let result = (|| {
        let key = session
            .find_objects(&[Attribute::Class(ObjectClass::PRIVATE_KEY), Attribute::Id(found.id)])?
            .into_iter()
            .next()
            .ok_or_else(bad_cert)?;
        match session.sign(&Mechanism::EcdsaSha256, key, &data) {
            Ok(signature) => Ok(json!({ "result": BASE64.encode(signature) })),
            Err(P11Error::Pkcs11(RvError::FunctionRejected, _)) => Err(fail("bad_pin", "Atšaukta")),
            Err(e) => Err(e.into()),
        }
    })();
    // Ends this login's approval, so the next one asks again. The card
    // itself stays logged in.
    let _ = session.logout();
    result
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name, value).expect("valid header")
}

fn request_header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    request.headers().iter().find(|h| h.field.equiv(name)).map(|h| h.value.as_str())
}

/// One query parameter's raw value.
fn query_param<'a>(url: &'a str, name: &str) -> Option<&'a str> {
    let (_, query) = url.split_once('?')?;
    query.split('&').find_map(|pair| match pair.split_once('=') {
        Some((key, value)) if key == name => Some(value),
        _ => None,
    })
}

fn handle(p11: &Pkcs11, request: &mut Request) -> Response<std::io::Cursor<Vec<u8>>> {
    let origin = request_header(request, "Origin").map(str::to_owned);
    // Browsers send an Origin with every cross-site request: refuse other
    // sites outright rather than only hiding the answer from them.
    if origin.as_deref().is_some_and(|o| o != ALLOWED_ORIGIN) {
        return Response::from_string("Forbidden").with_status_code(403);
    }
    let cors = |response: Response<_>| match &origin {
        Some(origin) => response.with_header(header("Access-Control-Allow-Origin", origin)).with_header(header("Vary", "Origin")),
        None => response,
    };

    let url = request.url().to_owned();
    let path = url.split('?').next().unwrap_or_default();
    let json = |result: Result<Value, Failure>| {
        let value = result.unwrap_or_else(|f| json!({ "exception": f.message, "errorCode": f.code }));
        Response::from_string(value.to_string()).with_header(header("Content-Type", "application/json"))
    };
    let text = |s: &str| Response::from_string(s).with_header(header("Content-Type", "text/html; charset=utf-8"));

    let response = match (request.method(), path) {
        (Method::Options, _) => {
            // CORS preflight, for the JSON POST.
            let mut response = Response::from_string("")
                .with_status_code(204)
                .with_header(header("Access-Control-Allow-Methods", "GET, POST, OPTIONS"))
                .with_header(header("Access-Control-Max-Age", "600"));
            if let Some(headers) = request_header(request, "Access-Control-Request-Headers") {
                response.add_header(header("Access-Control-Allow-Headers", headers));
            }
            // Chrome's Private Network Access: a public site calling localhost.
            if request_header(request, "Access-Control-Request-Private-Network") == Some("true") {
                response.add_header(header("Access-Control-Allow-Private-Network", "true"));
            }
            response
        }
        (Method::Get, "/") => text("<p>Parašo serveris veikia.</p>"),
        // The user's name, for Elpako's own software that runs as root on
        // behalf of several users. Any name will do here.
        (Method::Get, "/Handshake/Browser") => text("jonas"),
        (Method::Get, "/Signing/GetVersion") => text("3.3.9"),
        (Method::Get, "/Signing/SelectCertificate") => json(select_certificate(p11, query_param(&url, "purpose"))),
        (Method::Post, "/Signing/Sign") => {
            let mut body = Vec::new();
            match request.as_reader().take(MAX_BODY as u64 + 1).read_to_end(&mut body) {
                Ok(n) if n > MAX_BODY => Response::from_string("Too large").with_status_code(413),
                Ok(_) => json(sign(p11, &body)),
                Err(e) => Response::from_string(e.to_string()).with_status_code(400),
            }
        }
        _ => Response::from_string("Not found").with_status_code(404),
    };
    cors(response)
}

/// The listening socket systemd passed us (socket activation), if any.
fn activated_listener() -> Option<TcpListener> {
    let pid = std::env::var("LISTEN_PID").ok()?;
    let fds = std::env::var("LISTEN_FDS").ok()?;
    if pid.parse::<u32>().ok()? != std::process::id() {
        return None;
    }
    if fds.parse::<u32>().ok()? != 1 {
        eprintln!("expected one socket from systemd");
        return None;
    }
    // The first passed descriptor is 3 (SD_LISTEN_FDS_START).
    Some(unsafe { TcpListener::from_raw_fd(3) })
}

fn main() {
    let module: PathBuf = std::env::args_os().nth(1).map(Into::into).unwrap_or_else(|| DEFAULT_MODULE.into());
    let p11 = Pkcs11::new(&module)
        .and_then(|p11| p11.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)).map(|()| p11))
        .unwrap_or_else(|e| {
            eprintln!("loading {}: {e}", module.display());
            std::process::exit(1);
        });

    let tls = SslConfig { certificate: TLS_CERT.to_vec(), private_key: TLS_KEY.to_vec() };
    let server = match activated_listener() {
        Some(listener) => {
            eprintln!("using {}, listening on the socket from systemd", module.display());
            Server::from_listener(listener, Some(tls))
        }
        None => {
            eprintln!("using {}, listening on https://{LISTEN}", module.display());
            Server::https(LISTEN, tls)
        }
    };
    let server = server.unwrap_or_else(|e| {
        eprintln!("listening: {e}");
        std::process::exit(1);
    });

    // One request at a time: a login waits for the user's answer in
    // lt-eidd's dialog, and later requests wait for it.
    for mut request in server.incoming_requests() {
        let response = handle(&p11, &mut request);
        if let Err(e) = request.respond(response) {
            eprintln!("responding: {e}");
        }
    }
}
