// SPDX-License-Identifier: LGPL-2.1-or-later
//! lt-eid: asks lt-eidd to manage the card's PINs.
//!
//! The daemon does the work and shows every dialog, including the outcome,
//! so this also works without a terminal (e.g. from the desktop entry).

use std::io;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use cryptoki_sys::*;
use lt_eid_proto::{PROTO_VERSION, Request, Response, read_frame, write_frame};

const USAGE: &str = "usage: lt-eid change-pin";

fn call(request: &Request) -> io::Result<Response> {
    let path = lt_eid_proto::socket_path()
        .ok_or_else(|| io::Error::other("neither LT_EID_SOCKET nor XDG_RUNTIME_DIR is set"))?;
    let mut conn = UnixStream::connect(&path).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))?;
    write_frame(&mut conn, &Request::Hello { proto: PROTO_VERSION, app: "lt-eid".to_owned() })?;
    match read_frame(&mut conn)? {
        Response::Hello { proto: PROTO_VERSION } => {}
        _ => return Err(io::Error::other("lt-eidd speaks another protocol version")),
    }
    write_frame(&mut conn, request)?;
    read_frame(&mut conn)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let request = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["change-pin"] => Request::ChangePin,
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let rv = match call(&request) {
        Ok(Response::Ok) => return ExitCode::SUCCESS,
        Ok(Response::Rv(rv)) => rv,
        Ok(other) => {
            eprintln!("lt-eid: unexpected answer from lt-eidd: {other:?}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("lt-eid: talking to lt-eidd: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The daemon already told the user why; this is for a terminal.
    let why = match rv {
        CKR_FUNCTION_CANCELED => "cancelled".to_owned(),
        CKR_TOKEN_NOT_PRESENT => "no card".to_owned(),
        CKR_PIN_LOCKED => "PIN blocked".to_owned(),
        rv => format!("failed ({rv:#x}), see journalctl --user -u lt-eidd"),
    };
    eprintln!("lt-eid: {why}");
    ExitCode::FAILURE
}
