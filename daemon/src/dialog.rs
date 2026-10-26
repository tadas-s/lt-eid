//! PIN and approval dialogs, shown through pinentry.

use std::ffi::OsString;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use cryptoki_sys::*;
use lt_eid_proto::{Role, Token};
use pinentry::{Error, PassphraseInput};
use secrecy::SecretString;

const TITLE: &str = "Lithuanian eID";
/// Seconds before an unanswered dialog counts as cancelled.
const TIMEOUT: u16 = 60;
const CAN_TIMEOUT: u16 = 300;

/// Why a dialog is shown.
#[derive(Clone, Copy)]
pub enum Purpose {
    Login,
    Sign,
}

pub struct Dialogs {
    /// `$LT_EID_PINENTRY`, or `pinentry` from `$PATH`.
    binary: OsString,
}

impl Dialogs {
    pub fn new() -> Self {
        let binary = std::env::var_os("LT_EID_PINENTRY").unwrap_or_else(|| "pinentry".into());
        Dialogs { binary }
    }

    /// Ask the user to let `app` go ahead without a PIN: to use a token
    /// someone already logged in to, or to sign.
    pub fn approve(&self, app: &str, token: &Token, purpose: Purpose) -> Result<(), CK_RV> {
        let ok = match purpose {
            Purpose::Login => "Allow",
            Purpose::Sign => "Sign",
        };
        let timeout = TIMEOUT.to_string();
        let setup = [
            ("SETTITLE", TITLE),
            ("SETDESC", &describe(app, token, purpose)),
            ("SETOK", ok),
            ("SETCANCEL", "Deny"),
            ("SETTIMEOUT", &timeout),
        ];
        match self.confirm(&setup) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CKR_FUNCTION_CANCELED),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err(missing(&self.binary)),
            Err(e) => {
                eprintln!("pinentry: {e}");
                Err(CKR_FUNCTION_FAILED)
            }
        }
    }

    /// Run pinentry's CONFIRM after the `setup` requests: `true` for OK,
    /// `false` for Cancel or timeout. Spoken here directly because the
    /// crate's `ConfirmationDialog` never sends its title, which leaves the
    /// dialog headed "Message".
    fn confirm(&self, setup: &[(&str, &str)]) -> io::Result<bool> {
        let mut child = Command::new(&self.binary).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()?;
        let mut input = BufReader::new(child.stdout.take().expect("piped"));
        let mut output = child.stdin.take().expect("piped");
        let answer = (|| {
            reply(&mut input)?.map_err(|code| io::Error::other(format!("greeting: error {code}")))?;
            for (command, argument) in setup {
                output.write_all(request(command, argument).as_bytes())?;
                reply(&mut input)?.map_err(|code| io::Error::other(format!("{command}: error {code}")))?;
            }
            output.write_all(b"CONFIRM\n")?;
            match reply(&mut input)? {
                Ok(()) => Ok(true),
                Err(GPG_ERR_CANCELED | GPG_ERR_TIMEOUT | GPG_ERR_NOT_CONFIRMED) => Ok(false),
                Err(code) => Err(io::Error::other(format!("CONFIRM: error {code}"))),
            }
        })();
        let _ = output.write_all(b"BYE\n");
        drop(output);
        let _ = child.wait();
        answer
    }

    /// Ask `app`'s user for the PIN of `token`. `error` explains why we ask
    /// again after a failed attempt.
    pub fn pin(&self, app: &str, token: &Token, purpose: Purpose, error: Option<&str>) -> Result<SecretString, CK_RV> {
        let Some(mut input) = PassphraseInput::with_binary(&self.binary) else {
            return Err(missing(&self.binary));
        };
        let mut description = describe(app, token, purpose);
        if token.flags & CKF_USER_PIN_FINAL_TRY != 0 {
            description += "\n\nThis is the last try: a wrong PIN will block it.";
        } else if token.flags & CKF_USER_PIN_COUNT_LOW != 0 {
            description += "\n\nAn earlier PIN attempt was wrong.";
        }
        // GNOME's pinentry shows the prompt as the dialog's heading.
        let prompt = match token.role {
            Role::Auth => "eID PIN",
            Role::Qes => "PIN.QES",
        };
        input
            .with_title(TITLE)
            .with_description(&description)
            .with_prompt(prompt)
            .with_ok(match purpose {
                Purpose::Login => "Log in",
                Purpose::Sign => "Sign",
            })
            .with_timeout(TIMEOUT);
        if let Some(error) = error {
            input.with_error(error);
        }
        input.interact().map_err(failed)
    }

    /// Ask for the card access number of a newly inserted card. `error`
    /// explains why we ask again after a failed attempt.
    pub fn can(&self, error: Option<&str>) -> Result<SecretString, CK_RV> {
        let Some(mut input) = PassphraseInput::with_binary(&self.binary) else {
            return Err(missing(&self.binary));
        };
        input
            .with_title(TITLE)
            .with_description(
                "A Lithuanian eID card was inserted. To use it, enter its card access number (CAN): \
                 the 6 digits in the bottom right corner of the card's front.",
            )
            .with_prompt("Card access number")
            .with_ok("Continue")
            // Long enough to go and find the card.
            .with_timeout(CAN_TIMEOUT);
        if let Some(error) = error {
            input.with_error(error);
        }
        input.interact().map_err(failed)
    }
}

// libgpg-error codes pinentry answers with (the low 16 bits of an ERR).
const GPG_ERR_TIMEOUT: u32 = 62;
const GPG_ERR_CANCELED: u32 = 99;
const GPG_ERR_NOT_CONFIRMED: u32 = 114;

/// One Assuan request line, percent-escaping what can't appear raw.
fn request(command: &str, argument: &str) -> String {
    let mut line = format!("{command} ");
    for c in argument.chars() {
        match c {
            '%' | '\n' | '\r' | '\\' => line.push_str(&format!("%{:02X}", c as u32)),
            c => line.push(c),
        }
    }
    line.push('\n');
    line
}

/// Read up to the next OK (`Ok`) or ERR (`Err` with its error code),
/// skipping status and comment lines.
fn reply(input: &mut impl BufRead) -> io::Result<Result<(), u32>> {
    loop {
        let mut line = String::new();
        if input.read_line(&mut line)? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let line = line.trim_end();
        if line == "OK" || line.starts_with("OK ") {
            return Ok(Ok(()));
        }
        if let Some(rest) = line.strip_prefix("ERR ") {
            let code: u32 = rest.split(' ').next().and_then(|c| c.parse().ok()).unwrap_or(0);
            return Ok(Err(code & 0xFFFF));
        }
    }
}

/// How dialogs name an application, from the program name its module
/// reported (see the module's `app_name`).
fn display_name(app: &str) -> &str {
    match app {
        "firefox" | "firefox-bin" | "firefox-esr" => "Firefox",
        "thunderbird" | "thunderbird-bin" => "Thunderbird",
        "chrome" | "google-chrome" => "Google Chrome",
        "chromium" | "chromium-browser" => "Chromium",
        "autogram" | "Autogram" => "Autogram",
        "evolution" => "Evolution",
        "soffice.bin" => "LibreOffice",
        app => app,
    }
}

fn describe(app: &str, token: &Token, purpose: Purpose) -> String {
    let app = display_name(app);
    let what = match (purpose, token.role) {
        (Purpose::Login, Role::Auth) => "to use your eID to authenticate you",
        (Purpose::Login, Role::Qes) => "to use your eID for qualified electronic signatures",
        (Purpose::Sign, Role::Auth) => "to sign with your eID authentication key",
        (Purpose::Sign, Role::Qes) => "to make a qualified electronic signature",
    };
    format!("{app} wants {what}.\n\n{}", token.label)
}

fn missing(binary: &OsString) -> CK_RV {
    eprintln!("pinentry program {binary:?} not found");
    CKR_FUNCTION_FAILED
}

fn failed(e: Error) -> CK_RV {
    match e {
        Error::Cancelled | Error::Timeout => CKR_FUNCTION_CANCELED,
        e => {
            eprintln!("pinentry: {e}");
            CKR_FUNCTION_FAILED
        }
    }
}
