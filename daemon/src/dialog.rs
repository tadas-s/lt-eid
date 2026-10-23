//! PIN and approval dialogs, shown through pinentry.

use std::ffi::OsString;

use cryptoki_sys::*;
use lt_eid_proto::{Role, Token};
use pinentry::{ConfirmationDialog, Error, PassphraseInput};
use secrecy::SecretString;

const TITLE: &str = "Lithuanian eID";
/// Seconds before an unanswered dialog counts as cancelled.
const TIMEOUT: u16 = 60;

pub struct Dialogs {
    /// `$LT_EID_PINENTRY`, or `pinentry` from `$PATH`.
    binary: OsString,
}

impl Dialogs {
    pub fn new() -> Self {
        let binary = std::env::var_os("LT_EID_PINENTRY").unwrap_or_else(|| "pinentry".into());
        Dialogs { binary }
    }

    /// Ask the user to let `app` use a token someone already logged in to.
    pub fn approve(&self, app: &str, token: &Token) -> Result<(), CK_RV> {
        let Some(mut dialog) = ConfirmationDialog::with_binary(&self.binary) else {
            return Err(missing(&self.binary));
        };
        dialog.with_title(TITLE).with_ok("Allow").with_cancel("Deny").with_timeout(TIMEOUT);
        match dialog.confirm(&describe(app, token)) {
            Ok(true) => Ok(()),
            Ok(false) => Err(CKR_FUNCTION_CANCELED),
            Err(e) => Err(failed(e)),
        }
    }

    /// Ask `app`'s user for the PIN of `token`. `error` explains why we ask
    /// again after a failed attempt.
    pub fn pin(&self, app: &str, token: &Token, error: Option<&str>) -> Result<SecretString, CK_RV> {
        let Some(mut input) = PassphraseInput::with_binary(&self.binary) else {
            return Err(missing(&self.binary));
        };
        let mut description = describe(app, token);
        if token.flags & CKF_USER_PIN_FINAL_TRY != 0 {
            description += "\n\nThis is the last try: a wrong PIN will block it.";
        } else if token.flags & CKF_USER_PIN_COUNT_LOW != 0 {
            description += "\n\nAn earlier PIN attempt was wrong.";
        }
        let prompt = match token.role {
            Role::Auth => "PIN:",
            Role::Qes => "PIN.QES:",
        };
        input
            .with_title(TITLE)
            .with_description(&description)
            .with_prompt(prompt)
            .with_ok("Log in")
            .with_timeout(TIMEOUT);
        if let Some(error) = error {
            input.with_error(error);
        }
        input.interact().map_err(failed)
    }
}

fn describe(app: &str, token: &Token) -> String {
    let purpose = match token.role {
        Role::Auth => "to authenticate you",
        Role::Qes => "for qualified electronic signatures",
    };
    format!("{app} wants to use your eID {purpose}.\n\n{}", token.label)
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
