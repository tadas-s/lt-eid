// SPDX-License-Identifier: LGPL-2.1-or-later
//! Watches the card readers for a Lithuanian eID being inserted.
//!
//! Watching reads PC/SC reader status only: the card itself stays with
//! OpenSC, which may hold it exclusively. Only `held_by_another` connects,
//! briefly.

use std::ffi::CString;
use std::time::Duration;

use pcsc::{Context, Error, PNP_NOTIFICATION, Protocols, ReaderState, Scope, ShareMode, State};

/// The Lithuanian eID ATR, as in opensc.conf; the last three bytes vary.
const ATR: [u8; 21] = [
    0x3b, 0x9d, 0x18, 0x81, 0x31, 0xfc, 0x35, 0x80, 0x31, 0xc0, 0x69, 0x4d, 0x54, 0x43, 0x4f, 0x53, 0x73, 0x02,
    0x00, 0x00, 0x00,
];
const ATR_MASK: [u8; 21] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00,
];

fn is_lteid(atr: &[u8]) -> bool {
    atr.len() == ATR.len() && atr.iter().zip(ATR_MASK).zip(ATR).all(|((byte, mask), want)| byte & mask == want)
}

/// Whether another program has the card in `reader` open, so that OpenSC
/// can't have it (it connects exclusively). Our own OpenSC must have let go
/// of it first. Tries an exclusive connection, and drops it right away.
pub fn held_by_another(reader: &str) -> bool {
    let (Ok(ctx), Ok(reader)) = (Context::establish(Scope::User), CString::new(reader)) else {
        return false;
    };
    matches!(ctx.connect(&reader, ShareMode::Exclusive, Protocols::ANY), Err(Error::SharingViolation))
}

/// Call `changed` whenever a card or reader comes or goes, and right away.
/// Then, after `changed`, call `inserted` with the reader's name whenever a
/// Lithuanian eID is inserted, and once for each one already in a reader.
/// Never returns; if pcscd goes away, starts over once it is back.
pub fn watch(mut changed: impl FnMut(), mut inserted: impl FnMut(&str)) -> ! {
    loop {
        // Cards may have come or gone while we weren't watching.
        changed();
        if let Err(e) = watch_until_error(&mut changed, &mut inserted) {
            eprintln!("card monitor: {e}");
        }
        std::thread::sleep(Duration::from_secs(5));
    }
}

fn watch_until_error(changed: &mut impl FnMut(), inserted: &mut impl FnMut(&str)) -> Result<(), Error> {
    let ctx = Context::establish(Scope::User)?;
    // The PnP entry wakes us when readers are plugged in or out.
    let mut states = vec![ReaderState::new(PNP_NOTIFICATION(), State::UNAWARE)];
    let mut had_readers = true;
    loop {
        states.retain(|rs| !rs.event_state().intersects(State::UNKNOWN | State::IGNORE));
        let names = match ctx.list_readers_owned() {
            Ok(names) => names,
            Err(Error::NoReadersAvailable) => Vec::new(),
            Err(e) => return Err(e),
        };
        if had_readers && names.is_empty() {
            eprintln!("no card readers");
        }
        had_readers = !names.is_empty();
        for name in names {
            if !states.iter().any(|rs| rs.name() == name.as_c_str()) {
                eprintln!("reader {:?} found", name.to_string_lossy());
                states.push(ReaderState::new(name, State::UNAWARE));
            }
        }
        for rs in &mut states {
            rs.sync_current_state();
        }

        ctx.get_status_change(None, &mut states)?;

        for rs in &states {
            if rs.name() == PNP_NOTIFICATION() {
                continue;
            }
            let reader = rs.name().to_string_lossy();
            let (now, before) = (rs.event_state(), rs.current_state());
            if now.intersects(State::UNKNOWN | State::IGNORE) {
                eprintln!("reader {reader:?} gone");
                changed();
            } else if now.contains(State::PRESENT) && !before.contains(State::PRESENT) {
                changed();
                let atr = rs.atr();
                let lteid = is_lteid(atr);
                let what = if lteid { "Lithuanian eID" } else { "not a Lithuanian eID" };
                eprintln!("{reader}: card inserted, ATR {}: {what}{}", hex(atr), flags(now));
                if lteid {
                    inserted(&reader);
                }
            } else if before.contains(State::PRESENT) && !now.contains(State::PRESENT) {
                eprintln!("{reader}: card removed");
                changed();
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
}

/// Reader states worth knowing about when a card won't work, e.g. one
/// another program holds exclusively, or one that doesn't answer.
fn flags(state: State) -> String {
    [(State::EXCLUSIVE, "exclusive"), (State::INUSE, "in use"), (State::MUTE, "mute"), (State::UNPOWERED, "unpowered")]
        .into_iter()
        .filter(|&(flag, _)| state.contains(flag))
        .map(|(_, name)| format!(" ({name})"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_lithuanian_eid_atr() {
        let card = [
            0x3b, 0x9d, 0x18, 0x81, 0x31, 0xfc, 0x35, 0x80, 0x31, 0xc0, 0x69, 0x4d, 0x54, 0x43, 0x4f, 0x53, 0x73,
            0x02, 0x06, 0x05, 0xd0,
        ];
        assert!(is_lteid(&card));
        assert!(!is_lteid(&card[..20]));
        let mut other = card;
        other[1] = 0x9e;
        assert!(!is_lteid(&other));
    }
}
