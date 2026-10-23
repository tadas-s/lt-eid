# lt-eid

PKCS#11 access to the Lithuanian eID card through one central daemon.

Applications (browsers, Autogram, `pkcs11-tool`) load a small proxy module.
The proxy never touches the card; it forwards to `lt-eidd` over a unix socket.
`lt-eidd` loads a private OpenSC build (`/opt/opensc`) and owns the only
connection to the card, so PACE runs once and clients never fight over it.

    Firefox ─┐
    Chrome  ─┼─ liblt_eid_pkcs11.so ── $XDG_RUNTIME_DIR/lt-eid/sock ──▶ lt-eidd ──▶ opensc-pkcs11.so ──▶ card
    Autogram ┘

## Crates

- `proto/`: requests, responses and framing (little-endian `u32` length + postcard).
- `pkcs11/`: the proxy module, a `cdylib` built as `liblt_eid_pkcs11.so`.
- `daemon/`: `lt-eidd`.
  - `card.rs` drives OpenSC through raw `C_*` calls (`cryptoki-sys`), so
    attribute bytes and `CK_RV` codes pass through unchanged.
  - `dialog.rs` shows PIN and approval dialogs through pinentry.
  - `main.rs` serves clients and decides who may use which token.

## Status

- Two fixed slots: 0 is the authentication token ("PACE-PIN"), 1 the
  qualified signature token ("PIN.QES"). The daemon tells them apart by the
  OpenSC token label.
- Slot and token info, object search, `C_GetAttributeValue` and login go to
  the daemon. Crypto still returns `CKR_FUNCTION_NOT_SUPPORTED`.
- Sessions are local to the module. The daemon keeps one shared read-only
  session per OpenSC slot and runs each search start to finish under its lock.
- With the daemon down, the module still loads and shows empty slots;
  operations on open sessions return `CKR_DEVICE_REMOVED`. Clients reconnect
  on their own once the daemon is back.

## Login

Tokens advertise `CKF_PROTECTED_AUTHENTICATION_PATH`, so applications call
`C_Login` without a PIN (a PIN passed anyway is ignored). The daemon then:

- asks for the PIN if the token is logged out. It retries on a wrong PIN,
  showing the card's retry warnings, and rejects a PIN of the wrong length
  before it reaches the card. Cancel returns `CKR_FUNCTION_CANCELED`.
- asks only for approval (Allow / Deny) if another application already
  logged the token in.

Approvals belong to the application's connection and to that particular
card login: `C_Logout`, closing the last session, exiting, or the card
being reset all end it. The daemon never logs the card out (the lteid
driver's logout tears down PACE, logging out both tokens).

Until an application is logged in to a token, searches only return its
public objects, even if the card itself is logged in.

Dialogs use `pinentry` from `$PATH`, or `$LT_EID_PINENTRY`. Start `lt-eidd`
from inside the desktop session so pinentry can open a window.

## Build and try

    cargo build --release
    target/release/lt-eidd [path/to/opensc-pkcs11.so]   # default /opt/opensc/lib/opensc-pkcs11.so

    M=target/release/liblt_eid_pkcs11.so
    pkcs11-tool --module $M -I     # library info
    pkcs11-tool --module $M -L     # slots / tokens from the card
    pkcs11-tool --module $M --slot 0 --login -O    # PIN dialog, then private objects too

`LT_EID_SOCKET` overrides the socket path for both sides.

### Without a card

Any PKCS#11 module can stand in for OpenSC, e.g. SoftHSM:

    export SOFTHSM2_CONF=/path/to/softhsm2.conf LT_EID_SOCKET=/tmp/lt-eid-test.sock
    softhsm2-util --init-token --free --label "Test eID" --pin 123456 --so-pin 12345678
    target/release/lt-eidd /usr/lib64/pkcs11/libsofthsm2.so &
    pkcs11-tool --module $M -O

To register the module with p11-kit, so that NSS, GnuTLS and others find it,
create `~/.config/pkcs11/modules/lt-eid.module` containing:

    module: /home/robot/src/lt-eid/target/release/liblt_eid_pkcs11.so

## How the module works

- `crate-type = ["cdylib"]` builds a plain C shared library.
- `cryptoki-sys` provides the C structs, constants and function-pointer types.
- `C_GetFunctionList` returns a pointer to a static `CK_FUNCTION_LIST`.
  Applications call everything else through that table.
- Global state is a `Mutex<Option<State>>`. `None` means "not initialized".
  The daemon connection lives in it, opened on first use and reopened after
  `fork()`; only one request per process is in flight.
- `panic = "abort"` is set in the release profile, so a Rust panic never unwinds
  into the C caller.
