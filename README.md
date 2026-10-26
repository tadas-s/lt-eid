# lt-eid

PKCS#11 access to the Lithuanian eID card through one central daemon.

Applications (browsers, Autogram, `pkcs11-tool`) load a small proxy module.
The proxy never touches the card; it forwards to `lt-eidd` over a unix socket.
`lt-eidd` loads a private OpenSC build (`/opt/opensc`) and owns the only
connection to the card, so PACE runs once and clients never fight over it.

    Firefox ─┐
    Chrome  ─┼─ lt-eid-pkcs11.so ──── $XDG_RUNTIME_DIR/lt-eid/sock ──▶ lt-eidd ──▶ opensc-pkcs11.so ──▶ card
    Autogram ┘

## Crates

- `proto/`: requests, responses and framing (little-endian `u32` length + postcard).
- `pkcs11/`: the proxy module, a `cdylib` built as `liblt_eid_pkcs11.so`
  (installed as `lt-eid-pkcs11.so`).
- `daemon/`: `lt-eidd`.
  - `card.rs` drives OpenSC through raw `C_*` calls (`cryptoki-sys`), so
    attribute bytes and `CK_RV` codes pass through unchanged.
  - `dialog.rs` shows PIN and approval dialogs through pinentry.
  - `main.rs` serves clients and decides who may use which token.

## Status

- Two fixed slots: 0 is the authentication token ("PACE-PIN"), 1 the
  qualified signature token ("PIN.QES"). The daemon tells them apart by the
  OpenSC token label.
- Slot and token info, object search, `C_GetAttributeValue`, login and
  signing go to the daemon. Other crypto (verify, decrypt, ...) returns
  `CKR_FUNCTION_NOT_SUPPORTED`.
- Sessions are local to the module. The daemon keeps one shared read-only
  session per OpenSC slot and runs each search start to finish under its lock.
- With the daemon down, the module still loads and shows empty slots;
  operations on open sessions return `CKR_DEVICE_REMOVED`. Clients reconnect
  on their own once the daemon is back, and must log in again (object
  handles from before the restart are invalid).

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

## Card access number (CAN)

The card only talks to OpenSC after PACE with its CAN, the 6 digits on the
front. The lteid driver keeps one CAN in `~/.cache/opensc/lteid_can`.

`lt-eidd` watches the readers (PC/SC status only, without connecting). When a
card with the Lithuanian eID ATR is inserted, or is already in when the
daemon starts, and OpenSC can't open it with the cached CAN, the daemon asks
for the CAN. It then stores it with `lteid-tool --verify-can` (from the same
OpenSC build as the module, `<prefix>/bin/lteid-tool`), restarting its OpenSC
around that: OpenSC must let go of the card, and it won't retry a card it
failed to open until the card is reinserted. A wrong CAN asks again; after a
cancel, reinserting the card asks again.

To see the dialog in time, `lt-eidd.service` starts with the desktop session
(`graphical-session.target`).

Both units run only in a regular user's desktop session
(`ConditionEnvironment=XDG_SESSION_CLASS=user`, bound to
`graphical-session.target`) and stop at logout. Outside one there is no
socket, and the module shows empty slots.

## Signing

The module offers `CKM_ECDSA` and `CKM_ECDSA_SHA256/384/512` (when the card
offers `CKM_ECDSA`). It hashes the message itself, so the card only ever does
raw `CKM_ECDSA`; single- and multi-part signing both work. The daemon signs
in one go under the card lock, and the module keeps the signature for the
second call of the size-query pattern, so the card signs once.

What the user sees per signature:

- authentication key: nothing; logging in was enough.
- a key with `CKA_ALWAYS_AUTHENTICATE` (expected for the QES key): a PIN
  dialog. The daemon logs in for that one signature
  (`CKU_CONTEXT_SPECIFIC`); an application's own context-specific `C_Login`
  is accepted without a PIN.
- a QES key without it: an approval dialog.

A refused or cancelled signature returns `CKR_FUNCTION_REJECTED`. After a
failed signature the daemon replaces its shared session, since PKCS#11 2.40
can't cancel an operation (it opens the new session first: closing a slot's
last session would log it out).

Dialogs name the application by its program name (for `java -jar`, the
jar's name), shown nicer for known ones ("firefox" becomes "Firefox").

Dialogs use `pinentry` from `$PATH`, or `$LT_EID_PINENTRY`. Start `lt-eidd`
from inside the desktop session so pinentry can open a window.

## Build and try

    cargo build --release
    target/release/lt-eidd [path/to/opensc-pkcs11.so]   # default /opt/lt-eid/lib/opensc-pkcs11.so
                                                        # (or let systemd start it, below)

    M=target/release/liblt_eid_pkcs11.so
    pkcs11-tool --module $M -I     # library info
    pkcs11-tool --module $M -L     # slots / tokens from the card
    pkcs11-tool --module $M --slot 0 --login -O    # PIN dialog, then private objects too

`LT_EID_SOCKET` overrides the socket path for both sides.

### As a systemd user service

`systemd/` has a socket unit and a service: in a desktop session systemd
listens on `$XDG_RUNTIME_DIR/lt-eid/sock` and runs `lt-eidd`. The
service inherits the desktop session's environment, which pinentry needs to
open its window.

    systemctl --user link $PWD/systemd/lt-eidd.socket $PWD/systemd/lt-eidd.service
    systemctl --user enable lt-eidd.socket lt-eidd.service   # from the next desktop login

The service runs `/opt/lt-eid/bin/lt-eidd`. To run a development build instead, add
a drop-in (`systemctl --user edit lt-eidd.service`):

    [Service]
    ExecStart=
    ExecStart=/path/to/lt-eid/target/release/lt-eidd

After rebuilding, `systemctl --user restart lt-eidd.service` (this logs the
card out). Logs: `journalctl --user -u lt-eidd`. Started by hand while the
socket unit is active, `lt-eidd` refuses to take over its socket.

### RPM package

`packaging/lt-eid.spec` builds one package with everything in `/opt/lt-eid`:

    /opt/lt-eid/bin/lt-eidd
    /opt/lt-eid/bin/{opensc-tool,pkcs11-tool,pkcs15-tool,opensc-explorer,lteid-tool}
    /opt/lt-eid/lib/lt-eid-pkcs11.so       the module applications load
    /opt/lt-eid/lib/opensc-pkcs11.so       private OpenSC, libopensc linked in
    /opt/lt-eid/etc/opensc.conf            lteid driver only, exclusive card access

plus the systemd user units (with a preset that enables the socket for every
user) and a p11-kit registration of the module. The private OpenSC is the
same snapshot as Fedora's, built with `packaging/opensc-static-libopensc.patch`
so that it installs no `libopensc.so` and stays out of the system OpenSC's way.

    packaging/make-sources.sh      # this tree, vendored crates, OpenSC patch
    rpmbuild -bb packaging/lt-eid.spec

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
