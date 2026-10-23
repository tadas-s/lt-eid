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
- `daemon/`: `lt-eidd`. Drives OpenSC through raw `C_*` calls (`cryptoki-sys`),
  so attribute bytes and `CK_RV` codes pass through unchanged.

## Status

- Slot and token info, object search and `C_GetAttributeValue` come from the
  card via the daemon. `pkcs11-tool -O` lists the card's objects.
- Sessions are local to the module. The daemon keeps one shared read-only
  session per OpenSC slot and runs each search start to finish under its lock.
- Login is still a local stand-in (any PIN is accepted). Crypto returns
  `CKR_FUNCTION_NOT_SUPPORTED`.
- With the daemon down, the module still loads and shows an empty slot;
  operations on open sessions return `CKR_DEVICE_REMOVED`. Clients reconnect
  on their own once the daemon is back.

## Build and try

    cargo build --release
    target/release/lt-eidd [path/to/opensc-pkcs11.so]   # default /opt/opensc/lib/opensc-pkcs11.so

    M=target/release/liblt_eid_pkcs11.so
    pkcs11-tool --module $M -I     # library info
    pkcs11-tool --module $M -L     # slot / token from the card

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
