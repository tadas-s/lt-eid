# dummy-pkcs11

A minimal PKCS#11 (Cryptoki 2.40) module written in Rust that does nothing useful.
It shows how a module is put together.

- One slot (`0`) with an empty, initialized token
- Sessions, login (any PIN accepted) and object search work. Searches find nothing.
- No mechanisms. Every crypto or object function returns `CKR_FUNCTION_NOT_SUPPORTED`.

## Build

    cargo build --release
    # -> target/release/libdummy_pkcs11.so

## Try it

    M=target/release/libdummy_pkcs11.so
    pkcs11-tool --module $M -I               # library info
    pkcs11-tool --module $M -L               # slots / token
    pkcs11-tool --module $M --login --pin 1234 -O

To register it with p11-kit, so that NSS, GnuTLS and others can find it, create
`~/.config/pkcs11/modules/dummy.module` containing:

    module: /home/robot/src/dummy-pkcs11/target/release/libdummy_pkcs11.so

## How it works

- `crate-type = ["cdylib"]` builds a plain C shared library.
- `cryptoki-sys` provides the C structs, constants and function-pointer types.
- `C_GetFunctionList` returns a pointer to a static `CK_FUNCTION_LIST`.
  Applications call everything else through that table.
- Global state is a `Mutex<Option<State>>`. `None` means "not initialized".
- `panic = "abort"` is set in the release profile, so a Rust panic never unwinds
  into the C caller.
