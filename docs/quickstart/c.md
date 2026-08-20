# C ABI quickstart

The C header is Aster's stable native application boundary and the foundation
for the Go and Python bindings. It is also the integration point for C, C++, and
languages with a C-compatible foreign-function interface.

**Time:** about ten minutes after Rust and a C compiler are installed.

## Prerequisites

- A checkout of this repository
- The [shared Rust toolchain prerequisite](README.md#shared-toolchain-prerequisite)
- A C11 compiler and system linker

## Build the library and example

From the repository root:

```sh
cargo build -p aster-ffi
cc -std=c11 \
  -I bindings/c \
  examples/c_basic.c \
  -L target/debug -laster_ffi \
  -o /tmp/aster-c-basic
```

Run it on Linux or macOS:

```sh
LD_LIBRARY_PATH="$PWD/target/debug" \
DYLD_LIBRARY_PATH="$PWD/target/debug" \
  /tmp/aster-c-basic \
  bindings/testdata/non-production-provisioning.bundle \
  /tmp/aster-c-example.db
```

The output contains a stable ItemID and the payload:

```text
item=<64 hexadecimal characters> payload={"lat":38.9,"lon":-77.0}
```

Read the fully commented source in
[`examples/c_basic.c`](../../examples/c_basic.c).

## Rules the example demonstrates

### Initialize every versioned structure

```c
aster_publish_request_t request = ASTER_STRUCT_INIT(aster_publish_request_t);
```

ABI v1 uses `abi_version` and `struct_size` to reject incompatible layouts
cleanly. `aster_node_options_init` and `aster_blob_publish_options_init` also
populate policy defaults; call them before overriding fields.

### Input slices are borrowed for one call

`aster_bytes_t` does not take ownership. Keep its memory valid until the called
function returns. Node open and publish copy what they retain.

### Output objects have matching release functions

Items, deliveries, status objects, and owned buffers are independent copies.
Release each with the matching `*_free` function, close every page/result handle,
and close or zeroize the node.

### Check status and retrieve the diagnostic immediately

Every function returns an `aster_status_t`. On failure, `aster_last_error` copies
the calling thread's sanitized diagnostic, or a process-wide fallback if that
thread has no message. Read it before another Aster call changes the
thread-local state.

### Keep handles process-local

Numeric handles are capabilities for the current process. Never serialize them.
Stable ItemIDs, Blob IDs, bridge authorization IDs, and route handles are
different: those fixed 32-byte values are designed for durable application use.

## Linking notes

- Linux usually loads `libaster_ffi.so`.
- macOS loads `libaster_ffi.dylib`.
- Windows loads `aster_ffi.dll`; use the import-library flow for your compiler.
- Build the header and native library from the same source revision.
- The release library uses unwind semantics so Rust panics can be contained at
  the ABI boundary instead of aborting the embedding process.

## Replace the test fixture

The checked-in bundle is public test material. A real node needs a unique bundle
from an approved authority workflow and durable storage that protects both the
bundle and publisher counter state.

The fixture's grants and regeneration procedure are documented in
[Non-production binding test material](../../bindings/testdata/README.md).

## Next steps

- Read the full [C ABI reference](../../bindings/c/README.md).
- Read [Core concepts](../concepts.md) for the application model.
- Review the [current live-synchronization boundary](../README.md#current-capability-boundary),
  then read [Carriers and contacts](../transports.md).
- Run the FFI tests with `cargo test -p aster-ffi`.
