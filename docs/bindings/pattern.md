# Language Binding Pattern

Every first-class binding wraps the shipped C ABI; it does not reimplement wire,
crypto, storage, or sync semantics.

## ABI rules

- Opaque handles only; no Rust layout crosses the boundary.
- Every versioned input structure begins with ABI version and byte size.
- Inputs are caller-owned byte slices valid only for the call.
- Outputs are library-owned handles or buffers with an explicit destructor.
- Move-only native capabilities are process-local handles. A consuming call
  takes the handle by mutable reference and zeros it before provider work can
  fail.
- No borrowed pointer survives a call and no callback runs while an internal
  lock is held.
- Every exported function catches Rust unwinding and converts it to a stable
  numeric status. Panics never cross the ABI.
- `aster_node_close` cancels and joins owned background work.
- `aster_zeroize` invalidates the handle even when a platform hook reports an
  error; later operations return `ASTER_ZEROIZED`.
- Error details are copied from a per-handle buffer and contain no secrets.

## Required operations

`node_open/close` (where `node_open` installs the opaque provisioning bundle),
`publish`, atomic `publish_batch`, streaming `blob_writer_open/write/finish`,
atomic `publish_blob_batch`, `blob_reader_open/read`, `subscribe`,
`query`, `next_event`, `delivery_ack`, `conflicts`, `resolve`, `peer_status`,
`sync_status` (included in each peer snapshot), `set_emission`,
`configure_bridge`, bridge enrollment enable/disable, first/nested bridge-hop
creation, exact bridge status and bounded status pagination, and `zeroize`.

## Required binding surface

A language package exposes `Node`, singleton and batch publication,
`Subscription`, `Query`, `Delivery`, `Conflict`, `BlobWriter/Reader`,
`PeerStatus`, `SyncStatus`, and `EmissionPolicy`. It maps status values to native
exceptions/errors and provides deterministic cleanup plus a finalizer as a leak
backstop.

Publishing is complete when the local durable transaction commits; it does not
wait for connectivity. Subscription delivery carries ItemID and may repeat after
a crash until acknowledged.

Explicit batch publication accepts 2–64 ordered items with one class, topic,
scope, publisher, and active epoch. Retained dual representation is the safe
default/zero-value policy; batch-only is an explicit opt-out from retaining
unchanged format-2 singleton representations for semantic-v1 peers. A
successful result preserves publish-result order and reports
aggregate post-insert evictions. Rejection commits no member and consumes no
publisher counter or Event sequence.

Generic publish must reject Blob-class payloads. Blob finish first finalizes
bounded encrypted chunks, then idempotently queries-or-publishes the authenticated
manifest using the full Blob ID as its logical key. A retry after either durable
boundary returns the same semantic item. Reader creation derives the stored
manifest's content epoch internally and authorizes that retained grant; bindings
never expose epoch selection, keys, or sealed envelopes, and never accept an
application-supplied manifest as trusted input.

Blob batch publication accepts 2–64 distinct unpublished writers, finalizes
their manifests and route commitments internally, and commits them through the
same atomic batch boundary. Writers remain open and retryable after failure;
after success, each writer's ordinary idempotent finish returns its matching
batch receipt.

Bridge bindings expose a process-local move-only enrollment, fixed 32-byte
durable authorization IDs and route handles, exact topic lists, an explicit
four-bit priority mask, and a 1-8 authority hop bound. Enable consumes the
enrollment after ABI validation even when authority verification fails. First
hop accepts an application ItemID; later hops accept only an opaque route
handle. Exact status lookup and pages expose authenticated origin/current scope
metadata but never sealed objects, credentials, route descriptors, keys,
provider handles, transports, or synchronization state machines.

## Build template

1. Generate or copy the versioned `aster_mesh.h` shipped by the same release.
2. Link only `aster_ffi`; do not expose its transitive Rust dependencies.
3. Package the correct static/shared artifact per target and verify its checksum.
4. Compile the header from C and C++ and verify exported symbols.
5. Run the common behavioral suite through the language binding.
6. Add package/dependency/license entries to the source register and SBOM.

## Mandatory binding tests

- basic offline publish/query in fewer than 50 example lines;
- binary payload and embedded NUL handling;
- invalid UTF-8/name/enum/length errors;
- subscribe, repeat-before-ack, and ack;
- conflict enumeration and resolution;
- streaming Blob without whole-file allocation, including retry/reopen at both
  finish persistence boundaries;
- batch bounds, mixed-field rejection, retained-dual/batch-only selection,
  ordered receipts and aggregate evictions, and all-or-nothing counter/Event
  behavior;
- distinct Blob-writer batch success, failure retryability, and idempotent
  per-writer finish after commit;
- cancellation and concurrent calls;
- repeated open/close and zeroize;
- ownership misuse returns errors or is prevented by the language wrapper;
- bridge enrollment close/consume/purge, policy bounds, exact-edge disable,
  first/nested route creation, status pagination, and durable reopen by 32-byte
  ID/handle;
- reference conformance scenarios produce the same ItemIDs and results.

The candidate instantiates this template for Go (cgo) and Python (`ctypes`, no
runtime package dependency). A future binding copies the ABI/build/ownership
template above and must pass the same behavioral contract before being called
first class.
