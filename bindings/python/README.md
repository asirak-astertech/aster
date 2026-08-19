# Python binding

The `aster_mesh` package uses only Python's standard-library `ctypes`; it wraps
the shipped ABI rather than reimplementing protocol or cryptographic behavior.
Build `aster-ffi` first or set `ASTER_MESH_LIBRARY` to the matching shared
library.

`PROTOCOL_VERSION` is retained as the legacy name for replication-wire version
`1`; new code should use `REPLICATION_WIRE_VERSION`. The separate
`DEFAULT_SEMANTIC_VERSION` and `HIGHEST_SUPPORTED_SEMANTIC_VERSION` values are
both `2` in this build. These process-wide constants do not report a particular
session's negotiated result.

`Node` accepts opaque authority-issued provisioning bytes. Use it as a context
manager, or call `close()`/`zeroize()` explicitly. Native result handles and
owned buffers are copied into Python values and released deterministically.
Transport-owned sealed envelopes are intentionally not exposed by this
application binding.

`Node.publish_batch()` atomically commits 2-64 ordered, same-route
`BatchPublishItem` values. `BatchPublicationPolicy.RETAINED_DUAL` is the
offline-safe default, while `BATCH_ONLY` explicitly omits semantic-v1 singleton
retention. Results contain ordered receipts and aggregate eviction IDs;
rejection consumes no publisher counter or event sequence.

Use `Node.blob_writer(...)` for large immutable values, stream bounded writes,
then call `finish()` before `close()`. `Node.blob_reader(...)` returns a
file-like raw reader whose `readinto()` authenticates incrementally into a
caller-owned buffer. Generic `Node.publish(DataClass.BLOB, ...)` is rejected.
`Node.publish_blob_batch()` finalizes and atomically publishes 2-64 distinct
writers. Writers remain retryable on failure, and their normal `finish()` calls
return matching batch receipts after success.

Queried and subscribed `Item` values expose `origin_scope` and
`current_scope`; `scope` remains an exact compatibility alias of
`current_scope`.

Cross-scope administration stays high-level. A bridge node creates a
process-local `BridgeEnrollment`; an authority passes it to
`Node.enable_bridge()`, which move-consumes it once native authority processing
starts, including rejection paths. Close an unused enrollment explicitly or
use it as a context manager. `Node.disable_bridge()` selects one exact directed
edge. `Node.bridge_item()` creates a first hop from an ItemID and
`Node.extend_bridge_route()` appends one hop from an opaque durable route
handle.

Bridge authorization IDs and route handles are exactly 32 bytes and remain
valid status/page cursors after reopen. `Node.bridge_authorization_status()` and
`Node.bridge_route_status()` perform exact lookup;
`Node.bridge_authorizations()` and `Node.bridge_routes()` return bounded pages.
Policies use exact topics, an explicit nonzero `PriorityMask`, and a 1-8
authority hop bound. No Python type contains sealed wrapper/control bytes,
credentials, keys, provider handles, transports, or sync internals.

Control-authority nodes call `Node.rekey_scope(...)` with opaque signed registry
bytes, a caller-retained minimum generation, a newer epoch, and explicit
`RekeyRecipient.route_only(...)` or `RekeyRecipient.read_topics(...)` values.
Nested `ctypes` storage exists only for the synchronous call. Only the durable
non-secret receipt is returned; keys, provider state, grant plans, and sealed
controls are never represented.

Run the actual shared-library tests with:

```sh
cargo build -p aster-ffi
python3 -m unittest discover -s bindings/python/tests
```
