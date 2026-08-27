# Application recipes

These recipes show the framework's main application mechanisms with commented
Python because it is the most compact binding. Rust, C, Go, and Python share
the core local-data operations shown here. Rust additionally exposes explicit
Event-gap inspection, process-local merge-policy ID registration (which
annotates Rust conflict results but does not execute policy code during
replication), and garbage collection; the
[capability table](#operation-names-across-bindings) marks those boundaries.

Start with a working node from the [Python quickstart](quickstart/python.md):

```python
from aster_mesh import (
    BatchPublishItem,
    DataClass,
    EmissionThreshold,
    Node,
    Priority,
)

node = Node(database_path, provisioning_bundle)
```

The snippets use the disposable fixture's authorized scope and topic names. In
a real application, those names and the payload schema are part of your
deployment contract.

## Selected production-lane boundary

The recipes below use the broader semantic language bindings. The selected
`aster-node` application boundary is deliberately different: Event, State, and
Record have cloneable live Rust handles backed by the running actor; all three
also retain exclusive stopped Rust facades. State and Record live commands
share Event's bounded actor lane and the same mission-bound store authority,
while their objects reconcile over protected semantic-v4/v5 contacts. Blob now
has a cloneable live Rust handle plus its exclusive stopped streaming facade;
semantic v5 separately transfers already-durable Blob objects directly between
current content-capable peers. The
selected handshake offers `[5, 4, 3, 2, 1]`. Event keeps v1-v5 compatibility;
v1-v3 contain no State/Record mechanics and v1-v4 emit zero Blob frames.

`RunningNode::selected_state()` exposes async `publish`, `query`, `subscribe`,
`poll`, `acknowledge`, and `unsubscribe`;
`RunningNode::selected_records()` exposes async `publish`, `query`, and guarded
`resolve`; `RunningNode::selected_blobs()` exposes async durable regular-file
`publish` and authenticated `read_page`. Blob pages are at most 64 KiB and own a
zeroize-on-drop plaintext allocation. Clones use the actor's bounded application
admission rather than opening another writer; Blob work is dispatched to one
bounded joined worker. Graceful shutdown and live zeroization close admission,
reject queued work, and join that worker before authority release, so retained
handles fail with sanitized `StateUnavailable`. Caller-copied Blob bytes and
caller-owned source files remain outside node zeroization. Durable Record/Blob
delivery, State contact/status and materialized-view/synthetic-withdrawal
behavior, dynamic State network interests, ConnectRPC/C/Go/Python selected-node
bindings, finite TTL, and representative physical or mixed-implementation
acceptance remain open. A
[retained 7,752-byte v2 live-path receipt](implementation/evidence/selected-live-mutable-6cabb4c.json)
(SHA-256
`054945ecf94e8bfba1b130f6a5f47e9b1e0e17ad69f3b1472085a1d10f05eeaa`,
signed source `6cabb4c`) covers peerless State/Record publication, direct
convergence, exact concurrent State heads, a causal successor, an authenticated
empty tombstone that remains current through one immediate peerless restart,
Record conflict resolution, and closed-handle behavior. This is a
producer-attested ordered, one-host, same-implementation loopback chain—not
indefinite tombstone retention, garbage collection, delete-wins, physical or
mixed implementations, scale, or release acceptance. Its zero Blob counters
make it neither live-Blob evidence nor a claim about the newer Blob mechanism.

A separate
[retained 9,656-byte State-delivery receipt](implementation/evidence/selected-live-state-subscription-8912fc3.json)
(SHA-256
`7d0b568dd4d57c3f2967da55953896829261877513c59c51a0b274eeda69485f`,
signed source `8912fc3`) observes forced termination after a flushed
unacknowledged State poll and fresh-process attempt-2 redelivery,
acknowledgement, idempotent re-acknowledgement, and empty poll. Its one-host,
same-implementation run also retains static network/application selector
separation, causal ancestor suppression, a current tombstone, and final
peerless subscription replay. It is not State status, a materialized-view or
synthetic-withdrawal feed, dynamic network-interest mutation, physical/mixed
or scale/resource evidence, or release authorization.

Selected State/Record lanes are separated by class and receiver direction. They
use Offer `MutableApplyResult`, Fetch `MutableFetchResult` plus required
`MutableFetchResultAck`, exact finish remainders, typed
capacity deferral, and durable peer/class/local Offer/Fetch rotation. Each
object is at most 1 MiB; each class is capped at 4,096 rows and 16 MiB. Current
source route lineage is required. After a same-epoch replacement, historical
lineage is withheld from ordinary current projection/query and network
inventory/transfer, although an exact idempotent State publish or Record
publish/resolution retry may recover its committed result only through strict
cached/projection/historical verification. Selected finite State
and Record TTL is rejected and remains open.

Normal and `AtLeast` run those mutable lanes and the v5 Blob lane because
`AtLeast` is an Event threshold only. `ReceiveOnly` initiates and discloses no
mutable or Blob lane. Event last-contact status is not State/Record/Blob
convergence. The Blob network slice is 16-KiB peer-neutral resume with
completion-gated visibility. Terminal/stale cleanup retains one bounded,
non-public, quota-charged depot import and any expected/committed chunk staging
after removing source/prefix/cache visibility, so a different same-epoch
lineage still requires epoch advance. It adds no Blob subscription/status
convergence, route-only custody, TTL/GC, pure-byte deduplication, large/RSS
acceptance, or representative physical or mixed-implementation acceptance.

A [retained 10,728-byte v2 live-Blob receipt](implementation/evidence/selected-live-blob-044d90f.json)
(SHA-256
`4fea2ffbd16608862a67167fb1b8fcb6d5d8b4b82c576aa9a6b7e25ee9c55909`)
binds signed source commit `044d90ff07c8e754b3d490cb810d42de3c915e3d`
with `Good` signature status. Its three participants ran 11 actor lifetimes and
32 error-free direct `CONTACT` records: a publisher committed while peerless; a replica
received all 98,638 carrier bytes; a receiver retained an interrupted
exactly-one-contact 16,384-byte prefix, reopened peerless with that exact
progress, resumed exactly 16,384 bytes from the different replica without
refetching the source, fetched the exact remaining 65,870 bytes, reconstructed
all 98,638 carrier bytes, and reopened peerless for a final authenticated read.
Its source-to-execution link remains operator-attested, not cryptographically
proven. This is one-host, same-implementation evidence of graceful same-process
actor/store/provider reopen only. It does not prove process-crash, power-loss,
long-offline, arbitrary-peer, or route-only resume; NAT, Internet, relay, or
BTLE paths; independent-implementation interoperability; scale beyond three
participants; resource thresholds or soak; physical sanitization; or release
authorization.

## Publish each data class

### State: replaceable current value

```python
position_result = node.publish(
    DataClass.STATE,
    "position.current",
    "mission/team/alpha",
    b'{"lat":38.9,"lon":-77.0}',
    # Every update for this entity reuses the same logical key.
    logical_key=b"unit-7",
    # Urgency and expiry are independent policy choices.
    priority=Priority.IMMEDIATE,
    ttl_ms=60_000,
)
```

Use State when consumers want one projected current value. Concurrent heads
converge on the value with the greatest full ItemID, while losing heads remain
queryable with `include_recoverable=True`. The current `conflicts()` and
resolution workflow is Record-only; use Record when an application requires an
explicit concurrent-writer signal. A short-lived position should usually
expire; a device's long-lived configuration may have no TTL. `position_result`
is a publish result: it confirms the local durable commit, not delivery to a
peer.

### Event: immutable history

```python
message_result = node.publish(
    DataClass.EVENT,
    "chat.events",
    "mission/team/alpha",
    b'{"from":"unit-7","text":"checkpoint clear"}',
    # The logical key may name an application stream. Aster assigns the
    # publisher's durable Event sequence; the app does not invent it.
    logical_key=b"operations-chat",
    priority=Priority.PRIORITY,
)

print(message_result.event_sequence)  # Nonzero sequence assigned by Aster.
```

Use Event when every entry matters. A receiver can inspect event-gap reporting
to distinguish “nothing happened” from “an event has not arrived yet.” Explicit
`ApplicationNode::event_gaps` inspection is Rust-only today; C, Go, and Python
do not expose it. Reusing a logical key to name a stream does not collapse its
entries: matching `query()` and `poll()` calls return every retained Event.

### Record: mutable data with explicit conflicts

```python
plan_result = node.publish(
    DataClass.RECORD,
    "record.plan",
    "mission/team/alpha",
    b'{"objective":"north","status":"draft"}',
    # Concurrent edits to this logical record remain visible as siblings.
    logical_key=b"plan-red",
    priority=Priority.PRIORITY,
)
```

Use Record when disconnected editors can legitimately change the same object and
losing either version would be wrong.

### Blob: streamed large immutable content

```python
# Generic node.publish(DataClass.BLOB, ...) is intentionally rejected. The
# streaming API keeps large content out of one Python/native allocation.
with node.blob_writer(
    "imagery.blob",
    "mission/team/alpha",
    media_type="image/tiff",
    chunk_size=64 * 1024,
    priority=Priority.ROUTINE,
) as writer:
    with open("map.tiff", "rb") as source:
        while block := source.read(64 * 1024):
            writer.write(block)
    finished = writer.finish()

print(finished.blob_id.hex())
```

`finish()` is idempotent and safe to retry. The Blob ID commits to manifest
identity fields—including total length, chunk size, media type, and schema
ID—as well as the ordered plaintext chunk digests and whole-plaintext digest.
The same plaintext published with a different chunk size therefore has a
different Blob ID. Deduplication and reads also require the exact authenticated
route commitment and manifest bytes; an ID match alone is insufficient. Partial
authenticated transfer progress survives contact changes; the current profile
rejects an empty Blob.

Read a locally available Blob incrementally:

```python
import os

temporary_path = "map-copy.tiff.part"
with node.blob_reader(
    "imagery.blob", "mission/team/alpha", finished.blob_id,
) as reader:
    with open(temporary_path, "wb") as output:
        while block := reader.read(64 * 1024):
            output.write(block)
os.replace(temporary_path, "map-copy.tiff")
```

Each chunk is authenticated before its plaintext is returned, but the
whole-content digest is checked only when the reader reaches end-of-file. Do not
act on the output as a complete verified Blob before the final read returns
end-of-file; the staging-and-rename pattern above prevents a partial result from
being mistaken for a completed file.

The selected live Rust composition uses a narrower shape than these broader
language bindings. Obtain `let blobs = running.selected_blobs()`, pass an owned
regular `std::fs::File` at offset zero to async `publish`, and loop over async
`read_page` calls using the returned `next_offset()`. A live publication is
nonempty and at most 64 MiB; each page request is `1..=64 KiB`. The node may have
no peers when publication commits. An exact operation-key retry recovers the
durable result, while different bytes or identity metadata under that key fail
as a conflict. After a later v5 direct contact, an eligible receiver can expose
the completed Blob through its own live handle and retain it across restart.
See the [selected Blob quickstart](quickstart/selected-blob-api.md) for the full
Rust example and its cancellation, closure, and zeroization limits. That path
has no Blob subscription/status API; its retained live-path evidence is bounded
to the receipt and nonclaims above.

## Query current local data

```python
items = node.query(
    topic="position.current",
    scope="mission/team/alpha",
    logical_key=b"unit-7",
    data_class=DataClass.STATE,
    limit=100,  # Every query is bounded.
)

for item in items:
    print(item.item_id.hex(), item.payload)
```

A query is a bounded snapshot of the local store. It does not contact peers. Use
`include_descendants=True` only when the caller is intentionally reading a scope
subtree. Recoverable superseded versions and tombstones are excluded unless
explicitly requested.

## Process a durable subscription

```python
subscription = node.subscribe(
    "chat.events",
    "mission/team/alpha",
    data_class=DataClass.EVENT,
)

for delivery in subscription.poll(limit=64):
    # Make application processing idempotent using delivery.item.item_id.
    application_store.commit(delivery.item.item_id, delivery.item.payload)

    # Acknowledge after the application's commit, not before it.
    subscription.acknowledge(delivery)
```

Stopping before acknowledgment can cause redelivery. That is the intended
at-least-once contract. Acknowledging a projected current State or Record head
does not promote a causally superseded ancestor into new work; concurrent Record
siblings are acknowledged independently.

For the selected production-lane Rust node, State alone currently exposes this
delivery pattern as a freshly authenticated positive-current-version queue;
see [Deliver positive current State versions durably](quickstart/selected-state-api.md#deliver-positive-current-state-versions-durably).
Record and Blob selected-node delivery remain open, and the State queue is not
a materialized view, transition feed, or dynamic network-interest controller.

## Publish an atomic batch

```python
batch_result = node.publish_batch([
    BatchPublishItem(
        DataClass.EVENT,
        "chat.events",
        "mission/team/alpha",
        b'{"text":"first"}',
        logical_key=b"operations-chat",
        priority=Priority.PRIORITY,
    ),
    BatchPublishItem(
        DataClass.EVENT,
        "chat.events",
        "mission/team/alpha",
        b'{"text":"second"}',
        logical_key=b"operations-chat",
        priority=Priority.PRIORITY,
    ),
])
```

An explicit batch has 2–64 ordered members with the same publisher, class,
topic, scope, and active epoch. Either every item commits or none does. The
default retained-dual policy keeps unchanged format-2 singleton envelopes
alongside the semantic-v2/v3/v4/v5 compact batch representation, preserving delivery to
semantic-v1 contacts. At the maximum 64 items with 128-byte scope and topic and
256 group entries, the compact representation is 39,414 serialized bytes versus
1,207,414 bytes for retained-dual publication (about 30.6×). Those figures are
object serialization, not measured transport throughput. Opt into batch-only
retention only after evaluating mixed-version contacts, not merely to reduce
local storage.

## Delete data with a tombstone

```python
node.publish(
    DataClass.STATE,
    "position.current",
    "mission/team/alpha",
    b"",
    logical_key=b"unit-7",
    tombstone=True,
    priority=Priority.IMMEDIATE,
)
```

A tombstone is a replicated update, not an immediate physical deletion. It
prevents a returning node from resurrecting an older value only within the
configured tombstone-retention window. The deployment baseline is 30 days of
offline tolerance plus a 15-day margin; after that bound, resurrection is
possible. [`ApplicationNodeOptions`](../crates/aster-core/src/api.rs)
configures `tombstone_retention_ms` and `superseded_retention_ms`. Rust also
exposes explicit `ApplicationNode::collect_garbage`; C, Go, and Python do not.

## Inspect and resolve Record conflicts

```python
conflicts = node.conflicts(
    topic="record.plan",
    scope="mission/team/alpha",
    logical_key=b"plan-red",
    data_class=DataClass.RECORD,
)

for conflict in conflicts:
    # Recoverable history includes Concurrent heads and may also include older
    # superseded revisions. Select only the exact annotated sibling IDs.
    recoverable = node.query(
        topic="record.plan",
        scope="mission/team/alpha",
        logical_key=conflict.logical_key,
        data_class=DataClass.RECORD,
        include_recoverable=True,
        limit=4096,
    )
    by_id = {item.item_id: item for item in recoverable}
    missing = set(conflict.siblings) - set(by_id)
    if missing:
        raise RuntimeError("a current Record sibling is not recoverable; retry")
    siblings = [by_id[item_id] for item_id in sorted(conflict.siblings)]
    merged_payload = merge_plan_versions(siblings)

    # The expected sibling set prevents resolving a stale view after another
    # concurrent update has arrived.
    node.resolve(
        "record.plan",
        "mission/team/alpha",
        conflict.logical_key,
        conflict,
        merged_payload,
        priority=Priority.PRIORITY,
    )
```

`resolve()` is the implemented merge path. Direct and forwarded replicated
ingestion never invoke registered application policy code. Rust's process-local
`register_merge_policy` retains an application-supplied policy ID for high-level
conflict annotations only; the node does not retain the executable policy
object. Applications must inspect the siblings, compute and review any merged
payload themselves, and submit it through `resolve()`.
Any helper used for this purpose must receive siblings in ascending full-ItemID
order and return identical bytes for identical inputs across every supported
implementation and version; Aster does not verify that application-level
obligation.
Registration is lost when the node process restarts. Automatic registered-policy
merge in requirements §5.3 remains partial.

## Enter a constrained-emission mode

```python
# Emit only Immediate and Flash data. Inbound sync, configured contacts, and
# their required protocol/control work remain allowed.
node.emission_threshold = EmissionThreshold.IMMEDIATE

# Suppress contact initiation, discovery, inventory, and item transmission while
# continuing to receive. A connection-oriented contact may still send mandatory
# authentication or link acknowledgements needed for ingestion.
node.emission_threshold = EmissionThreshold.RECEIVE_ONLY

# Restore ordinary emission later.
node.emission_threshold = EmissionThreshold.ROUTINE
```

Emission policy affects what the node may send. It does not change item
priority, delete queued data, or broaden provisioning and bridge policy.
`RECEIVE_ONLY` is not a guarantee of RF silence, and the high-level application
APIs do not expose the separate `PassiveOnly` scheduler mode. In the selected
semantic-v4/v5 node, `AtLeast` filters Event only and does not suppress State,
Record, or v5 Blob work; `ReceiveOnly` discloses no State/Record/Blob lane.

## Operation names across bindings

An em dash means that the operation is not exposed by that language binding.

| Purpose | Rust | Python | Go | C ABI |
|---|---|---|---|---|
| Open node | `ApplicationNode::open` | `Node(...)` | `Open` | `aster_node_open` |
| Publish | `publish` | `publish` | `Publish` | `aster_node_publish` |
| Query | `query` | `query` | `Query` | `aster_node_query` |
| Subscribe | `subscribe` | `subscribe` | `Subscribe` | `aster_node_subscribe` |
| Poll / acknowledge | `poll` / `acknowledge` | `poll` / `acknowledge` | `Poll` / `Acknowledge` | `aster_node_poll` / `aster_node_acknowledge` |
| Atomic batch | `publish_batch` | `publish_batch` | `PublishBatch` | `aster_node_publish_batch` |
| Stream Blob | `open_blob_service` | `blob_writer` | `NewBlobWriter` | `aster_node_blob_writer_open` |
| Inspect conflicts | `conflicts` | `conflicts` | `Conflicts` | `aster_node_conflicts` |
| Resolve a conflict | `resolve` | `resolve` | `Resolve` | `aster_node_resolve` |
| Inspect Event gaps | `event_gaps` | — (Rust-only) | — (Rust-only) | — (Rust-only) |
| Register process-local policy ID (no automatic execution) | `register_merge_policy` | — (Rust-only) | — (Rust-only) | — (Rust-only) |
| Run garbage collection explicitly | `collect_garbage` | — (Rust-only) | — (Rust-only) | — (Rust-only) |
| Emission policy | `set_emission_policy` | `emission_threshold` | `SetEmissionThreshold` | `aster_node_set_emission` |
| Zeroize | `zeroize` | `zeroize` | `Zeroize` | `aster_node_zeroize` |

See the [language quickstarts](quickstart/README.md) for setup and resource
ownership details, and [Carriers and contacts](transports.md) for live sync.
