# Decision 0009: Separate the application API from adapter internals

- Status: accepted as an application ergonomics boundary; prior adapter
  security-boundary claim withdrawn
- Date: 2026-08-18
- Amended: 2026-08-24

The default Rust library and every first-class language binding expose only
application operations: node lifecycle, offline publish, streamed Blob I/O,
subscribe and acknowledge, bounded query, conflict inspection/resolution,
emission policy, bridge policy, peer/sync status, provisioning installation,
and zeroization.

Cryptographic algorithms and keys, source-envelope construction, handshake
flights, fragmentation, inventory trees, reconciliation messages, sealed-object
ingest/emission, and link choice are not application APIs. Rust transport
adapters and conformance tooling require some of these contracts, so the core
places them behind the explicit, non-default `adapter-sdk` feature. The IP,
BTLE, C-boundary implementation, and conformance packages opt into that feature;
ordinary Rust dependents do not.

The intended carrier path moves opaque frames through the authenticated runtime,
but the implemented `adapter-sdk` feature is broader than that path. It publicly
exports engine, crypto/provider, store, wire, and control-facing modules,
including `RecordStore`/`StoredItem` mutation seams. Code compiled with this
feature can bypass provider validation or directly mutate state below the
application boundary. It is therefore a privileged, trusted integration
contract and part of Aster's in-process trusted computing base, not a security
boundary for third-party adapter code.

Cargo feature unification expands that public surface for every dependent crate
in the same build when `aster-host`, a workspace adapter, or another dependency
enables `adapter-sdk`. Import discipline is a convention, not capability
enforcement. The claim that untrusted carrier input cannot authorize peer or
application state applies to bytes processed through the built-in `Link` and
runtime path; it does not constrain arbitrary in-process code with access to the
broad feature.

The C header must not export the internal sealed-object emission/ingest seam.
Language bindings are generated from the application portion of that header and
must not reconstruct a transport or sync engine. Internal integration tests may
compile against the adapter feature without turning it into the default public
surface.

The implemented Rust boundary is `ApplicationNode`. It owns the generic engine,
accepts either a provider-owned protected artifact through `open_protected` or
canonical unprotected inner bytes through the documented compatibility/test
path, requires bounded query/delivery pages, rejects generic whole-buffer Blob
publication, selects Blob epochs internally, and maps items/publication receipts
to application records that omit causal vectors and sealed bytes. The
application API never returns keys or protection-provider internals. The
explicit application merge-helper input contains only IDs, publisher IDs,
payloads, and tombstone flags; callers must supply it in ascending full-ItemID
order. All underlying modules are private unless `adapter-sdk` is selected;
every workspace adapter/tool that needs them opts in explicitly.

This separation follows the supplied requirement that application developers
need no knowledge of cryptography, fragmentation, transport selection, or sync
internals while preserving a documented path for future transport packages.

## Required follow-on boundary

Before Aster claims that third-party carrier implementations cannot bypass
authentication, the public feature must be split. A narrow carrier-only SDK
should expose opaque frame I/O, route hints, MTU/characteristics, and discovery
lifecycle without exporting store records, engine ingest, crypto providers, or
control mutation. Compile-time API-surface tests and adversarial integration
tests must prove that code confined to that SDK cannot construct or commit
authenticated application/control state directly.

That split would be a protocol-level least-privilege boundary, not isolation
from hostile code in the same process. Treating an adapter implementation itself
as untrusted additionally requires a separate process or an equivalent OS/runtime
sandbox with a narrow authenticated IPC contract. Neither split nor isolation is
implemented today, so no code-hardening claim is made by this amendment.

## Implementation correction (2026-08-20)

`register_merge_policy` is retained for API compatibility, but registration is
process-local and its only automatic effect is to associate the policy ID with
high-level Record conflict annotations. Direct and forwarded replicated
ingestion never invoke application policy. Applications inspect siblings and
publish reviewed output through explicit `resolve()`. This prevents
peer-triggered ingestion from creating recursive merge publications and leaves
requirements §5.3 automatic merge partial pending a convergent design.

## Selected production-lane Event slices (2026-08-24)

`aster-node::application::SelectedEventNode` was the first high-level surface
over the selected redb/runtime security composition. It owns the exact
mission-bound redb writer authority while the mesh process is stopped and
exposes arbitrary policy-authorized Event publication and bounded
marker-ordered query. Publication is durably idempotent by an application
operation key. A stacked slice adds durable Consume subscriptions, bounded
at-least-once poll attempts, and idempotent semantic-Event acknowledgement.
Queries return freshly source/content-verified plaintext application fields and
semantic Event identities; they omit exact transfer IDs, sealed bytes, keys,
provider selection, inventories, reconciliation, and carrier choice.

Subscription filters are durable receive intent, not capabilities. The live
runtime projects Consume plus internal route-only Carry selectors into a
canonical mission-protected interest, where an empty set means receive-none.
For overlapping local selectors, Consume dominates Carry so forwarding intent
cannot suppress an otherwise authorized application delivery.
Legacy selected stores migrate with an empty selector set and therefore also
receive nothing until explicit local intent is created; there is no wildcard
compatibility fallback or pre-interest Event inventory.
Each contact reconciles a separate exact-ID universe for each receiver and
rechecks source, active control/epoch state, negotiated interest, and current
route authority before transfer or commit. Poll discovery scans unfiltered
acceptance rows so stored header metadata cannot suppress fresh source
verification before the durable cursor advances. The selected surface exposes
only fixed, sanitized error categories rather than store, envelope, provider,
carrier, or transfer details.

The mission channel protects selector names from outside observers, but an
authenticated mission peer can read their topic/scope values under the current
membership-visible forwarding-metadata policy. Route checks still withhold
unauthorized Event identities and bytes. Scope-private subscription intent is
a separate future opaque-selector boundary, not a claim of this slice.

`aster-redb-store` remains an unpublished, privileged composition crate. Its
two-phase poll plan and commit-selection types carry trusted classifications
from the selected node; they do not mint or prove cryptographic authority on
their own. Calling those methods directly is inside Aster's in-process trusted
computing base, just like the broader `adapter-sdk` seams above. The supported
application boundaries are stopped `SelectedEventNode` and live
`SelectedEventHandle`. Both freshly authenticate planned rows, open content only
for authorized Consume deliveries, and return only sanitized application
records and errors.

The live handle is a cloneable command capability for the running node's sole
actor; it does not open another store. It adds idempotent unsubscribe, bounded
authenticated gap inspection, and peer/last-contact status. Selector insertion
and removal serialize against contact policy capture. A replacement selector is
an explicit unsubscribe followed by subscribe, not an atomic update. Gap
intervals are anchored only by freshly source/content-verified positions already
observed in the mission-bound store. Last-contact status is process-local and
does not claim reachability, publisher completeness, or global convergence.

At the PR-C boundary these Event slices did not replace the broader proven
semantic `ApplicationNode` or complete the accepted boundary. They had no
atomic subscription update, live State/Record, Blob, selected-node bindings,
protected operational provisioning, generalized control administration, or
finite TTL. The later selected custody slice now adds Linux-only semantic-v3
finite Event TTL with authenticated cumulative forwarding age and expiry; it
does not close the other boundaries above.
The compiled example and exact claim boundary are documented in the
[selected Event API quickstart](../quickstart/selected-event-api.md).

## Selected production-lane local State slice (2026-08-24)

`aster-node::application::SelectedStateNode` adds a second high-level boundary
over the same selected mission-bound writer, control policy, source-envelope
provider, and causal ledger. It is intentionally an exclusive stopped-node
surface: application callers can publish one source-authenticated State version
idempotently and query the deterministic projection for one exact
topic/scope/logical key. It has no live command handle, subscription, carrier,
or reconciliation operation.

The facade returns semantic `StateId`, authenticated application fields, one
`Current` value, and optionally retained active `Concurrent` and `Superseded`
versions. It omits transfer identities, sealed representations, keys, provider
selection, causal vectors, redb table names, and structural plan tokens. A
current tombstone remains a visible `StateItem` with an empty payload; it is not
collapsed into an unauthenticated absence. Concurrent tombstones and edits use
the same deterministic semantic-ID tie-break as every other State maximum;
there is no special delete-wins rule.

The stopped facade treats redb results as untrusted structural candidates. On
publish it freshly verifies the full authenticated header, semantic and exact
identities, and exact plaintext against the caller's request after the atomic
commit or idempotent replay. On query it freshly source/content verifies all
retained candidates, including inactive revoked or old-epoch rows, recomputes
causal dominance and the complete-semantic-ID tie-break independently, and
requires the exact policy-bound projection plan to remain unchanged. Only active
versions are exposed. The operation mapping remains a privileged store
mechanism, not a capability; current authority and revocation checks precede an
exact replay.

Event and State share publisher counters and the causal frontier, so the new
class cannot reuse an Event dot. The State tables and operation ledger have
dedicated count/byte bounds and participate in aggregate store quotas. None of
this changes the Event frame grammar or reconciliation lanes. Live State,
network replication, subscriptions, TTL, expiry, garbage collection, selected-
node bindings, live or replicated Record, Blob, independent interoperability, and acceptance
evidence remain open. The compiled example and exact boundary are documented in
the [selected State API quickstart](../quickstart/selected-state-api.md).

## Selected production-lane local Record slice (2026-08-24)

`aster-node::application::SelectedRecordNode` adds an exclusive stopped-node
Record boundary over the same mission-bound writer, current control policy,
source-envelope provider, and publisher causal ledger as Event and State. It
publishes source-authenticated Record revisions by durable operation key,
queries one exact topic/scope/logical key, and accepts an explicit reviewed
successor through an opaque exact-sibling resolution guard. It has no live
command handle, subscription, carrier, reconciliation, or language-binding
operation.

The facade exposes semantic `RecordId`, authenticated application fields, one
deterministic `Current` head, every other active causal maximum as
`Concurrent`, optional active `Superseded` history, and an explicit
`RecordConflict` containing sorted sibling identities and a private guard. It
does not expose exact transfer identities, sealed representations, keys,
provider selection, causal vectors, redb table names, or structural plan
tokens. A current tombstone remains a visible empty-payload `RecordItem`;
concurrent deletion has no special delete-wins priority.

The selected slice never invokes registered application merge code during
ingest. An ordinary publication cannot silently collapse an existing conflict:
if its reserved context observes at least two heads, the transaction fails and
leaves the projection unchanged. An application may inspect the verified
siblings, compute a result in its own code, and call `resolve` with the exact
guard it received. The successor must observe every guarded head. The store
rejects stale guards atomically, and the durable operation digest binds the
sorted head set so the same operation key cannot resolve a different conflict.
An exact authorized retry returns the original immutable result after restart
or rekey; a new operation cannot reuse an old-policy guard.

The stopped facade treats stored rows and projection plans as privileged,
untrusted structural inputs. Query freshly source/content verifies every
retained candidate, including inactive rows, independently recomputes causal
maxima, current/concurrent/superseded dispositions, and the exact sorted head
set, then requires the policy-bound plan to remain unchanged. Resolve repeats
that verification for the supplied guard before the store atomically checks and
commits it. Only active rows cross the application boundary, and all errors are
mapped to the same fixed sanitized categories as the other selected facades.

Event, State, and Record share publisher counter high-water and causal frontier
state so Record cannot reuse another class's dot. Record exact/semantic indexes,
acceptance markers, versions, and the bounded operation ledger remain disjoint;
the Event inventory and frame grammar are unchanged. This is local mechanism
evidence only. There is no automatic registered-policy merge, Record network
ingestion, disconnected-process acceptance, live status, finite TTL, expiry,
garbage collection, or retained execution receipt. The compiled example and
exact boundary are documented in the
[selected Record API quickstart](../quickstart/selected-record-api.md).

## Semantic-v4 State/Record network amendment (2026-08-25)

This amendment supersedes the earlier present-tense statements that selected
State/Record objects have no network path; those statements remain above only
as the historical boundary of the stopped-slice decisions and their receipts.

The stopped application boundary remains unchanged: State and Record publish,
query, and guarded resolution still require exclusive ownership while the live
actor is absent. The selected live actor now reconciles their already durable
source objects only after the mission session selects semantic version 4. This
does not create a live State/Record application handle or subscription. The
default offer is `[4, 3, 2, 1]`; Event retains v1-v3 compatibility and v1-v3
contacts expose no mutable frames.

The v4 mechanics boundary is protected, class- and direction-separated, and
bounded. Offer returns exact `MutableApplyResult`; Fetch returns exact
`MutableFetchResult` and requires exact `MutableFetchResultAck`;
Finish/Finished bind exact remaining. Valid class, byte, or causal-
frontier saturation is `DeferredCapacity`, while integrity and policy failures
remain fatal. State and Record each cap objects at 1 MiB and retained network
admission at 4,096 rows/16 MiB. A durable peer/class/local Offer/Fetch cursor
rotates bounded attempts across at most 256 peers and 1,024 rows.

Current source route lineage is mandatory. A same-epoch replacement withholds
the historical lineage from ordinary current projection/query and network
inventory/transfer; it does not delete the row. Exact idempotent State publish
and Record publish/resolution retries may recover their committed historical
result only through the strict cached/projection/historical verification path.
Selected finite State/Record TTL is rejected.

Normal and every AtLeast threshold run the v4 mutable lanes because AtLeast is
an Event-only threshold. ReceiveOnly initiates and discloses no mutable lane.
`SelectedEventHandle` last-contact status remains Event/contact evidence and is
not State/Record convergence. Blob networking and every retained acceptance or
release gate remain open.

## Semantic-v5 stopped-Blob network amendment (2026-08-25)

The default offer is now `[5, 4, 3, 2, 1]`. V5 inherits the State/Record
mechanics above and adds direct transfer of already-durable Blob sources and
carrier prefixes; v1-v4 emit zero Blob frames. This does not create a live Blob
application handle or subscription. `SelectedBlobNode` remains an exclusive
stopped publish/read facade, while `MutableSourceInterests::with_blob` is an
additive runtime receive configuration rather than an application delivery API.

The v5 lane is direct content-capable only, source-before-carrier, bounded to
16-KiB peer-neutral prefix extensions, and completion-gated before ordinary
visibility. Route-only Blob relay/custody, TTL/GC, pure-byte deduplication,
large/RSS/physical/mixed/release acceptance, and selected-node language
bindings remain outside the public boundary.

## Live State/Record application and retained acceptance amendment (2026-08-26)

This amendment supersedes the earlier present-tense statements that selected
State and Record have no live application handle or retained live-path receipt.
Those statements remain above as the dated boundaries of the stopped and
network-mechanics slices; they are not descriptions of the current composition.

`RunningNode::selected_state()` now returns a cloneable `SelectedStateHandle`,
and `RunningNode::selected_records()` returns a cloneable
`SelectedRecordHandle`. Publish, query, and guarded Record resolution commands
share the running actor's one bounded Event/State/Record lane and its sole
mission-bound store/policy authority. Clones do not open a writer. Graceful
shutdown and live zeroization close admission before authority release, and
retained handles fail with sanitized `StateUnavailable`. The exclusive stopped
facades remain available only while no live actor owns the store.

The [retained canonical receipt](../implementation/evidence/selected-live-mutable-2ccfba0.json)
is 5,660 bytes with SHA-256
`299a3c3b8d1685deb5980ed091797f7d46119562b67c3d853b94d8552c83b67a`
and binds the execution to good-signature source commit `2ccfba0`. Two distinct
participants publish State and Record while peerless, then run four paired
direct `CONTACT` records with exact aggregate 5/5/5 selected-item
offer/fetch/insert accounting. The six actor lifetimes never exceed two
concurrent actors. State preserves the max-ID-current/other-concurrent projection
across restart. Record preserves two siblings, rejects an ordinary
conflict-collapsing publish, resolves under the exact guard, supersedes both
originals, retries without insertion, and preserves the result across restart.
Six graceful shutdowns and four closed retained handles pass; Event, control,
and Blob counters remain zero.

This is bounded one-host, same-implementation loopback evidence. The
source-to-execution link is operator-attested, not cryptographically proven or
reproducible, and the participant secret artifacts are inspected by metadata
only. The amendment does not claim physical hosts, NAT or Internet operation,
controlled/public relay, BTLE, independent interoperability, scale beyond two,
resource thresholds, long-duration operation, live Event or Blob application
acceptance, or release authorization. State/Record durable subscriptions,
selected-node bindings, finite TTL/forwarding age, relay/multi-hop acceptance,
expiry, garbage collection, and automatic Record merge remain open.

## Live selected Blob application amendment (2026-08-27)

This amendment supersedes the earlier present-tense statements that selected
Blob has no live application handle. Those statements remain above as the dated
boundaries of the stopped-Blob and semantic-v5 network slices; they are not a
description of the current composition. The earlier retained State/Record
receipt also remains exactly what it was: its zero Blob counters provide no
evidence for this amendment.

`RunningNode::selected_blobs()` now returns a cloneable `SelectedBlobHandle`.
It shares the running actor's bounded application admission and dispatches each
accepted command to one bounded, joined blocking Blob worker; clones do not
open another Store or depot authority. Async `publish` accepts an owned,
nonempty regular file at cursor offset zero, bounded to 64 MiB and the selected
1,024 canonical 64-KiB chunks. It may commit while no peer is configured.
Success is one durable, source-authenticated, operation-key-idempotent local
publication, not delivery. An exact authorized retry freshly verifies and
returns the original publisher counter and acceptance marker. Different bytes
or identity metadata under the same operation key fail closed as a conflict.
Cancellation after enqueue may leave an indeterminate committed result, so the
exact operation key is the recovery path.

Async `read_page` selects the exact current authorized source and returns one
freshly authenticated, nonempty plaintext page of at most 64 KiB. Plaintext is
private behind a borrow and its owned allocation is zeroized on drop; no raw
`Vec` is returned. An application copy becomes caller custody. The live page is
not a streaming provider handle, subscription delivery, peer observation, or
convergence-status assertion. The exclusive stopped `SelectedBlobNode` remains
available for seekable-source publication and caller-owned streaming output
only while no live actor owns the same store.

The semantic-v5 amendment above remains the networking boundary. A peerless
live publication can be synchronized later, after restart, by direct
source-before-carrier transfer to an exactly interested, current
content-capable peer. Receiver source/prefix progress is durable and ordinary
visibility remains gated on whole-Blob verification and promotion; a later
peerless restart can read the completed Blob through the receiver's live
handle. This composes the live application and existing network mechanisms; it
does not create Blob route-only forwarding or custody.

Graceful shutdown and live zeroization close application admission, reject
queued commands, and join the Blob worker before releasing Store authority.
Retained handles then fail with sanitized `StateUnavailable`, and undisclosed
page allocations are zeroized. The node cannot erase caller-copied page bytes,
the caller's backing source file, or externally cloned descriptors. A blocking
FUSE, NFS, device, or other hostile filesystem syscall may delay the joined
worker and therefore shutdown or zeroization; no bounded-latency claim is made
for such providers.

This is mechanism and current-code test coverage, not a retained execution
receipt or acceptance amendment. Blob subscription/status convergence,
route-only custody, TTL/expiry/garbage collection, metadata-independent
whole-byte deduplication, 100+ MiB or RSS/resource thresholds, representative
physical IP/NAT/relay or BTLE operation, mixed-implementation interoperability,
selected-node language bindings, and release authorization remain open.

## Retained live Blob acceptance amendment (2026-08-27)

This amendment supersedes only the preceding statement that the live selected
Blob composition has no retained execution receipt. It does not change the
application ownership, page custody, cancellation, shutdown, or zeroization
decision above. The canonical
[`selected-live-blob-036d068.json`](../implementation/evidence/selected-live-blob-036d068.json)
receipt is 8,220 bytes with SHA-256
`484eafe504d958881dc7b871fbf788f733d9c8814e02fc27253ece38e6169735`
and binds the bounded execution to good-signature source commit
`036d068a8d055154beeffe265ceea8cf97079fa6`.

Two distinct participant identities under one common mission authority execute
four actor lifetimes with at most two concurrent. The publisher's live handle
publishes one fixed nonempty file
while peerless, proves exact retry and changed-payload conflict behavior, and
reads the exact two-page result. After the plaintext source files are unlinked
and their parent is synchronized, a direct-Iroh phase transfers the Blob to the
receiver, whose live handle reads the completed result. A later graceful
peerless receiver reopen reproduces that read. Four retained handles fail
closed after shutdown, and both direct bind addresses are reacquired. The
private mission, identity, database, depot-marker, and ciphertext contents are
inventoried by metadata only and are not opened, read, or hashed by the
projector. The independent-oracle checker suite passed 49/49.

The source/binary/execution link remains operator-attested, the selected source
list is not a complete reproducible-build closure, and transcript timing is
producer-attested. The reopen is a graceful same-process actor/store/provider
reopen rather than crash or power-loss recovery. Source unlink plus parent sync
is not physical-media sanitization. The run contains no interrupted partial
transfer and proves no long-offline continuation. It also establishes no Blob
subscription/status convergence, route-only custody, independent black-box
conformance, physical or representative network, mixed implementation,
scale/resource target, complete MVP, release artifact, or production
authorization.
