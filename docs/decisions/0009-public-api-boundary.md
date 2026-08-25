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

These Event slices do not replace the broader proven semantic `ApplicationNode`
or complete the accepted boundary. They have no atomic subscription update,
live State, Record, Blob, selected-node bindings, protected operational
provisioning, or generalized control administration. Finite TTL is absent and
therefore cannot be requested until authenticated cumulative forwarding age and
expiry exist.
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
node bindings, Record, Blob, independent interoperability, and acceptance
evidence remain open. The compiled example and exact boundary are documented in
the [selected State API quickstart](../quickstart/selected-state-api.md).
