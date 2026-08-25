# Production implementation requirements status

- Status date: 2026-08-24
- Requirements authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Requirements SHA-256: `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Atomic requirements index: [`requirements-matrix.csv`](../evaluations/0005/requirements-matrix.csv)
- Exhaustive cross-lane trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Matrix SHA-256: `57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`
- Retained receipt baseline (parent PR-A/pre-subscription): signed commit `ee57c0f1a0ff67b9a301220b63bb009593ef626b`
- PR-B code baseline: signed commit `e5feff0b03bff70018825212cab905cebeefadcb`
- PR-C source freeze: exact SHA-256 identities in
  [Current PR-C automated evidence](#current-pr-c-automated-evidence)
- Current selected State source freeze: exact SHA-256 identities in
  [Current selected State automated evidence](#current-selected-state-automated-evidence)
- Current selected Record source freeze: exact SHA-256 identities in
  [Current selected Record automated evidence](#current-selected-record-automated-evidence)
- Release status: **not production-authorized**

This is the tracked implementation ledger for the active production lane. It
does not create a proposal, choose a provider, or convert research evidence into
release evidence. Update it only when reviewed reproducible evidence changes
the status of a requirement. `implemented-uncredited` may be supported by reviewed
source plus repeatable automated tests; `observed-bounded` additionally requires
the stated retained execution receipt. Neither class implies release evidence.

## Trace vocabulary

The `selected_status` column uses only `observed-bounded`,
`implemented-uncredited`, and `open`. The remaining values below describe
separate source, evidence, or gate dimensions.

| Trace value | Meaning |
|---|---|
| `observed-bounded` | Real production-lane code passed a stated, reproducible test, but only within the recorded environment and claim boundary |
| `implemented-uncredited` | A mechanism exists, but the complete requirement has not been demonstrated |
| `open` | The selected production composition does not yet implement the obligation |
| `semantic-source` | Proven current semantic code or tests remain an equivalence source until the selected composition passes the replacement tests |
| `research-only` | Evaluation informed implementation, but its result is not production acceptance |
| `external-gate` | Completion requires target hardware, independent authorship/review, an admitted cryptographic module, or stakeholder-set values |

## Selected composition and authority boundaries

The production lane is Iroh-first. Carrier authentication is deliberately not
mission authentication, and neither is source or control authorization:

1. Iroh authenticates the expected direct carrier endpoint.
2. The unchanged `aster-core` four-flight hybrid-PQ mission session authenticates
   the independently provisioned mission `NodeId` before any inventory is loaded
   or disclosed.
3. The unchanged `aster-core` control-envelope provider authenticates the stable
   mission authority, delegated signer, exact sequence/predecessor chain, and
   revocation or recipient-filtered scope-epoch effect. Flash controls reconcile
   and activate from a durable contiguous prefix before the Event lane opens.
4. The unchanged `aster-core` source-envelope provider authenticates each
   Event's publisher and protected header. Typed State and Record seams apply
   the same source/content capability split to stopped/local projections.
   Neither class enters the Event reconciliation wire. Content authorization
   remains separate from route authorization.

| Component | Selected responsibility | Deliberately excluded |
|---|---|---|
| `aster-profile` | Requirements-owned complete reconciliation key and canonical inventory ordering | Semantic identity, source security, policy, or a competing product object model |
| `aster-redb-store` | One mission-bound transaction authority for an audited ordered control prefix, exact policy snapshots, content-verified Events and local State/Record revisions, their shared publisher causal frontier, bounded per-class operation ledgers, canonical Consume/Carry selectors, Event delivery cursors/pending attempts/acknowledgements, exact-key State/Record projection plans, guarded Record resolution, a bounded route-only Event cache, and a terminal software-zeroization intent/phase receipt; retained opaque compatibility data has a disjoint namespace | Deriving identity from unverified bytes, activating controls before commit, promoting route-only data into semantics, executing application merge code, live application policy, State/Record replication or garbage collection, physical sanitization, or a second reconciliation authority |
| `aster-negentropy` | Sole bounded set-difference mechanism over exact Event transfer identities, with timestamp zero | Object transfer, semantic identity, policy, or durable contact progress |
| `aster-iroh` | Direct endpoint lifecycle, exact carrier identity, allowlist admission, and bounded exchange | Mission identity, item/source authorization, hosted discovery, relays, port mapping, or NAT acceptance |
| `aster-node` | Sole composition root, mission-before-inventory and control-before-Event ordering, exact control/Event transfer, current route-grant plus protected receiver-interest filtering, authority commands, live sample applications, live/stopped selected Event operations, exclusive stopped/local State publish/query and Record publish/query/guarded-resolution, bounded authenticated Event peer/last-contact status, a same-UID Unix local software-zeroization lifecycle, receipts, and CLI | Global convergence or publisher-completeness claims from status/gap absence, live or replicated State/Record, automatic registered-policy merge, atomic subscription update, generalized control management, Blob, finite-TTL custody, platform-complete zeroization assurance, or release authorization |
| `aster-core` | Spec-verified mission session, control-envelope, recipient-filtered rekey, and typed Event/State/Record source-envelope security capabilities used by the selected slices | A replaceable legacy subsystem; it remains authoritative migration source and is not deleted while replacements lack equivalent tests |

Each control transfer ID is the exact envelope digest authenticated against its
mission authority, delegated signer, chain sequence, predecessor, and effect.
Event, State, and Record transfer IDs are SHA-256 digests of exact randomized sealed
representations. Each is intentionally distinct from the semantic `ItemId`
derived by the source-envelope profile. Negentropy and Fetch/Offer use only
exact Event transfer IDs in this slice; redb maintains disjoint semantic
indexes plus one authenticated publisher-dot and causal-frontier authority
across Event, State, and Record. State and Record transfer identities remain
local and never enter the Event frame grammar.

The selected node's normal dependency graph contains neither SQLite nor
`rusqlite`. The old caller-ID opaque `put` path remains isolated for compatibility
and is not reconciled by the selected Event protocol. No old semantic path has
been deleted.

## Production-lane requirements trace

The machine-readable trace contains exactly one row for every one of the 348
atomic matrix requirements. It keeps selected-production status independent
from proven migration sources, non-credit artifacts, research pointers,
disposition, and external-gate ownership. It also carries the matrix level,
phase, class, and final-stack flag.
`python3 tools/check-implementation-requirements.py` verifies complete ID parity,
unique rows, valid selected states, exact selected-status containment, and the
conservative generated claim boundary.

The current generated totals are 45 `implemented-uncredited`, 37
`observed-bounded`, and 266 `open` rows across 83 exact selected mappings. The
selected State slice moved `DM-5.1-01`, `DM-5.1-02`, `DM-5.3-01`, and
`DM-5.3-02`; the selected Record slice now moves `DM-5.1-08`, `DM-5.1-09`, and
`DM-5.3-06` through `DM-5.3-10` from `open` to
`implemented-uncredited`. Those Record movements are based on typed source
capabilities, a bounded transactional causal projection and operation ledger,
freshly verified stopped facade, explicit exact-sibling resolution guard,
compiled example, shipped instructions, and repeatable automated tests—not
documentation presence alone. They remain partial because Record is
stopped/local, disconnected concurrency is exercised only through privileged
local test ingestion, and the class is absent from the live runtime,
reconciliation wire, subscriptions, selected-node bindings, and acceptance
receipts. No row moves to `observed-bounded`; automatic registered-policy merge
`DM-5.3-05` remains `open`.

PR C previously moved `DM-7-11`, `DM-7-14`, `DM-7-15`, and `DM-7-18` to
`implemented-uncredited` for the live Event boundary. The preceding PR-B
movement was `DM-5.5-02`; the most recent retained-receipt movement remains
`DM-6-22` to `observed-bounded`.

### Where the selected lane stands

This roll-up is calculated from all 348 rows in the generated trace. Counts are
not completion percentages: `implemented-uncredited` means a partial mechanism
exists, and `observed-bounded` means only the stated environment and claim
boundary passed.

All 57 rows with an external gate are included within the 266 `open` rows:
`gate_kind` is an independent ownership dimension, not a fourth selected status.
The generator validates the trace totals; this family roll-up is the human
summary of that same CSV.

| Requirement family | Implemented, not fully credited | Observed, bounded | Open | Total |
|---|---:|---:|---:|---:|
| DM-1 Project brief | 0 | 3 | 4 | 7 |
| DM-2 Scope | 1 | 0 | 13 | 14 |
| DM-3 Operating environment | 0 | 1 | 12 | 13 |
| DM-5 Functional requirements | 34 | 10 | 78 | 122 |
| DM-6 Security requirements | 3 | 18 | 15 | 36 |
| DM-7 Developer experience | 5 | 2 | 14 | 21 |
| DM-8 Implementation constraints | 0 | 2 | 17 | 19 |
| DM-9 Performance and scale | 1 | 0 | 31 | 32 |
| DM-10 Compatibility | 0 | 0 | 6 | 6 |
| DM-11 MVP scope | 1 | 0 | 32 | 33 |
| DM-12 Acceptance criteria | 0 | 1 | 10 | 11 |
| DM-13 Deliverables | 0 | 0 | 11 | 11 |
| DM-14 Open design items | 0 | 0 | 23 | 23 |
| **Total** | **45** | **37** | **266** | **348** |

The selected lane is strongest today in bounded Event synchronization and
security ordering: real-process direct contacts, temporal payload-blind relay,
source authentication, mission-before-inventory, control-before-Event,
durable Consume/Carry receive intent, protected receiver-directed filtering,
live high-level Event operations and last-contact status, freshly verified gap
inspection, stopped/local source-authenticated State causal projection,
stopped/local source-authenticated Record conflict annotation and guarded
resolution,
recipient-filtered rekey, captured-node exclusion, restart/no-op behavior, and
same-UID Unix terminal software zeroization. The largest remaining blocks are
live/replicated State/Record, automatic registered-policy merge, Blob,
selected-node bindings and broader conflict workflows, finite-TTL custody and
constrained-operation controls, protected provisioning/control administration,
physical and mixed-implementation carrier acceptance, scale/resource evidence,
language bindings onto the selected node, independent interoperability/review,
and release/dependency admission.

Against the six-item high-leverage closure sequence:

1. **Selected Event live surface — implemented, not accepted complete.** PR C
   composes publish/query/subscribe/poll/ack, unsubscribe, authenticated gaps,
   and bounded peer/last-contact status with the running actor. A current-code
   real-process test publishes offline and delivers later. There is no retained
   PR-C acceptance artifact, and status/gap absence does not prove convergence
   or publisher completeness.
2. **State, Record, and Blob — State and Record local slices implemented;
   composition still incomplete.** Stopped `SelectedStateNode` now source-seals and durably
   publishes State, shares causal counters/frontier with Event, and returns a
   freshly verified exact-key current/recoverable projection. Stopped
   `SelectedRecordNode` preserves and annotates every causal head, rejects an
   ordinary publish across an unresolved conflict, and commits only an exact-
   guard application-reviewed successor. State and Record have no live/network
   paths, disconnected Record acceptance is absent, automatic registered-policy
   merge remains open, and Blob remains open. Their broader proven semantic
   implementation remains the migration source.
3. **Finite TTL, forwarding age, expiry, quotas, priority, and receive-only —
   open in the selected composition.** Existing lower-level primitives do not
   satisfy the integrated obligation.
4. **Protected operational provisioning and generalized control
   administration — open.** Bounded provider and control primitives exist but
   are not the selected operational workflow.
5. **Physical IP/NAT/relay, BTLE, mixed implementation, N=32, and resources —
   open.** Loopback and N=8 receipts do not satisfy these brackets.
6. **Targets, licenses, cryptographic module, independent review, SBOM, and
   signed release — open external/release gates.** No production authorization
   follows from the implementation slices.

The next implementation sequence continues item 2 with live/replicated State
and Record plus Blob, while retaining separate acceptance tasks for item 1 and
the local State/Record slices.

### First selected Event API stack

The first sequence item is deliberately split so the selected store keeps one
authority and each claim can be tested independently:

1. **PR A — foundation:** `SelectedEventNode` publishes arbitrary
   policy-authorized Events idempotently and performs bounded acceptance-marker
   queries. The selected redb store maintains and audits the durable
   acceptance-marker inverse index used by those queries. The compiled
   [quickstart](../quickstart/selected-event-api.md) exercises the public
   application projection without exposing sealed bytes, keys, inventory, or
   carrier/reconciliation mechanics.
2. **PR B — durable delivery and receive intent:** idempotent
   durable Consume subscriptions drive stopped-state poll/ack; Carry selectors
   support receive/forward without local application delivery. Poll plans are
   bounded, source/content authorization is freshly re-verified, attempts are
   committed before return, semantic-ID acknowledgement is idempotent, and
   restart/conflict/gap/zero-match/inactive-pending/stale-plan tests preserve
   the cursor and pending-ledger invariants. The canonical union of active
   Consume and Carry selectors is exchanged inside the mission-protected
   session and intersects both directional inventory and Offer/Fetch with
   current route authority. Empty selectors mean receive-none. A negative
   runtime test transfers subscribed `beta`, withholds authorized but
   unsubscribed `alpha`, and transfers nothing to a receiver with no selectors.
3. **PR C — live application handle (current code):** the cloneable
   `SelectedEventHandle` sends bounded commands to the running actor's sole
   authority and exposes publish/query/subscribe/poll/ack, unsubscribe, gaps,
   and status. Selector insertion/removal serialize against contact policy;
   shutdown and zeroization close command admission. A focused process test
   publishes with no peer, restarts into later synchronization, polls and
   acknowledges at the receiver, and verifies the acknowledgement after
   receiver restart.

PR C completes this Event-only code surface, not the generalized multi-class
MVP. `LastContactComplete` is only the most recent bounded authenticated
negotiation with active configured peers. A gap-free page is anchored only by
freshly verified positions already observed by the local store. Subscription
replacement is unsubscribe followed by subscribe, not an atomic update.
At the PR-C boundary, finite TTL, State/Record/Blob, selected-node
bindings/local-agent integration, protected provisioning/control
administration, physical and mixed-implementation acceptance, N=32/resource
brackets, and dependency/cryptographic/review/SBOM/signed-release gates all
remained open. The later local State and Record slices change only their
explicitly mapped rows. Stakeholder-owned supported targets and resource values remain
external decisions rather than values inferred by this implementation.

### First selected State API slice

The next stack begins State without changing the Event wire:

1. **Typed source capabilities:** `aster-core::source_state` constrains the
   existing source-envelope provider to State and distinguishes route-verified
   metadata from content-verified semantic acceptance. Exact payload, class,
   publisher, topic, scope, priority, causal stamp, logical key, tombstone,
   content length, key epoch, and durable no-TTL decisions are verified.
2. **Bounded transactional projection:** `aster-redb-store` adds disjoint State
   semantic/exact/operation/projection tables while sharing the authenticated
   publisher-dot and causal-frontier authority with Event. It rejects
   cross-class namespace and dot reuse, retains bounded exact-key history,
   marks dominated versions `Superseded`, preserves all active causal maxima,
   and selects the greatest complete semantic ID as current. The dedicated
   operation ledger is capped at 4,096 rows and 512 KiB and participates in the
   aggregate store limits.
3. **Stopped high-level facade:** `SelectedStateNode` owns the exclusive stopped
   writer, publishes by durable application operation key, and queries one exact
   topic/scope/logical key. It freshly verifies every active and inactive plan
   candidate, independently recomputes the reducer, and race-rechecks the exact
   policy-bound plan. Only active versions are exposed; an authenticated current
   tombstone remains visible, and optional active concurrent/superseded versions
   remain recoverable.

This source/store/facade composition provides current-code automated evidence,
not a retained acceptance artifact. State has no live handle, subscription,
inventory, Fetch/Offer frame, relay cache, or reconciliation identity in this
slice. Old-epoch exact operation replay still requires current authorization;
future-epoch State is rejected. No TTL, expiry, garbage collection, delete-wins,
State convergence across nodes, independent interoperability, or physical
acceptance is claimed. Live/replicated Record remains open, and Blob remains
open.

### First selected Record API slice

The next local slice adds Record without changing the Event wire:

1. **Typed source capabilities:** `aster-core::source_record` constrains the
   existing source-envelope provider to Record and distinguishes route-verified
   metadata from content-verified semantic acceptance. Exact payload, class,
   publisher, topic, scope, priority, causal stamp, logical key, tombstone,
   content length, key epoch, and durable no-TTL decisions are verified.
2. **Bounded transactional conflict projection:** `aster-redb-store` adds
   disjoint Record semantic/exact/operation/projection tables while sharing the
   authenticated publisher-dot and causal-frontier authority with Event and
   State. It preserves every active causal maximum, marks one stable complete-
   semantic-ID head `Current`, annotates the others `Concurrent`, retains
   dominated versions as `Superseded`, and has no delete-wins rule. Ordinary
   operation-bound publication cannot collapse a context that observes multiple
   heads. Explicit resolution requires at least two exact guarded heads, binds
   that sorted set into the operation digest, requires a successor observing all
   of them, and rejects a stale plan without mutation.
3. **Stopped high-level facade:** `SelectedRecordNode` owns the exclusive
   stopped writer, publishes by durable application operation key, queries one
   exact topic/scope/logical key, and returns an opaque resolution guard with an
   explicit conflict. It freshly verifies every active and inactive candidate,
   independently recomputes all dispositions and the sorted head set, and race-
   rechecks the policy-bound plan. An application computes reviewed output in
   its own code and submits the exact guard through `resolve`; no application
   merge policy runs during ingest.

The durable operation and guard rules distinguish idempotent retry from silent
conflict loss. A changed payload or head set under the same operation key fails
closed. An exact successful resolution retry returns its original immutable
revision after restart and after an authorized rekey, while a new operation
cannot reuse an old-policy guard. A current tombstone remains visible; a
concurrent tombstone and edit retain both heads in either semantic-ID order.

This source/store/facade composition provides current-code automated evidence,
not a retained acceptance artifact. Record has no live handle, subscription,
inventory, Fetch/Offer frame, relay cache, or reconciliation identity.
Independently source-authenticated publishers and N-way heads are exercised
through privileged local test ingestion, not disconnected processes or a
network path. No automatic registered-policy merge, TTL, expiry, explicit-
policy garbage collection, Record convergence across nodes, independent
interoperability, physical acceptance, or release credit is claimed. Blob
remains open.

No row below means that an entire source requirement passes. Credit is limited
to the production-lane mechanism and evidence boundary named in the final
column.

| Requirement | Current state | Production-lane implementation | Credit and remaining gap |
|---|---|---|---|
| `DM-1-03`, `DM-1-04`, `DM-1-05` peer flow, temporal relay, and resynchronization | `observed-bounded` | `aster-node` + source Event seam + redb + Negentropy + Iroh | Peerless publication committed Ping before isolated per-edge forwarding; peerless destination publication then committed a causally observing Pong before isolated per-edge return. Every directed-edge cohort moved one pre-existing Event and the final no-op moved none. Physical systems, longer custody, all data classes, generalized policy, mixed implementations, and scale remain open. |
| `DM-2-14` adopting-program key policy | `implemented-uncredited` | Existing `aster-core` control formats plus authority CLI and atomic redb publication intent | Authority inputs choose the revoked subject/generation and exact route-only/member recipient set for one rekey. Protected administration, a generalized adopter-facing API, policy governance, and additional key-management mechanisms remain open. |
| `DM-5.1-01`, `DM-5.1-02` State class and convergence | `implemented-uncredited` | Typed source-authenticated State capabilities, bounded local redb versions/operations, shared Event-State causal frontier, and stopped `SelectedStateNode` exact-key projection | Local sequential, concurrent, restart, tombstone, idempotency, and shared-counter tests exercise the deterministic projection. State has no live or reconciliation path, so multi-node convergence, independent interoperability, scale, bindings, and retained acceptance remain open. |
| `DM-5.1-04` Event support | `observed-bounded` | Existing `aster-core` Event envelope ported through selected redb/runtime, with live and stopped high-level projections | The retained sample seals, persists, reconciles, verifies, and reacts to Event. Current-code live-handle tests publish, query, consume, and later synchronize arbitrary authorized Events, but they are not a retained PR-C acceptance receipt. Other data classes and independent wire interoperability remain open. |
| `DM-5.1-05` through `DM-5.1-07` Event immutability, order, and gaps | `implemented-uncredited` | Authenticated Event sequence/dot, semantic and exact-transfer indexes, publisher/topic/scope positions, and a public bounded verified gap view | Gap pages freshly verify every observed anchor and race-recheck their exact policy-bound store plan. No gap means only that locally observed verified positions are contiguous; it does not prove publisher completeness or convergence. Cross-process missing-position and independent interoperability evidence remain open. |
| `DM-5.1-08`, `DM-5.1-09` Record class and disconnected concurrency mechanism | `implemented-uncredited` | Typed source-authenticated Record capabilities, bounded local redb revisions/operations, shared Event-State-Record causal frontier, independently authenticated test publishers, and stopped `SelectedRecordNode` projection/resolution | Local arrival-order, two-way/N-way, restart, tombstone, idempotency, stale-guard, and guarded-resolution tests exercise the mechanism. Record has no live or reconciliation path; independent publishers enter through privileged test ingestion, so disconnected-process delivery/convergence, mixed implementations, scale, bindings, and retained acceptance remain open. |
| `DM-5.1-17` through `DM-5.1-22` common item fields | `implemented-uncredited` / `observed-bounded` | The Event header authenticates class, topic, scope, priority, TTL, publisher, causal stamp, logical key, tombstone, and key epoch; the facade accepts and verifies the implemented Event fields for publish/query/poll without exposing finite TTL | These exact row statuses remain Event-derived. The local State and Record slices authenticate their corresponding fields but add no live/replication or acceptance evidence; Blob, transmission/eviction use of priority, and finite-TTL custody remain open. |
| `DM-5.2-01` eventual convergence | `observed-bounded` | Negentropy difference over exact Event transfer IDs plus mission-bound redb | Three and eight loopback stores reached the same two transfers after temporal forwarding, live reaction, and restart. Event now has bounded topic/scope receive selectors; multiple-scope lifecycle, physical links, other classes, mixed implementations, and requirement scale remain open. |
| `DM-5.2-02` subscribed in-scope convergence | `implemented-uncredited` | Durable canonical Consume/Carry selectors projected as protected receiver interests and intersected with route authority | An in-process test withholds authorized-unsubscribed `alpha`, and a current-code real-process test delivers one offline Event to a later subscribed receiver. One two-node observation is not all-reachable-node or global convergence; repeated multi-scope lifecycle, other classes, physical peers, scale, mixed implementations, and a retained PR-C receipt remain open. |
| `DM-5.2-06` through `DM-5.2-08` delivery, duplicate suppression, and idempotent outcome | `implemented-uncredited` / `observed-bounded` | Exact transfer acceptance, durable operation-keyed publication, and an at-least-once Event pending ledger with attempt-before-return and semantic-ID idempotent acknowledgement | Live and stopped poll freshly re-verify source/content authorization. Current-code real processes synchronize, poll, ack, and preserve the ack across receiver restart. The retained receipt still covers the built-in reaction only; unacknowledged process-crash retry, every external crash point, other classes, bindings, and independent implementations remain open. |
| `DM-5.2-09`, `DM-5.2-10`, `DM-5.2-13`, `DM-5.2-14` causality and clock-independent correctness | `observed-bounded` / `implemented-uncredited` | Authenticated dots/context, atomic Event-State-Record causal frontier/high-water, Pong observation of Ping, local causal projections, and Negentropy timestamp zero | Pong publication is isolated after Ping is durable at the destination, and its authenticated context observes Ping before any return-edge process starts. Event causality has retained bounded evidence; local State and Record causal projections have current-code tests only. Networked Record conflicts, replicated State, finite TTL, long-running operation, and independent interoperability remain open. |
| `DM-5.2-18` difference-proportional synchronization | `implemented-uncredited` | Bounded Negentropy exact-ID reconciliation | Equal inventory transferred nothing, but total-size-versus-difference cost evidence at requirement scale remains open. |
| `DM-5.3-01`, `DM-5.3-02` State causal resolution and concurrent tie-break | `implemented-uncredited` | Freshly verified exact-key causal maxima; authenticated context dominance; greatest complete semantic State ID current; retained `Concurrent`/`Superseded` history | The facade independently recomputes store dispositions and plan identity. A current tombstone remains visible and has no special delete-wins priority. Network replication, mixed implementations, expiry/GC, adversarial scale, and acceptance evidence remain open. |
| `DM-5.3-06` through `DM-5.3-10` Record sibling preservation, annotation, API, no-discard, and recoverable history | `implemented-uncredited` | Freshly verified exact-key causal heads; explicit `RecordConflict`; sorted sibling IDs and opaque exact guard; atomically guarded successor; optional superseded history | Ordinary publish cannot collapse multiple observed heads, stale or changed guards insert nothing, and every inspected head becomes recoverable history after resolution. Automatic registered-policy merge (`DM-5.3-05`), selected Record wire/live ingestion, explicit-policy GC, bindings, mixed implementations, scale, and acceptance remain open. |
| `DM-5.5-01` through `DM-5.5-03`, `DM-5.5-05` through `DM-5.5-07` topic/scope and payload-blind relay boundary | `implemented-uncredited` / `observed-bounded` | Authenticated topic/scope; durable Consume/Carry selectors; protected receiver interest; current peer scope/epoch route commitments; bounded route-only cache | Canonical selectors bound desired receipt while route authority remains an independent upper bound; empty means receive-none. Unsubscribe removes one selector and its delivery ledger; replacement is a later subscribe, not an atomic update. Dynamic multi-scope lifecycle, quotas/priority, bridges, other classes, physical/mixed implementations, and scale remain open. |
| `DM-5.6-01` through `DM-5.6-03`, `DM-5.6-05` direct, infrastructure-free, intermediate, and duplicate-bounded transfer | `implemented-uncredited` / `observed-bounded` | Direct Iroh line with hosted discovery/relay/port mapping disabled | Exact Events moved through payload-blind intermediates and restart no-op. Physical transport, independent conformance, cycles/broadcast, NAT, alternate carriers, and generalized custody remain open. |
| `DM-6-01` through `DM-6-07`, `DM-6-09` through `DM-6-12` source/route protection | `observed-bounded` / `implemented-uncredited` | Existing `aster-core` source envelope, exact-byte re-verification, separate route/content capabilities, and mission-protected mechanics | Event endpoints verified source and content while relays verified protected route metadata without plaintext content. This is Event-only loopback, not packet-capture acceptance, complete class coverage, key lifecycle completion, or independent cryptographic review. |
| `DM-6-13`, `DM-6-14`, `DM-6-18`, `DM-6-19`, `DM-6-25`, `DM-6-26` identity, authorization, and hybrid mission/source mechanics | `observed-bounded` | Carrier identity and mission `NodeId` are independent; mission auth completes before inventory; dynamic topic-content and scope-route grants remain distinct | Protected operational provisioning, non-Unix and physical zeroization assurance, generalized control administration/recovery, all data classes, admitted-module/algorithm-policy gates, and independent review remain open. |
| `DM-3-12`, `DM-6-20` captured-node exclusion and intermittent propagation | `observed-bounded` | Source-authenticated ordered Flash controls, payload-blind forwarding, durable revocation checks before Event | The authority CLI and carrier node were absent while one relay forwarded the two-control suffix to a survivor. After control convergence, that survivor published epoch-two Ping alone with no peer or contact; a separate later cohort forwarded the Event, and two captured-node cohorts were denied. Longer impaired partitions, multiple relays/carriers, physical systems, broader topologies, and independent implementations remain open. |
| `DM-6-21`, `DM-12-08` recipient-filtered field rekey and integrated acceptance | `observed-bounded` | Existing recipient-filtered `aster-core` rekey ported through source control, redb, and the Iroh runtime | One scope advanced from epoch one to two. A no-contact cohort separated eligible epoch-two Ping publication from later route-only forwarding. Four later barriers separately delivered durable Ping to the eligible Pong member, committed causal Pong without a peer or contact, moved Pong into the route-only cache, and returned Pong to the survivor. The omitted captured node learned no fresh content and its stale publication was not admitted. This remains one-host loopback, not physical field or release acceptance. |
| `DM-6-22` local zeroization | `observed-bounded` | Same-UID Unix `aster zeroize`, retained-inode secret handles, live drain, and durable terminal redb cleanup phases | A live child drained and destroyed its exact mission-bundle and carrier-identity contents; another child exited immediately after the terminal marker and a later CLI resumed cleanup. Data rows and zero-length pathnames were preserved, and restored credential bytes could not reopen the retained database. This does not prove inode deletion, deterministic remote observation of mid-flight teardown, physical/copy-on-write/snapshot/swap/backup sanitization, redb rollback/replacement resistance, non-Unix behavior, remote triggering, or independent platform assurance. |
| `DM-6-23` freshness and replay rejection | `observed-bounded` | Protected session replay checks, exact chained controls, policy-bound Event transactions, and durable/idempotent publication, selector, delivery-attempt, acknowledgement, and live-admission operations | Control rollback/fork, stale epoch, revoked-source traffic, stale plans, and commands after shutdown/zeroization fail closed in bounded tests; acknowledgement survives receiver restart. Physical capture replay, abrupt interruption at every live command/contact boundary, every data class, long retention/eviction, and independent implementations remain open. |
| `DM-11-20` MVP revocation | `implemented-uncredited` | Durable revocation is present in the selected production lane | One real-process captured-leaf scenario passed, but the complete MVP, protected administration, platform-complete zeroization assurance, generalized control management, and release gates remain incomplete. |
| `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-18` high-level documented boundary | `implemented-uncredited` | Typed live Event operations, typed stopped State/Record operations, sanitized errors/status, no transport or reconciliation types in application handles, and compiled shipped examples | These row movements remain based on PR C's live Event boundary. The stopped State/Record facades are additive; live State/Record, Blob, automatic merge, selected-node bindings, operational provisioning, and an independent developer-usability study remain open. |
| `DM-7-16`, `DM-7-17`, `DM-7-20` offline publication/later sync/sample | `implemented-uncredited` / `observed-bounded` | Built-in applications plus compiled live/stopped selected Event examples | Retained built-in receipts publish peerless and forward later. Current-code real processes also publish through the live handle with no peer, restart into later contact, poll/ack, and preserve the ack across receiver restart. This does not establish the supported offline interval, no-loss acceptance, other classes, physical systems, or independent interoperability. |
| `DM-8-01`, `DM-8-02` Rust implementation | `observed-bounded` | Rust 1.91 workspace and current selected-lane checks/tests | The retained locked/offline Darwin arm64 artifact identified below belongs to the parent PR-A/pre-subscription freeze. PR B, PR C, and the selected State/Record slices have source/test evidence only until a new release receipt is produced; supported-target and release acceptance remain open. |
| `DM-9-21A` many-node operation | `implemented-uncredited` | Demo accepts `--nodes 2..=32`; its deterministic schedule is `2N+1` cohorts and `5N-2` children | Parent PR-A/pre-subscription N=3/13-process and N=8/38-process receipts passed. N=32 would schedule 65 cohorts and 158 children, but no N=32 execution is claimed. Neither receipt proves the full range, bracketed many-node target, physical scale, or resource targets. |

The broader replicated State/Record behavior, automatic registered-policy
Record merge, and Blob continue to exist in the proven semantic implementation
and specification. Only the bounded local State and Record mechanisms named
above receive new selected-composition credit.

## Current PR-C automated evidence

PR C was pinned to these exact source identities at its own stack freeze:

```text
2ad1b080bfed2ba654b0d29c0cd6eab5f1eb6f4799dbb09203dc18a085b713d0  crates/aster-node/src/application.rs
81021e226bd413826e3afcea6adf7e8c6e0f22f547f59631a30238e1a015c6c2  crates/aster-node/src/runtime.rs
b3a684b32b474c5ee22d1c24e0e7bdb19ff2f9613ca42cf3cdf3ebda5262476c  crates/aster-node/src/lib.rs
e31a456a98950d5439b3b6ecd6492f0cbdfb50ad827856c97041b9645d278f82  crates/aster-node/examples/live_event_application.rs
59c858c0bc559944546e88eefee550523fd64905e4b2779a9a3d1a7eb2b8ce0e  crates/aster-node/tests/mesh_cli.rs
364e5a1d8d7f7b24ab75afe8ec2791023db83b11997bd07722c7d107a16a6a00  crates/aster-redb-store/src/lib.rs
```

At that PR-C freeze, the exact-byte gates included every-target `cargo check`,
Clippy with warnings denied, Rust formatting, and `git diff --check`. The
application module had seven passing tests. Focused runtime tests cover the
peerless live Event lifecycle, shutdown and live-zeroization admission closure,
rejection of an overflowing `run_for` before readiness or state mutation, queued
zeroization ahead of an already elapsed deadline, a nonzero operational window
under saturated application callers, and authenticated contact/status progress
under saturated callers plus continuously overdue one-nanosecond ticks. The
current-toolchain selected-code suite passed 499 of 499 tests: 336 core, 68
node-library, six node-binary, 13 `mesh_cli`, and 76 selected-store tests; the
examples had no tests.

A later timeout-only hardening gave the offline cell one shared 40-second
cold-start deadline across retries and kill/reap cleanup on publisher spawn
failure. Against the final test bytes, that exact Unix offline
publish, later authenticated synchronization, poll/acknowledge, and
receiver-restart cell then passed twice on the current toolchain and three
times on Rust 1.91.

The separate exact-tree Rust 1.91.0 matrix then passed 499 of 499: core 336/336
(126.48s), node library 68/68 (28.43s), node binary 6/6 (0.02s), `mesh_cli`
13/13 (148.26s), and selected store 76/76 (31.81s); the examples had no tests.
The current-toolchain and Rust 1.91 results are separate executions and their
timings are not pooled.

Representative focused commands and the selected CI gate are documented in
[Continuous integration](../ci.md#selected-composition-coverage). The two
499-test totals above are recorded exact-tree validation results; this ledger
does not claim that the focused command excerpt is a complete transcript of
either matrix execution.

This is automated source/test evidence, not a retained execution receipt. No
PR-C root, log bundle, artifact identity, physical-system run, independent
implementation, or release artifact is claimed. `LastContactComplete` remains
only a process-local report about each active configured peer's most recent
bounded authenticated negotiation. Gap absence remains limited to freshly
verified positions already observed by the local store. Selector replacement
remains unsubscribe followed by subscribe, not an atomic update. These checks
alone do not close State/Record/Blob or any later item in the six-step sequence;
the separately mapped local slices below remain non-networked.

## Current selected State automated evidence

The stopped/local selected State slice is pinned to these exact frozen Rust
source identities:

```text
1b33111f631ed417205849a7ec031ff7068f6b7f816d09392d146b0b8f3d57ea  crates/aster-core/src/source_state.rs
5da5c9bd7e36995e6315f29b7354a78d863ed97c94b33c10f5f7d9946d6a7a6b  crates/aster-core/src/lib.rs
835a508f56a4b07b6aa9301f6bbf2a9f3bb01717fff0bc218f02b58bc22e245c  crates/aster-node/src/application.rs
4f0d04afa2b5fe2b78ed1fdd88bd0a5e4007a05915e11bc08fedba9ba70e2982  crates/aster-node/src/application/state.rs
c45a02fdfe159a2da57f42145b0fbb0fcba25a71d2d722c0359ec9485d59d6b3  crates/aster-node/src/lib.rs
0151703349198128867f1751fbd33ca0a3e134a93d83ee5ed36c99869e811e1d  crates/aster-node/examples/state_application.rs
b973dc98bbde2d04555358f88c3b00a99180d059711bca7e2114c47749905424  crates/aster-redb-store/src/lib.rs
```

The documented two-node fixture and State example passed end to end on these
final bytes in a disposable root. The first run returned:

```text
STATE current=96e109dccac01630a0263cb00d8cfb97e0cc391c20ad6c9b759bc47bc26ff820 value=moving counter=3 ready_inserted=true moving_inserted=true recoverable=1
```

The immediate exact rerun returned the same semantic identity, value, publisher
counter, and recoverable count with both `ready_inserted` and `moving_inserted`
set to `false`. That is local executable evidence for durable operation replay
and causal projection, not State transfer or acceptance. The temporary root is
not retained as an execution receipt.

The final current-toolchain selected-code matrix passed 517 of 517 tests: core
library 342/342 (44.69s), node library 73/73 (4.64s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (136.20s), and selected store 83/83 (8.48s). The core basic
example and the Event, live Event, and State examples had no tests.

The separate exact Rust 1.91.0 matrix also passed 517 of 517: core library
342/342 (45.83s), node library 73/73 (4.70s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (135.07s), and selected store 83/83 (8.62s); the same examples
had no tests. Strict all-target/all-feature Clippy with warnings denied passed
on both toolchains. Rust formatting and `git diff --check` passed on the frozen
tree. These are separate executions; their timings and counts are not pooled.

Within those totals, five selected-node State tests exercise independent
reducer recomputation, restart-stable idempotent publication/query, visible
tombstones, Event-State shared counters with disjoint Event sequence positions,
and exact writer exclusion. The selected-store tests cover State operation
conflict and quotas, semantic/representation/cross-class collision, sequential
and concurrent reduction, deterministic full-ID tie-break, inactive-row
retention, stale/future epoch behavior, projection-plan races, schema/reopen
audit, and fail-closed aggregate invariant rejection.

Raw State operation lookup, stored rows, and projection plans remain privileged
structural data. Only the selected node's fresh source/content verification,
full request/header/payload/identity comparison, current-policy checks,
independent reducer recomputation, and exact plan recheck form the application
exposure boundary.

This slice has no State reconciliation frame, carrier path, live handle, or
retained execution root. It moves only `DM-5.1-01`, `DM-5.1-02`, `DM-5.3-01`,
and `DM-5.3-02` to `implemented-uncredited`; it adds no `observed-bounded`
credit and by itself closes no replication, Record, Blob, TTL/expiry/garbage-collection,
physical, mixed-implementation, scale, or release gate.

## Current selected Record automated evidence

The stopped/local selected Record slice is pinned to these exact frozen Rust
source and dependency-boundary identities:

```text
0942f0115e41eb901315ed93dab59a6bf90c0e039d2c81516d21e5884e39e4eb  crates/aster-core/src/source_record.rs
10292c32280dfe76d561404fe6e7bdb064ca5bd0fe968afbab052d1a15861263  crates/aster-core/src/lib.rs
abbd075bf8aaa331761c94cde8ec129441740b0e0d7197526af3a3cfad5458e3  crates/aster-redb-store/src/lib.rs
9f106a1879c6989399e97586c337232cf0bb2d291911c99b44030cc70d0839b0  crates/aster-node/Cargo.toml
de5a864e4eb81e2953761406b9036d987c6df8d69109e1e1d131d4f6070f7e1b  crates/aster-node/src/application.rs
2c2e19e702505988f667676c9569c13e983224b487022db4e03f8ebb634de735  crates/aster-node/src/application/record.rs
299da58603b0166100da51d589a9e08aad1297f6c8063e858fa36c4291d98132  crates/aster-node/src/lib.rs
bfac8e4c0e45fd3c573ca0ba51f9b86044fb52680a2b7074086f02e64aec2aff  crates/aster-node/examples/record_application.rs
2d4730bb12ea8a1e669228caff6fbf346df1cec1172660da1095f5a96f78d927  Cargo.lock
```

The focused Record suites passed on both the pinned current toolchain and exact
Rust 1.91.0: core Record 7/7, selected store Record 7/7, and selected-node
Record 8/8. Those tests cover typed route/content capability separation,
class/header/payload/TTL rejection, semantic-versus-exact identity, local
sequential and independently authenticated two-way/N-way heads, arrival and
complete-ID ordering, operation conflict/restart replay, ordinary-publish
conflict bypass rejection, exact guard-bound resolution, stale-plan atomic
rollback, changed-guard operation conflict, authorized exact retry after rekey,
visible tombstones without delete-wins, hidden-but-freshly-verified post-rekey
rows, tampered valid metadata with unchanged sealed bytes, cross-class causal
counter sharing/collision rejection, quotas, schema migration/reopen audit, and
terminal-store preservation. Application errors remained sanitized.

The documented two-node fixture completed in 27.21 seconds. On those final
bytes, the Record example's first run completed in 1.26 seconds and returned:

```text
RECORD current=4fa993318f7b61570f427afd644f8f6b4ab64289aa06dff5b49667c9ab89820c value=moving counter=3 ready_inserted=true moving_inserted=true concurrent=0 superseded=1 conflict=false
```

The immediate exact rerun completed in 0.84 seconds and returned the same
semantic identity, value, publisher counter, and projection counts with
`ready_inserted=false` and `moving_inserted=false`. That is local executable
evidence for durable Record operation replay and causal projection, not Record
transfer or acceptance. The disposable root is not retained as an execution
receipt.

The final current-toolchain selected-code matrix passed 539 of 539 tests: core
library 349/349 (44.44s), node library 81/81 (5.19s), node binary 6/6 (0.00s),
`mesh_cli` 13/13 (135.87s), and selected store 90/90 (8.75s). The five example
targets—core basic, Event, live Event, State, and Record—had no tests. The
test-harness time sum was 194.25 seconds;
the complete orchestration used 220.35 seconds wall, 425.76 seconds user, and
123.55 seconds system time.

The separate exact Rust 1.91.0 matrix also passed 539 of 539: core library
349/349 (45.77s), node library 81/81 (5.42s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (135.76s), and selected store 90/90 (8.61s), with the same five
zero-test targets. Its test-harness time sum was 195.57 seconds; complete
orchestration used 221.18 seconds wall, 426.45 seconds user, and 124.92 seconds
system time. These are separate executions; their timings and counts are not
pooled.

Strict all-target/all-feature Clippy with warnings denied passed on the current
toolchain in 10.32 seconds and on Rust 1.91 in 10.30 seconds. Rust formatting
passed on both toolchains in 0.73 and 0.85 seconds respectively, and
`git diff --check` passed in 0.03 seconds. The full dual-toolchain aggregate
validation took 463.76 seconds wall time.

Raw Record operation lookup, stored rows, causal dispositions, and projection
plans remain privileged structural data. Only the selected node's fresh
source/content verification of every candidate, complete
request/header/payload/identity comparison, current-policy checks, independent
head/disposition recomputation, exact plan recheck, and guard-bound commit form
the application exposure boundary.

This slice has no Record reconciliation frame, carrier path, live handle,
automatic registered-policy merge, explicit-policy garbage collection, or
retained execution root. It moves only `DM-5.1-08`, `DM-5.1-09`, and
`DM-5.3-06` through `DM-5.3-10` to `implemented-uncredited`; it adds no
`observed-bounded` credit and closes no networked Record, disconnected-process
acceptance, Blob, TTL/expiry/garbage-collection, physical,
mixed-implementation, scale, or release gate. `DM-5.3-05` remains `open`.

## Reproducible receipt

Every retained root, binary identity, and source hash below belongs to the
parent PR-A/pre-subscription snapshot. PR B, PR C, and the selected State/Record slices
change store, frame, runtime, application, core, example, or integration-test
bytes; their credit in this ledger is limited to the exact current code and
tests mapped above. No fresh retained real-process receipt for those slices is
claimed.

The source-level invocation is:

```sh
ASTER_DEMO_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 3 --root "$ASTER_DEMO_PARENT/mesh"
```

The `--root` path must not already exist. On 2026-08-24 the final frozen-tree
binary used for these real-process receipts completed this three-node run with
exit status zero in 33.44 seconds:

```sh
target/debug/aster demo --nodes 3 \
  --root /private/tmp/aster-final-default-causal-20260824-n3.fPvORJ/mesh \
  --base-port 64000
```

Its terminal invariant block was:

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-2 transfer_id=4058145515bbe6b44ce5eb97af487d1b4c87b72cb0b4ab3d276eb950a260745d semantic_id=4d5104aba312faa316ab1e5098b7f82fe1f29d9df8cf9018d16f82e6ee521774 producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=1 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-2 destination_state=node-0 correlation_semantic_id=4d5104aba312faa316ab1e5098b7f82fe1f29d9df8cf9018d16f82e6ee521774 transfer_id=9b1e72a60a664b157351d9d57b65c370bb7c716f8f07790ae3968e32f0be55e0 semantic_id=eeafea8fe3ceb0135ef3e1e8b295bba89ee086ea52e9e20feeb0ec2328071a4e source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=3 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=3 processes=13 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n3.fPvORJ/mesh
```

Read-only inspection on that retained root reported:

```text
node-0 zeroization=live opaque_items=0 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
node-1 zeroization=live opaque_items=0 events=0 event_acceptance_markers=0 event_sealed_bytes=0 route_cached_events=2 route_cached_bytes=21130 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
node-2 zeroization=live opaque_items=0 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
```

The environment was one host, direct loopback sockets, exact
carrier-to-mission bindings, a three-node line, three independent redb files,
and 13 child-process executions across seven (`2N+1`) causal cohorts. Node 0 and
node 2 had content grants for `mesh.ping-pong`; node 1 had only the corresponding
route grant. The peerless Ping publisher ran before the two isolated forward
edges; the peerless Pong publisher observed already-durable Ping before the two
isolated return edges. Each directed-edge cohort reconciled exactly one
pre-existing Event difference, emitted no application Event, and retained all
six control counters at zero. All 13 child stdout logs are nonempty (142 lines,
81,708 bytes), all 13 child stderr files are empty, and all terminal invariants
passed. The final no-op retained 36 passing contacts with all six control and
all five Event reconciliation counters zero. This single run's empty stderr is
observed receipt data, not a general zero-error guarantee.

The tracked [`mesh_cli` integration test](../../crates/aster-node/tests/mesh_cli.rs)
runs the same Ping/Pong invariants at four nodes with a 120-second bound. Omitting
`--scenario` must produce `scenario=ping-pong nodes=4 processes=18`; a separate
integration test selects the explicit four-node control scenario with a
120-second outer bound. The retained
default-N4 Ping/Pong root is
`/private/tmp/aster-final-default-causal-20260824-n4.wSr6so/mesh`;
it passed in 40.74 seconds and retained 18 nonempty child stdout logs (210 lines,
121,209 bytes) plus five transient no-op lines (1,067 bytes) across two stderr
files: two duplicate-concurrent-contact notices, two connection losses, and one
clean peer-close notice. Its final no-op retained 62 passing contacts with all
11 reconciliation counters zero.

The default receipt's Ping transfer ID was
`1748e202aafb841eab20bf54acc792bcec7df1de1972a6e0a1b7bd9bf0e6e903`
with semantic ID
`370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3`.
Its Pong transfer ID was
`a4e9ce024127d7b36d4e5e08e3a67b84f6e7fef605f08e7c86a8e311bd3c3757`
with semantic ID
`1022ba758399a264e625782b96d58dd0efa26bab58497dad3e31a65ecff1afd6`
and the Ping semantic ID as its causal correlation.

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-2-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-3 transfer_id=1748e202aafb841eab20bf54acc792bcec7df1de1972a6e0a1b7bd9bf0e6e903 semantic_id=370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3 producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-3-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=2 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-3 destination_state=node-0 correlation_semantic_id=370b7e3c9b26ece4877eed6077664a987eee609384fbbb21ec94bc691d1deda3 transfer_id=a4e9ce024127d7b36d4e5e08e3a67b84f6e7fef605f08e7c86a8e311bd3c3757 semantic_id=1022ba758399a264e625782b96d58dd0efa26bab58497dad3e31a65ecff1afd6 source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=4 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n4.wSr6so/mesh
```

The parent PR-A/pre-subscription receipt freeze identifies its composition and
real-process test sources by SHA-256:

```text
bf1555b8749454ae12ac39da284d0d7815a815b9fe957154dbfcdf31b1a15ae0  crates/aster-node/src/runtime.rs
5ae2d26abb08d40bc2d8e48eca2f065f17159db4f706301867ae455df5288165  crates/aster-node/src/main.rs
c3586133d1cee158ab20f9148d7787a4113beef2c182e0b792c240321c00ab5a  crates/aster-node/src/lib.rs
be99c4abdee33ffe92a369a958a84e37a905550f197ca6b390a175dce73d8131  crates/aster-node/tests/mesh_cli.rs
7efab9b8c2fd9a566d35bada2e0ee5865d9ef4f4033fb376b93d5eb26f54e697  crates/aster-node/src/mission.rs
3c33c90dd03c2bd8612e14a94af298164453ebcf53603e51af7b178f14ce3624  crates/aster-node/src/identity.rs
09c17d7fd4233834c783aafc7422869ed833f5e3de07a6685e615fdceedbde0c  crates/aster-redb-store/src/lib.rs
9d1686436d1bfab26ccefeea89b49d5104d30d303e5295d0b668cf525586b56f  crates/aster-redb-store/Cargo.toml
```

The debug artifact stayed byte-identical across the retained real-process
receipts:

```text
path=target/debug/aster
target=Darwin-arm64
format=Mach-O-64-bit
size_bytes=61742936
mtime=2026-08-24T05:45:49-0500
sha256=f7bf097c03d050d99fdfe0fdf83401db870279a300ecfc37d9d5631eea7dd16e
```

The locked/offline Darwin arm64 release build on the same frozen tree used Rust
1.91:

```sh
cargo +1.91.0 build --release --locked --offline -p aster-node --bin aster
```

```text
path=target/release/aster
target=Darwin-arm64
format=Mach-O-64-bit
size_bytes=8776928
mtime=2026-08-24T06:08:48-0500
sha256=c905ffadb6481b2fa947c88ba60141b8117094b0836271a05a23fc07ab4a0a65
```

This is artifact identity and bounded execution evidence, not release
authorization, supported-target coverage, reproducibility proof, signing, or a
cryptographic-module claim.

## Bounded scale probes

The same frozen-tree binary completed an eight-node line with exit status zero
in 84.32 seconds:

```sh
target/debug/aster demo --nodes 8 \
  --root /private/tmp/aster-final-default-causal-20260824-n8.uduyD4/mesh \
  --base-port 64400
```

```text
PHASE status=pass name=ping-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=ping-forward-0-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-1-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-2-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-3-to-4 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-4-to-5 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-5-to-6 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=ping-forward-6-to-7 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PING status=received emitted_by=origin-process producer_state=node-0 destination_state=node-7 transfer_id=71b8e4b43d39de9e69337692daa5132910f7c558afb532128cf0dfbe9024182c semantic_id=b315bc9207e3d4ba00b0a658a07cbcc54d625e13661447e1e7e3000d41fc34be producer_process_absent=true source_authenticated=true ttl=none
PHASE status=pass name=pong-return-7-to-6 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-6-to-5 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-5-to-4 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-4-to-3 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-3-to-2 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-2-to-1 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return-1-to-0 processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
RELAY status=pass intermediates=6 exact_forward=true content_access=denied semantic_acceptance=none
PONG status=received emitted_by=destination-process producer_state=node-7 destination_state=node-0 correlation_semantic_id=b315bc9207e3d4ba00b0a658a07cbcc54d625e13661447e1e7e3000d41fc34be transfer_id=2f2667a3d80866d85d5e90b5affbdee23a9bbbac4becd2967f54d362079b3d77 semantic_id=044c6d80c803e5c3c33ffd834d8d2e624868e9d28f977034066930545e746ef5 source_authenticated=true causal_observation=verified ttl=none
PHASE status=pass name=noop processes=8 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
DEMO_RESULT status=pass scenario=ping-pong nodes=8 processes=38 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy producer_process_absent=true restarts=pass atomic_reaction=pass equal_inventory_noop=pass transfers_each=2 semantics=source-authenticated-event emitted_by=running-node-processes payload_blind_relays=pass ttl=durable-none root=/private/tmp/aster-final-default-causal-20260824-n8.uduyD4/mesh
```

Both endpoints had two semantic Events, two acceptance markers, 21,130 sealed
bytes, and no route-cache row. Each of the six intermediates had zero semantic
Events, two route-cache rows, and 21,130 exact cached bytes. All eight nodes
reported `zeroization=live`, zero opaque items, and zero controls. The schedule
used 17 cohorts and 38 children. Every directed-edge cohort moved exactly one
pre-existing Event and retained all six control counters at zero. All 38 child
stdout logs are nonempty (572 lines, 331,748 bytes). Seven of 38 child stderr files retain
ten transient no-op lines (2,195 bytes): five duplicate-concurrent-contact
notices and five connection losses. All 228 passing no-op contacts reported all
11 reconciliation counters zero. Corresponding required contacts succeeded and
convergence passed; this is not a zero-error claim.

Eight nodes are not the bracketed many-node target, proof of the full 2–32
range, physical multi-system acceptance, throughput evidence, or target-tier
memory/CPU/power evidence. The formula would schedule 65 cohorts and 158
children at N=32; that arithmetic is not an N=32 execution receipt.

## Mission-control revocation and rekey receipt

The control scenario is explicit; omitting `--scenario` continues to run the
configurable Ping/Pong demonstration. The frozen invocation was:

```sh
target/debug/aster demo --nodes 4 --scenario control \
  --root /private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh \
  --base-port 64600
```

The four role-bound nodes were authority/member node 0, route-only node 1,
surviving member node 2, and captured member node 3. Two short-lived authority
CLI processes first committed the exact chained controls:

```text
CONTROL status=emitted kind=revocation transfer_id=be65255a87fc078dd35a94a731628e6fe071198c8dd8d36ee40d10c4ffb2e2f1 sequence=1 subject=4978b65eab267816587ffe95b4ce02097a84043dafff50843d55a7dc547a9745 generation=1 activated=1 source_authenticated=true commit_before_activate=true emitted_by=authority-process
CONTROL status=emitted kind=scope-rekey transfer_id=22bb4f203bc6aaa5b7ffdbc70b7601dfe12695c2d7ce04704f7f9e424e08e74b sequence=2 scope=demo/mesh epoch=2 recipients=3 activated=1 source_authenticated=true recipient_filtered=true commit_before_activate=true emitted_by=authority-process
```

Node 0 seeded the route-only node, then both the authority CLI and carrier node
were absent while node 1 forwarded the exact controls to node 2. The demo next
ran node 2 alone with `peers=0` and `contacts=0`; it source-sealed and committed
epoch-two Ping only after its control high-water reached two. A separate
node-1/node-2 cohort then transferred that one exact Event with no control
transfer, making control convergence, local publication, and later forwarding
three distinct process barriers. Two later cohorts required the
node-2/node-3 contact to fail; node 3 could only source-seal one stale local
epoch-one Ping and received neither the control prefix nor epoch-two content.
Node 0 later returned as an ordinary eligible Event process. Four stopped-state
barriers first moved the already-durable Ping from node 1's route cache to node
0, then ran node 0 alone with `peers=0` and `contacts=0` to commit causal Pong,
then moved the already-durable Pong to node 1's route cache, and finally moved
it from node 1 to node 2. Each two-process transfer barrier reconciled one
pre-existing Event difference. The eligible line then restarted to an
equal-inventory no-op: every passing contact reported zero for all six control
counters and all five Event offer/fetch/insert/duplicate/remaining counters.
The terminal receipts were:

```text
PHASE status=pass name=control-authority-seed processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=control-authority-absent-event-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=captured-publication-denied processes=2 carrier_authenticated_edges=denied-as-required mission_authenticated_edges=denied-as-required provisioning=unprotected-reference
PHASE status=pass name=captured-rejoin-denied processes=2 carrier_authenticated_edges=denied-as-required mission_authenticated_edges=denied-as-required provisioning=unprotected-reference
PHASE status=pass name=pong-ping-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-publish processes=1 carrier_authenticated_edges=not-applicable mission_authenticated_edges=not-applicable provisioning=unprotected-reference
PHASE status=pass name=pong-relay-forward processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PHASE status=pass name=pong-return processes=2 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
PING status=received emitted_by=surviving-member-process producer_state=node-2 destination_state=node-0 transfer_id=5a1a8436798aad16f2d583dfc7d48d70c7e5471063b9a783b1f4e3102bf43a59 semantic_id=2dd815a4b996957aab71ec2c4c5197483be26a508087dcda96a2d5c0acfba3c3 authority_absent_during_forwarding=true source_authenticated=true key_epoch=2 ttl=none
PONG status=received emitted_by=eligible-member-process producer_state=node-0 destination_state=node-2 correlation_semantic_id=2dd815a4b996957aab71ec2c4c5197483be26a508087dcda96a2d5c0acfba3c3 transfer_id=8cd6cf3245299839c12f398b53e85466713add41f37577221716fef05e8656f1 semantic_id=8e465990083848f1b3b96d0c3d8671700e6091f82e291cdcbdb24bd4d15cc381 source_authenticated=true causal_observation=verified key_epoch=2 ttl=none
RELAY status=pass intermediates=1 exact_forward=true content_access=denied semantic_acceptance=none key_epoch=2
PHASE status=pass name=noop processes=3 carrier_authenticated_edges=verified mission_authenticated_edges=verified provisioning=unprotected-reference
CONTROL_RESULT status=pass nodes=4 authority_processes=2 emitted_by=authority-process controls=2 control_priority=flash authority_absent_forwarding=pass route_only_forward=pass survivor_epoch=2 captured_node=3 captured_sync=denied captured_epoch2_read=denied captured_mesh_publication=denied captured_rejoin=denied captured_local_signing=stale-only commit_before_activate=true mission_auth=hybrid-pq root=/private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh
DEMO_RESULT status=pass scenario=control nodes=4 processes=23 contacts=real-iroh mission_auth=hybrid-pq provisioning=unprotected-reference stores=independent-redb reconciliation=negentropy authority_absent_during_forwarding=true authority_cli_absent_after_commit=true authority_carrier_restart=pass controls=source-authenticated-flash recipient_filtered=true payload_blind_relay=pass captured_exclusion=pass epoch2_ping_pong=pass restarts=pass atomic_reaction=pass equal_inventory_noop=pass eligible_transfers_each=2 epoch2_publisher=node-2 root=/private/tmp/aster-final-control-causal-v4-20260824.M8mlbv/mesh
```

Read-only inspection of the retained stores reported:

```text
node-0 zeroization=live events=2 route_cached_events=0 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-1 zeroization=live events=0 route_cached_events=2 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-2 zeroization=live events=2 route_cached_events=0 controls=2 applied_controls=2 pending_controls=0 control_highwater=2
node-3 zeroization=live events=1 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
```

The 53-second run retains the exact 16-line parent terminal stdout (3,851
bytes) and empty parent stderr, plus 23 nonempty child stdout files (128 lines,
72,159 bytes) and 23 child stderr files. Four child stderr files are nonempty
with 109 lines (26,431 bytes), all inside the two required captured-contact
denial cohorts: 30
durable-revocation errors, 25 duplicate-concurrent-carrier-contact notices, and
54 peer-close effects. Every successful cohort retained zero stderr.
This is not a general zero-error claim. It is also not physical capture,
protected provisioning, a zeroization receipt, generalized control
administration, multi-scope or repeated rekey, independent interoperability,
scale, or release evidence.

## Local software zeroization receipt

The bounded local hook is a separate acceptance path; it does not reinterpret
the control scenario's `captured_local_signing=stale-only` result. The retained
post-fsync frozen-tree root is:

```text
/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm
```

After the same binary completed a two-node Ping/Pong setup at base port 64800
with exit status zero in 20.31 seconds and eight causal child processes, node 0
contained two source-authenticated Events and one additional opaque
compatibility row. A
setup Ping used transfer ID
`27542ed3a77ec77dfdfbe8f9fed53db73a0dbd109027ff163ae35fd09a7d5b09`
and semantic ID
`b8603f5b41cd8a614dc104d74019408dab9db12d5ab90705b98b71980c2d67c4`;
Pong used transfer ID
`010703ba7dcf1240ca3bf121031d0aea94108b7fa5bc4036ee9aa8d70b333718`
and semantic ID
`0b9fc8310aacec4ce9549f912b9f9f2a1587f286d4b9a19854bdf63719a3f697`,
causally correlated to that Ping. A same-UID process then started node 0 with
no peers on port 64810 and invoked:

```sh
target/debug/aster zeroize \
  --state /private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 \
  --mission-bundle-unprotected-reference \
    /private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0/mission.unprotected-reference.bundle \
  --wait-seconds 20
```

The live node and CLI emitted:

```text
READY selected=true pid=22080 carrier_id=69443fe89e3b54b1d97f6be1d4ee213d788c0b82d2abe8ac8012626a6fa8af78 mission_id=cec7fde3bb78ed74a584be51244bd025473bf3e81206b9d70a354e68f3e22f6f mission_authority=d0e5df62e9c8ca1aa5eb5cce201f4e60684bed215d500fcc40e25bd451699504 sockets=127.0.0.1:64810 state=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 peers=0 application=relay mission_auth=hybrid-pq provisioning=unprotected-reference semantics=source-authenticated-event controls=source-authenticated-flash commit_before_activate=true content_admission=capability-gated
STOP lifecycle=zeroized sync_status=terminal-lockout carrier_id=69443fe89e3b54b1d97f6be1d4ee213d788c0b82d2abe8ac8012626a6fa8af78 mission_id=cec7fde3bb78ed74a584be51244bd025473bf3e81206b9d70a354e68f3e22f6f contacts=0 contact_errors=0 opaque_items=1 opaque_acceptance_markers=1 events=2 event_acceptance_markers=2 route_cached_events=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0 mission_auth=hybrid-pq provisioning=unprotected-reference assurance=bounded-software physical_sanitization=not-claimed
ZEROIZE status=pass mode=live state=complete mission_destroyed=true carrier_identity_destroyed=true mission_pathname=retained-zero-length carrier_identity_pathname=retained-zero-length data_rows_preserved=true opaque_items=1 events=2 route_cached_events=0 controls=0 assurance=bounded-software physical_sanitization=not-claimed local_authority=same-uid-operator state_root=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0
```

The zeroize CLI exited zero in 0.074759 seconds; the live node emitted its
terminal stop and exited zero in 0.164328 seconds. Read-only inspection then
reported:

```text
INSPECT status=pass state=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0 zeroization=complete opaque_items=1 opaque_acceptance_markers=1 opaque_bytes=11358 events=2 event_acceptance_markers=2 event_sealed_bytes=21130 route_cached_events=0 route_cached_bytes=0 controls=0 applied_controls=0 pending_controls=0 control_highwater=0
ITEM id=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Before destruction the owner-only mission bundle was 5,675 bytes at inode
266049362, `identity.key` was 32 bytes at inode 266049359, and `mesh.redb` was
184,320 bytes at inode 266049367. All three were on device 16777230, mode
`0600`, effective UID 502, and link count one. After the receipt, both secret
pathnames kept their exact device, inode, mode, owner, and single-link count but
had length zero and the empty-file SHA-256. The redb inode remained and held the
terminal marker and preserved rows. This is retained-inode content destruction,
not inode or pathname deletion.

The mission bundle moved from SHA-256
`36ae0f10f03dfbf965245d444619848acfccec205a3dc240c8d84d7dc080121c`
to the empty-file digest
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
The carrier identity moved from
`08423318e7dc663976c4ed043f6523fced1818a82668deb81a9dc83368728377`
to that same empty digest. Restoration and the later idempotent replay retained
the original digest for each exact inode. The retained store changed from
`9735f2704fbbac13c8a6cda69a58c91a7d1f05797c2ae450de5cd01184873555`
to `dd0114425580b39c06f9685a8987a757936c9856b8c9ab7b02e7be3c12a65ff2`
when it committed the terminal marker. The idempotent replay retained the same
device, inode, mode, owner, link count, size, terminal state, and data rows but
updated the redb file digest to
`ee7bf5d705cd25fdb16df22a702b351fcfc26cf960471e4f0c6459450449e9d0`.

The harness then restored the exact original credential bytes and hashes into
the same two inodes. A normal node restart exited one in 0.006637 seconds,
emitted no `READY` or contact, and returned:

```text
ERROR error=store%20is%20terminally%20locked%20out%20in%20Complete%20state
```

An idempotent replay exited zero in 0.032051 seconds, reported both pathnames as
`retained-external-change`, left the externally restored files untouched, and
left terminal inspection unchanged:

```text
ZEROIZE status=pass mode=stopped state=complete mission_destroyed=true carrier_identity_destroyed=true mission_pathname=retained-external-change carrier_identity_pathname=retained-external-change data_rows_preserved=true opaque_items=1 events=2 route_cached_events=0 controls=0 assurance=bounded-software physical_sanitization=not-claimed local_authority=same-uid-operator state_root=/private/tmp/aster-final-zeroize-v3-20260824.8V18Qm/mesh/node-0
```

The retained root contains 64 files totaling 467,815 bytes. Its receipt summary
has SHA-256
`fcf9d110253a7396af93c2e251883627c93e6a3b36a314f2eea59b866f507fd7`.
Its 62-entry file/byte manifest lists 448,617 bytes and has SHA-256
`450d97bc536d344efa5c85f93d248da4066e91a605a0fb4a236155ffda290066`;
the verified 63-entry evidence manifest has SHA-256
`c7ce69404b8e9463e81d1b8c56d61604d75f71b2b0694e850762f2785fbd8edb`.
The summary pins the unchanged frozen binary and both changed sources to the
digests recorded above. Its independent full-root scan found neither complete
credential encoded as hex nor complete credential encoded as base64;
`secret-scan.matches` is empty. The retained 11,358-byte `LICENSE` opaque row
has SHA-256
`cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`.
A separate
integration child commits the
Immediate-durability terminal marker and exits abruptly before artifact
destruction; the later CLI resumes only the exact recorded inodes, reaches
`complete`, and preserves its preexisting row. Store and node tests also require
wrong authority, corrupt/partial marker, symlink, hard-link, owner/mode,
path/inode replacement, and phase-order failures to remain terminal and fail
closed without erasing replacement data.

This is `observed-bounded` evidence for DM-6-22 only. It covers same-UID Unix
software erasure of the selected unprotected-reference mission bundle and Iroh
carrier identity. The manual live receipt had no active peer or mid-flight
stream. It does not prove deterministic remote teardown observation, inode
deletion, physical flash or copy-on-write sanitization, snapshot/swap/backup
destruction, redb rollback or replacement resistance, non-Unix support, remote
triggering, protected provisioning, or independent platform assurance.

## Mission-authenticated runtime validation

The current verification lanes include:

```sh
cargo test --locked --offline -p aster-core --all-features
cargo test --locked --offline -p aster-redb-store
cargo test --locked --offline -p aster-node --all-features
```

On 2026-08-24 the parent PR-A/pre-subscription frozen tree passed 336 `aster-core` tests, 57 redb-store tests,
48 node-library tests, six node-binary tests, ten node integration tests
(including the default four-node Ping/Pong, explicit four-node control, live
zeroization, abrupt-marker recovery, and dirty-process recovery cells), and doc
tests. Current-toolchain formatting, Clippy with warnings denied, and the full
workspace check passed; every target and feature also checked on Rust 1.91.
Five fuzz campaigns completed 10,000 iterations each (50,000 total) over wire,
fragment, envelope, selected-frame, and selected-Negentropy decode paths with no
finding. Those counts and retained roots are historical parent evidence, not
current PR-B, PR-C, or selected State execution receipts.

The signed PR-B code baseline above passed the same current and exact
Rust 1.91.0 matrix with 336 `aster-core` tests, 73 redb-store tests, 62
node-library tests, six node-binary tests, and 11 real-process integration tests
(488 total per toolchain). Both strict Clippy gates and formatting passed. After
the directional Event-frame update, all five fuzz campaigns again completed
10,000 iterations each (50,000 total) with no crash. The documented two-node
capability tour passed, and the selected Event example demonstrated publish,
fresh query, durable subscribe/poll/ack, and an exact idempotent second run.
These are current code/test execution checks, not protected-provisioning,
physical-carrier, mixed-implementation, scale, or release evidence.

The runtime suite covers mission authentication before inventory, independent
carrier/mission binding, protected mechanics, exact negotiated Fetch/Offer
sets, source-authenticated control chains, control-before-Event admission,
pending control gaps, atomic commit-before-activate, control restart replay,
Event source/content verification, peer scope-route filtering, route-only relay
behavior, durable operation replay, and fail-closed stale-epoch and revoked-peer
cells. It also retains the negative cells for wrong carrier, wrong mission,
cross-mission credentials, tamper, plaintext mechanics, replay, and unauthorized
Fetch/Offer. The zeroization cells add live drain, terminal store lockout,
retained-inode destruction, restored-credential refusal, idempotent replay,
abrupt-marker resumption, fail-closed artifact/path adversaries, and an injected
Unix parent-directory synchronization failure before any writable store or
terminal cleanup handle becomes usable. This does not replace physical-network,
packet-capture, physical sanitization or power-loss acceptance, database
rollback resistance, non-Unix, independent interoperability, or cryptographic
review evidence.

## Dependency-admission gate

The Iroh-first implementation removed the active unmaintained `paste` package
instead of expanding the retained-pilot exception. The workspace path-patches
exact `netlink-packet-core` 0.8.2 with byte-identical Rust sources so its
dependency key resolves to maintained `pastey` 0.2.2. The root lock and active
graphs contain no `paste`; CI fails if it reappears. Patch provenance and the
upstream-removal condition are recorded in
[`ASTER-PATCH.md`](../../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md).

Release admission remains blocked on explicit policy decisions. Native Iroh
reaches compiled Mozilla trust-root data in `webpki-roots` 1.0.9, licensed
`CDLA-Permissive-2.0`; the all-target inventory also includes
`webpki-root-certs` 1.0.9 under that license. Three browser-WASM-only packages
(`async_io_stream` 0.3.3, `pharos` 0.5.3, and `ws_stream_wasm` 0.7.5) use the
OSI-approved `Unlicense`, which is not on the repository allowlist. No exception
was added. The release owner must define the supported target matrix, and the
policy/legal owner must approve exact package/version treatment or require a
different technical trust-root path.

## Requirements still open in the selected lane

| Requirement class | Current state | What must be delivered before complete credit |
|---|---|---|
| Remaining data model | `implemented-uncredited` / `open` | Carry selected State and Record through the live/runtime reconciliation composition and verify multi-node convergence/conflict preservation; design convergent registered-policy Record merge; add Blob; deliver deterministic independent wire interoperability, State/Record retention/GC, and broader conflict/deletion behavior |
| Source and mission security | `implemented-uncredited` / `observed-bounded` / `open` / `external-gate` | Generalized and protected control administration; multi-scope, repeated, longer-partition, and physical revocation/rekey propagation; non-Unix and physical/copy-on-write/snapshot/swap/backup zeroization assurance; database rollback/replacement resistance; protected operational provisioning; all data classes; admitted FIPS boundary where required; packet-capture acceptance; and independent cryptographic review |
| Custody and constrained operation | `open` | Authenticated cumulative forwarding age for finite TTL, expiry/garbage collection, priority scheduling/retry/eviction, emission thresholds, receive-only mode, and operator quota controls |
| Scope and application policy | `open` | Multi-class selectors, State/Record receive and delivery behavior, automatic registered-policy Record merge, atomic subscription update, multi-scope join/leave, bridges, dynamic peer policy, and equivalent live status/gap semantics beyond the selected Event surface |
| Blob behavior | `open` | Authenticated chunking, streaming, resume across contacts/peers/carriers, content-addressed deduplication, and hundreds-of-MB acceptance |
| Carrier portfolio | `open` / `external-gate` | Physical IP, NAT traversal and relay fallback, discovery, BTLE platform driver, smallest-MTU framing, link characteristics, and future-carrier proof |
| DDIL resilience | `open` / `external-gate` | Loss/bandwidth floors, long custody/offline interval, crash/corruption recovery, partial-contact durable progress, alternate-peer/carrier continuation, mobility, and power/emission measurements |
| Developer surface | `implemented-uncredited` / `open` | Extend the stopped State/Record and live Event boundaries into live State/Record/Blob; add automatic merge only after a convergent design, atomic subscription update if required, C FFI and at least two selected-node bindings, broader multi-class examples, protected operational provisioning, an independent usability study, and a decision on the optional local agent |
| Scale and resources | `open` / `external-gate` | Stakeholder-confirmed bracketed targets plus repeatable node count, inventory size, memory, CPU, binary, bandwidth, and energy evidence on target tiers |
| Interoperability and release assurance | `open` / `external-gate` | Independent conformant implementation, mixed-version/downgrade evidence, completed hostile-peer campaigns, admitted dependency/license/SBOM graph, physical acceptance, and signed release disposition |

The proven semantic implementation remains the source to migrate. Its existence
outside the selected composition alone is not selected-composition credit, and
research evidence cannot replace production-lane verification.
