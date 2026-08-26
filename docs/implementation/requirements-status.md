# Production implementation requirements status

- Status date: 2026-08-26
- Requirements authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Requirements SHA-256: `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Planning view: [`capability-roadmap.md`](capability-roadmap.md)
- Atomic requirements index: [`requirements-matrix.csv`](../evaluations/0005/requirements-matrix.csv)
- Exhaustive cross-lane trace: [`requirements-implementation.csv`](requirements-implementation.csv)
- Matrix SHA-256: `57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2`
- Retained receipt baseline (parent PR-A/pre-subscription): signed commit `ee57c0f1a0ff67b9a301220b63bb009593ef626b`
- PR-B code baseline: signed commit `e5feff0b03bff70018825212cab905cebeefadcb`
- Current controlled Iroh relay source/test freeze: signed commit
  `b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`; exact source manifest and gates in
  [Current controlled Iroh relay automated evidence](#current-controlled-iroh-relay-automated-evidence)
- Prior semantic-v4 State/Record source/test freeze: signed commit
  `a0813a2b30b26f69ea7653dd0d3e04eba454c1b3`; exact source manifest and gates in
  [Prior selected State and Record network automated evidence](#prior-selected-state-and-record-network-automated-evidence)
- Prior semantic-v5 direct Blob source/test freeze: exact source manifest and
  bounded gates in [Prior semantic-v5 direct Blob network automated evidence](#prior-semantic-v5-direct-blob-network-automated-evidence)
- Prior PR-C source freeze: exact SHA-256 identities in
  [Prior PR-C automated evidence](#prior-pr-c-automated-evidence)
- Prior selected State stopped-slice source freeze: exact SHA-256 identities in
  [Prior selected State stopped-slice automated evidence](#prior-selected-state-stopped-slice-automated-evidence)
- Prior selected Record stopped-slice source freeze: exact SHA-256 identities in
  [Prior selected Record stopped-slice automated evidence](#prior-selected-record-stopped-slice-automated-evidence)
- Prior selected Blob source freeze: exact SHA-256 identities in
  [Prior selected Blob automated evidence](#prior-selected-blob-automated-evidence)
- Prior semantic-v3 selected Event custody source freeze: exact SHA-256 identities in
  [Prior semantic-v3 selected Event custody automated evidence](#prior-semantic-v3-selected-event-custody-automated-evidence)
- Current protected live startup/control source freeze: signed commit
  `164ccc1dbafd7fa954c06eb7cf555671ff597ba1`; exact SHA-256 identities and
  current-code gates in [Current protected live startup and control automated evidence](#current-protected-live-startup-and-control-automated-evidence)
- Selected N=32 retained-receipt source freeze: signed commit
  `6f280b680c0481faae5067e87cdc52d6597dc83c`; exact Cargo release-profile binary identity,
  validator boundary, and sanitized evidence in
  [Selected N=32 retained receipt](#selected-n32-retained-receipt)
- Prior protected stopped provisioning/control administration source freeze:
  exact SHA-256 identities and full automated matrices in
  [Prior protected provisioning and control administration automated evidence](#prior-protected-provisioning-and-control-administration-automated-evidence)
- Release status: **not production-authorized**

This is the tracked implementation ledger for the active production lane. It
does not create a proposal, choose a provider, or convert research evidence into
release evidence. Update it only when reviewed reproducible evidence changes
the status of a requirement. `implemented-uncredited` may be supported by reviewed
source plus repeatable automated tests; `observed-bounded` additionally requires
the stated retained execution receipt. Neither class implies release evidence.
Use the capability roadmap for planning and merge review. The rows below are an
exhaustive evidence trace, not a flat backlog, a completion denominator, or a
release score.

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

1. Iroh authenticates the exact expected carrier endpoint over direct IP or one
   explicitly configured HTTPS relay. The relay origin and trust mode are
   bounded operator inputs; path choice is never mission or data authorization.
2. The unchanged `aster-core` four-flight hybrid-PQ mission session authenticates
   the independently provisioned mission `NodeId` before any inventory is loaded
   or disclosed.
3. The unchanged `aster-core` control-envelope provider authenticates the stable
   mission authority, delegated signer, exact sequence/predecessor chain, and
   revocation or recipient-filtered scope-epoch effect. Flash controls reconcile
   and activate from a durable contiguous prefix before the Event lane opens.
4. The unchanged `aster-core` source-envelope provider authenticates each
   Event, State, Record, or Blob publisher and protected header. State and
   Record enter the semantic-v4/v5 class- and direction-separated mutable
   lanes. Blob enters only semantic v5: its authenticated source phase precedes
   direct carrier ranges, and v1-v4 emit zero Blob frames. Content authorization
   remains separate from route authorization.

| Component | Selected responsibility | Deliberately excluded |
|---|---|---|
| `aster-profile` | Requirements-owned complete reconciliation key and canonical inventory ordering | Semantic identity, source security, policy, or a competing product object model |
| `aster-redb-store` | One mission-bound transaction authority for ordered control/policy, content-verified Event/State/Record/Blob publication, the shared causal frontier, Event delivery/custody, class-specific operations/cursors, guarded Record resolution, route-only Event cache, Blob depot markers, and v5 exact pending Blob source plans plus peer-neutral carrier prefixes. It grants ordinary Blob visibility only after exact depot, fresh full-content, and fresh current-lineage completion agree atomically. | Deriving identity from unverified bytes, route-only Blob relay/custody, executing application merge code, State/Record/Blob TTL or GC, complete physical allocation/sanitization, automatic revoke-plus-rekey, or a second authority |
| `aster-negentropy` | Sole bounded set-difference mechanism over class-specific exact Event, State, Record, and v5 Blob source transfer identities, with timestamp zero | Object transfer, Blob carrier-prefix ownership, semantic identity, policy, or durable contact progress |
| `aster-iroh` | Direct endpoint lifecycle, exact carrier identity, allowlist admission, bounded exchange, and an opt-in singleton controlled HTTPS relay with explicit WebPKI or replacement DER-root trust and observation-only path telemetry | Mission identity, item/source authorization, hosted discovery or public/default relay fallback, port mapping, lifetime IP pinning, NAT acceptance, or physical-path proof |
| `aster-node` | Sole composition root for mission-before-inventory/control-before-data; exact control/Event/State/Record transfer; semantic-v3/v4/v5 Event custody; semantic-v4/v5 State/Record lanes; semantic-v5 direct content-capable Blob source-before-carrier transfer with repeated peer proof/current-lineage checks, 16-KiB ranges, resume cursors, and completion promotion; constrained emission with ReceiveOnly zero Blob; caller-provided protected live `NodeConfig`; live Event and privileged control handles; exclusive stopped Event/State/Record/Blob/control facades; local zeroization; receipts and CLI | Production SecretStore or protected stock CLI/bindings, cross-process admin IPC, automatic revoke-plus-rekey, global convergence claims, live State/Record/Blob application handles, route-only Blob relay/custody, Blob TTL/GC, broader State/Record partitions/relays, physical RF silence, automatic merge, generalized policy, coordinated provider destruction, platform-complete zeroization, or release authorization |
| `aster-core` | Spec-verified mission session, control-envelope, authenticated recipient-filtered rekey planning, typed Event/State/Record/Blob source-envelope security capabilities, and provider-neutral bounded provisioning protection plus operation-bound opaque SecretStore install/load/destroy contracts, of which exact load is used by the selected live config and stopped Event/admin slices | A production SecretStore/protection backend, hardware/platform custody policy, operational recovery or physical-erasure assurance; the core remains authoritative migration source and is not deleted while replacements lack equivalent tests |

Each control transfer ID is the exact envelope digest authenticated against its
mission authority, delegated signer, chain sequence, predecessor, and effect.
Event, State, Record, and Blob transfer IDs are SHA-256 digests of exact randomized sealed
representations. Each is intentionally distinct from the semantic `ItemId`
derived by the source-envelope profile. Negentropy and Fetch/Offer use
class-specific exact Event, State, and Record transfer IDs and semantic-v5 Blob
source IDs; redb maintains disjoint semantic
indexes plus one authenticated publisher-dot and causal-frontier authority
across Event, State, Record, and Blob. Canonical strict kind-2 Blob carrier IDs
enter only the v5 carrier-range grammar.

The selected handshake default/highest semantic version is 5 with offer
`[5, 4, 3, 2, 1]`. Event remains compatible across all five values;
State/Record mechanics run in v4/v5, and Blob mechanics are v5-only. V1-v4 emit
zero Blob frames. Stable
wire/profile, ABI, handshake framing, and source-object formats remain version
1. Current-code v4/v5 automation does not alter any retained v1-v3 receipt.

The selected node's normal dependency graph contains neither SQLite nor
`rusqlite`. The old caller-ID opaque `put` path remains isolated for compatibility
and is not reconciled by the selected Event protocol. No old semantic path has
been deleted.

## Production-lane requirements trace

The machine-readable trace contains exactly one row for every one of the 348
atomic matrix requirements. It keeps selected-production status independent
from proven migration sources, non-credit artifacts, research pointers,
disposition, and external-gate ownership. It also carries the matrix level,
phase, class, and final-stack flag. Atomization deliberately retains repeated
phase, acceptance, and deliverable statements, so row totals must not be used as
product progress percentages or as a count of independently ratified work
items.
`python3 tools/check-implementation-requirements.py` verifies complete ID parity,
unique rows, valid selected states, exact selected-status containment, and the
conservative generated claim boundary.

The current generated totals are 79 `implemented-uncredited`, 38
`observed-bounded`, and 231 `open` rows. The exact selected-mapping count is
121 and is validated from the generated trace. The
selected State slice moved `DM-5.1-01`, `DM-5.1-02`, `DM-5.3-01`, and
`DM-5.3-02`; the selected Record slice moved `DM-5.1-08`, `DM-5.1-09`, and
`DM-5.3-06` through `DM-5.3-10` from `open`. Semantic-v4/v5 class- and
direction-specific State/Record reconciliation now moves already durable source
objects over a mission-authenticated Iroh contact under explicit receiver
interests. Exact Apply/Fetch outcomes are acknowledged before the next attempt,
Finish reports an exact remaining count, valid saturation is typed capacity
deferral, and durable peer/class/local Offer/Fetch cursors rotate fairly within
the 256-peer/1,024-row bound. Each mutable object is at most 1 MiB and each class
is capped at 4,096 rows/16 MiB. Current-code automation observes State delivery,
disconnected Record publishers preserving the same two retained causal heads,
capacity deferral, cursor fairness, and current source-lineage replacement. It
is not a retained execution receipt, so `DM-5.1-09`, `DM-5.3-06`, and
`DM-5.3-09` remain `implemented-uncredited` rather than moving to
`observed-bounded`. State/Record application handles remain stopped/exclusive, and the
runtime has no durable application delivery API for those classes. The result
does not claim longer partitions, relay custody, divergent State convergence,
mixed implementations, scale, or release acceptance. Automatic
registered-policy merge `DM-5.3-05` remains `open`. The stopped/local selected Blob slice additionally
moves `DM-5.1-10`, `DM-5.1-11`, `DM-5.3-04`, `DM-9-13`, and `DM-9-14` from
`open` to `implemented-uncredited`. Those movements are limited to local
fixed-profile authenticated manifest/chunking, immutable publication, bounded
encrypted depot resume, and bounded-memory streaming. Semantic v5 now adds a
direct, content-capable-peer-only Blob source/carrier path with durable
peer-neutral range prefixes and completion-gated publication. The six further
requirements `DM-5.1-12`, `DM-5.1-13`, and `DM-5.2-19` through `DM-5.2-22`
move from `open` to `implemented-uncredited`. The repaired store retains one
bounded, non-public unfinished physical-lineage fence across terminal/stale
cleanup while reclaiming all chunk/file/reserved-byte authority. The repaired
runtime serializes durable source and authenticated-cache transitions through
delayed-insert/abort races and advances terminal multi-carrier scheduling to the
lexicographically greatest carrier ID. Exact regressions and independent final
audit are green. No `observed-bounded` credit or retained Blob receipt is
created. Neither the existing nor current movement claims route-only
relay/custody, a live Blob handle or
delivery subscription, TTL/GC, metadata-independent pure-byte identity,
hundreds-of-MiB or physical/resource acceptance, mixed implementations, a
release artifact, or complete physical allocation accounting.

The selected controlled-Iroh slice moves exactly `DM-5.8-06`, `DM-5.8-09`,
`DM-11-02`, and `DM-13-04` from `open` to `implemented-uncredited`. Direct IP is
composed into the selected Rust node and CLI. An additive opt-in accepts one
exact root-origin HTTPS relay, with either embedded WebPKI trust or bounded
explicit DER roots that replace WebPKI, while hosted discovery, public/default
relay fallback, and port mapping remain disabled. Current-code real processes
observe direct contacts while that relay is unavailable; a separate local
fixture gives the initiator an unusable initial direct candidate, disables IP at
the responder, observes Relay at both authenticated endpoints, synchronizes one
Event, and repeats as an exact no-op. A different focused runtime test rejects
the wrong expected mission before inventory construction. Initial direct
candidates may be probed in parallel with the relay,
and authenticated Iroh negotiation may learn later direct paths, so this is not
a direct-first chronology, lifetime address pin, or NAT result. The path witness
is bounded coalesced diagnostic state and never authorizes or proves delivery.
No retained receipt or `observed-bounded` credit is created by that controlled-
relay slice. Physical IP, representative NAT direct/fallback, BTLE, mixed
implementation, resource thresholds, State/Record/Blob-over-relay acceptance,
and every release gate remain open.

The selected N=32 retained receipt moves exactly `DM-9-21A` from
`implemented-uncredited` to `observed-bounded`. One operator-attested Cargo
release-profile binary run for the signed current-tree source completed the
selected Event Ping/Pong line on one macOS arm64 host over direct loopback with
32 distinct mission identities and stores, 65 exact cohorts, 158 exact-named
executions with distinct READY PIDs, 30 payload-blind intermediates, and 32
distinct log-observed READY PIDs in the final zero-difference no-op. No overlap
timing or OS sampler proves simultaneity. This does not move the bracketed
`DM-9-21` target of at least 100 nodes or any physical, distributed, NAT,
controlled-relay, BTLE, cross-transport, independent-implementation, resource,
or release row.

The selected Event custody slice moves `DM-5.4-05`, `DM-5.4-09`,
`DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`, `DM-5.4-22`,
`DM-5.7-03`, `DM-9-24`, `DM-9-25`, `DM-11-15`, and `DM-11-17` from `open`
to `implemented-uncredited`. It also strengthens the existing partial evidence
for `DM-5.4-01` and `DM-5.5-07`. Those movements are limited to selected
Event/RouteEvent semantic-v3-format custody inherited by v4/v5, Linux finite Event
TTL, priority scheduling and retry, logical quotas/retirement, and constrained
emission/receive-only automation. `DM-5.4-11` remains open: selected pressure
deliberately orders route-only victims before priority and State/Record/Blob
have no custody retirement path. In v4/v5, Normal and AtLeast still run mutable
reconciliation, and in v5 may run direct Blob work, because AtLeast is strictly
an Event threshold; ReceiveOnly initiates and discloses no mutable or Blob work.
No row moves to `observed-bounded`.

PR C previously moved `DM-7-11`, `DM-7-14`, `DM-7-15`, and `DM-7-18` to
`implemented-uncredited` for the live Event boundary. The preceding PR-B
movement was `DM-5.5-02`; the most recent retained-receipt movement is now
`DM-9-21A` to `observed-bounded`. The already-merged local ConnectRPC agent
moves `DM-7-09` and `DM-7-10` from `open` to `implemented-uncredited` and
extends the mapped evidence for the existing Event application boundary. That
agent remains an alpha same-host, same-implementation surface; it adds no live
State/Record/Blob or production deployment claim.

The protected stopped provisioning/control-administration slice changes no
selected status. It strengthens existing evidence for `DM-2-14`, `DM-3-12`,
`DM-6-13`, `DM-6-14`, `DM-6-18` through `DM-6-23`, `DM-11-20`, and
`DM-12-08`, and adds explicit partial-evidence mappings while keeping
`DM-3-11`, `DM-11-18`, and `DM-11-19` `open`. The totals above therefore do
not move. The extra three mappings prevent useful stopped-Rust mechanisms from
being mistaken for completed operational provisioning or MVP credit. The later
protected live Rust startup mechanism likewise changes evidence wording only.

### Where the selected lane stands

This roll-up is calculated from all 348 rows in the generated trace. Counts are
not completion percentages: `implemented-uncredited` means a partial mechanism
exists, and `observed-bounded` means only the stated environment and claim
boundary passed.

All 57 rows with an external gate are included within the 231 `open` rows:
`gate_kind` is an independent ownership dimension, not a fourth selected status.
The generator validates the trace totals; this family roll-up is the human
summary of that same CSV.

| Requirement family | Implemented, not fully credited | Observed, bounded | Open | Total |
|---|---:|---:|---:|---:|
| DM-1 Project brief | 0 | 3 | 4 | 7 |
| DM-2 Scope | 1 | 0 | 13 | 14 |
| DM-3 Operating environment | 0 | 1 | 12 | 13 |
| DM-5 Functional requirements | 59 | 10 | 53 | 122 |
| DM-6 Security requirements | 3 | 18 | 15 | 36 |
| DM-7 Developer experience | 7 | 2 | 12 | 21 |
| DM-8 Implementation constraints | 0 | 2 | 17 | 19 |
| DM-9 Performance and scale | 4 | 1 | 27 | 32 |
| DM-10 Compatibility | 0 | 0 | 6 | 6 |
| DM-11 MVP scope | 4 | 0 | 29 | 33 |
| DM-12 Acceptance criteria | 0 | 1 | 10 | 11 |
| DM-13 Deliverables | 1 | 0 | 10 | 11 |
| DM-14 Open design items | 0 | 0 | 23 | 23 |
| **Total** | **79** | **38** | **231** | **348** |

The selected lane is strongest today in bounded Event synchronization and
security ordering: real-process direct contacts, one controlled connectivity-
relay Event path, temporal payload-blind Event relay,
source authentication, mission-before-inventory, control-before-Event,
durable Consume/Carry receive intent, protected receiver-directed filtering,
live high-level Event operations and last-contact status, freshly verified gap
inspection, stopped/exclusive source-authenticated State causal projection,
stopped/exclusive Record conflict annotation and guarded resolution,
class-specific State/Record reconciliation with one bounded real-Iroh conflict
observation, stopped immutable Blob streaming through a bounded encrypted
depot plus semantic-v5 direct source-before-carrier transfer and peer-neutral
resume, recipient-filtered rekey, captured-node exclusion, typed bounded live
and stopped control administration, caller-provided protected/opaque-reference
live `NodeConfig` plus stopped Event/admin opens, restart/no-op behavior, and
same-UID Unix terminal software zeroization.
The largest remaining blocks are
live State/Record application operations, broader State/Record partition/relay
acceptance, automatic registered-policy merge, a live Blob application and
subscription boundary, route-only Blob relay/custody, Blob TTL/GC and larger
resource acceptance, selected-node bindings and broader conflict workflows,
cross-class and non-Linux custody plus physical constrained-operation
acceptance,
physical and mixed-implementation carrier acceptance, scale/resource evidence,
language bindings onto the selected node, a production provisioning/SecretStore
backend and protected stock CLI/bindings, automatic or atomic revocation-to-rekey
remediation, independent interoperability/review, and release/dependency
admission.

Against the six-item high-leverage closure sequence:

1. **Selected Event live surface — implemented, not accepted complete.** PR C
   composes publish/query/subscribe/poll/ack, unsubscribe, authenticated gaps,
   and bounded peer/last-contact status with the running actor. A current-code
   real-process test publishes offline and delivers later. There is no retained
   PR-C acceptance artifact, and status/gap absence does not prove convergence
   or publisher completeness.
2. **State and Record reconcile durable objects; their live application surface
   remains incomplete, while Blob has one bounded direct network slice.**
   Stopped `SelectedStateNode` source-seals and durably
   publishes State, shares causal counters/frontier with Event, and returns a
   freshly verified exact-key current/recoverable projection. Stopped
   `SelectedRecordNode` preserves and annotates every causal head, rejects an
   ordinary publish across an unresolved conflict, and commits only an exact-
   guard application-reviewed successor. Stopped `SelectedBlobNode` prepares a
   fixed-profile canonical manifest, resumes bounded encrypted local chunks,
   source-seals a publication only after exact completion, and synchronously
   streams freshly verified plaintext into caller-owned output. Separately, the
   runtime reconciles durable State/Record objects in semantic v4/v5 through
   protected class/direction exact-ID lanes under explicit interests. Exact
   result acknowledgement, exact Finish remainder, typed capacity deferral,
   per-object/per-class limits, and fair durable cursor rotation bound each
   contact. Semantic v5 additionally stages each exact Blob source before its
   carriers, persists peer-neutral 16-KiB prefixes, resumes the exact complement
   from another eligible content peer after receiver reopen, and withholds the
   publication until depot, full-content, and current-lineage proofs agree.
   Current-code real-Iroh automation transfers State, preserves two disconnected
   Record heads on both stores, and exercises that bounded direct Blob resume,
   but is not a retained receipt. Live State/Record commands,
   broader disconnected/relay acceptance, automatic registered-policy Record
   merge, a live Blob handle/subscription, route-only Blob relay/custody,
   metadata-independent byte identity, Blob TTL/GC, and large-Blob acceptance
   remain open.
   Their broader proven semantic implementation remains the migration source.
3. **Selected Event finite TTL, forwarding age, expiry, quotas, priority, and
   receive-only — implemented, not accepted complete.** Semantic-v3-format
   mechanics, inherited by semantic v4/v5, bind cumulative custody to the
   authenticated session and exact Event transfer;
   Linux supplies suspend-inclusive finite age; redb atomically owns quota,
   retirement, lease, retry, receipt, and replay-fence state; the node schedules
   priority work, exposes aggregate/scope configuration and live thresholds,
   and accepts bounded authenticated inbound Event work in ReceiveOnly. Normal
   and AtLeast still run v4 mutable reconciliation because the threshold is
   Event-only; ReceiveOnly initiates and discloses no mutable objects.
   State/Record/Blob custody,
   cross-class lowest-priority eviction, non-Linux finite TTL, physical RF
   silence, v1/v2 deterministic partials, scale, mixed implementations, and a
   retained acceptance root remain open.
4. **Protected operational provisioning and generalized control
   administration — bounded live/stopped Rust mechanisms implemented;
   operational composition open.** Caller-provided `NodeConfig` and stopped
   `SelectedEventNode`/`SelectedControlAdmin` accept a bounded authenticated
   protected artifact or exact operation-bound opaque SecretStore reference.
   The running actor's `SelectedControlHandle` and stopped admin publish bounded
   revocation/rekey controls with sanitized errors and exact retry. No production
   SecretStore/protection backend, protected stock CLI or binding,
   cross-process admin IPC, registry/credential issuance and recovery,
   automatic/atomic revoke-plus-rekey workflow, coordinated provider destroy,
   or physical-erasure assurance is delivered.
5. **Selected IP and one controlled-relay mechanism — implemented, not accepted
   complete; physical IP/relay deployment, representative NAT, BTLE, mixed
   implementation, at-least-100-node scale, and resources remain open.** The bounded carrier and
   selected CLI support direct IP plus exactly one opt-in relay with explicit
   TLS trust and no public fallback. Same-implementation localhost direct/relay
   automation does not satisfy the named physical gates. The separate one-host
   direct-loopback N=32 Event receipt below moves only `DM-9-21A`; it does not
   satisfy the at-least-100-node or resource brackets.
6. **Targets, licenses, cryptographic module, independent review, SBOM, and
   signed release — open external/release gates.** No production authorization
   follows from the implementation slices.

The next implementation sequence must extend the bounded item-2 data lanes
through live State/Record/Blob application operations, broader partition and
relay acceptance, larger/resource evidence, and retained acceptance without
weakening the custody or protected-administration stack. Item 4's admitted
operational backend, live startup/CLI/bindings, recovery, and coordinated
lifecycle remain separate work. Items 1 through 5 retain their stated
acceptance and composition gaps; completing one code slice does not silently
satisfy those gates.

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
At the PR-C boundary, finite TTL was still open; the later selected Event
custody slice now adds it on Linux together with semantic-v3-format age,
priority, quota, and constrained emission inherited by v4. State/Record/Blob
custody (distinct from v4 mutable reconciliation), selected-node
bindings/local-agent integration, operational/live provisioning and broader
control policy administration, physical and mixed-implementation acceptance,
N=32/resource brackets, and dependency/cryptographic/review/SBOM/signed-release
gates all remained open. The later local State, Record, and Blob slices change
only their explicitly mapped rows. Stakeholder-owned supported targets and
resource values remain
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

This source/store/facade composition provided the first stopped-slice
current-code evidence, not a retained acceptance artifact. At that historical
slice State had no live handle, subscription, inventory, Fetch/Offer frame,
relay cache, or reconciliation identity. The later v4 runtime adds protected
reconciliation without relabelling this evidence. Old-epoch exact operation
replay still requires current authorization;
future-epoch State is rejected. No TTL, expiry, garbage collection, delete-wins,
State convergence across nodes, independent interoperability, or physical
acceptance was claimed by that slice. Live application State/Record operations
remain open; the first Blob slice described later was stopped/local, and the
subsequent semantic-v5 section separately records the bounded direct network
mechanism without relabelling this historical evidence.

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

This source/store/facade composition provided the first stopped-slice
current-code evidence, not a retained acceptance artifact. At that historical
slice Record had no live handle, subscription, inventory, Fetch/Offer frame,
relay cache, or reconciliation identity; publishers and N-way heads were
exercised only through privileged local ingestion. The later v4 runtime adds
protected reconciliation without relabelling this evidence. No automatic
registered-policy merge, finite TTL, expiry, explicit-policy garbage
collection, independent interoperability, physical acceptance, or release
credit is claimed. The first Blob slice described next was stopped/local; the
subsequent semantic-v5 section separately records the bounded direct network
mechanism without relabelling this historical evidence.

### First selected Blob API slice

The final local data-class slice adds Blob without changing the Event wire:

1. **Typed source and manifest capabilities:** `aster-core::source_blob`
   constrains the existing source-envelope provider to a nonempty fixed-64-KiB
   Blob profile. The capability binds exact sealed bytes, canonical manifest,
   Blob ID, content group, epoch, route commitment, chunk records, media/schema
   identity metadata, and plaintext. A private keyless completion verifier
   requires every authenticated expected and committed store record plus the
   finalized manifest digest; raw mechanical store finalization is not
   publication authority.
2. **Bounded transactional publication and encrypted depot:**
   `aster-redb-store` adds disjoint Blob exact/semantic/publication/operation
   tables and structural read plans while sharing the authenticated publisher
   dot and causal frontier with Event, State, and Record. Ciphertext files live
   in a private sibling depot. File write/sync/rename/directory-sync precedes an
   exact redb marker; unmarked remnants may be reclaimed, while a marked
   missing or different file fails integrity. Dedicated byte/chunk-row/variant
   limits and operation limits participate in fail-closed reopen, collision,
   mission, quota, and terminal audits.
3. **Stopped streaming facade:** `SelectedBlobNode` owns the exclusive stopped
   writer, makes bounded preparation and encryption passes over a seekable
   source, commits one signed publication only after exact depot completion,
   and synchronously streams freshly verified chunks into caller-owned output.
   It verifies every retained active or inactive publication, independently
   selects the greatest active semantic publication ID, rechecks the exact
   store plan, and mints completion only for the winner.

`BlobId` commits exact plaintext bytes, the canonical chunk profile, and
media/schema identity metadata; it is not a separate metadata-independent
whole-byte content ID. Exact operation retry rehashes the source, passes current
authorization, and freshly verifies the original publication and historical
variant. A new operation may sign another publication over the same completed
variant; a rekey creates an epoch-specific encrypted variant.

The database is pinned to one fixed depot owner from its first successful Store
open, not treated as a relocatable backup. Redb persists a domain-separated
commitment over a random owner token, canonical store path, and, on Unix, the
exact device/inode; the sibling depot marker must carry the same binding before
any chunk/variant scan or reclaim. The first database to initialize a parent’s
depot wins, and another cannot adopt it. Moving/copying even an empty bound
database to another path fails on reopen. On Unix, a new inode also fails,
moving the depot with the database does not preserve the binding, and a
same-path replacement cannot adopt an existing depot. This slice provides no
supported rebind/restore migration. Non-Unix keeps token-plus-canonical-path
binding but cannot distinguish a copied database restored over that same path,
so equivalent inode/rollback resistance is not claimed.
Owner-token or owner-binding migration is all-or-none and admits missing fields
only for canonical empty Blob rows/counters with no fixed depot root; partial
fields, any logical Blob state, or any fixed depot root fail without repair.

At this historical stopped/local freeze, the source/store/facade composition
provided current-code automated evidence, not a retained acceptance artifact.
It had no Blob inventory, carrier object, remote chunk transfer, any-peer
resume, or network reconciliation; the later semantic-v5 slice below supersedes
only those network absences. Blob still has no live handle or subscription.
Unfinished chunk rows/import variants continue to consume their
admission caps pending explicit GC. The byte cap measures redb-marked canonical
ciphertext-file bytes, not redb allocation, directory blocks, hostile unrelated
entries, snapshots, backups, swap, or complete physical usage. No pure-byte
dedup, maximum-size or hundreds-of-MiB acceptance, physical sanitization,
independent interoperability, or release credit is claimed.

### Semantic-v5 selected Blob network slice

The selected offer is now `[5, 4, 3, 2, 1]`. V5 inherits Event v1-v4 and
State/Record v4 behavior and adds Blob class `3` source lanes plus one carrier
range lane. V1-v4 emit and accept zero Blob frames. Stable wire/ABI version 1,
session framing, `ASTRENV2`/`ASTRENV3`, manifests, `ASTRBT01`, typed ObjectIDs,
and cryptographic suite remain unchanged.

The v5 slice is direct between content-capable peers. Each exact
topic/scope/epoch interest carries an opaque 32-byte provider proof bound to
mission authority, authenticated claimant NodeID, and the current content
grant. Inventory, source, and every range send recheck that proof, current route
authority, durable nonrevocation, source route lineage, and physical content
lineage. Route-only authority is insufficient.

The fully authenticated source and exact manifest plan is staged atomically
before any carrier range. Redb stores one contiguous prefix under the exact
source transfer ID plus strict kind-2 carrier ID. A prefix extension is at most
16 KiB and is not owned by the peer or session, so another eligible content
peer can continue the exact complement after runtime/store/provider-cache
teardown and reopen. Peer cursor state affects bounded fair selection only. The
requester's Finish remaining count is echoed for sequencing; each exact
Result/Ack tuple binds accepted durable-prefix progress and is not an
independent responder attestation of requester disk truth.

Network admission is capped at 64 MiB plaintext and 1,024 64-KiB chunks. The
source envelope remains capped at 1 MiB, one carrier at 128 KiB, pending source/
manifest/prefix metadata at 10,000 rows, pending prefix bytes at 64 MiB, and
configured cursor peers at 256. Capacity deferral preserves accepted and
existing pending state. Conflicting prefixes, stale policy/lineage, wrong
identity or proof, and integrity failure do not become absence or success.

Pending state is absent from ordinary Blob publication inventory, query, read,
and service. Atomic promotion requires the exact pending plan, every verified
canonical carrier, matching `BlobDepotCompletion`, a freshly streamed
`VerifiedBlobContentCompletion`, and a fresh `CurrentBlobLineage`. The content
proof decrypts/authenticates every exact chunk, checks each plaintext digest,
and verifies the whole BlobID. A merely staged, partial, or carrier-complete
object remains nonpublic.

Same-epoch replacement invalidates peer proofs and current-lineage checks and
withholds old rows. Redb deliberately rejects another physical lineage for the
same `(BlobID, content group, numeric epoch)` with
`PhysicalLineageConflict`; republishing or resuming that Blob requires advancing
the numeric epoch. Normal and AtLeast run the v5 lane because AtLeast is
Event-only. ReceiveOnly advertises, requests, stages, promotes, and counts zero
Blob work.

The focused provider/frame/redb tests are current-code same-implementation
automation. The final runtime gate is one small bounded three-node direct-Iroh
case in which the first source leaves a durable prefix, all receiver runtime/
store/provider-cache ownership tears down, and a different completed eligible
content peer continues the exact complement after reopen to proof-gated
visibility. It creates no retained execution root and does not relabel any
historical Event/control receipt. Live Blob application access/subscription,
selected route-only Blob relay/custody, TTL/expiry/GC, pure whole-byte identity
or metadata-independent deduplication, 100+ MiB/RSS and resource acceptance,
physical carriers, mixed implementations, and release authorization remain
open.

### Protected provisioning and live or stopped control administration slice

This slice composes the existing protected-artifact boundary with selected
live/stopped Rust entry points and makes persistent custody a typed provider
seam:

1. **Provider-neutral secret custody contract:** `aster-core::provisioning`
   exposes a versioned, bounded, redacted `ProvisioningSecretRef`, separate
   caller-chosen install/load/destroy operation identities, sanitized failures,
   and checked install/load/destroy helpers. Plaintext construction rejects
   empty or oversized input, and checked install rejects a zeroized value
   before backend invocation. Install validates the exact operation; load and
   destroy validate the exact operation and caller-supplied opaque reference.
   Loaded plaintext
   remains an Aster-owned zeroizing in-process value. A destroy receipt records
   only the trusted backend's durable-tombstone assertion; `NotFound` is
   indeterminate, and neither result proves physical erasure.
2. **Protected live and stopped opens:** caller-provided `NodeConfig` plus
   stopped `SelectedEventNode` and `SelectedControlAdmin` can authenticate one
   bounded protected file or byte slice through a caller-owned
   `ProvisioningUnprotector`, or load one exact operation-bound opaque reference
   through a caller-owned `ProvisioningSecretLoader`. Live construction first
   validates the complete private `NodeConfigOptions` value and durable terminal
   state. Passing preflight invokes the provider/loader exactly once without
   creating state; failure never falls back to plaintext parsing. The stock CLI
   and bindings remain on explicitly named unprotected compatibility paths.
3. **Typed live and stopped administration:** stopped `SelectedControlAdmin`
   and the running actor's cloneable `SelectedControlHandle` publish a
   nonzero-generation `RevocationRequest` or `ScopeRekeyRequest`. Rekey input is
   rejected before provider/RNG/store work unless it carries a nonempty signed
   registry of at most 16 MiB, an independently retained nonzero registry
   generation floor, 1–128 unique recipients, and at most 256 aggregate topic
   grants. Registry credentials and canonical recipients authenticate before
   key generation. Publication either durably commits and activates the exact
   local control or returns an exact same-signer historical receipt; a remote or
   different signer cannot be relabeled as local recovery.
4. **Bounded live lifecycle:** the process-local control queue has capacity one,
   takes the actor's policy write lease, and yields after at most four commands.
   A successful publication refreshes live policy before response. An
   authenticated pending gap is deferred rather than actor-fatal: fresh work
   returns `PolicyUnsettled`, while exact historical retry remains recoverable.
   Cancellation after enqueue does not cancel actor-owned work and the command
   may still commit, so callers must retain and exactly retry requests. A lost
   self-revocation response is recovered through stopped admin after actor
   teardown; no cross-process live-admin IPC exists.
5. **Fail-closed post-revocation chain:** a fresh recipient-package rekey
   rejects a recipient already revoked when the request is evaluated. An exact
   same-signer historical duplicate can still recover its original durable
   receipt after a recipient is later revoked. A legacy recipient-less scope
   control may remain authenticated historical state if it predates revocation,
   but it is rejected after revocation. Authenticated predecessor/rollback poison
   purges its descendant suffix and leaves a durable rejected-sequence fence so
   replayed descendants cannot activate until a valid alternate fills the
   fenced sequence.

Relative state and file-artifact paths are resolved against one captured
absolute current directory before any caller provider/loader can change the
process current directory. Protected live config retains that exact absolute
lexical state pathname and rejects later public-field mutation before state
creation. It does not bind an inode, parent directory, symlink resolution,
rename history, database replacement, or rollback state. Protected file reads
have the documented no-follow Unix checks; equivalent non-Unix path-swap
assurance, parent-directory symlink or rename resistance across every boundary,
rollback-resistant persistent identity, and a supported restore/rebind
procedure remain open.

The slice remains Rust-only. The stock `aster node`, `control-revoke`, and
`control-rekey` paths still ingest an owner-only unprotected-reference bundle,
and C/Go/Python expose no selected protected path or live control handle. No
production SecretStore or protection backend is selected; the in-memory fixture
proves only the API model, not backend authentication, durability, hardware
custody, backup/recovery, or media sanitization. `READY` and `STOP` expose only
the non-identifying `provider-protected-artifact` or
`provider-secret-reference` origin. Both origins support graceful shutdown, but
live local zeroization cannot destroy provider custody. Revocation and rekey are
separate administrator transactions. There is no automatic affected-scope
discovery, durable rekey-required fence, atomic revoke-plus-rekey operation, or
coordination of live drain, store terminalization, and provider destroy.

No row below means that an entire source requirement passes. Credit is limited
to the production-lane mechanism and evidence boundary named in the final
column.

| Requirement | Current state | Production-lane implementation | Credit and remaining gap |
|---|---|---|---|
| `DM-1-03`, `DM-1-04`, `DM-1-05` peer flow, temporal relay, and resynchronization | `observed-bounded` | `aster-node` + source Event seam + redb + Negentropy + Iroh | Peerless publication committed Ping before isolated per-edge forwarding; peerless destination publication then committed a causally observing Pong before isolated per-edge return. Every directed-edge cohort moved one pre-existing Event and the final no-op moved none. Physical systems, longer custody, all data classes, generalized policy, mixed implementations, and scale remain open. |
| `DM-2-14` adopting-program key policy | `implemented-uncredited` | Existing control formats plus typed bounded live `SelectedControlHandle` and stopped `SelectedControlAdmin`, exact recipient-filtered planning, and atomic redb publication intent | Rust callers can choose one revocation or one scope/epoch and exact recipient/topic policy through sanitized requests; live publication serializes under the actor policy-write authority and refreshes policy before response. This is not generalized policy governance: no production backend, protected stock CLI/bindings, cross-process admin IPC, registry issuance/recovery, automatic/atomic revoke-plus-rekey workflow, or additional key-management mechanism is shipped. |
| `DM-3-11`, `DM-11-18`, `DM-11-19` pre-mission provisioning/identity/keying | `open` | Protected-artifact and opaque-reference live `NodeConfig` plus stopped Rust opens and provider-neutral SecretStore contracts | Current Rust construction validates bounded options and terminal state before one provider/loader call or state creation and binds credentials to one absolute lexical state pathname. This mechanism is not the operational window or complete MVP: the stock CLI remains unprotected-reference, and identity/key issuance, production backend, recovery/backup/rollback policy, inode/symlink/rename/rollback binding, selected-node bindings, coordinated destruction, admitted-module/FIPS decision, and retained operational evidence remain absent. |
| `DM-5.1-01`, `DM-5.1-02` State class and convergence | `implemented-uncredited` | Typed source-authenticated State capabilities, bounded redb versions/operations, shared Event-State causal frontier, stopped `SelectedStateNode` projection, and semantic-v4/v5 class/direction runtime reconciliation | Current-code automation covers sequential/concurrent/tombstone/restart projection, exact Offer `MutableApplyResult`, Fetch `MutableFetchResult`/`MutableFetchResultAck`, and Finish remainder, typed capacity deferral, fair durable cursor rotation, current-lineage replacement, and real-Iroh transfer to an interested independent store. There is no retained receipt, live State application handle, or delivery subscription; divergent State convergence, longer partitions, relay custody, independent interoperability, scale, and bindings remain open. |
| `DM-5.1-04` Event support | `observed-bounded` | Existing `aster-core` Event envelope ported through selected redb/runtime, with live and stopped high-level projections | The retained sample seals, persists, reconciles, verifies, and reacts to Event. Current-code live-handle tests publish, query, consume, and later synchronize arbitrary authorized Events, but they are not a retained PR-C acceptance receipt. Other data classes and independent wire interoperability remain open. |
| `DM-5.1-05` through `DM-5.1-07` Event immutability, order, and gaps | `implemented-uncredited` | Authenticated Event sequence/dot, semantic and exact-transfer indexes, publisher/topic/scope positions, and a public bounded verified gap view | Gap pages freshly verify every observed anchor and race-recheck their exact policy-bound store plan. No gap means only that locally observed verified positions are contiguous; it does not prove publisher completeness or convergence. Cross-process missing-position and independent interoperability evidence remain open. |
| `DM-5.1-08`, `DM-5.1-09` Record class and disconnected concurrency mechanism | `implemented-uncredited` | Typed source-authenticated Record capabilities, bounded redb revisions/operations, shared causal frontier, stopped `SelectedRecordNode` projection/resolution, and semantic-v4/v5 class/direction runtime reconciliation | Local tests cover N-way conflict and guarded resolution. Current-code v4/v5 real-Iroh contacts leave the same two disconnected heads on both stores without merge execution and exercise exact outcome/finish, deferral, cursor, and lineage mechanics, but no retained execution receipt exists. There is no live Record application handle/delivery subscription; longer partitions, relays, mixed implementations, scale, bindings, and retained release acceptance remain open. |
| `DM-5.1-10`, `DM-5.1-11` Blob class, streaming, and immutability | `implemented-uncredited` | Typed source-authenticated Blob capabilities, canonical fixed-64-KiB manifest, bounded encrypted depot, immutable exact publication, stopped `SelectedBlobNode` publish/read streaming, and a semantic-v5 direct source-before-carrier network path | Local multi-chunk tests cover exact retry, restart, rekey variants, dedup within one physical lineage, tamper, revocation, terminal lockout, and bounded buffers. V5 stages exact sources before canonical carrier ranges, persists peer-neutral 16-KiB prefixes, and withholds ordinary publication until depot, full-content, and current-lineage proofs agree. There is no live Blob handle or delivery subscription, route-only relay/custody, TTL/GC, pure-byte metadata-independent identity, physical/resource acceptance, large-Blob bracket, mixed implementation, release artifact, or retained receipt. |
| `DM-5.1-12`, `DM-5.1-13`, `DM-5.2-19` through `DM-5.2-22` Blob chunk transfer and peer-neutral resume | `implemented-uncredited` | Semantic-v5 exact source-before-carrier transfer among directly authenticated content-capable peers; peer-bound content proof on inventory and every range; peer-neutral durable 16-KiB prefixes; exact missing-complement scheduling; atomic completion-gated visibility | One same-process, one-host, three-node direct-Iroh run covers one 96-KiB Blob: A completes B, A leaves C with source plus one durable prefix, C's runtime/store/provider cache reopens and A is removed, then fresh B→C sends no source and only the exact complement. Cleanup retains a bounded non-public unfinished physical-lineage fence, source/cache transitions share one lifecycle lock, and terminal multi-carrier scheduling advances to the lexicographic maximum; exact repair regressions and independent audit are green. This is current-code same-implementation automation, not a retained receipt, and adds no `observed-bounded` credit. It does not claim an OS-process boundary, route-only relay/custody, a live Blob application handle/subscription, TTL/GC, pure-byte identity/dedup, 100+ MiB/RSS/physical or mixed-implementation acceptance, or release authorization. |
| `DM-5.1-17` through `DM-5.1-22` common item fields | `implemented-uncredited` / `observed-bounded` | Event, State, Record, and Blob authenticate their applicable class, topic, scope, priority, publisher, causal stamp, logical key, tombstone, epoch, and content commitments; the Event facade additionally publishes and returns exact finite TTL without exposing custody/store internals | The exact row statuses remain Event-derived. Semantic-v3/v4/v5 Event contacts use authenticated priority, source TTL, and cumulative age. State and Record add v4/v5 replication and current-source-lineage automation; Blob adds v5 direct content-capable-peer transfer with separate current route and physical-content lineage proofs. None adds a retained receipt, live application handle, Blob/State/Record finite TTL, or custody evidence. Cross-class eviction and acceptance remain open. |
| `DM-5.2-01` eventual convergence | `observed-bounded` | Class-specific Negentropy difference over exact Event transfer IDs in v1-v5, State/Record transfer IDs in v4/v5, and Blob source IDs in v5, plus mission-bound redb | Retained Event receipts cover three/eight-node temporal forwarding. Current-code v4/v5 real-Iroh contacts transfer State, preserve two disconnected Record revisions, and exercise one bounded direct Blob resume, but they are not retained or all-reachable-node results. Longer partitions, route-only Blob relay/custody, mixed implementations, physical links, requirement scale, and release acceptance remain open. |
| `DM-5.2-02` subscribed in-scope convergence | `implemented-uncredited` | Durable canonical Event Consume/Carry selectors, v4/v5 class-separated State/Record interests, and v5 exact Blob selectors carrying a peer-bound current content proof, all projected as protected receiver interests and intersected with route authority | Current-code tests deliver selected Event, State, Record, and one bounded Blob. Normal and AtLeast run mutable lanes and may run v5 Blob transfer, but AtLeast satisfaction is Event-only; ReceiveOnly initiates and discloses neither mutable nor Blob work. Same-implementation bounded observations are not all-reachable-node or global convergence; repeated multi-scope lifecycle, longer partitions, route-only Blob relay, physical peers, scale, mixed implementations, and a retained multi-class receipt remain open. |
| `DM-5.2-06` through `DM-5.2-08` delivery, duplicate suppression, and idempotent outcome | `implemented-uncredited` / `observed-bounded` | Exact transfer acceptance, durable operation-keyed publication, an at-least-once Event pending ledger, and separate v4 Offer `MutableApplyResult` and Fetch `MutableFetchResult`/required `MutableFetchResultAck` before the next attempt, plus exact Finish remainder | Live and stopped Event poll freshly re-verify source/content authorization. Current-code real processes synchronize, poll, ack, and preserve the Event ack across receiver restart; mutable acknowledgements instead govern durable protocol satisfaction and do not create State/Record application delivery. The retained receipt still covers the built-in Event reaction only; unacknowledged process-crash retry, every external crash point, bindings, and independent implementations remain open. |
| `DM-5.2-09`, `DM-5.2-10`, `DM-5.2-13`, `DM-5.2-14` causality and clock-independent correctness | `observed-bounded` / `implemented-uncredited` | Authenticated dots/context, atomic Event-State-Record-Blob causal frontier/high-water, Pong observation of Ping, causal projections, class-specific Negentropy timestamp zero, and monotonic semantic-v3-format Event custody age inherited by v4/v5 | Pong publication is isolated after Ping is durable at the destination, and its authenticated context observes Ping before any return-edge process starts. Event causality has retained bounded evidence; current-code v4/v5 real-Iroh automation preserves two disconnected Record heads without wall-clock arbitration; Linux finite Event TTL has automation only. Divergent State transfer, tombstone propagation, Blob causal-convergence acceptance, finite State/Record/Blob TTL, non-Linux Event TTL, long-running operation, and independent interoperability remain open. |
| `DM-5.2-18` difference-proportional synchronization | `implemented-uncredited` | Bounded class-specific Negentropy exact-ID reconciliation for Event in v1-v5, State/Record in v4/v5, and Blob source plans in v5; Blob carrier work requests only the exact missing contiguous complement | Equal Event inventory transferred nothing; current-code mutable and Blob automation bounds each attempt and rotates durable cursors fairly. Total-size-versus-difference cost evidence across all four classes at requirement scale remains open. |
| `DM-5.3-01`, `DM-5.3-02` State causal resolution and concurrent tie-break | `implemented-uncredited` | Freshly verified exact-key causal maxima; authenticated context dominance; greatest complete semantic State ID current; retained `Concurrent`/`Superseded` history; immutable-fact v4 ingest with current source lineage | Current-code v4 automation transfers State and withholds same-epoch old lineage from ordinary current projection/query and network inventory/transfer without deleting it; an exact idempotent publish retry may recover its committed historical result only through strict cached/projection/historical verification. The facade recomputes dispositions and plan identity, and a current tombstone remains visible. Divergent/concurrent network convergence, mixed implementations, expiry/GC, adversarial scale, and retained acceptance remain open. |
| `DM-5.3-04` Blob preservation outside causal merge | `implemented-uncredited` | Immutable Blob bytes/identity metadata remain outside State/Record reducers; multiple signed source publications may reference one exact completed depot variant; semantic-v5 transfer stages bytes outside the ordinary publication indexes until exact completion | The direct network mechanism preserves immutable content and never exposes a partial publication. Route-only relay/custody, adversarial multi-writer interoperability, retention/GC policy, pure-byte identity, large/physical/resource scale, mixed implementations, and acceptance remain open. |
| `DM-5.3-06` through `DM-5.3-10` Record sibling preservation, annotation, API, no-discard, and recoverable history | `implemented-uncredited` | Freshly verified exact-key causal heads; explicit `RecordConflict`; sorted sibling IDs and opaque exact guard; atomically guarded successor; optional superseded history; merge-free v4 ingest with current source lineage | Ordinary publish cannot collapse heads, stale or changed guards insert nothing, and current-code real-Iroh contacts preserve disconnected revisions on both stores without executing application merge code. Same-epoch old lineage is withheld from ordinary current projection/query and network inventory/transfer while an exact publish/resolution retry may recover its committed result only through strict cached/projection/historical verification. Automatic registered-policy merge (`DM-5.3-05`), live application delivery, explicit-policy GC, bindings, longer partitions/relays, mixed implementations, scale, and retained acceptance remain open. |
| `DM-5.4-01`, `DM-5.4-05`, `DM-5.4-09`, `DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`, `DM-5.4-22` selected priority, TTL, and constrained operation | `implemented-uncredited` | Source-authenticated Event priority/TTL; semantic-v3-format cumulative custody inherited by v4/v5; Linux expiry; bounded scheduler/retry/retirement; Normal/AtLeast/ReceiveOnly startup and live policy | Current automation covers charged Event age/expiry boundaries, priority order, stale-work/final-send races, v3/v4/v5 custody inheritance, and receive-only inbound. Normal and AtLeast run v4/v5 mutable reconciliation and may run v5 Blob work because AtLeast is strictly an Event threshold; ReceiveOnly initiates/discloses no mutable or Blob work. Selected finite State/Record/Blob TTL is rejected/open. Priority count/names, `DM-5.4-11` generic global eviction, optional defaults/caps/overrides, non-Linux Event TTL, physical RF silence, scale, mixed implementations, and retained acceptance remain open. |
| `DM-5.5-01` through `DM-5.5-03`, `DM-5.5-05` through `DM-5.5-07` topic/scope and payload-blind relay boundary | `implemented-uncredited` / `observed-bounded` | Authenticated topic/scope; durable Consume/Carry selectors; protected receiver interest; current peer scope/epoch route commitments; bounded route-only cache; aggregate and exact-scope Event custody quotas | Canonical selectors bound desired receipt while route authority remains an independent upper bound; empty means receive-none. Unsubscribe removes one selector and its delivery ledger; replacement is a later subscribe, not an atomic update. Limits are logical rather than complete physical accounting. Dynamic multi-scope lifecycle, bridges, other classes, physical/mixed implementations, and scale remain open. |
| `DM-5.6-01` through `DM-5.6-03`, `DM-5.6-05` direct, infrastructure-free, intermediate, and duplicate-bounded transfer | `implemented-uncredited` / `observed-bounded` | Default direct Iroh line with hosted discovery, public/default relays, and port mapping disabled; additive controlled relay is explicit and singleton | Exact Events moved through payload-blind Aster intermediates and restart no-op. The controlled connectivity-relay fixture is separate and creates no custody claim. Physical transport, independent conformance, cycles/broadcast, NAT, alternate carriers, and generalized custody remain open. |
| `DM-5.8-06`, `DM-11-02`, `DM-13-04` selected IP transport, MVP inclusion, and adapter deliverable | `implemented-uncredited` | Bounded `aster-iroh` direct UDP/QUIC endpoints composed by `aster-node`, plus exact endpoint/mission peer binding and selected CLI configuration | Source and current same-implementation loopback automation prove the selected IP mechanism, including direct contact while a configured relay is unavailable. This is not a supported/released adapter acceptance result. Physical IP and NAT networks, target packaging/stability, bindings, mixed implementations, dependency/license/SBOM admission, retained acceptance, and release authorization remain open. |
| `DM-5.8-09` controlled relay-assisted connectivity | `implemented-uncredited` | One exact HTTPS relay origin with explicit WebPKI or replacement DER-root trust; no hosted lookup, public/default fallback, or port mapping; optional relay-only mode disables IP | A same-implementation localhost process fixture gives the initiator an unusable initial direct candidate, disables responder IP, observes Relay at both authenticated endpoints, transfers one Event, and repeats as a no-op. A separate focused direct-Iroh runtime test proves wrong expected mission failure before inventory; it is not part of that relay process proof. Iroh may probe initial paths in parallel and learn authenticated direct paths later, so this is not a direct-first chronology, representative NAT failure/fallback, physical relay service, lifetime IP pin, State/Record/Blob-over-relay acceptance, retained receipt, or release evidence. |
| `DM-6-01` through `DM-6-07`, `DM-6-09` through `DM-6-12` source/route protection | `observed-bounded` / `implemented-uncredited` | Existing `aster-core` source envelope, exact-byte re-verification, separate route/content capabilities, mission-protected mechanics, and typed Event/State/Record/Blob capabilities | Event has retained endpoint/relay evidence; State/Record have current-code semantic-v4/v5 direct-contact source/content and current-lineage automation; Blob v5 additionally requires a peer-bound current content proof at inventory and every source/range send, current source-route and physical-content lineages, exact manifest/carrier proofs, and fresh full-content completion before publication. Same-epoch key replacement withholds old Blob rows and proofs; a bounded non-public unfinished physical-lineage fence preserves `PhysicalLineageConflict` across cleanup until numeric epoch advance. This is not packet-capture acceptance, route-only Blob relay/custody, complete networked class acceptance, key lifecycle completion, or independent cryptographic review. |
| `DM-6-13`, `DM-6-14`, `DM-6-18`, `DM-6-19`, `DM-6-25`, `DM-6-26` identity, authorization, and hybrid mission/source mechanics | `observed-bounded` | Carrier identity and mission `NodeId` are independent; mission auth completes before inventory; dynamic topic-content and scope-route grants remain distinct; current live Rust config and stopped Event/admin opens accept protected artifacts or opaque secret references | The retained runtime receipt still uses unprotected-reference provisioning; protected live startup and control refresh are current-code automation only and add no observed credit. Current bootstrap validates options/terminal state before one provider call, binds one absolute lexical state pathname, and reports only a coarse origin. A production backend, protected stock CLI/bindings, operational issuance/recovery, provider-aware destruction, non-Unix/physical zeroization, all data classes, admitted-module/algorithm-policy gates, and independent review remain open. A fresh recipient-package rekey refuses an already-revoked recipient; exact historical retry remains recoverable. There is no automatic remediation workflow. |
| `DM-3-12`, `DM-6-20` captured-node exclusion and intermittent propagation | `observed-bounded` | Source-authenticated ordered Flash controls, payload-blind forwarding, durable revocation checks before Event, durable rejected-sequence fencing, and exact local historical retry | The retained authority-absent relay scenario denied two captured-node cohorts. Rejection-fence, same-signer historical retry, self-revocation receipt ordering, and cancelled-enqueued stopped recovery have focused current-code automation only. The live additions do not create new intermittent-propagation evidence. Revocation/rekey remain separate; longer impaired partitions, multiple relays/carriers, physical systems, broader topologies, process/power crash injection, and independent implementations remain open. |
| `DM-6-21`, `DM-12-08` recipient-filtered field rekey and integrated acceptance | `observed-bounded` | Recipient-filtered rekey through typed bounded live/stopped planning, source control, redb, and Iroh runtime; a fresh request fails closed for an already-revoked recipient, while exact same-signer historical receipt remains recoverable; post-revocation legacy recipient-less controls fail closed | The retained receipt advanced one scope once and excluded the captured node. Current-code live automation additionally refreshes epoch-two policy before Event publication and recovers the same receipt after canonical recipient reorder and a higher witness; it adds no observed credit. Both paths use separate revocation and rekey transactions, not automatic affected-scope discovery or atomic remediation. Repeated/multi-scope churn, production provisioning/custody, physical field evidence, independent implementations/review, and release acceptance remain open. |
| `DM-6-22` local zeroization | `observed-bounded` | Same-UID Unix `aster zeroize` plus a separate provider-neutral operation/reference-bound SecretStore destroy contract | The retained receipt covers drain and bounded software overwrite of the two unprotected-reference files only. Protected/secret-reference live nodes support graceful shutdown, but local zeroization has no provider destroyer and cannot destroy provider custody. No production SecretStore backend or coordinated drain-plus-provider-destroy workflow exists; a backend tombstone does not prove its own durability or physical erasure. Inode deletion, physical/copy-on-write/snapshot/swap/backup sanitization, redb rollback resistance, non-Unix behavior, remote triggering, and independent platform assurance remain open. |
| `DM-6-23` freshness and replay rejection | `observed-bounded` | Protected session replay checks, exact chained controls, rejected-sequence fencing, exact historical local receipts, policy-bound Event transactions, and durable/idempotent application/control operations | Current focused cells purge authenticated predecessor/rollback poison, fence replayed descendants, return nonfatal `PolicyUnsettled` for a pending gap while exact retry remains recoverable, and retain actor ownership after post-enqueue caller cancellation. The retained receipt predates these additions. This covers one caller-cancellation boundary, not process/power interruption; physical capture replay, every data class, other live command/contact boundaries, long retention/eviction, and independent implementations remain open. |
| `DM-11-20` MVP revocation | `implemented-uncredited` | Durable revocation plus typed bounded live `SelectedControlHandle`, stopped `SelectedControlAdmin`, and exact historical retry | Current live tests return self-revocation receipt before teardown and recover cancelled enqueued work through stopped exact retry. One older real-process captured-leaf scenario passed, but the complete MVP, production provisioning/custody, protected stock CLI/bindings, cross-process admin IPC, automatic/atomic revoke-plus-rekey remediation, platform-complete zeroization assurance, generalized policy management, and release gates remain incomplete. |
| `DM-7-09`, `DM-7-10` optional local agent and gRPC-like IPC | `implemented-uncredited` | `aster-agent`, repository-owned v1alpha1 Protobuf schema, authenticated loopback listener, and real-node ConnectRPC integration test | Same-implementation Connect unary/streaming calls reject unauthenticated access and preserve durable redelivery. Independent gRPC/gRPC-Web clients, protected provisioning, credential reload/rotation, stronger OS identity, packaging, supported targets, and production deployment acceptance remain open. |
| `DM-7-11`, `DM-7-14`, `DM-7-15`, `DM-7-18` high-level documented boundary | `implemented-uncredited` | Typed live Event operations, typed stopped Event/State/Record/Blob operations, separate privileged live/stopped control administration, authenticated agent RPCs, sanitized errors/status, no transport or reconciliation types in application handles or agent RPCs, and compiled shipped examples | The agent preserves the live Event application boundary but does not broaden its class support; the privileged control handle likewise adds administration rather than application credit. Live State/Record/Blob handles, automatic merge, selected-node bindings, operational backend/CLI/issuance/recovery, production agent packaging, a shipped live-admin example, and an independent developer-usability study remain open. |
| `DM-7-16`, `DM-7-17`, `DM-7-20` offline publication/later sync/sample | `implemented-uncredited` / `observed-bounded` | Built-in applications, compiled Event/custody examples, and the local-agent sample | Retained built-in receipts publish peerless and forward later. Current-code real processes publish through the live handle with no peer, restart into later contact, poll/ack, and preserve the ack across receiver restart; the agent exercises that same authority. This does not establish independent usability, the supported offline interval, no-loss acceptance, other live classes, physical systems, or independent interoperability. |
| `DM-8-01`, `DM-8-02` Rust implementation | `observed-bounded` | Rust 1.91 workspace and current selected-lane checks/tests | The retained locked/offline Darwin arm64 artifact identified below belongs to the parent PR-A/pre-subscription freeze. PR B, PR C, the selected State/Record/Blob, Event-custody, protected/admin, and controlled-relay slices have only their separately stated source/test evidence until a new release receipt is produced. The current relay freeze passed the serialized repository gate and fresh all-feature Rustdoc, but supported-target and release acceptance remain open. |
| `DM-9-13`, `DM-9-14` Blob streamed reading and bounded working memory | `implemented-uncredited` | Synchronous `read_into`, canonical independently authenticated chunks, final whole-content verification, one manifest-bounded digest vector, independently chunk-bounded adapter buffers, and semantic-v5 16-KiB network ranges | The public metric is the core reader capacity, not whole-operation peak memory. Current local fixtures and one small 96-KiB network case do not establish supported-target resident-memory behavior. Alternate carriers, 100+ MiB brackets, complete physical accounting, mixed implementations, and retained resource evidence remain open. |
| `DM-9-24`, `DM-9-25` bounded/configurable local storage | `implemented-uncredited` | Validated accounted-namespace aggregate `StoreLimits`, exact-scope Event `CustodyQuota`, authority/tombstone partitions, 1-MiB mutable-object and 4,096-row/16-MiB per-class caps, 256-peer/1,024-row cursor caps, bounded retirement and one-snapshot scheduling | Typed v4 mutable capacity deferral preserves valid differences and fair cursor rotation prevents one saturated peer/class/local Offer-or-Fetch mode from monopolizing attempts. Accepted-dot, causal-frontier, and Event-position/high-water ledgers still lack an aggregate retirement bound. Complete redb/filesystem/Blob-depot/hostile-entry/snapshot/swap/backup accounting, live quota administration, physical pressure, scale, mixed implementations, and retained resource evidence remain open. |
| `DM-11-15`, `DM-11-17` MVP TTL and receive-only | `implemented-uncredited` | Public finite Event publication plus semantic-v3-format cumulative custody/expiry inherited by v4/v5 and startup/live ReceiveOnly policy with authenticated inbound Event ingestion | The mechanisms exist in the selected Rust Event slice, but the complete MVP does not. Finite Event TTL is Linux-only; selected finite State/Record/Blob TTL is rejected/open. Normal and AtLeast run v4/v5 mutable work and may run v5 Blob work because AtLeast remains Event-only; ReceiveOnly initiates/discloses no mutable objects or Blob frames but is not physical RF silence. Bindings, physical/mixed acceptance, protected provisioning, and release gates remain open. |
| `DM-9-21A` many-node operation | `observed-bounded` | Demo accepts `--nodes 2..=32`; its deterministic schedule is `2N+1` cohorts and `5N-2` children | One operator-attested Cargo release-profile binary run for the signed current-tree source passed an N=32 direct-loopback line on one macOS arm64 host: 32 distinct mission identities/stores, 65 exact cohorts, 158 exact-named executions with distinct READY PIDs, 30 payload-blind intermediates, and 32 distinct log-observed READY PIDs in the final zero-difference no-op. No overlap timing or OS sampler proves simultaneity, and the receipt does not cryptographically prove the source-to-binary-to-execution link. This does not prove the full 2–32 range, the separate bracketed target of at least 100 nodes, distributed/physical scale, NAT/relay/BTLE/cross-transport behavior, independent interoperability, resource thresholds, or release acceptance. |

Broader State/Record partition, relay, crash, and mixed-implementation behavior,
route-only Blob relay/custody, live Blob delivery, TTL/GC, pure-byte
identity/dedup, large/physical/resource and mixed-implementation Blob behavior,
automatic registered-policy Record merge, and release acceptance remain open.
Selected-composition credit is limited to the exact stopped application
mechanisms, current-code bounded direct-Iroh semantic-v4/v5 State/Record and
semantic-v5 Blob automation, and the exact controlled carrier evidence named
above; none of that current-code automation is retained evidence.

## Current controlled Iroh relay automated evidence

The current controlled-carrier code freeze is signed commit
`b0a1203f4f24c05edd31e5ce1ea0f3b7f9bd2f52`. Its signature verifies as Good
against the repository signer. The exact ordered nine-file
`shasum -a 256` block is below; SHA-256 of the newline-terminated block itself is
`729917a6d596a38e3eda7d3da2cce76c0ba19e1a0f8fed3dc4912d96ef5e90b7`.

```text
55503cbd3747d96f282396a7e37cd3c05122a9fc76e44a41863346cd052dfe95  Cargo.toml
5b26134242180affeeaa555175e7400f682c47e14b2e7d2df2decfe14ee5f90c  Cargo.lock
633501b83d0efcacf7bb0f9c0f46bc5d16dcc20589f6a974b7df8a3add9f95c8  crates/aster-iroh/Cargo.toml
d773516cdff95878d50e6296be0363681ef583679ff4f93da82f76fb084aee4f  crates/aster-iroh/src/lib.rs
e5e5bc2c0cb96c8f93809256b2e32b95077f7246523d1c26b2d341b1e653c0d5  crates/aster-node/Cargo.toml
bcce6280c8ff61bebaa772510f62105ad71236afad0806732d1490132d721587  crates/aster-node/src/main.rs
f73349707d66fc864545297ed391ba091ee2774bed7dd552dd619c1fcad56bf0  crates/aster-node/src/runtime.rs
f81b8de1c89e50be866f259c98d6413b25dfff9f5b892686f0b440becb96c9c0  crates/aster-node/tests/mesh_cli.rs
511cd30571eacbe2314bdecdcb27b7f171622a40bca5a1a821265e6de7716fea  fuzz/Cargo.lock
```

`aster-iroh` admits one exact HTTPS relay origin alongside at most eight sorted
unique operator-supplied initial direct candidates. A relay URL is at most 2
KiB, the complete carrier route text is at most 3,072 bytes, and the URL must
name a root origin with a host and no user information, query, or fragment.
Trust is explicit: embedded WebPKI or one through eight valid DER CA roots, each
at most 64 KiB and together at most 256 KiB. Explicit roots replace WebPKI; no
insecure or unrelated-CA fallback exists. The selected node CLI currently
supplies one initial direct locator from each existing `--peer` value. Hosted
lookup, public/default relay substitution, and port mapping remain disabled.

Direct-plus-controlled-relay startup defers relay readiness, so an unavailable
relay does not block an exact direct contact. Relay-only startup requires the
configured relay to become ready and disables all IP transports. Iroh may probe
the supplied initial paths in parallel; this API promises no temporal
direct-first ordering. After exact endpoint authentication, Iroh may negotiate
additional direct paths, so initial locators are not a lifetime IP allowlist and
the mechanism is not NAT acceptance evidence. Endpoint identity and the sole
configured relay origin remain exact.

Every connection retains a bounded diagnostic `Direct`, `Relay`, or `Unknown`
path witness. It subscribes before the initial snapshot, coalesces observed
path-kind transitions, preserves the last observed Direct/Relay value across an
ordinary path close, caps the count at 1,024, and marks saturation or lost
continuity. It is not an exact event ledger and never establishes identity,
membership, authorization, receipt validity, or synchronization success.

The carrier all-feature suite passed 13/13 in 9.28 seconds. It covers exact route
and trust bounds; relay-only exchange under explicit roots; rejection of a valid
but unrelated CA without fallback; usable direct selection; direct operation
after the configured relay is already unavailable; wrong endpoint/relay
substitution; and bounded failure after relay loss with no public substitute.
The fixture is a test-only local HTTPS relay. The normal selected-node graph
uses Iroh's client relay support but does not enable `iroh-relay/server` or
`test-utils`; the server/test graph is confined to the dev/all-feature fixture.

The `mesh_cli` suite passed 20/20 in 153.91 seconds within the full serialized
gate. Its controlled-relay real-process case gives the lower-carrier-ID
initiator one deliberately unusable initial direct locator while the responder
uses relay-only mode. Both endpoints report Relay for successful hybrid-mission-
authenticated contacts, one offline Event is delivered, and the repeat contact
is an exact no-op. The separate focused runtime test
`right_carrier_with_wrong_expected_mission_fails_before_inventory` proves that
the independently expected mission mismatch fails before inventory
construction; the carrier path observation is not that ordering proof. Another
real-process test observes only Direct while the exact configured relay is
unavailable. Partial configuration, malformed DER roots, and duplicate
token-bearing relay URLs fail before state or mission access, with values
redacted from parse errors. After the final harness correction, the focused
controlled-relay Event test passed 1/1 again in 204.69 seconds on the frozen
`mesh_cli.rs` bytes above.

The exact final serialized repository gate was:

```sh
env CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-full-check \
  CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
```

It exited zero when run outside the sandbox for loopback tests. Visible
constituent results included `aster-node` library 170/170 in 157.48 seconds,
`aster-node` `mesh_cli` 20/20 in 153.91 seconds, `aster-iroh` 13/13 in 9.28
seconds, `aster-ip` 50/50 in 2.20 seconds, and `aster-lab` library 32/32 in
53.56 seconds. The complete command also passed the remaining workspace tests
and doctests plus language, conformance, license, dependency, formatting, and
strict lint gates. No trustworthy aggregate wall time was retained.

Fresh all-feature Rustdoc with warnings denied also exited zero in 57.67
seconds:

```sh
env RUSTDOCFLAGS=-Dwarnings \
  CARGO_TARGET_DIR=/private/tmp/aster-controlled-relay-rustdoc-final-20260825 \
  CARGO_BUILD_JOBS=2 \
  cargo doc --locked --workspace --all-features --no-deps
```

This is current-code, same-implementation, one-host automated evidence, not a
retained execution root. It moves only `DM-5.8-06`, `DM-5.8-09`, `DM-11-02`,
and `DM-13-04` from `open` to `implemented-uncredited`; it creates no
`observed-bounded` credit and relabels no historical receipt. It does not prove
a physical relay deployment, direct operation across NAT, direct-first
fallback, multi-host operation, BTLE, mixed implementations, N=32/resource
brackets, packet-capture confidentiality, State/Record/Blob-over-relay behavior,
route-only Blob custody, supported-target packaging, dependency/license/SBOM
admission, or release authorization. The connectivity relay is below the
peer-to-peer QUIC and mission/source protections; it is not the payload-blind
Aster Event node from retained temporal-relay receipts.

## Prior PR-C automated evidence

PR C was pinned to these exact source identities at its own stack freeze:

This freeze predates semantic v4 and v5; the current v5 source tree and its
separate bounded network evidence do not relabel it as current evidence.

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
alone do not close State/Record/Blob or any later item in the six-step sequence.
The prior Blob evidence below is the historical stopped/local freeze; the newer
semantic-v5 network slice has separate current-code evidence and does not
relabel this PR-C result.

## Prior selected State and Record network automated evidence

At this prior freeze, the production-lane source ran State and Record networking
in semantic v4 and v5. The default offer was `[5, 4, 3, 2, 1]`; Event retained v1-v5
compatibility and v1-v3 contacts send, accept, reserve, and count no mutable
frames. V5 inherits the v4 State/Record behavior unchanged. In v4/v5,
class-tagged State and Record interest, inventory,
difference, Fetch/Offer, outcome, and Finish frames run after the existing
control/Event lanes. Both classes and both receiver directions are independent.
The receiver declares canonical topic/scope interests separately for each
class; empty means receive-none.

The repository-facing code/test freeze is the following exact ordered 26-file
`sha256sum` block. SHA-256 of the newline-terminated block itself is
`577a835d5bd85322bf8e5bddfc4c425446344714397ff9822f45ed4ba5482559`;
the unchanged `Cargo.lock` is
`9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f`.

```text
033b10cc48eb19e3d6e81c9942e6d7cfe2c36b3991b4a5ea67192419d638d70d  bindings/c/aster_mesh.h
e0bd3cea2d0ce1351695b1a3cce6dd571c4949a3c076874036ff0ce2cef85f4e  bindings/c/header_smoke.c
f1764b6d4aca157e7d6f477e2392d94c10705bf5ce7b4cdb03e299a25c2c3870  bindings/c/header_smoke.cpp
5736c259d932983e3cf1163a1e7a0164810acd34848d2e5993cc99f361426778  bindings/go/aster_test.go
6ed380b67e5bbbacb90c6b46aacf9b2a47d7b800f5845cc5b514f1bca5835e21  bindings/python/tests/test_binding.py
fc37299c9eb22a87b3e8b48c0d5bd9dd0abce42b75ec85f103792a4505c7a8a9  crates/aster-core/src/batch.rs
9175de40a0ab471a8e5f30f8e33daa16c6bf66af199267a044fa407ae04b905e  crates/aster-core/src/crypto.rs
cbd5452c71d9dbd2c16e636027ff852341ad8bae18fb5d822ac3ed228cccb040  crates/aster-core/src/crypto/reference.rs
e05d26baa88ae27b6473770065cbc25f006c80c38f431d3a14f06ca1cccb0861  crates/aster-core/src/lib.rs
a3011fba77c52014a63705f310adf3358b839ae158fbecb9b9db69f27237db2e  crates/aster-core/src/runtime.rs
f606f7052017bbae1e40494557098d99dac141005cc11f2dc9b6849fe7d39d7c  crates/aster-core/src/runtime/reference_semantic.rs
cf58edd83229d0f8609da5319e8a8cc82bf154cafa99981c96e0df63cb9773dc  crates/aster-core/src/source_event.rs
03ffd6e9adb5a2a0488cf76e0d9cb8f6d35ae2f2ba7d2fa263bb0dfc09abaf26  crates/aster-core/src/source_record.rs
1ccb1d8eb403a0e4f0f2901857787f80c5bed66232e7d0f60cf1fe749715a717  crates/aster-core/src/source_state.rs
57f6d237a5ee31aba7d1f6a85cfecadae8887e95670b358b95e8326bae8c0558  crates/aster-core/src/store.rs
0c1033f0a8c5d68fd3be60573a03c94881034ad8cac98baaecdbcfd5fc070c55  crates/aster-core/src/wire.rs
ab7668867ada6d31e8d929cf7fa5ebaac5d35f7a374a7e340b97b1e6192901ec  crates/aster-ffi/src/lib.rs
40479cb44dab91e8cd6332b4400dbf2f9b2054c2f5f38bc3d0ef93d1a7e1aaca  crates/aster-node/examples/custody_application.rs
c0755906768e80096f4e516812abeecf8b1c93ec9bcdb95f7d9ceebd8baa5354  crates/aster-node/src/application.rs
54410bafabd92124731c266c9e91452561b1d358ca321657b894ce4b5b7ae032  crates/aster-node/src/application/record.rs
9005b320d80782b371eccbe07f05f1b87ba82d9f0f8c78ded400afa4b77f4bd6  crates/aster-node/src/application/state.rs
b984e221ade2475ff5ce8a01702e2a6c9bb75b74ba25683f6a82352c42185a4e  crates/aster-node/src/frame.rs
bb9fafa7c25014651cb0eb58ec3631a366db553997f94994aa27bb8dc9d9a8da  crates/aster-node/src/runtime.rs
790b71ad0b51c730a2b22d91fbfd5867e9c1549576a62af67e88a8cad6637dfe  crates/aster-redb-store/src/lib.rs
2c089b401709aba7117b14e2686a7317e3bc2cdfeb9f699b7e027779252be42c  fuzz/fuzz_targets/selected_frame_decode.rs
84daaed0af0c09f1b9d73870b103d246245e9786eaaf81960f11baf055d82ecd  tools/check-implementation-requirements.py
```

The contact holds one control-policy read lease, filters both inventories
through current route/content authority and current source route lineage,
freshly verifies every source object before transfer and admission, rejects
stale/revoked/wrong-class/wrong-interest/wrong-lineage objects, and commits
remote rows idempotently under the exact current policy. A same-epoch route-key
replacement withholds historical lineage from ordinary current projection/query
and network inventory/transfer without deleting the row. Exact idempotent State
publish and Record publish/resolution retries may recover their committed
historical result only through the strict cached/projection/historical
verification path. Selected finite State/Record TTL is rejected; no mutable
forwarding-age or expiry path is claimed.

Offer returns exact `MutableApplyResult`. Fetch returns exact
`MutableFetchResult` and requires exact `MutableFetchResultAck` before another
Fetch or Finish. The tuple
binds class, direction, transfer ID, and `Inserted`, `Duplicate`, or
`DeferredCapacity` disposition. Finish/Finished bind the same exact remaining
count, including deferred work. Missing, duplicate, changed, cross-lane, or
out-of-order result/ack/finish fails the contact. `DeferredCapacity` applies
only to an otherwise-valid authenticated object blocked by effective
ordinary-aggregate or per-class item/byte capacity, the 1,024-version
per-logical-key projection bound, or the causal-frontier bound. An object over
1 MiB is structurally invalid and fatal, not deferred; integrity and policy
failures likewise remain fatal.

Each object is capped at 1 MiB and each class at 4,096 rows/16 MiB of encoded
source bytes. Existing mutable rows are not pruned. Repeated bounded contacts
rotate after a durable authenticated peer/class/local Offer/Fetch cursor. Cursor
metadata is reserved outside ordinary quota, capped at 256 configured peers and
1,024 rows, CAS-advanced only after the exact authenticated outcome, and pruned
for stale configured peers after mandatory startup proof and before sockets.
Normal and every AtLeast threshold run these lanes because AtLeast is Event-
only. ReceiveOnly initiates and discloses no mutable lane. Event last-contact
status deliberately remains separate and is not mutable convergence.

`runtime::tests::real_iroh_contact_converges_state_and_disconnected_record_siblings`
uses two independently bound redb stores and two independently authenticated
mission publishers. One publisher creates State plus Record `alpha`; the other
creates concurrent Record `bravo` for the same exact key while disconnected.
After one real direct-Iroh, hybrid-mission-authenticated contact under explicit
State/Record interests, the destination has the State and both stores have the
same two Record exact inventories and two causal heads. Ingest executes no
application merge callback. Store tests separately cover policy binding,
idempotent duplicate receipt, typed inventory, and preservation of disconnected
Record siblings without merge execution. Additional current-code real-Iroh
contacts saturate State and Record in both directions, observe exact deferral,
progress after reopen, and prove Offer/Fetch rotation prevents a fixed prefix
from starving later IDs. Focused frame/store/runtime tests cover the exact
result/ack/remaining protocol, fixed bounds, typed frontier deferral, cursor
CAS/reopen/prune/audit/terminal preservation, v1-v3 absence, policy modes, and
same-epoch current-lineage behavior.

On the current toolchain and Rust 1.91, locked all-target/all-feature workspace
check, strict Clippy with warnings denied, 17-target Rustdoc with warnings
denied, and the full all-feature workspace test matrix passed. In both full
test matrices, `aster-core` passed 385/385, `aster-node` passed 158/158 library
and 7/7 binary tests, `mesh_cli` passed 13/13 real-process tests, and
`aster-redb-store` passed 156/156; examples and doctests also passed, with one
explicit local reconciliation performance experiment ignored. The final Rust
1.91 `mesh_cli` and store cells took 160.79 and 88.49 seconds respectively.
Binding gates passed C and C++ syntax/link/runtime smoke, Python 12/12, and Go;
the conformance self-test, independent Python wire oracle, v0-r2 profile, and
162-test Python lab suite also passed.

The first full Rust 1.91 attempt hit the pre-existing intermittent
`aster-lab` `Sync(SnapshotMismatch)` volume-oracle failure. The exact failure
reproduced on untouched signed base `5cc0904d39220bdf4f70959b9ce5d190c39e11b0`,
whose test and synchronization reducer are byte-identical to this tree, and an
immediate identical base rerun passed. Isolated current and Rust 1.91 reruns and
the final full Rust 1.91 matrix all passed; no reconciliation-stability change
is attributed to this slice.

This was exact-freeze automated evidence, not a retained execution root. These
are same-implementation, one-host, two-node tests. The convergence case uses
one contact; capacity and fairness use bounded repeated contacts/reopens. They
include no long partition, complete restart/contact crash sweep,
relay/multi-hop custody, divergent State conflict, mixed implementation,
physical network, scale bracket, or release artifact.
The application State/Record handles remain stopped/exclusive; the live actor
reconciles already durable rows but exposes no live State/Record publish/query
or durable application delivery API. Because there is no retained execution
receipt, this bounded automation adds no `observed-bounded` credit.
`DM-5.1-09`, `DM-5.3-06`, and `DM-5.3-09` remain
`implemented-uncredited`, and all row statuses remain exactly as generated by
the requirements checker.

## Prior semantic-v5 direct Blob network automated evidence

At this prior freeze, the production lane offered `[5, 4, 3, 2, 1]`. Event v1-v4 behavior and
State/Record v4 behavior are inherited unchanged by v5; v1-v4 emit, accept,
reserve, and count zero Blob frames. Stable wire/profile and ABI remain version
1, and the established source envelopes, canonical manifests, strict kind-2
carrier IDs, and `ASTRBT01` carrier bytes are unchanged.

The repository-facing code/test freeze is the following exact ordered 16-file
`shasum -a 256` block. SHA-256 of the newline-terminated block itself is
`f234ea83859a24adbcc100bb7e655b80c35c1a13511a6d5c97cc4dcea28cd220`.

```text
ee531438eb5475fad73ea5cbb6ed5322e4abc4bc4ca1281690b9a9e52f80c02b  crates/aster-core/src/blob.rs
8d842cca04b46ed4c975251a45e3bebb428064b6cec3216754dd53fa126bc5c4  crates/aster-core/src/source_blob.rs
868b9f83c3dee97ca902aec06868ed12144f1af60aeb453ab64048ff4a68f50b  crates/aster-core/src/crypto.rs
5caeed2687c492603158a43160ae6df4019b060a4598b7f943b26aa675975288  crates/aster-core/src/crypto/reference.rs
97453907a0c93534354f5b9b2e0683622c359e6ca30feafa079a3ea57236d9a9  crates/aster-core/src/lib.rs
1cc175946855dde60e6bb81e15355cef80d098b649463ea101c81f5e9ff18cab  crates/aster-core/src/store.rs
7b2932a6a9e550403f10a99da6898eb8496f42915ced2acd37c50e0d7d246e16  crates/aster-core/src/wire.rs
8f8969b9a597a56fabd7732936914c562b6eba1dab9d020e872ba0f159d3c1fc  crates/aster-node/src/application.rs
3e927e158cebbfc204fc68d9449721f05cbf77429d792115a4f15e08985077c3  crates/aster-node/src/frame.rs
bd7b931b61a3b453e1ddecf072cae5bf4913643b15fd027ebca97e9656f884e4  crates/aster-node/src/main.rs
bd03bcbac1b0a4818b3fd5d7b969c032f43dbe73785f563098d44c23fe60c91c  crates/aster-node/src/runtime.rs
44e75e2f94dc2fac7fbacfc69f4ac6e74f4c4308db280d3bf8ee4e48e3dbc493  crates/aster-redb-store/src/blob.rs
0ac3920e942bafbffb0e61f6553cc46c50f359856df2784959a451a4abe942a5  crates/aster-redb-store/src/blob/depot.rs
6f883effa427a2bc07f141f58064a8f53247067b08a83f2be5f4b344201b468c  crates/aster-redb-store/src/lib.rs
bb63d3f7d11438eada510fb684a2dbe3984d9f384a3f1346a778f5e42149034f  fuzz/fuzz_targets/selected_frame_decode.rs
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
```

Core source-Blob tests passed 7/7. In particular,
`blob_peer_content_proof_is_exact_current_and_identity_bound` accepts only the
correct authenticated claimant with the current exact content grant and route,
and rejects route-only/no-content, wrong mission authority, peer, topic, scope,
epoch, same-epoch replacement, stale proof, and tampering. The schema
`schema_v14_migrates_and_v5_provenance_survives_restart` test preserves
semantic versions 1 through 4 while adding v5 provenance. The nonconstructible
transfer-plan, full-content-completion, and current-lineage capabilities bind
the exact source, manifest, canonical carriers, BlobID, physical lineage, and
mission authority without exposing content keys or raw grants.

The frame suite passed 18/18. It covers strict class-3 source identities,
kind-2 33-byte carrier IDs, canonical proof-bearing interest, bounded range,
exact Result/Ack, Finish/Finished tuple sequencing, malformed/cross-tuple
rejection, and legacy zero-Blob behavior. The maximum protected Blob interest
plaintext is 76,807 bytes and its two-frame exchange is 153,718 bytes. One
complete carrier settlement reserves 17,127 protected bytes: Fetch 123, Range
at most 16,480, two Result/Ack frames of 92, two Finish/Finished frames of 14,
and six 52-byte protection overheads. Finish echoes requester remaining for
sequencing; exact Result/Ack proves each accepted durable prefix, not an
independent responder assertion about receiver disk truth.

The final redb library suite passed 166/166, formatting/diff checks passed, and
all-target/all-feature Clippy passed with warnings denied. Focused tests cover
atomic invisible staging through carrier completion, freshly streamed
full-content/current-lineage promotion, ordinary and typed-frontier capacity
failure without mutation, competing reservation/reopen/terminal reclaim,
same-epoch `PhysicalLineageConflict`, and range service after reopen.
`network_blob_same_epoch_physical_lineage_requires_epoch_advance` now retires a
committed file and reopens with exactly one unfinished import variant, zero
finalized variants/chunks/file bytes/reserved bytes/pending sources/prefixes,
permits exact-lineage refill, rejects a different same-epoch lineage without
mutation, admits numeric epoch advance under the existing bounded variant cap,
and preserves the fence through terminal open. Zero durable physical lineage is
an audit failure. No table, schema, or capacity class was added. The final
cross-table/migration regressions are:

- `predecessor_nine_table_blob_schema_migrates_network_additively_with_owner_tokens`;
- `pending_blob_audit_binds_exact_manifest_route_and_carriers_on_all_open_paths`;
- `pending_blob_audit_rejects_self_consistent_missing_depot_plan_without_repair`;
- `pending_and_completed_blob_namespaces_are_exclusive_without_repair`.

Together they require an all-or-none writable nine-to-13-table network-schema
migration under the owner-token/binding rules, refuse read-only or partial-group
repair, bind pending source/manifest route/carriers to the exact depot plan on
every open mode, and forbid a pending/completed namespace collision. Network
admission is 64 MiB/1,024 chunks, one source is at most 1 MiB, and one carrier is
at most 128 KiB. Pending staging is 10,000 aggregate source/prefix rows and 64
MiB of prefix bytes; each durable peer-neutral extension is at most 16 KiB and
cursor state is bounded to 256 configured peers. Pending bytes and retained
unfinished lineage fences remain absent from ordinary publication inventory,
query, read, and service until exact atomic promotion.

The isolated direct-Iroh gate
`blob_source_carrier_reopen_resumes_exact_complement_from_different_peer`
passed 1/1 in 76.77 seconds for one 96-KiB Blob. A completed B; A then sent C
the authenticated source plus one carrier range; all C runtime/store/provider-
cache ownership tore down and reopened; A was removed; and fresh eligible
content peer B sent no source retransmission and only C's exact missing
complement. The final state held one ordinary publication, no pending source or
prefix, and the exact decrypted plaintext. This is a different eligible peer,
not a route-only peer.

`stale_pending_blob_cleanup_reclaims_exact_cache_and_depot_state` passed 1/1 in
43.63 seconds on the repaired cleanup path. Same-epoch route/physical lineage replacement, numeric epoch
advance, and publisher revocation each begin with a pending source plus one
durable range, then startup reclaims the exact pending source/cache claim/
prefix/network staging/chunks/file and reserved-byte authority while retaining
one bounded, non-public unfinished physical-lineage fence. Valid later work
succeeds and a second reopen is clean. Old source rows and peer proofs are
withheld after same-epoch key replacement; exact-lineage refill succeeds, a
different lineage for the same `(BlobID, content group, numeric epoch)` fails
without mutation, and numeric epoch advance admits a new bounded variant.

The final runtime repair regressions are exact. The earlier concurrent-restage
case `pending_blob_abort_reconciles_concurrent_exact_restage_without_restart`
passed 1/1 in 0.68 seconds. The stronger
`blob_lifecycle_lock_serializes_delayed_projection_insert_and_abort` passed 1/1
in 0.90 seconds by pausing a freshly authenticated restage before cache
insertion while abort wins; the shared lifecycle lock leaves neither an orphan
claim nor an unclaimed durable source and requires no restart.
`terminal_blob_poison_advances_scheduler_past_source_to_later_candidate` passed
1/1 in 0.70 seconds with a multi-carrier plan whose manifest-last ID is below
its lexicographic maximum, then selected the later eligible source.
Independent final audit found no P0–P3: the lifecycle guard covers admission,
sender-cache repair, stale/terminal abort, startup/live cleanup, and promotion;
lock order is consistent, no production guard crosses an await or content
stream, nested acquisition is absent, and lock poisoning fails closed with a
fixed sanitized error.

The node Blob-focused suite passed 17/17 in 53.31 seconds. The corrected
`authenticated_peer_without_scope_grant_learns_no_event_id_and_cannot_fetch`
privacy/v5-empty-lane regression passed 1/1 in 63.51 seconds. Node all-target
no-run/check, strict all-target Clippy with warnings denied, selected-frame fuzz
target check, formatting, and diff check passed after the final lifecycle
repair. Strict workspace Rustdoc and a fresh isolated `aster-node` plus
`aster-iroh` documentation build passed; the earlier missing-helper diagnostic
was stale Cargo rmeta and required no source or hash change. Normal and AtLeast
run eligible v5 Blob work because AtLeast is Event-only; ReceiveOnly advertises,
requests, stages, promotes, and counts zero Blob work.

This was exact-freeze same-implementation automation on one host and in one OS
process, not a retained execution root. It moves exactly `DM-5.1-12`,
`DM-5.1-13`, and `DM-5.2-19` through `DM-5.2-22` from `open` to
`implemented-uncredited`; it creates no `observed-bounded` credit and does not
relabel any historical Event/control receipt. Live Blob application access or
subscription, route-only
Blob relay/custody, TTL/expiry/GC, pure-byte identity/deduplication, 100+ MiB
and process-RSS evidence, physical carriers, mixed implementations, and release
authorization remain open.

## Prior selected State stopped-slice automated evidence

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

At that prior frozen slice there was no State reconciliation frame, carrier
path, live handle, or retained execution root. It moved only `DM-5.1-01`,
`DM-5.1-02`, `DM-5.3-01`, and `DM-5.3-02` to
`implemented-uncredited` and added no `observed-bounded` credit. The newer
network test above does not change those four statuses.

## Prior selected Record stopped-slice automated evidence

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

At that prior frozen slice there was no Record reconciliation frame, carrier path, live handle,
automatic registered-policy merge, explicit-policy garbage collection, or
retained execution root. It initially moved `DM-5.1-08`, `DM-5.1-09`, and
`DM-5.3-06` through `DM-5.3-10` to `implemented-uncredited`. The newer bounded
network observation above advances `DM-5.1-09`, `DM-5.3-06`, and `DM-5.3-09`;
automatic merge, TTL/expiry/garbage collection, physical/mixed-implementation,
scale, and release gates remain open. `DM-5.3-05` remains `open`.

## Prior selected Blob automated evidence

The stopped/local selected Blob slice is pinned to these exact frozen Rust
source and dependency-boundary identities:

This freeze predates semantic v4; the current v4 source tree does not relabel it
as current evidence.

```text
c9750fa4f627f53c4084579a67bbd350c082de51fefd4c80777d509636b091df  crates/aster-core/src/blob.rs
38891bcfe7f40d148087781e723bea5c27714565b96f1fc5af8c3b07e3359d54  crates/aster-core/src/source_blob.rs
483c32c099b11d263bad500f6a0c6f21936b297e405f215c8f85321140dbff28  crates/aster-core/src/lib.rs
f9be1a1b3d8285e4ca47c531603ce692ad3db0502e3706270249517c4d88d0ec  crates/aster-core/src/crypto/reference.rs
56fa5d5e1c3b6745e34cd5369c3283bab67a0e4b88ac01911c176bac17cbd89c  crates/aster-redb-store/Cargo.toml
45be120b18261bd499705e42d8605802a27d45e6fad288d5b9feb546de0e6067  crates/aster-redb-store/src/lib.rs
92eb8a1f8ef291bf2293a4138c4107f3e3b7e3d6797ec6bcfc2c821335628c5e  crates/aster-redb-store/src/blob.rs
6cc85cbc387b75e3ef14980ba3c5e5583472155d8bfd0ddf8ee937319dd1b3bd  crates/aster-redb-store/src/blob/depot.rs
9f106a1879c6989399e97586c337232cf0bb2d291911c99b44030cc70d0839b0  crates/aster-node/Cargo.toml
b802c979691a6fb709239ca5861a73ca2c1742c9e5206ed00b1d74a82e37501a  crates/aster-node/src/application.rs
e0eb7d4cb2f7239e49fa1ee0bb93965cabd89669edbe5cd0987fd99dba83e1c0  crates/aster-node/src/application/blob.rs
0f36acd42b5b12177a1ee89868c887c9f964b991217d0b80e32dd8d3e16b162f  crates/aster-node/src/lib.rs
5d5fa063bd89f9bf4bb6f6949c282c979d05ff453576b23f6fd65ebef4639b9c  crates/aster-node/src/runtime.rs
3ac76a4d8bfdea6d486345e67cdfb46e4a7a92d0635bf4ceebf4ced0f9dea4b6  crates/aster-node/tests/mesh_cli.rs
407b7f3b4f0b3ee276a472deb389b73bf3766b69b6164f2e9ba7ccd260a5b721  crates/aster-node/examples/blob_application.rs
41932294316bd930b9d86c07392448e8dbb092355a8c0933b7b7b895faf98148  Cargo.lock
```

Focused current-toolchain runs passed the six typed source-Blob tests, the
dedicated core reader retry-state adversary, all 28 selected-store Blob tests,
and all seven selected-node Blob tests. The current tracked-Cargo-target matrix
passed 576 of 576: core library 351/351 (44.68s), node library 88/88 (11.29s),
node binary 6/6 (0.00s), `mesh_cli` 13/13 (153.69s), and selected store 118/118
(12.33s). The separate exact Rust 1.91.0 matrix passed the same 576 tests in
45.57, 28.63, 0.01, 153.99, and 12.44 seconds respectively. The core basic
example and five node examples had no tests. These totals count only the listed
tracked Cargo targets; no auxiliary non-workspace scratch harness is counted.

Strict workspace all-target Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 28.36 and 34.71 seconds. Current Rustdoc with
warnings denied, global formatting, and `git diff --check` passed. A
loopback-enabled current-toolchain workspace test also passed every runnable
suite; one performance experiment remained explicitly ignored. These are
separate executions, and no retained root or artifact is claimed.

The documented disposable fixture ran the compiled Blob example twice over
18,783 input bytes. The first run completed in 4.792 seconds and returned:

```text
BLOB id=85c3f98504cc9e671212256c994698ce2d8c1e947aa5b3841d61a943d3660fde bytes=18783 chunks=1 inserted=true media_type=application/octet-stream
```

The 0.714-second exact rerun returned the same ID, size, chunk count, and media
type with `inserted=false`. Both outputs matched the input byte-for-byte at
SHA-256 `f3d9ba32b0825abfec157aadf8c16581608220f48dd2a8f0a3a39bef29bdd966`.
That is local executable evidence for durable operation replay and verified
streaming, not Blob transfer, remote resume, physical-storage acceptance, or a
release receipt; the fixture is not retained.

Raw Blob imports, operation mappings, publications, chunk metadata, files, and
read plans remain privileged structural state. Only the selected node's current
policy and revocation checks, typed source/content capability verification of
every candidate, exact topic/scope/Blob-ID/variant comparison, deterministic
active-publication recomputation, exact plan recheck, private completion proof,
and synchronous verified reader form the application exposure boundary.

This slice has no Blob reconciliation frame, carrier path, live handle,
subscription, remote chunk transfer, any-peer resume, metadata-independent
whole-byte identity, explicit staging GC, complete physical allocation
accounting, or retained execution root. It moves only `DM-5.1-10`,
`DM-5.1-11`, `DM-5.3-04`, `DM-9-13`, and `DM-9-14` to
`implemented-uncredited`; it adds no `observed-bounded` credit and closes no
networked Blob, maximum-size acceptance, physical, mixed-implementation,
scale, custody/TTL, or release gate.

## Prior semantic-v3 selected Event custody automated evidence

This retained source-freeze section records the custody slice before semantic
v4 became the default. Semantic v4 now inherits these semantic-v3-format Event
mechanics, but that current-code inheritance does not change or relabel the
frozen identities, totals, or claim boundary below. The selected
Event/RouteEvent custody slice was pinned to the following exact source and
dependency-boundary SHA-256 identities:

```text
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
ceb4898bb8d21fa70d2f31ef0d45f8975c51135774c187c77d4c5bf4879aa8f0  crates/aster-core/src/custody.rs
2813d283d0295513418ee24134fbbe631aa8b4f7012284b769eb0f0eea683f62  crates/aster-core/src/crypto.rs
d306b541dc09e2ad96470c53f1e32917133b642266b60d04540991ce3e632e39  crates/aster-core/src/crypto/reference.rs
9e94c6d85468842f421cd38e075af53d5186f58cc054d7220520b88af1cdce3e  crates/aster-core/src/source_event.rs
c0b7cf943df149f2c37f3f1939b5dbbad790347e2beab7e9dcae2b4352373ab2  crates/aster-core/src/source_control.rs
b6b239329ae4ae34a1702f44a6221f0292e5278310233e7d4d5821e21fda4434  crates/aster-core/src/lib.rs
5584b0168879bc75c0c0debeded0ea881b5c26c42185887b29f0a87da4fb0a52  crates/aster-core/src/store.rs
9931a163bba38bb052c6baaf8a9f050b0839a04d8d459a17fb88c3542099a644  crates/aster-core/src/runtime/reference_semantic.rs
a2a1625bb5dca6e0369e40b3e84c0a7c25c5537c5472e4894578e0ed7faff316  crates/aster-core/src/batch.rs
592cd79b230fd8e7b506acd40382f0f5934dfa81eda04a8459a5b766f06ca981  crates/aster-core/src/bridge_service.rs
6ac2c4e75eddedfea39ca6e2a6dfee9f5b922ee90a133e30f226f0522cb91206  crates/aster-core/src/runtime.rs
aa757c12baf006a05c5f8fcdc41755eaef2a072a1bd7195ae028cff1fe9be84e  crates/aster-core/src/wire.rs
37fd985318a3837355273e1cbd5a47151c8908ff74e0016097024f0bc7471ff2  crates/aster-iroh/src/lib.rs
d927bda6172d58e01dcf99df99502dcd531d31ca8af1c2483b39432c0c50e83f  crates/aster-redb-store/src/lib.rs
55f8460e3b4cca534463cded90b9b90fa662fa78bdf8c26c98a86372ee0819aa  crates/aster-redb-store/src/custody.rs
c1decbe0e89c71a46c38ab6b67c49dc3ecdfedc6614ab21b2124d4d56b08be8d  crates/aster-redb-store/src/blob.rs
cbbd11f8a80acf46dbf396af4733801c7af8d8ce50614a649415133ecad3284d  crates/aster-node/Cargo.toml
0c6d4b59764992f1857bc3c27a538c208a51b8af3758abdd55365d162cac3ced  crates/aster-node/src/application.rs
acd6c5c80f374bc834adfd665819662454a0f41fe554c7263592b24b08f5bed3  crates/aster-node/src/frame.rs
c193db439513bf61c2cee0dead3621e6bee058c9f76e433bf8d388f3ab0a05d3  crates/aster-node/src/lib.rs
3d27d0d0ad37c032a7ec1905aa75274cedfecfa539ce18340a482b244b4eda9c  crates/aster-node/src/main.rs
44cebc7201ea6447d3b14110e433fbc8d168a52f97878cf81a6d534be36c304a  crates/aster-node/src/mission.rs
a30ae1e158a5fd8928d970d36c69939340c6a64cda3293a3f34110d91478942c  crates/aster-node/src/runtime.rs
f9d6531b3d1b53453b8449d2566dda80263d5810a77ee62c20c8cd12d9101c51  crates/aster-node/examples/custody_application.rs
e32c98edb74fa1560217d3d78c0fec2632045fab3bd99c948b2e4a8fbb5dee58  crates/aster-ffi/src/lib.rs
3d482bc238d9c75fd3a8e1e3cc7136e740a4fef48321233a48407957119e4455  bindings/c/aster_mesh.h
e1778498733672b3225f5eae19f3a9e6bd45a85142ed5d0358adaa9e9287f9e8  bindings/c/header_smoke.c
a3e951fb09d81533f9d631be5749eed681aa642b7b56d17610388012fc231496  bindings/c/header_smoke.cpp
c7224b04c031a36ef9e3c9c1aa7e4422a9833e0942a0cfb03d33c12671079996  bindings/go/aster_test.go
3cff2050fd3986ddf02eaa2e2eeb8486578ee0185ffaa227784e61209fe7b83b  bindings/python/tests/test_binding.py
5f3705bcdcf04cc1186b3860db59b6a90d6acbf63192b5129037c6ccad33a706  crates/aster-lab/src/lib.rs
e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987  data-mesh-requirements.md
57518c2aaeb7341f0d2ef7169a30a1666e337def2bb6a34f9225fad6e438e5b2  docs/evaluations/0005/requirements-matrix.csv
e72e4fab25c0e327a1a4dd55ab87f05f641a0c4dae9f54ea7c178fc3ee352058  docs/implementation/requirements-implementation.csv
d88d9347362f5577efe60c916fc259c8ac73bb5ec44fbc815e79c0812265ee55  tools/check-implementation-requirements.py
```

The complete current-toolchain command

```sh
cargo test --workspace --all-features --all-targets -- --test-threads=1
```

passed every runnable workspace target in 1,178.21 seconds. Summing the
per-binary Cargo reports gives 895 passed tests and one explicitly ignored local
performance experiment. The separate exact Rust 1.91.0 command passed the same
895 tests plus the same one ignored experiment in 2,069.41 seconds, including an
11 minute 25 second clean compile. The nonzero selected counts included core
372/372, FFI 13/13, host 74/74, IP/relay 50/50, Iroh carrier 6/6, lab library
32/32, Negentropy 10/10, node library 117/117, node binary 6/6, real-process
`mesh_cli` 13/13, and selected redb store 137/137. All six node examples and
the other listed example targets compiled successfully and contained no tests.

Strict workspace all-feature/all-target Clippy with warnings denied passed on
the current and Rust 1.91 toolchains in 211.01 and 206.85 seconds. Current Cargo
also emitted its separate upstream future-incompatibility notice for
`proc-macro-error2 2.0.1`; no workspace warning escaped `-D warnings`. A final
exact-current selected-store rerun passed 137/137 in 71.65 test seconds
(114.93 seconds including compilation). The only source changes after the full
matrices were two Rustdoc-only comment corrections; exact-current and Rust 1.91
strict `aster-lab` Clippy then passed in 2 minutes 21 seconds and 3 minutes 30
seconds. A fresh-target locked/offline workspace Rustdoc build with warnings
denied passed all 17 workspace crate-target documents in 16.58 seconds. Rust
formatting, `git diff --check`, and the generated requirements validator passed.

Focused tests within those matrices cover checked custody age/overflow and the
exact TTL boundary; authenticated v3 claim and replay binding; same-clock
high-water concurrency; route-to-content promotion; startup source proof before
maintenance; priority/TTL/length/class tamper; exact-scope quota configuration
and aggregate quota enforcement/rejection; authority and tombstone reserves;
retirement, lease, retry, receipt, and crash/reopen accounting;
equal-priority multi-peer retry fairness; opaque selector-generation receipt
invalidation; Carry-to-Consume promotion in normal and blind ReceiveOnly
contacts; receiver-relative Satisfied/Pending settlement; common-set cleanup and
due-boundary retry; pre-open stale-work continuation; post-stream-open zero-byte
final rejection; final policy recheck; lane deferral; whole-contact budget
bounds; same-epoch historical lineage and legacy-witness migration; source
revocation/rekey; and v3 downgrade-transcript rejection.

The exact public example invocation was:

```sh
cargo run -p aster-node --example custody_application -- \
  /tmp/aster-custody-example.FEbSuK/mesh/node-0 \
  /tmp/aster-custody-example.FEbSuK/mesh/node-0/mission.unprotected-reference.bundle \
  demo/mesh mesh.ping-pong
```

On the Darwin arm64 host it completed a clean peerless lifecycle and printed:

```text
CUSTODY_APPLICATION finite_ttl=unsupported_on_this_platform,durable_fallback=true id=ea28599c6e8287132cc5293da33cebb2124e75f2c99c015242c80982e40cc41c inserted=true authenticated_ttl_ms=None initial_policy=AtLeast(Priority) initial_revision=1 updated_policy=Normal updated_revision=2 observed_revision=2 events=3
```

The Linux branch of the same compiled example requests a positive 60,000 ms
finite TTL; this Darwin run does not claim Linux expiry execution.

Native binding/version follow-ups passed the focused FFI version test on the
current and Rust 1.91 toolchains, strict FFI Clippy on both, native library
build, C11 and C++17 syntax plus linked-runtime smoke tests, Python 12/12, and
the complete Go suite. At that pre-v4 source freeze, ABI and wire versions were
1 and the default/highest semantic version was 3, with semantic versions 2 and
1 retained for negotiated compatibility. Current code instead offers
`[5, 4, 3, 2, 1]`; v4 and v5 inherit the same Event custody mechanics without
changing this receipt.

This evidence moves exactly `DM-11-15`, `DM-11-17`, `DM-5.4-05`,
`DM-5.4-09`, `DM-5.4-10`, `DM-5.4-12` through `DM-5.4-19`, `DM-5.4-21`,
`DM-5.4-22`, `DM-5.7-03`, `DM-9-24`, and `DM-9-25` from `open` to
`implemented-uncredited`; it strengthens the existing `DM-5.4-01` and
`DM-5.5-07` rows and adds no `observed-bounded` credit. At that source freeze,
the trace contained 348 requirements, 106 exact selected mappings, 68
implemented-uncredited, 37 observed-bounded, and 243 open.

The claim is deliberately limited to semantic-v3 selected Event/RouteEvent
custody, Linux finite TTL, the documented logical/accounted namespaces and hard
ledger caps, direct-Iroh loopback software tests, and the exact application and
binding surfaces above. Generic cross-class lowest-priority eviction
(`DM-5.4-11`), State/Record/Blob custody, non-Linux finite TTL, accepted-dot and
causal/frontier aggregate retirement, physical storage/RF/network behavior,
NAT/hosted relay/BTLE, mixed implementations, scale/resource acceptance,
operational protected provisioning/administration, independent interoperability/review,
FIPS validation, a retained externally anchored receipt, and release
authorization remain open.

## Current protected live startup and control automated evidence

The current source tree adds caller-provided protected live `NodeConfig`
construction and actor-owned `SelectedControlHandle` administration after the
historical stopped Step 4 freeze below. This section intentionally records no
signed documentation commit or retained execution root. The source freeze is
signed commit `164ccc1dbafd7fa954c06eb7cf555671ff597ba1`. It moves no status and grants no
additional `observed-bounded` credit; at that protected-source freeze the
generated totals were 78
`implemented-uncredited`, 37 `observed-bounded`, 233 `open`, and 119 exact
selected mappings.

The exact frozen source identities are:

```text
82e736ed113800cd1aa2aecfee2fb94d97524f5dfa579f489bca780a74bfb3e9  crates/aster-core/src/provisioning.rs
068d1ae37bf986aafa6dfd1f45cebfe14adcedbd1f22fb7d4b179dc433d6f017  crates/aster-node/src/control_admin.rs
438e4cc3d0a9c3d984d4344cfdf394b4968712af0715af09fc1a224f801e76b1  crates/aster-node/src/lib.rs
79be3dc2e718b24459176382f7a33f7abfb8fff576022370b10cd4335d56b602  crates/aster-node/src/mission.rs
ad7f4b54719fdc92edaa342e36e62950ab087e5ea1b711f221880f238e6b1c14  crates/aster-node/src/runtime.rs
68100051afaa92af67268b69527c23638150eec613eb1598f7edd90aff5a06ae  crates/aster-node/tests/protected_runtime.rs
```

At those identities, these exact reported current-code gates passed:

```sh
cargo test --locked -p aster-core --lib
# 380 passed; 0 failed; 45.21s
cargo test --locked -p aster-node --lib
# 180 passed; 0 failed; 69.94s
cargo test -p aster-node --test protected_runtime
# 12 passed; 0 failed; 0.15s
cargo check --locked -p aster-node --all-targets --all-features
# passed; 12m04s
cargo clippy --locked -p aster-node --all-targets --all-features -- -D warnings
# passed; 25.84s
env CARGO_TARGET_DIR=/private/tmp/aster-protected-admin-rustdoc-fresh RUSTDOCFLAGS=-Dwarnings \
  cargo doc --locked --workspace --all-features --no-deps
# passed from a fresh target; 17.97s
cargo fmt --all -- --check
git diff --check
# both passed
```

The final serialized gate over those source identities and the preceding frozen
documentation bytes ran outside the sandbox for real-Iroh loopback:

```sh
CARGO_TARGET_DIR=/private/tmp/aster-protected-admin-full-check CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 mise run check
# exit 0
```

The all-feature workspace tests and strict Clippy passed. Major test results
were core 388/388, node library 180/180, node main 12/12, `mesh_cli` 20/20,
`protected_runtime` 12/12, redb 166/166, `aster-iroh` 13/13, host 74/74, IP
50/50, lab 32/32, and FFI 13/13; all doctests also passed. C/C++ syntax,
conformance and Python wire checks, Python bindings 12/12, lab Python 162/162,
Go, license, dependency, and requirements gates were green. At that frozen
protected-source gate the requirements trace had 348 IDs, 119 mappings, 78
`implemented-uncredited`, 37
`observed-bounded`, and 233 `open`. This is a non-retained current-code CI
receipt: it creates no execution root, observed credit, status movement, or
signed documentation commit.

The Unix `crates/aster-node/tests/protected_runtime.rs` target names these twelve
exact cells:

- `protected_bytes_preserve_exact_options_and_origin_without_creating_state`
- `protected_artifact_invokes_provider_once_without_creating_state`
- `relative_state_is_bound_before_path_provider_and_loader_cwd_callbacks`
- `invalid_protected_options_do_not_invoke_provider_or_create_state`
- `uninspectable_state_fails_before_provider_invocation`
- `terminal_state_precedes_protected_provider_and_secret_loader_without_mutation`
- `raw_canonical_bundle_never_reaches_protected_provider`
- `protected_rejection_is_sanitized_and_source_free`
- `missing_protected_artifact_fails_before_provider_or_state_creation`
- `secret_loader_receives_exact_request_and_preserves_secret_origin`
- `secret_loader_rejects_mismatched_receipt_echoes_without_state_creation`
- `protected_state_witness_rejects_mutation_before_state_creation`

They cover exact option preservation; artifact/byte/opaque-reference origins;
one-call provider behavior; option, terminal-state, and filesystem prechecks
before state creation; sanitized rejection; exact load-receipt echoes; one
captured absolute lexical state pathname; and rejection of later public
`NodeConfig::state` mutation. They do not establish inode, parent-directory,
symlink-resolution, rename-history, database-replacement, or rollback binding.
Additional exact unit cells are
`secret_reference_is_bounded_canonical_versioned_and_redacted`,
`provisioning_origins_have_stable_nonidentifying_receipt_labels`,
`protected_state_witness_is_lexical_and_clone_local`,
`live_control_handle_retains_only_stable_identity_accessors`,
`closed_live_control_channel_returns_only_sanitized_state_unavailable`, and
`runtime_rejection_closes_live_control_call_with_fixed_category`.

The live actor's exact runtime cells are:

- `protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown`
- `live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry`
- `saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish`
- `cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable`
- `live_self_revocation_returns_receipt_before_actor_teardown`

Those cells bound a capacity-one control queue and four-command yield budget;
live rekey/revocation policy refresh; exact retry; nonfatal pending-policy
deferral; Event/status progress under cloned retry pressure; graceful shutdown;
self-revocation receipt-before-teardown; and one post-enqueue caller-cancellation
case whose committed receipt is recovered by stopped exact retry. Cancellation
may still commit, so it is not a rollback guarantee. A lost self-revocation
response requires stopped admin after teardown. The protected and
secret-reference origins can shut down gracefully, but the live local
zeroization path cannot destroy provider custody. The post-enqueue cancellation
cell is Unix-only.

Useful focused reproduction commands are:

```sh
cargo test --locked -p aster-core provisioning --lib
cargo test --locked -p aster-node mission::tests --lib
cargo test --locked -p aster-node control_admin::tests --lib
cargo test --locked -p aster-node --test protected_runtime -- --test-threads=1
cargo test --locked -p aster-node \
  protected_live_controls_refresh_policy_retry_exactly_and_close_on_shutdown --lib
cargo test --locked -p aster-node \
  live_control_pending_gap_returns_policy_unsettled_and_preserves_exact_retry --lib
cargo test --locked -p aster-node \
  saturated_cloned_live_control_retries_do_not_starve_event_status_or_publish --lib
cargo test --locked -p aster-node \
  cancelled_enqueued_live_control_remains_actor_owned_and_exactly_retryable --lib
cargo test --locked -p aster-node \
  live_self_revocation_returns_receipt_before_actor_teardown --lib
```

No production SecretStore/protection backend, stock protected CLI, selected-node
binding, cross-process live-admin IPC, issuance/recovery workflow, automatic or
atomic revoke-plus-rekey, coordinated drain/store-terminalization/provider-
destroy workflow, physical sanitization, or release authorization follows from
these tests.

## Prior protected provisioning and control administration automated evidence

Step 4 is source-frozen at the identities below. At that frozen Step 4 tree, the
current Rust 1.97.1 and minimum-supported Rust 1.91.0 executable workspace
matrices each passed 927 tests with zero failures and one deliberately ignored
local performance experiment. Both runs included every library, binary,
integration-test, and example target; their commands intentionally separated
doctests from the 927 executable-test count. Fresh-target Rustdoc with warnings
denied then generated all 17 workspace crate-target documents on each
toolchain.

That freeze predates semantic v4; the current v4 source tree does not relabel it
as current evidence.

This is an unreleased draft and must not be published under the retained
workspace version `0.1.0`. It intentionally removes the raw node control
publisher reexports, requires a nonzero registry-generation witness in the
rekey CLI, adds an opaque authenticated-plan capability to the unpublished
redb local-rekey commit seam, and expands unpublished redb control
records/errors for migration and rejection fencing. The wire profile and C ABI
do not change. Any release must increment the draft/package identifier and
record these Rust/CLI migrations in the release notes and compatibility matrix.

The exact whole-workspace commands were:

```sh
CARGO_TARGET_DIR=/private/tmp/aster-step4-current-tests \
  cargo test --locked --workspace --all-features \
  --lib --bins --tests --examples -- --test-threads=1
CARGO_TARGET_DIR=/private/tmp/aster-step4-rust191-tests \
  cargo +1.91.0 test --locked --workspace --all-features \
  --lib --bins --tests --examples -- --test-threads=1
CARGO_TARGET_DIR=/private/tmp/aster-step4-current-tests \
  cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
CARGO_TARGET_DIR=/private/tmp/aster-step4-rust191-tests \
  cargo +1.91.0 clippy --locked --workspace --all-targets --all-features -- -D warnings
CARGO_TARGET_DIR=/private/tmp/aster-step4-rustdoc-current \
  RUSTDOCFLAGS=-Dwarnings \
  cargo doc --locked --offline --workspace --all-features --no-deps
CARGO_TARGET_DIR=/private/tmp/aster-step4-rustdoc-191 \
  RUSTDOCFLAGS=-Dwarnings \
  cargo +1.91.0 doc --locked --offline --workspace --all-features --no-deps
```

The current run recorded core 382/382 (129.37s), FFI 13/13 (3.75s), host
74/74 (13.86s), IP 50/50 (2.21s), Iroh 6/6 (0.16s), lab library 32/32
(52.51s), node library 133/133 (66.13s), node binary 6/6 (0.01s), real-process
`mesh_cli` 13/13 (144.36s), and redb store 143/143 (79.71s). Rust 1.91
recorded the corresponding core 382/382 (135.14s), FFI 13/13 (3.89s), host
74/74 (14.34s), IP 50/50 (2.21s), Iroh 6/6 (0.15s), lab library 32/32
(53.78s), node library 133/133 (70.49s), node binary 6/6 (0.01s),
`mesh_cli` 13/13 (139.03s), and redb store 143/143 (81.73s). The smaller
workspace targets account for the remaining passing tests. The current and
Rust 1.91 results are separate executions; timings are not pooled.

The real-process harness raises the ordinary ready bound to 40 seconds. Its cold
offline-publication cell separately bounds worker startup at 90 seconds,
authenticated contact at 120 seconds, and overall worker completion at 150
seconds. Those are test-harness deadlines, not an operational availability or
offline-duration claim.

Focused development gates included:

```sh
cargo test -p aster-core provisioning --lib
cargo test -p aster-node control_admin::tests --lib
cargo test -p aster-node \
  relative_paths_remain_bound_across_path_provider_and_loader_cwd_changes --lib
cargo test -p aster-redb-store \
  authenticated_pending_predecessor_and_rollback_poison_is_purged_without_losing_gap_closer --lib
cargo test -p aster-redb-store \
  rejected_sequence_fence_blocks_replayed_descendants_until_valid_alternate_applies --lib
cargo test -p aster-redb-store \
  legacy_scope_epoch_is_historical_before_revocation_but_rejected_afterward --lib
cargo test -p aster-node \
  historical_local_control_receipts_survive_later_highwaters_but_remote_rows_do_not --lib
```

The provisioning filter passed 11 tests and the stopped control-admin filter
passed five; every focused regression above also appears in both complete
workspace matrices. They exercise checked operation/reference
receipt binding and zeroizing plaintext ownership; terminal-before-provider
ordering and sanitized admin failures; relative state/artifact binding across a
provider/loader current-directory change; authenticated control-poison purge
and durable descendant fencing; pre-revocation historical legacy scope state
versus post-revocation rejection; and exact same-signer historical publication
recovery without treating a remote row as locally emitted.

The final external-surface and policy gates also passed: native FFI build;
C11/C++17 warnings-denied header syntax; Rust conformance self-test; the Python
wire oracle's 10 accepted and 21 rejected vectors; standalone conformance
profile agreement 18/18; Python bindings 12/12; lab controller 162/162; the Go
binding suite and `gofmt`; Apache-2.0 project/package policy for 15 packages;
selected-node dependency isolation; the vendored netlink equivalence plus
13/13 tests; retained-libp2p boundary plus 16/16 regression tests; dependency
exception scope and its fail-closed regression; and the implementation trace
at 348 requirements and 109 exact selected mappings.

The frozen source identities are:

```text
e5c4201b70abae043dfa8bd2a8fe736f0b21aa4d10f3ff44deb00f0f828e8a4f  crates/aster-core/src/crypto/reference.rs
be66f9a3d83cd37c8d21a94bb7f62ed6722928ee7f888b06deb810f19ca4f91c  crates/aster-core/src/lib.rs
ae55f3a2dcd23af759a66c5152195e916b725a0158493b99d69c884333075970  crates/aster-core/src/provisioning.rs
070de70c8b484a6af5c461f9c4903a612091e10d7d4413149d5e63fdb53751ee  crates/aster-core/src/source_control.rs
ed7e95d57a6f17429639ff4ca3453952a43295ed027a98e5cce0b041f802c544  crates/aster-node/src/application.rs
7aa1fa7b50d73187d4fe7e0569d48303e7ecb74010e2516b751062570fa54103  crates/aster-node/src/control_admin.rs
095f26fa11c962ebc23b38573b170d7d7487abd8751d2433ad344f5459f3c5f4  crates/aster-node/src/lib.rs
d1eb655e15626b3e27fdbfd52d206124f63329ef2a5c5eb27d266da93bf76621  crates/aster-node/src/main.rs
0a65802f2bdcae9d41a756df8f3888faa6445b8edb4f9bc2a736c281e9836385  crates/aster-node/src/mission.rs
2dee780f04159fce4b4e368502e042bacb1eb903892d472fc72a6f688777d1a5  crates/aster-node/src/runtime.rs
b5e2928fdcfcb92765d14fa0c095bffb13760f4a42428acabceef58bab0506b2  crates/aster-node/tests/mesh_cli.rs
b3dea6db88e7eb64c8b309124bc63a35c1d6ad8b6461b0a715aaeed184735fe7  crates/aster-redb-store/src/lib.rs
9e66fad1c6ef70f7932ddfb467acb75e6cb993bae4613f9ba262b85b6b07b74f  Cargo.lock
```

The in-memory SecretStore test fixture is not a production backend or evidence
of backend durability, access control, at-rest secrecy, backup/recovery, or
physical erasure. The focused path tests establish a lexical current-directory
binding only. The focused control tests do not establish automatic or atomic
revocation remediation, physical/long-partition propagation, independent
interoperability, or release acceptance. This section moves no status: the
trace at that source freeze remained 348 requirements, 109 exact selected mappings, 68
implemented-uncredited, 37 observed-bounded, and 243 open.

## Reproducible receipt

Every retained root, binary identity, and source hash below belongs to the
parent PR-A/pre-subscription snapshot. PR B, PR C, the selected
State/Record/Blob and Event-custody slices, and the prior protected/admin
slice change store, frame, runtime, application, core, example, or
integration-test bytes; their credit in this ledger is limited to the exact
source/test boundaries mapped above. No fresh retained real-process receipt for
those slices is claimed.

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

This parent-snapshot eight-node root is not the bracketed many-node target,
proof of the full 2–32 range, physical multi-system acceptance, throughput
evidence, or target-tier memory/CPU/power evidence. At that freeze, the formula
only predicted 65 cohorts and 158 children at N=32. The separate current-tree
receipt below supplies one bounded N=32 observation without relabeling this
historical root or satisfying those broader gates.

## Selected N=32 retained receipt

On 2026-08-25, one operator-attested Cargo release-profile binary run for the
signed source commit `6f280b680c0481faae5067e87cdc52d6597dc83c` completed
the selected Event Ping/Pong line at N=32. The retained local root token is
`aster-selected-n32.uEVcAg`; it remains under `/private/tmp` on the validating
host and is not a source artifact. The source tree was
`02167328f8c4dd04ca6f62992d983aff3d8127ff`, and the recorded build and run
were:

```sh
cargo build --release --locked -p aster-node --bin aster
/usr/bin/time -l target/release/aster demo --nodes 32 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  > /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  2> /private/tmp/aster-selected-n32.uEVcAg/demo.stderr
```

The wrapper exited zero. The operator attests that the worktree was clean at
both build and execution and records rustc 1.97.1 at commit
`8bab26f4f68e0e26f0bb7960be334d5b520ea452` for
`aarch64-apple-darwin`. The validator independently requires the exact signed
Git commit and tree, exact checkout HEAD, public authority-file hashes, binary
size/hash, transcript shape, and every stated scenario invariant. It does not
derive the historical worktree cleanliness and does not cryptographically
prove the source-to-binary-to-execution link. Those two facts remain explicit
operator attestations. The binary is a Cargo release-profile build, not a
signed or product release artifact and not release authorization.

The checked-in
[`aster-selected-n32-receipt/v1` receipt](evidence/selected-n32-6f280b6.json)
is 6,069 bytes with SHA-256
`0138158300b7676efbe074b29b50c62017ab5e0b3cba11fb29ffbe3ee07721eb`.
It contains only bounded sanitized aggregates:

| Evidence dimension | Validated result |
|---|---|
| Topology and identities | One Darwin arm64 host; 32 loopback sockets, 32 mission identities, 32 carrier identities, 32 state directories, and 32 distinct store artifacts; same binary and implementation; one scope, authority, and topic; line topology |
| Schedule and processes | 65 exact phases; 158 exact-named child executions with 158 distinct nonzero READY PIDs; the 62 data-motion phases were serial two-process directed edges; the final no-op phase declared `processes=32` and contained 32 distinct READY PIDs |
| Event interest and relay boundary | Consume 2, Carry 30, 32 selectors; 30 intermediates; `payload_blind_relays=pass`; a terminal inventory of exactly two Event transfers (Ping and Pong) at every node |
| Final no-op | 31 authenticated edges, 451 mirrored cycles, and 902 endpoint receipts; all control, Event, mutable, and Blob reconciliation counters were zero |
| Outer transcript | 70 stdout lines/12,113 bytes; 18 stderr lines/777 bytes classified exactly as Darwin `time -l`; transcript-only safe manifest 318 records/33,102 bytes |
| Child transcripts | 158 stdout files, 1,594 lines, 1,417,290 bytes; 158 stderr files, all empty; 1,274 passing direct-contact receipts |
| Sensitive retained state | Parent mode `0700`, owned by the current validator UID; 32 state directories; 32 mission bundles, 32 identity keys, and 32 stores on 96 distinct inodes; every artifact `0600` or narrower; 33,997,190 aggregate bytes |

The READY-PID checks are log-observed process evidence. Distinct nonzero PIDs
bind each exact-named execution and the 32 final-no-op logs, but no overlap
timestamps or independent OS sampler prove that all 32 processes were running
simultaneously. The receipt makes no concurrency-performance claim.

The validator inspects sensitive state only with metadata operations needed to
bind exact regular-file names, ownership, modes, inode uniqueness, counts, and
sizes. It never opens, reads, or hashes mission bundles, identity keys, or redb
stores. The raw root and raw logs contain credentials or identity-bearing data
and must not be committed, copied into documentation, or treated as a shareable
receipt. The committed JSON contains no input path, PID value, socket, mission
or carrier identity, transfer identity, port, or secret-file digest.

The exact public and sanitized identities are:

```text
6f280b680c0481faae5067e87cdc52d6597dc83c  signed source commit
02167328f8c4dd04ca6f62992d983aff3d8127ff  source tree
5b26134242180affeeaa555175e7400f682c47e14b2e7d2df2decfe14ee5f90c  Cargo.lock
e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987  data-mesh-requirements.md
a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea  target/release/aster; 11,962,608 bytes
fdc828b5bc0462e621a71f958537fe2778d4c5c9b928c5a6ebf8bf9907e24345  exact run argv
8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395  safe transcript manifest
72a0d2bda675984ebe85a05f4d1e93d6e77067030e180c14b518004cfd0de5c3  sanitized outer stdout
5eb12c6684037dafca13b2db94cd12a34b0bf50512b7d29ddc8e702952e3c1a6  sanitized Darwin time stderr
8a2e4a701c1fb93f5678a2a3ce2b8b988c87f1519cbed1a64e1309b53c1ade94  sanitized child-stdout aggregate
59e14b66b830621643c2fc478bcf604616983ad90838d340d1166e81dabe5362  empty child-stderr aggregate
d5ffdf083fb2d715098c8e15d2f879246f6a398947c40a18e2d9af20c042e965  tools/check-selected-n32-receipt.py
8ecb091f3b433a7e8938fb2042220f0fb3747a958a1ca87e8124fbbf9da2a092  tools/test-selected-n32-receipt.py
0138158300b7676efbe074b29b50c62017ab5e0b3cba11fb29ffbe3ee07721eb  sanitized checked-in receipt; 6,069 bytes
```

The original validator generation used these exact arguments while the source
checkout HEAD was the signed source commit:

```sh
python3 tools/check-selected-n32-receipt.py \
  --source . \
  --source-commit 6f280b680c0481faae5067e87cdc52d6597dc83c \
  --binary target/release/aster \
  --binary-sha256 a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea \
  --binary-size 11962608 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  --stdout /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  --stderr /private/tmp/aster-selected-n32.uEVcAg/demo.stderr \
  --transcript-manifest-sha256 8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395 \
  --build-command 'cargo build --release --locked -p aster-node --bin aster' \
  --run-argv '/usr/bin/time -l target/release/aster demo --nodes 32 --root /private/tmp/aster-selected-n32.uEVcAg/run' \
  --wrapper-exit-code 0 \
  --host-os Darwin \
  --host-arch arm64 \
  --rustc-version 1.97.1 \
  --rustc-commit 8bab26f4f68e0e26f0bb7960be334d5b520ea452 \
  --build-target aarch64-apple-darwin \
  --worktree-clean-at-build-and-run \
  --output /private/tmp/aster-selected-n32.uEVcAg/receipt-pid-bound.json
```

That block records the original pre-documentation-commit generation context:
the working checkout was still at `6f280b680c0481faae5067e87cdc52d6597dc83c`.
It must not be run unchanged from a later evidence checkout, whose HEAD includes
the checker and documentation and therefore differs from the signed source
commit. For a future review, invoke the checker from the current evidence
checkout, but pass `--source` a separate checkout or worktree detached exactly
at the signed source commit. Keep the retained binary and raw-root inputs, and
use a fresh nonexistent output path, for example:

```sh
python3 tools/check-selected-n32-receipt.py \
  --source /path/to/aster-source-worktree-detached-at-6f280b68 \
  --source-commit 6f280b680c0481faae5067e87cdc52d6597dc83c \
  --binary target/release/aster \
  --binary-sha256 a0d520be34c6065b1cf482426c6c6800ae27188fb4af75e34a558eaf2c1321ea \
  --binary-size 11962608 \
  --root /private/tmp/aster-selected-n32.uEVcAg/run \
  --stdout /private/tmp/aster-selected-n32.uEVcAg/demo.stdout \
  --stderr /private/tmp/aster-selected-n32.uEVcAg/demo.stderr \
  --transcript-manifest-sha256 8a90c39e4c5eb876ca85274877755eb87e180db5449a64b0e3ec0d309ed08395 \
  --build-command 'cargo build --release --locked -p aster-node --bin aster' \
  --run-argv '/usr/bin/time -l target/release/aster demo --nodes 32 --root /private/tmp/aster-selected-n32.uEVcAg/run' \
  --wrapper-exit-code 0 \
  --host-os Darwin \
  --host-arch arm64 \
  --rustc-version 1.97.1 \
  --rustc-commit 8bab26f4f68e0e26f0bb7960be334d5b520ea452 \
  --build-target aarch64-apple-darwin \
  --worktree-clean-at-build-and-run \
  --output /private/tmp/aster-selected-n32.uEVcAg/review-receipt.json
```

The output path is exclusive and is never overwritten. A replay output must be
6,069 bytes with the checked-in receipt hash above. The independent final audit
reran the 27-case synthetic falsification suite and the complete retained-root
validator to a fresh output; the receipt reproduced byte-for-byte. The
synthetic suite fails closed for truncation, missing/extra/duplicate artifacts
or phases, binary/transcript mismatch, cap overflow, unclassified stderr,
nonzero no-op counters or wrapper exit, unsafe symlinks/hard links/modes or
ownership, missing clean-worktree attestation, duplicate/zero READY PIDs,
secret reads or hashes, and output overwrite.

The outer Darwin `time -l` measurement recorded 309.79 seconds elapsed, 36.27
seconds user, 42.10 seconds system, and a 26,181,632-byte maximum resident-set
field. These are host-specific, measurement-only `wait4` resource-usage fields
for the timed orchestrator and its descendants; maximum RSS is a maximum, not
summed concurrent process RSS. No CPU, memory, disk, network, energy,
target-tier, or other resource threshold receives credit.

This receipt moves only `DM-9-21A` from `implemented-uncredited` to
`observed-bounded`. It is one same-build, same-implementation, one-host,
direct-loopback, one-scope/authority/topic line. It does not move the separate
`DM-9-21` at-least-100-node target and provides no distributed or physical
topology, representative NAT, controlled-relay, BTLE/cross-transport,
State/Record/Blob scale, independent-implementation, packet-capture, resource-
threshold, product-release, or release-authorization evidence.

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

The controlled-relay slice adds a direct `rustls` 0.23.43 edge but no new
`rustls` package or version. The normal selected-node graph reaches Iroh's
client-side `iroh-relay` support without enabling its `server` or `test-utils`
features. The optional `aster-iroh/test-utils` dev/all-feature fixture enables
that local relay-server graph and adds its lockfile-only test dependencies.
Passing the serialized dependency/license gates records the current policy
result; it does not resolve the CDLA/Unlicense, supported-target, SBOM, or release
decisions above.

## Requirements still open in the selected lane

| Requirement class | Current state | What must be delivered before complete credit |
|---|---|---|
| Remaining data model | `implemented-uncredited` / `open` | Extend the bounded direct State/Record reconciliation into longer partitions, relays, divergent State convergence, restarts/crash windows, and independent interoperability; add live State/Record application operations; design convergent registered-policy Record merge; extend the bounded direct Blob transfer/resume slice through a live application boundary and route-only custody, then add multi-class retention/GC and broader conflict/deletion behavior |
| Source and mission security | `implemented-uncredited` / `observed-bounded` / `open` / `external-gate` | Extend the caller-provided protected live Rust config and stopped Event/admin seams through an admitted production backend, stock CLI and bindings, issuance/recovery, and a coordinated live-drain/store-terminalization/provider-destroy lifecycle; add generalized multi-family control policy plus automatic/atomic revocation remediation; verify multi-scope, repeated, longer-partition, and physical revocation/rekey propagation; replace the absolute lexical path witness with any required inode/parent-directory/symlink/rename/rollback assurance; add non-Unix and physical/copy-on-write/snapshot/swap/backup zeroization assurance, all data classes, any required admitted FIPS boundary, packet-capture acceptance, and independent cryptographic review |
| Custody and constrained operation | `implemented-uncredited` / `open` | Selected Event/RouteEvent now has semantic-v3-format cumulative age inherited by v4/v5, Linux finite Event TTL, expiry/GC, priority scheduling/retry, bounded quotas, thresholds, and receive-only inbound. Normal and AtLeast run v4/v5 mutable work and may run the v5 Blob lane because AtLeast is Event-only; ReceiveOnly initiates/discloses neither mutable nor Blob work. Selected finite State/Record/Blob TTL remains rejected/open. Still required are complete cross-class priority eviction/custody, route-only Blob custody, non-Linux Event age, physical RF silence, v1/v2 deterministic partials, bindings, scale, mixed implementations, and retained acceptance. |
| Scope and application policy | `implemented-uncredited` / `open` | Durable application-facing State/Record subscriptions and delivery behavior beyond explicit contact interests, automatic registered-policy Record merge, atomic subscription update, multi-scope join/leave, bridges, dynamic peer policy, and equivalent live status/gap semantics beyond the selected Event surface |
| Blob behavior | `implemented-uncredited` / `open` | The local authenticated fixed-profile chunking, encrypted resume, immutable publication, and bounded-memory reader now have one semantic-v5 direct content-capable-peer source/carrier path with peer-neutral range resume and completion-gated visibility. Add a live Blob handle/subscription, route-only relay/custody, TTL and explicit staging GC; decide whether a metadata-independent pure-byte content ID is required; add complete physical accounting and hundreds-of-MB acceptance. |
| Carrier portfolio | `implemented-uncredited` / `open` / `external-gate` | Selected direct IP and one explicitly trusted singleton relay mechanism now exist. Still required are physical IP, representative NAT direct/fallback, discovery policy, BTLE platform driver, smallest-MTU framing, link characteristics, State/Record/Blob-over-relay acceptance, mobility/outage recovery, mixed implementations, and future-carrier proof. |
| DDIL resilience | `open` / `external-gate` | Loss/bandwidth floors, long custody/offline interval, crash/corruption recovery, broader partial-contact durable progress and alternate-peer/carrier continuation beyond the one bounded direct Blob case, mobility, and power/emission measurements |
| Developer surface | `implemented-uncredited` / `open` | Add live application handles for the now-networked State/Record classes and a live Blob handle/subscription over the bounded network path; add automatic merge only after a convergent design, atomic subscription update if required, C FFI and at least two selected-node bindings, broader multi-class examples including live privileged administration, carry caller-provided protected Rust startup and typed live/stopped control administration into the stock CLI/bindings with a production backend/recovery/destroy workflow, run an independent usability study, and decide the optional local agent |
| Scale and resources | `observed-bounded` / `open` / `external-gate` | Retain the one-host direct-loopback selected Event N=32 receipt as the bounded `DM-9-21A` observation; still obtain stakeholder-confirmed bracketed targets plus repeatable at-least-100-node, inventory-size, memory, CPU, binary, bandwidth, and energy evidence on target tiers |
| Interoperability and release assurance | `open` / `external-gate` | Independent conformant implementation, mixed-version/downgrade evidence, completed hostile-peer campaigns, admitted dependency/license/SBOM graph, physical acceptance, and signed release disposition |

The proven semantic implementation remains the source to migrate. Its existence
outside the selected composition alone is not selected-composition credit, and
research evidence cannot replace production-lane verification.
