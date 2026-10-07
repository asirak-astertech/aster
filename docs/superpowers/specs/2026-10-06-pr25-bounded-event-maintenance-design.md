# PR 25 bounded Event maintenance and prompt propagation design

**Status:** Approved in chat on 2026-10-06; revised written-spec and final independent review complete on 2026-10-06
**Capability tracks:** causal/lifecycle correctness; intermittent store-and-forward  
**Evidence boundary:** current-code regression and engineering-resource coverage only

## Intent

PR 25 should make routine Event custody maintenance predictably bounded and
make durable Event work promptly attempt propagation when connectivity permits.
It must preserve offline-first durability, authenticated reconciliation,
ReceiveOnly behavior, contact fairness, numbered-publication recovery, and
crash-safe retirement. It must not claim immediate delivery, complete
convergence, target-device qualification, or broader requirement maturity.

Success means:

- advancing custody-clock observations remain durable even when a maintenance
  pass otherwise has no work;
- one maintenance pass has explicit candidate and dependency bounds and resumes
  cleanup after a crash or later wake;
- an admission can atomically free a selected victim's payload without walking
  that victim's complete dependency fan-out;
- audits do not duplicate the complete reverse-reference ledger in memory;
- local Events and Events first inserted by selected Event reconciliation arm a
  prompt contact attempt even if the carrying contact later fails;
- discovery promptly refreshes scheduling, and a candidate arriving for
  undispatched peerless Event work receives one forced attempt;
- a forced-only scheduler edge attempts only pending peers, while periodic edges
  retain ordinary scheduling; and
- deterministic regressions cover both contact directions without an
  ephemeral-port ownership race.

## Scope and compatibility decisions

This increment applies to Event and RouteEvent custody and selected Event
contact scheduling. State, Record, Blob, control, and bridge
prompt-propagation policy remain separate work. Aggregate contact metrics must
not be mistaken for an Event-specific insertion signal.

The semantic wire protocol and public receipt formats do not change. Internal
maintenance budgets are implementation controls, not protocol limits. No
requirements-status or roadmap maturity change is justified without new
retained evidence.

The custody schema remains version 3. Existing empty `CUSTODY_RETIRING` values
are read as legacy marked-cleanup records; new values use a versioned cleanup
record. Per the project owner's earlier decision, this evaluation-stage change
does not migrate predecessor schemas because there are no real deployments.
Stores using custody schema v1 or v2 cannot be opened and must be recreated; no
data is migrated. Genuine v1 and v2 rejection fixtures are distinct from
partial-schema corruption tests and should return an unsupported-version
diagnostic.

## Current defects

1. Garbage collection can return from its read fast path before persisting a
   newer sample from the same clock domain. Pressure collection has the same
   problem and can also roll back an observed sample after its locked capacity
   recheck.
2. Retirement lookup narrows work to selected objects but materializes every
   matching lease, retry, receipt, pending delivery, and acknowledgement.
3. Numbered-result retirement independently materializes and rewrites every
   result for one Event, whose fan-out can exceed a maintenance page.
4. Admission-triggered eviction and routine maintenance use unbounded candidate
   and dependency collections. Rolling back a failed admission can also discard
   partial cleanup, so retry alone does not guarantee progress.
5. Reverse-reference audits build complete expected and durable sets at the
   same time.
6. A publication wake can be stranded when discovery initially has no
   candidate, and a newly discovered candidate does not force an attempt.
7. Events inserted during a contact do not arm onward propagation; a later lane
   failure, timeout, panic, or collision can also discard a completion-only
   signal.
8. The global wake boolean cannot distinguish forced draining from a normal
   tick and can repeatedly redial a completed peer while another remains busy.
9. Live policy changes do not notify the actor, and policy comparison outside
   the update operation would be racy.
10. The reciprocal wake tests release reserved UDP ports before node start.

## Durable continuity

Garbage collection and pressure collection use the same decision rule:

- no sample: no continuity mutation;
- no durable continuity plus a sample: persist the first generation;
- same clock: persist only when the observed tick exceeds the durable tick;
- different clock: run the existing discontinuity path, advance generation,
  and perform retry/custody handling; and
- equal or stale same-clock samples may use a read-only fast path.

A writer that calls `observe_continuity_write` commits that observation even if
a locked capacity recheck says no pressure work remains. Later delayed reads
normalize against the durable maximum tick and cannot regress age.

## Bounded, resumable retirement

### Numeric work bounds

The caller-supplied object page remains bounded by `MAX_CUSTODY_PAGE = 1_024`.
Retirement scanning is separately bounded by
`MAX_CUSTODY_RETIREMENT_SCAN = MAX_CUSTODY_PAGE +
MAX_CUSTODY_TRANSFER_LEASES = 5_120`, so lease-blocked early rows cannot starve
the page while the bound remains explicit.

Every maintenance transaction shares
`MAX_CUSTODY_MAINTENANCE_DEPENDENCIES_PER_PASS = MAX_CUSTODY_PAGE = 1_024`.
One dependency unit is either one examined numbered-result reverse row or one
validated removable source/reverse pair plus its counter/state mutation.
Examining a numbered result advances the durable cursor; when it is raw
available, the same unit also rewrites it to retired and advances its client's
recovery revision. A unit starts only when at least one unit remains and a
source/reverse removal is atomic; no half-pair consumes the last unit. Lease
prefix-existence probes, candidate scans, source point-reads used by audit, and
fixed per-object fence/accounting work are reported separately and do not
consume the dependency budget.

For every pass:

`removed_pairs + examined_numbered_results <= examined_dependencies <= 1_024`,

and `rewritten_numbered_results <= examined_numbered_results`.

Reports expose examined candidates, lease probes, examined dependencies,
removed pairs, and rewritten numbered results. Tests assert both the inequality
and aggregate progress across passes.

### Durable lifecycle and cleanup queue

The versioned `CUSTODY_RETIRING` value is both the retirement index and durable
cleanup queue. It retains the original item revision, priority, semantic
identity, retirement reason, and numbered-result cursor. Existing empty values
decode as legacy `Marked` records reconstructed from the retained item.

The states are:

1. **Live:** item and payload exist; no fence or cleanup record.
2. **Marked:** the item is `retiring`; payload remains; cleanup record exists;
   leases and other dependencies may remain.
3. **FencedCleaning:** payload, custody item, and live accounting are gone;
   permanent fence and cleanup record exist; no leases remain, but other
   dependencies may remain.
4. **Retired:** permanent fence exists; the cleanup record and custody cleanup
   dependencies are absent. Canonical retired numbered results and their
   reverse index rows may remain until their clients acknowledge them.

Sender authority is false in states 2–4. Transition 1→2 is constant work: mark
the item, create cleanup state, clear sender eligibility, and stop new
dependencies without walking fan-out. When no lease exists, transition 2→3 may
happen immediately—even inside the same transaction as an incoming admission—
regardless of remaining fan-out. It inserts the fence and releases payload and
accounting, while the cleanup record anchors surviving dependencies. The
incoming admission and victim fence/release commit or roll back together.

Later passes remove retry, receipt, pending-delivery, acknowledgement, and
legacy-operation source/reference pairs under the shared budget. Removed prefix
keys are the durable cursor for those tables. Numbered results use the explicit
cursor described below. Once all removable dependencies are gone and the
numbered cursor has examined the complete prefix, the cleanup record is removed
and state 3→4 completes.

Every legacy Event-operation resolution path consults marked/fenced custody
authority before loading payload. An active alias targeting `Marked` or
`FencedCleaning` resolves logically as `Retired(reason)` after validating its
intent and Event identity. Cleanup converts that alias to the existing canonical
retired record and removes its active reverse edge as one dependency unit. A new
exact alias against marked/fenced authority is inserted canonical-retired and
creates no active cleanup edge. Thus exact replay is deterministic before and
after payload removal, including across reopen.

### Dependency interleavings

Every dependency-creation path checks retirement authority in its writer
transaction:

- new leases, retries, receipts, pending deliveries, and acknowledgements are
  accepted only for `Live` authority;
- a lease acquired before marking may complete afterward; it only removes its
  existing lease and the last lease enables fencing;
- retry settlement against `FencedCleaning` may remove the retry but cannot
  create a receipt;
- subscription polling skips marked/fenced pending rows within its scan bound;
  a poll commit racing retirement returns `EventSubscriptionPlanChanged`;
- a late acknowledgement cannot convert or recreate pending state; an already
  durable acknowledgement remains idempotent, otherwise the API returns
  `EventDeliveryNotFound`; and
- outbound selection never exposes marked, fenced, or retired payload.

Surviving rows always retain their exact reverse row. Audits accept a custody
cleanup dependency targeting `Marked` or `FencedCleaning` only when the cleanup
record and original revision/priority/semantic identity agree. A clean fence may
have no custody cleanup dependency; canonical retired numbered results and their
reverse rows are durable publication-result state rather than cleanup backlog.
Pending/ack validation resolves identity through retained Event metadata and
acceptance markers rather than removed `EVENT_BYTES`.

### Numbered publication results

Custody authority overlays the stored numbered-result content:

- raw `Available` plus a live item is `Available`;
- raw `Available` plus a marked item or matching fence is logically
  `Retired(reason)` immediately;
- raw `Retired` must agree with the marked/fenced reason; and
- no live item, cleanup state, or fence is an invariant failure.

Cleanup walks `RESULT_BY_EVENT` from the durable cursor. Every examined row
consumes one unit and advances the cursor, whether it is already canonical or
requires work. When raw available, that unit rewrites the result and advances
the affected client's recovery revision. The reverse edge remains until the
client acknowledges and removes the result. A retired exact replay inserted
behind the cursor is already canonical and does not require cursor restart.

Every numbered-result read path applies the overlay: session snapshot creation,
existing operation replay, recovery completion, and prospective admission
snapshots. `begin_event_publication_session` normalizes that client's existing
results before returning. `complete_event_publication_recovery` performs the
same bounded-by-existing-client-cap normalization; if retirement happened after
the prior snapshot, it advances the revision and returns
`RecoveryRevisionChanged`. This uses the existing 4,096-results-per-client and
response-size bounds, not a new per-Event or protocol limit.

### Selection memory

Pressure and admission selection scan retained custody rows but keep only the
best `MAX_CUSTODY_PAGE` candidates in a bounded heap. Pending-delivery
eligibility uses reverse-prefix existence rather than a complete semantic set.
The scan remains O(total retained custody items) under actual quota pressure;
scratch memory is O(page). Routine expiry/retirement uses the maintained indexes
and the explicit 5,120-row scan bound. Documentation must not claim that all
pressure-selection work is difference-proportional.

## Streaming reverse-reference audit

Reference equality is proved without full in-memory sets:

1. Stream each source table, derive its unique reverse key, and point-check an
   empty reverse row.
2. Stream the reverse table, parse each kind, point-read/decode its source, and
   verify that it derives the exact reverse key and target.
3. Count rows and enforce the existing global cardinality cap.

This detects missing, orphaned, malformed, wrong-kind, wrong-target, and
invalid-retirement-state references with constant scratch memory. Other startup
audits may remain O(total retained state); startup is not page-bounded.

## Event wake state machine

Replace the global forced-contact boolean with actor-owned bounded state:

- a set of pending Event peers, bounded by `MAX_CONFIGURED_PEERS = 256`;
- one peerless-Event marker that survives until an automatic candidate is
  actually launched, an explicit `Option<EndpointId>` forced-discovery slot,
  and an actor-lifetime set of at most `MAX_CONFIGURED_PEERS = 256` discovery
  identities that already armed an edge;
- a coalesced normal-contact cause bit; and
- the existing application-tick edge.

Transitions and invariants:

- A first-inserted local Event or RouteEvent adds all current peers.
- A first-inserted Event from reconciliation adds current peers except the
  carrying peer.
- A first-inserted Event with no current peer sets the peerless marker. A newly
  seen automatic candidate schedules one normal edge. When the marker is set
  and the forced-discovery slot is empty, the actor deterministically selects
  one current candidate for the slot and forces only that identity. The marker
  and slot clear together only when that contact actually launches. If the
  selected identity expires before launch, the slot clears, the marker remains,
  and the actor immediately selects and schedules exactly one other current
  candidate when available. The actor-lifetime set survives normal
  discovery-window expiry, so an unchanged
  continuously advertised `EndpointId` does not create one contact per window.
  Later events for a recorded identity are scheduling-silent when there is no
  peerless marker; the carrier registry may still refresh its private locator
  state. Once 256 identities have armed discovery-only edges, additional unseen
  identities may be retained by the bounded carrier registry but cannot arm a
  normal actor edge until process restart. The actor increments a saturation
  diagnostic and never evicts a seen identity, preventing identity cycling from
  recreating a discovery-only contact storm. The peerless marker overrides both
  seen-set deduplication and saturation for the identity in that one slot: it
  may arm a same-identity rediscovery after pre-launch expiry or an unseen
  saturated candidate.
- A forced-only edge launches only pending peers. A periodic or ordinary
  discovery edge sets the normal cause and may also consider nonpending peers.
- Forced membership is removed only when a contact launches. Busy or
  contact-cap-skipped peers remain pending. Any terminal contact path schedules
  another forced-only drain when pending peers remain.
- Ordinary failure does not reinsert the launched peer; periodic cadence and
  later durable work are retry edges. If the contact terminates specifically
  with `EmissionPolicyChanged`, its launched forced peer is restored under the
  latest snapshot because the guard, not the peer, invalidated the attempt.
  ReceiveOnly retains that restored work without initiating. Pending state
  alone never spins.
- ReceiveOnly retains pending configured-peer work but never initiates.
- Forced targets bypass the non-preferred identity delay once. Contact caps,
  round-robin order, collision handling, budgets, and authentication remain
  authoritative.
- Automatic candidates are dialable only while discovery is window-valid,
  policy is `Normal`, and `NearbyDiscoveryControl` has not permanently stopped.
  A stop transition clears automatic candidates, seen-candidate state, and
  their pending entries; later `Normal` does not revive them.

Policy update atomically returns whether its durable revision changed and sends
a capacity-one/watch-style actor notification. The actor rereads the latest
snapshot and yields after processing, so revisions coalesce without starving
other work. A policy wake occurs only when allowed Event priorities form a
strict superset:

- `ReceiveOnly` → any initiating policy;
- `AtLeast(old)` → `AtLeast(new)` only when `new` is a lower priority threshold;
- `AtLeast(old)` → `Normal` only when `Normal` admits priorities excluded by
  `old`; and
- `Normal`, `AtLeast(Routine)`, equal policies, and tightening transitions do
  not wake when their allowed Event set is unchanged or narrower.

Policy-relaxation tests use configured peers because nearby discovery does not
restart after a permanent stop.

## Event-specific insertion signal

`PeerReceipt::inserted` aggregates all data classes. Each contact task therefore
owns an `Arc<AtomicBool>`-equivalent Event insertion tracker retained in actor
task metadata. Event and RouteEvent receive lanes set it immediately after a
durable first insertion. Mutable-only and duplicate outcomes do not set it.

The actor reads the tracker on every terminal path: success, ordinary error,
finish failure, timeout, panic/join error, and collision cancellation. The wake
therefore survives failures after durable insertion. No wire or public receipt
field changes.

Local selected API, numbered publication, and sample-application publication
feed the same actor wake transition. Idempotent publication does not rearm it.

## Race-free test topology

Tests start the passive node on `127.0.0.1:0`, retain its endpoint sockets, and
use the actual address from test-only `bound_sockets`. They never reserve,
release, and rebind a port.

Two A→B→C layouts exercise both insertion directions:

- inbound at B: `A < B < C`; start C, then B, quiesce B→C, start and quiesce
  A→B, then publish on A;
- outbound at B: `C < B < A`; preseed A while peerless, start passive A and
  ReceiveOnly C, then start B; B initiates to A and its forced wake reaches C.

A has no route to C, periodic intervals are 60 seconds, and C observes the
Event within five seconds. Preservation/topology tests need not be red on the
old code; defect regressions must demonstrate red then green.

## Test-first implementation

Focused regressions cover:

1. advancing no-op GC and both pressure fast paths persist continuity; stale or
   equal samples stay read-only and clock changes preserve existing behavior;
2. one Event with dependency and numbered-result fan-out above 1,024 fences and
   frees capacity immediately, public reads report retired, and cleanup resumes
   across passes and reopen without exceeding the aggregate budget;
3. recovery begun before retirement fails completion with
   `RecoveryRevisionChanged`, then returns a higher all-retired snapshot;
4. mark/reopen with retry, receipt, pending, ack, legacy operation, and numbered
   rows: audits pass, outbound/poll expose none, exact legacy replay reports the
   same retirement in both `Marked` and `FencedCleaning`, and no new dependency
   appears;
5. deterministic interleavings cover late lease completion, retry settlement,
   pending poll commit, acknowledgement, and receipt creation;
6. high-priority admission atomically commits its Event, the victim fence,
   released accounting, and cleanup record despite fan-out above the budget;
   a fault after fencing restores the complete before-image;
7. an active lease blocks capacity release, then lease completion permits the
   later atomic admission;
8. candidate memory never exceeds 1,024, retirement scan never exceeds 5,120,
   and every cleanup pass satisfies both dependency inequalities, including a
   prefix of already-canonical numbered results;
9. writable/read-only audits reject missing/orphaned/malformed/wrong-target
   rows, clean-fence dependencies, missing cleanup records, and mismatched
   revision, priority, or retirement reason;
10. genuine schema-v1/v2 fixtures reject distinctly, partial v3 corruption
    remains a separate invariant test, and legacy empty retiring values reopen;
11. peerless work plus discovery forces one attempt in both identity orders;
    duplicate and unchanged cross-window rediscovery without peerless work do
    not storm; expiry before launch followed by same-identity rediscovery still
    launches peerless work; sequential candidates, a peerless candidate after
    exact 256-identity saturation, and permanent-stop cases behave as specified;
    when candidate A owns the forced slot, B arrives, and A expires before
    launch, exactly B becomes forced;
12. inbound and outbound insertion paths propagate A→B→C before the periodic
    tick; accepted Event and RouteEvent set the tracker, mutable-only does not;
13. post-insert error and collision cancellation retain the wake;
14. more than the outbound contact cap drains in round-robin order once each;
    busy peers do not redial completed peers, and pre-launch bursts coalesce;
15. ReceiveOnly retains work; exact relaxations resume it; same-policy and
    rapid-coalesced revisions do not create extra attempts; tightening does not
    wake idle peers, while an in-flight forced attempt aborted by a tightening
    is restored and retried under the new snapshot; and
16. lower/higher local publishers use continuously owned ports and contacts
    quiesce after convergence.

After focused tests, run `mise run check`. Parser, envelope, fragmentation, and
hostile-input framing are unchanged, so `mise run fuzz-smoke` is not required.
Before expensive validation, record free disk, available memory, and competing
processes to avoid repeating host-resource failures.

## Resource measurement and evidence boundary

Use the existing 10,000-item metadata workload and the existing maximum-
constructed per-object dependency-fan-out fixture. Record peak/steady RSS,
allocator high-water if available, wall time, CPU time, redb bytes/I/O or
transaction counts, and cleanup passes when the fixtures expose them. Also
measure advancing no-op maintenance write/commit cadence because preserving
high-water intentionally adds durable writes. A stopped run at the declared
20-minute boundary is an acceptable bounded engineering result for this
increment when its unavailable metrics and incomplete scope are recorded
without inference; it is not a resource qualification result.

The comparison is against the Tier-2 provisional 64 MiB steady-state / 32 MiB
preferred targets from `data-mesh-requirements.md`; it is engineering data, not
target qualification. If the whole process does not meet those brackets, the PR
reports the measured value and retains DM-9/DM-14 resource status as open. No
unmeasured limit is promoted into protocol or evidence claims.

## Documentation and evidence

The changelog and PR body should say:

- indexed expiry/retirement selection and a 1,024-unit durable cleanup queue
  bound routine maintenance work;
- fencing frees selected payload capacity atomically while dependency cleanup
  resumes across later passes;
- pressure victim selection still scans total retained custody rows but retains
  only a 1,024-candidate heap;
- new local or selected-reconciliation Events schedule coalesced prompt
  attempts; discovery refreshes normal scheduling and forces a candidate only
  for still-undispatched peerless Event work; and
- duplicate-only or mutable-only contacts do not rearm an Event attempt.

State explicitly that custody schema v1/v2 stores must be recreated with no
migration, startup audit remains O(total retained state), failed prompt contacts
fall back to periodic retry, bridge prompt propagation is excluded, and the PR
provides current-code/engineering evidence rather than target qualification.

No roadmap, requirements-status, or atomic trace-row changes are planned. If
implementation reveals a genuine evidence-boundary change, update only exact
affected requirement IDs and run
`python3 tools/check-implementation-requirements.py`.

## Acceptance gate

The increment is ready for handoff only when:

- every defect regression demonstrates red then green; preservation and harness
  safety tests pass;
- focused store and runtime suites pass;
- `mise run check` completes successfully;
- numeric candidate, scan, and dependency bounds are asserted;
- the existing 10,000-item attempt, maximum-constructed-fan-out measurements,
  and no-op write cadence are recorded with unavailable metrics and the
  non-qualification caveat stated explicitly;
- changed wake tests contain no bind/drop/rebind sequence;
- an independent final reviewer finds no unresolved Critical or Important
  issue; and
- PR text retains every scope, evidence, complexity, and compatibility limit.
