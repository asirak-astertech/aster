# PR 25 Bounded Event Maintenance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct PR 25 so Event custody maintenance has explicit durable work bounds and first-inserted Events schedule prompt, race-safe store-and-forward contacts.

**Status:** Complete locally on 2026-10-06; final independent-review findings
reconciled. Remote PR updates remain a controller-owned handoff action.

**Architecture:** Keep custody schema v3, replace fan-out materialization with a versioned retirement cleanup record and a shared 1,024-unit streaming budget, and make permanent retirement authority overlay legacy and numbered publication results. Replace the actor's global wake boolean with per-peer/cause state, policy notifications, and a contact-task-local Event insertion tracker that survives every terminal path.

**Tech Stack:** Rust 1.97.1, Tokio, redb, Iroh, cargo nextest, mise

**Spec:** `docs/superpowers/specs/2026-10-06-pr25-bounded-event-maintenance-design.md`

## Global Constraints

- Follow `CONTRIBUTING_CLEANROOM.md`; use only clean-team repository and live-approved Drive inputs.
- Preserve custody schema version 3; empty `CUSTODY_RETIRING` values decode as legacy marked records; custody schemas v1/v2 are unsupported and never migrated.
- `MAX_CUSTODY_PAGE = 1_024`, `MAX_CUSTODY_RETIREMENT_SCAN = 5_120`, and `MAX_CUSTODY_MAINTENANCE_DEPENDENCIES_PER_PASS = 1_024` are internal implementation controls, not protocol limits.
- Every pass proves `removed_pairs + examined_numbered_results <= examined_dependencies <= 1_024` and `rewritten_numbered_results <= examined_numbered_results`.
- No semantic wire, public receipt, protocol-version, roadmap-maturity, or requirements-status change.
- State, Record, Blob, control, and bridge prompt propagation remain out of scope.
- Use strict TDD: name the production break, run each defect regression red, then implement the minimum green change.
- Before full checks or resource runs, record disk, available RAM, and competing processes; run `mise run check` only after focused suites are green.

## Review Focus

- A contact that durably inserts an Event and then errors, times out, panics, or is collision-aborted must still arm onward propagation; Task 6 exercises every terminal family.
- A retirement mark racing a lease, retry settlement, delivery poll, or acknowledgement must never recreate authority or expose retired payload; Tasks 2 and 3 exercise these interleavings.
- Already-retired numbered rows must consume cursor budget without losing their reverse edge; Task 3 exercises a canonical prefix longer than one pass.
- Repeated discovery windows and identity churn must not create an unbounded contact loop or strand peerless Event work; Task 5 exercises same-ID rediscovery, saturation, and forced-slot replacement.
- A policy update that aborts an in-flight forced contact must restore only that launched peer, while idle tightening/no-op changes must not wake peers; Task 5 exercises both sides.

---

### Task 1: Durable Continuity Fast Paths

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs:6459-6768`
- Test: `crates/aster-redb-store/src/lib.rs:38227-38830`

**Interfaces:**
- Produces: `continuity_sample_requires_write_read(read: &redb::ReadTransaction, sample: Option<CustodySample>) -> Result<bool, StoreError>` used by both maintenance entry points.
- Preserves: existing discontinuity and `observe_continuity_write` semantics.

- [ ] **Step 1: Add failing continuity regressions**

  Add `custody_gc_advancing_noop_persists_continuity`, `custody_pressure_advancing_noop_persists_continuity`, and `custody_pressure_locked_fit_commits_observed_continuity`. Assert the durable tick advances for a newer same-clock sample even with no selected work; keep the existing equal/stale no-writer characterization and clock-change tests.

- [ ] **Step 2: Verify the regressions fail for the intended early returns**

  Run: `cargo test --locked -p aster-redb-store custody_ -- --nocapture`

  Expected: the three new tests fail because the stored tick stays at the earlier value; unrelated custody tests pass.

- [ ] **Step 3: Implement the shared fast-path decision**

  Add the exact helper above. Enter a writer only for a first sample, advancing same-clock sample, or clock change. After `observe_continuity_write`, commit before returning from the locked capacity-fit recheck.

- [ ] **Step 4: Verify focused store behavior**

  Run: `cargo test --locked -p aster-redb-store custody_ -- --nocapture`

  Expected: all custody tests pass, including the existing no-write equal/stale test.

- [ ] **Step 5: Commit**

  `git commit -am "fix: persist custody continuity on no-op maintenance"`

### Task 2: Fenced Retirement and Streaming Dependency Cleanup

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs:64-100,1329-1485,2983-4299,6459-6910,7160-8380`
- Modify: `crates/aster-redb-store/src/lib.rs:6500-6900`
- Test: `crates/aster-redb-store/src/lib.rs:37995-38720`

**Interfaces:**
- Produces: `RetirementCleanupRecord { original_revision: u64, priority: Priority, semantic_id: [u8; 32], reason: CustodyRetirementReason, numbered_cursor: Option<Vec<u8>> }` with versioned encode/decode and legacy-empty decoding.
- Produces: `MaintenanceBudget` with `try_consume_dependency()`, `examined_dependencies`, `removed_pairs`, `examined_numbered_results`, and `rewritten_numbered_results`.
- Produces: `cleanup_retirement_dependencies_write(write, key, cleanup, budget) -> Result<RetirementCleanupProgress, StoreError>`.
- Changes: `CustodyGcReport` exposes candidate/lease/dependency counters from the spec.
- Consumes: Task 1 continuity helper.

- [ ] **Step 1: Add failing lifecycle and budget tests**

  Add tests proving: a victim with more than 1,024 real retry/receipt/pending/ack dependencies fences and releases accounting without materializing all rows; each pass satisfies both numeric inequalities; progress resumes after reopen; an active lease blocks fencing; release permits a later atomic admission; and a fault after victim fencing rolls back both victim and incoming admission.

- [ ] **Step 2: Add failing dependency-race tests**

  Add deterministic tests for lease completion after mark, retry settlement after fence, poll plan racing mark (`EventSubscriptionPlanChanged`), late acknowledgement (`AlreadyAcknowledged` or `EventDeliveryNotFound` only), and receipt creation refusal. Each test asserts no dependency/reverse pair is recreated.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-redb-store retirement -- --nocapture`

  Expected: new tests fail through unbounded `RetirementBatchIndex` cleanup, missing cleanup state, or invalid post-fence row handling.

- [ ] **Step 4: Implement the versioned cleanup queue and state transitions**

  Replace fan-out vectors with prefix existence/removal helpers. Make Live→Marked constant-work; make lease-free Marked→FencedCleaning insert the permanent fence, remove payload/item/accounting, and retain cleanup state. Remove the cleanup row only after all removable prefixes are empty and the numbered cursor is complete.

- [ ] **Step 5: Guard all dependency writers and readers**

  Require Live authority for new leases/retries/receipts/pending/acks. Make sender inventory skip Marked/FencedCleaning; polling skip stale pending rows within its scan bound; retry settlement remove-only after fencing; and audits accept surviving dependencies only with a matching cleanup record.

- [ ] **Step 6: Bound retirement scanning and admission selection**

  Add `MAX_CUSTODY_RETIREMENT_SCAN = 5_120`. Replace full candidate and pending-semantic collections in GC, pressure, `make_admission_capacity_write`, and `make_aggregate_capacity_write` with maintained-prefix checks and a best-1,024 bounded heap. Keep pressure scan CPU O(total items) and scratch memory O(page).

- [ ] **Step 7: Verify store lifecycle and accounting**

  Run: `cargo test --locked -p aster-redb-store retirement -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_ -- --nocapture`

  Expected: all focused tests pass and report counters satisfy the exact inequalities.

- [ ] **Step 8: Commit**

  `git add crates/aster-redb-store/src/custody.rs crates/aster-redb-store/src/lib.rs && git commit -m "fix: bound resumable custody retirement"`

### Task 3: Legacy and Numbered Publication Retirement Overlays

**Files:**
- Modify: `crates/aster-redb-store/src/event_operation.rs:650-840`
- Modify: `crates/aster-redb-store/src/numbered_event_operation.rs:250-635,840-980,1140-1240`
- Modify: `crates/aster-redb-store/src/custody.rs:4178-4300`
- Modify: `crates/aster-redb-store/src/lib.rs:9994-10580`
- Test: `crates/aster-redb-store/src/tests/event_operation_retirement.rs`
- Test: inline tests in `crates/aster-redb-store/src/numbered_event_operation.rs`

**Interfaces:**
- Consumes: Task 2 `RetirementCleanupRecord`, `MaintenanceBudget`, and marked/fenced authority lookup.
- Produces: `canonical_numbered_result_write(write, result) -> Result<(NumberedEventResult, bool), StoreError>` where the boolean reports a raw-content rewrite.
- Produces: budgeted legacy alias conversion and numbered cursor advancement; numbered reverse edges remain until client acknowledgement.

- [ ] **Step 1: Add failing legacy replay tests**

  Extend `event_operation_retirement.rs` so exact replay in both Marked and FencedCleaning returns the same `Retired(reason)` before payload access, survives reopen, and creates no new active reverse edge.

- [ ] **Step 2: Add failing numbered recovery/cursor tests**

  Add tests for: more than 1,024 results for one Event; immediate logical retirement; recovery begun before retirement returning `RecoveryRevisionChanged`; next snapshot having a higher revision and all-retired content; an already-canonical prefix longer than one pass consuming examined budget; reverse edges surviving rewrite until acknowledgement; and retired exact replay behind the cursor needing no restart.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-redb-store event_operation_retirement -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store numbered_event_operation -- --nocapture`

  Expected: replay attempts load removed payload or retirement scans/revises the full Event result fan-out.

- [ ] **Step 4: Implement custody-authoritative legacy resolution**

  Resolve Marked/FencedCleaning aliases as retired before payload lookup. Convert active aliases and remove their active reverse edges under one budget unit; insert new marked/fenced exact aliases directly as canonical retired records.

- [ ] **Step 5: Implement numbered logical overlay and cursor cleanup**

  Apply the authority overlay in session snapshot, existing-operation replay, recovery completion, and prospective snapshots. Charge every examined reverse row; rewrite raw available content and advance the affected client revision when needed; never remove the numbered reverse edge during retirement cleanup.

- [ ] **Step 6: Verify operation and full store tests**

  Run: `cargo test --locked -p aster-redb-store event_operation -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store`

  Expected: all tests pass; recovery and acknowledgement semantics remain intact.

- [ ] **Step 7: Commit**

  `git add crates/aster-redb-store/src && git commit -m "fix: preserve publication recovery through retirement"`

### Task 4: Streaming Audits and Compatibility Diagnostics

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs:6914-8380`
- Modify: `crates/aster-redb-store/src/lib.rs:5600-5800,28250-28350,38340-38720`
- Test: `crates/aster-redb-store/src/tests/event_operation_audit.rs`

**Interfaces:**
- Consumes: Task 2 cleanup-record invariants and Task 3 canonical operation/result states.
- Produces: bidirectional streaming source→reverse and reverse→source audit helpers with O(1) scratch state.
- Produces: a typed unsupported custody-schema version error distinct from partial-v3 corruption.

- [ ] **Step 1: Add failing audit and compatibility fixtures**

  Add genuine schema-v1 and schema-v2 database fixtures, legacy empty-retiring reopening, and corrupt cases for missing/orphaned/malformed/wrong-kind/wrong-target references, clean-fence custody dependencies, missing cleanup records, and mismatched original revision/priority/reason.

- [ ] **Step 2: Verify red behavior**

  Run: `cargo test --locked -p aster-redb-store audit -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_schema -- --nocapture`

  Expected: predecessor versions share the incomplete-schema error and audit still builds full expected/reference sets.

- [ ] **Step 3: Implement streaming audit and version diagnostics**

  Point-check each source-derived reverse key, then stream reverse rows and point-check/decode their source. Retain global cardinality checks. Accept only spec-authorized Marked/FencedCleaning and canonical retired result states.

- [ ] **Step 4: Verify inspection/reopen behavior**

  Run: `cargo test --locked -p aster-redb-store audit -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store custody_schema -- --nocapture`

  Run: `cargo test --locked -p aster-redb-store`

  Expected: all focused and crate tests pass with distinct unsupported-version diagnostics.

- [ ] **Step 5: Commit**

  `git add crates/aster-redb-store/src && git commit -m "fix: stream custody reference audits"`

### Task 5: Per-Peer Event Wake, Discovery, and Policy State

**Files:**
- Modify: `crates/aster-node/src/runtime.rs:1900-2118,2440-2610,11565-11635,12235-13185`
- Test: inline tests in `crates/aster-node/src/runtime.rs:22770-25220,39440-40000`

**Interfaces:**
- Produces: `EventContactWakeState` containing pending peers, a normal-cause bit, peerless marker, `Option<EndpointId>` forced-discovery slot, and a non-evicting 256-entry seen set.
- Produces: `PolicyUpdate { snapshot: EmissionPolicySnapshot, changed: bool }` from `LiveEmissionPolicy::update` plus a coalesced watch notification subscribed by the actor.
- Produces: `event_policy_strictly_relaxes(previous, current) -> bool` using the exact policy partial order in the spec.
- Consumes later: Task 6 terminal-path insertion and forced-peer metadata.

- [ ] **Step 1: Add failing pure state-machine tests**

  Test forced-only vs normal causes, busy/contact-cap preservation, launch removal, pre-launch burst coalescing, round-robin drain beyond 16 peers, policy-change restoration, and no self-arming loop.

- [ ] **Step 2: Add failing discovery/policy tests**

  Test no-work same-ID rediscovery across windows is silent; peerless same-ID rediscovery after pre-launch expiry forces once; the 257th identity cannot arm a normal edge but can occupy the peerless override slot; A selected/B arrives/A expires selects exactly B; stop clears automatic state; Normal after permanent stop does not revive it. Test exact relaxations, same-policy/tightening silence, rapid revision coalescing, ReceiveOnly retention, and in-flight tightening restoration.

- [ ] **Step 3: Verify red behavior**

  Run: `cargo test --locked -p aster-node --features nearby-discovery event_contact_wake -- --nocapture`

  Run: `cargo test --locked -p aster-node --features nearby-discovery nearby -- --nocapture`

  Expected: tests fail because one global boolean loses peer/cause information and policy updates have no actor notification.

- [ ] **Step 4: Implement wake and policy state**

  Replace `event_contact_wake_pending` with `EventContactWakeState`. Add one coalesced policy-watch select arm, reread the latest snapshot, yield after processing, and restore a launched forced peer only for `EmissionPolicyChanged`. Forced-only edges consider only pending peers; periodic/normal edges may consider all eligible peers.

- [ ] **Step 5: Implement discovery deduplication and forced slot**

  Record at most 256 identities that armed normal discovery edges without eviction. Keep locator refresh internal and scheduling-silent for seen identities. Let peerless work select exactly one override identity, reselect deterministically on pre-launch expiry, and clear marker/slot only on launch.

- [ ] **Step 6: Verify focused actor tests**

  Run: `cargo test --locked -p aster-node --features nearby-discovery event_contact_wake -- --nocapture`

  Run: `cargo test --locked -p aster-node --features nearby-discovery nearby -- --nocapture`

  Expected: all focused state, discovery, and policy tests pass.

- [ ] **Step 7: Commit**

  `git add crates/aster-node/src/runtime.rs && git commit -m "fix: schedule event contacts per peer and cause"`

### Task 6: Event-Specific Contact Insertion Tracking and Real Topologies

**Files:**
- Modify: `crates/aster-node/src/runtime.rs:1951-1981,12253-13170,13440-15005,18580-20770,30416-30683`
- Test: inline tests in `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Consumes: Task 5 `EventContactWakeState` and task launch metadata.
- Produces: contact-task-local `Arc<AtomicBool>` insertion tracker, retained by actor task metadata and set immediately after first durable Event/RouteEvent admission.
- Preserves: public `PeerReceipt` unchanged; mutable-only `inserted` never sets the private tracker.

- [ ] **Step 1: Add failing tracker/terminal-path tests**

  Test accepted Event and RouteEvent set the tracker, mutable-only and duplicate contacts do not, and post-insert ordinary error, finish error, timeout, panic/join error, and collision cancellation all leave the actor with an Event wake.

- [ ] **Step 2: Add failing A→B→C tests and repair the socket harness**

  Replace bind/drop/rebind with nodes started on `127.0.0.1:0` and retained `bound_sockets`. Add the exact `A < B < C` inbound-at-B and `C < B < A` outbound-at-B layouts from the spec; use 60-second periodic intervals and require C to observe the Event within five seconds. Assert duplicate convergence quiesces.

- [ ] **Step 3: Verify defect tests fail for the insertion-signal gap**

  Run: `cargo test --locked -p aster-node event_insertion -- --nocapture`

  Run: `cargo test --locked -p aster-node newly_published_event -- --nocapture`

  Expected: post-insert failure and three-node propagation fail; existing two-node preservation tests may already pass.

- [ ] **Step 4: Implement task-local tracking on every Event receive lane**

  Scope inbound/outbound contact futures with the tracker. Set it only after durable first insertion from accepted Event or RouteEvent paths. Store tracker and launched-forced status in both task maps and consume them through one common terminal handler for success, error, timeout, join failure, and collision abort.

- [ ] **Step 5: Verify runtime tests**

  Run: `cargo test --locked -p aster-node event_insertion -- --nocapture`

  Run: `cargo test --locked -p aster-node newly_published_event -- --nocapture`

  Run: `cargo test --locked -p aster-node --features nearby-discovery`

  Expected: focused and full node-crate tests pass without a released-port reservation.

- [ ] **Step 6: Commit**

  `git add crates/aster-node/src/runtime.rs && git commit -m "fix: propagate reconciled events after contact failures"`

### Task 7: Resource Measurement, Documentation, and Full Verification

**Status:** Complete. The stopped 20-minute 10,000-item run is accepted as the
bounded engineering result for this increment: it did not produce final
resource metrics and therefore supports no Tier-2 qualification or protocol
limit claim.

**Files:**
- Modify: `CHANGELOG.md`
- Create: `docs/superpowers/reports/2026-10-06-pr25-maintenance-measurements.md`
- Modify only if exact evidence boundary changes: `docs/validation/capability-roadmap.md`, `docs/validation/requirements-status.md`, or exact trace rows

**Interfaces:**
- Consumes: Tasks 1–6 complete implementation and counters.
- Produces: engineering-only 10,000-item/max-fan-out measurement record and accurate PR/release wording.

- [x] **Step 1: Check host resources before expensive work**

  Run: `df -h . /tmp`, `free -h`, and `ps -eo pid,comm,%cpu,%mem --sort=-%cpu | head -n 20`.

  Expected: record free disk/RAM and competing load; defer expensive work if the host is again near exhaustion.

- [x] **Step 2: Run and record the bounded maintenance measurement**

  Use the existing focused high-fan-out fixture and existing 10,000-item scale
  fixture. Record every exposed metric and state unavailable metrics without
  inference. The 10,000-item debug run reached the 20-minute boundary and was
  stopped without final metrics; that bounded timeout is the accepted result
  and limitation for this increment. Compare focused observations with the
  provisional Tier-2 64 MiB/32 MiB brackets without claiming qualification.

- [x] **Step 3: Update documentation**

  Narrow the changelog claim to indexed routine expiry/retirement, 1,024-unit durable cleanup, O(total) pressure scanning with O(page) scratch memory, prompt selected-Event propagation, schema v1/v2 recreation, and current-code/engineering evidence only.

- [x] **Step 4: Run traceability checks if evidence files changed**

  Run: `python3 tools/check-implementation-requirements.py`

  Expected: PASS. Do not move roadmap or requirement maturity unless an exact evidence boundary genuinely changed.

- [x] **Step 5: Run formatting and focused verification**

  Run: `cargo fmt --all -- --check`

  Run: `cargo test --locked -p aster-redb-store`

  Run: `cargo test --locked -p aster-node --features nearby-discovery`

  Expected: PASS.

- [x] **Step 6: Run the repository gate**

  Recheck resources, then run: `mise run check`

  Expected: PASS. Do not run `mise run fuzz-smoke`; parser/framing/envelope hostile-input boundaries are unchanged.

- [x] **Step 7: Commit**

  `git add CHANGELOG.md docs/superpowers/reports docs/validation && git commit -m "docs: record bounded event maintenance evidence"`

- [x] **Step 8: Independent whole-branch review and local reconciliation**

  An independent reviewer checked the full branch against the spec, original
  Aster requirements, evidence limits, and reported PR findings. The local
  findings are reconciled in this plan and the measurement report. Updating
  remote PR 25 remains a controller-owned handoff action; do not merge or
  squash unless separately requested.
