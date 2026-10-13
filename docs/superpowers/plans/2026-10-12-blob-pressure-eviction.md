# Blob Pressure Eviction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the exact Blob storage partition rejected by admission by atomically evicting only strictly lower-priority work, then retry admission once without changing Blob wire, CLI, supported public Blob API, or TTL behavior.

**Architecture:** Extend the durable Blob lifecycle schema with deterministic pressure-order metadata and transactionally maintained candidate indexes. Selection is partition-specific and bounded: routine cleanup runs first, the highest-ranked eligible candidate is fully preflighted as one atomic work unit, and an oversized unit is never skipped. Store recovery returns the exact transfer identities it evicted so application/runtime caches can be reconciled while holding the existing Blob lifecycle lock before the single retry.

**Tech Stack:** Rust, redb, existing Aster Blob lifecycle/depot modules, Tokio runtime tests, cargo test.

**Spec:** `docs/superpowers/specs/2026-10-07-blob-lifecycle-design.md`

## Global Constraints

- Preserve all existing permanent invalidation, replay, lineage, and causal-frontier fences.
- Reuse `RetirementReason::Evicted`; do not add a second eviction state machine.
- Do not activate TTL or change existing durable Blob lifetime behavior in this increment.
- Do not change the Blob wire protocol, supported public Blob API, or CLI surface.
- Preserve the current single routine-cleanup/recovery attempt and single admission retry boundary.
- A pressure attempt may inspect and mutate only within explicit row, byte, root, operation, and deletion-manifest budgets.
- No float participates in completion ordering. Compare exact rational progress with widened, overflow-safe cross multiplication.
- A candidate is eligible only when its effective priority is strictly lower than the incoming work.
- All writes, migration, and audit paths fail closed on malformed, partial, orphaned, or contradictory pressure metadata.
- Focused tests run first. Broad workspace tests run serially with the repository resource wrapper after the increment is complete.
- Keep non-public inputs out of code, commits, documentation, test names, and the public pull request.

## Implementation Checks

Every task and whole-increment verification must explicitly check:

1. partition recovery is exact and cannot claim capacity that the chosen candidate does not release;
2. strict priority, exact completion, acceptance order, and identity ties are deterministic across reopen and migration;
3. full candidate retirement is atomic, bounded, lease-safe, and never skips an oversized highest-ranked candidate;
4. store eviction and in-memory cache reconciliation occur under the Blob lifecycle lock before the one retry; and
5. permanent fences survive while only reclaimable physical and live metadata capacity is recovered.

---

## Task 1: Add durable pressure identity, ordering, and migration

**Files:**

- Create: `crates/aster-redb-store/src/blob/pressure.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Test: colocated `#[cfg(test)]` modules in the files above

- [ ] Write failing codec/comparator tests for the exact canonical pressure keys and values, including minimum/maximum identities, malformed lengths/versions, and exact rational comparisons whose floating-point representations would tie or round incorrectly.
- [ ] Write failing schema tests proving read-only open rejects the predecessor schema, writable open migrates it atomically, interrupted/partial migration is rejected without repair, and a second writable open is idempotent.
- [ ] Extend pending-source durable state with a monotonic `pending_acceptance_order`. Allocate it only when a new source is first staged; retries retain the original value.
- [ ] Migrate legacy pending sources by exact transfer-identity order because historical arrival order is unavailable. Advance the counter beyond every assigned order and reject overflow before mutation.
- [ ] Define canonical pressure records for publication roots, pending roots, and whole variants. A whole variant summary carries effective priority, minimum root acceptance order, exact committed-progress numerator and authenticated denominator, finalization state, and exact root cardinalities needed to audit shared ownership.
- [ ] Add ordered pressure tables/indexes for global publications, per-content publications, pending sources, and whole variants. Per-content keys must retain or validate the complete canonical topic/scope/blob identity; a digest alone must never make an eviction decision.
- [ ] Keep exact rational comparison in one tested helper using widened cross multiplication. Zero denominators, overflow, and progress beyond the authenticated total are durable corruption.
- [ ] Add startup/read-only audits that derive every summary/index from authoritative Blob rows and reject missing, orphaned, duplicate, stale, or contradictory entries.
- [ ] Run focused store tests for codecs, comparator, schema migration, reopen, and corruption cases.
- [ ] Verify the task-level specification and code-quality criteria; fix findings before Task 2.

## Task 2: Maintain pressure metadata on every Blob state transition

**Files:**

- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/depot.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/pressure.rs`
- Test: colocated Blob store tests

- [ ] Write failing transition tests for first publication, additional shared publication, pending-source reservation, durable carrier-prefix progress, depot chunk commit, finalization, promotion, publication retirement, pending retirement, and final-root deletion.
- [ ] Update pressure roots and summaries in the same redb transaction as each authoritative transition. No transition may temporarily expose an index without its root or a root without its index.
- [ ] Compute shared-variant effective priority as the maximum surviving root priority and acceptance order as the minimum surviving root order. Promotion removes the pending root and receives the normal publication acceptance marker rather than reusing pending order.
- [ ] Track pending completion as durable carrier-prefix bytes over authenticated total carrier bytes. Track incomplete whole-variant completion as durable committed plaintext bytes over authenticated manifest total length.
- [ ] Re-key ordered indexes whenever priority, progress, acceptance order, finalization, or shared-root membership changes. Reject arithmetic overflow and impossible regressions before mutation.
- [ ] Prove reopen recomputes and audits the same summaries after every transition, including two sources sharing one physical variant and roots at different priorities.
- [ ] Add invariant tests showing a rolled-back transaction leaves authoritative rows, candidate indexes, counters, and depot accounting unchanged.
- [ ] Run focused transition and reopen tests.
- [ ] Verify the task-level specification and code-quality criteria; fix findings before Task 3.

## Task 3: Implement bounded, partition-specific pressure selection and atomic eviction

**Files:**

- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/pressure.rs`
- Modify: `crates/aster-redb-store/src/blob/depot.rs`
- Test: colocated Blob store tests

- [ ] Introduce an internal, fixed-size `BlobCapacityRecoveryDemand` carrying the rejected partition, incoming priority, and exact deficit. Partitions are aggregate items, aggregate bytes, per-content publications, network-staging rows, network-staging bytes, depot bytes, depot chunks, depot variants, operation, and publication lifecycle.
- [ ] For per-content pressure, carry a canonical fixed-size lookup identity plus authoritative full-key validation. Hash collision or key mismatch must fail closed and cannot select a candidate from another content group.
- [ ] Thread exact admission deficits into the existing typed capacity failure path. A failure must identify the first rejected partition without consuming acceptance order or mutating durable state.
- [ ] Keep operation, publication-lifecycle, causal-frontier, lease, lineage/replay-fence, and other security limits cleanup-only: pressure selection returns no candidate for them.
- [ ] Select candidates only from the rejected partition: aggregate/per-content pressure selects publications, staging pressure selects pending sources, and depot pressure selects whole variants.
- [ ] Apply the design order exactly: lower effective priority; incomplete transfers before completed content; expired finite, then live finite by nearest deadline, then durable; lower exact completion fraction; older acceptance order; then exact identity. Current durable-only data remains durable; this task must not synthesize expiry or activate TTL.
- [ ] Use ordered prefixes to reach the best eligible priority/class and bounded scans only where exact rational comparison is required. Charge every inspected row and decoded byte to the recovery budget. If the budget cannot prove the globally first candidate in the eligible bucket, make no mutation.
- [ ] Generalize the existing invalidation retirement preflight/mutation helper to accept `RetirementReason::Evicted` while preserving the invalidation behavior and tests.
- [ ] Preflight the complete candidate work unit: all roots, operation/delivery edges, indexes, lease generations, retirement rows, counters, and deletion-manifest rows. The final shared root schedules physical deletion in the same transaction; non-final publication eviction claims metadata recovery only.
- [ ] If the highest-ranked unit exceeds any remaining recovery budget, make no mutation, do not inspect a lower-ranked candidate as a substitute, and return the original capacity failure.
- [ ] Fence racing readers by lease generation and `DeletePending`; preserve permanent invalidation, replay, lineage, and causal-frontier records. Keep depot resources charged through resumable physical deletion and authorize retry only after finalization releases the rejected partition.
- [ ] Return a bounded recovery result containing exact evicted transfer IDs, recovered partition units, and whether the requested deficit was met. Audit claimed recovery against the committed accounting delta.
- [ ] Add tests for strict lower-priority eligibility, equal/higher protection, every ordering key and tie, legacy order after migration, shared higher-priority roots, metadata-only shared retirement, final-root retirement plus manifest, no-skip budget rollback, lease/root races, permanent-fence survival, deletion failure/reopen, exact deficit, and cleanup-before-pressure cursor continuity.
- [ ] Run focused store pressure tests.
- [ ] Verify the task-level specification and code-quality criteria; fix findings before Task 4.

## Task 4: Integrate local and remote admission retry and cache reconciliation

**Files:**

- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Test: colocated application/runtime tests

- [ ] Write failing local-publication tests showing routine cleanup runs first, pressure receives the exact partition/deficit and incoming priority, exact evicted IDs are removed from cache, and admission retries once.
- [ ] Write failing remote tests for pending staging and applicable carrier/finalization capacity boundaries with the same cleanup-pressure-retry sequence and unchanged `DeferredCapacity` behavior when recovery is insufficient.
- [ ] Extend the route cache with a lifecycle-lock-guarded exact removal operation that handles both pending and completed evicted transfers and clears any pending-completion memo without affecting unrelated routes.
- [ ] At each approved admission boundary, acquire the existing Blob lifecycle lock, run routine cleanup, run at most one bounded pressure recovery if the typed partition is eligible, reconcile every returned transfer ID, then retry the original admission exactly once.
- [ ] Keep candidate choice and store mutation below the store boundary. Runtime code supplies verified incoming priority/context and performs cache reconciliation; it must not reproduce ranking logic.
- [ ] Preserve the original typed capacity error when cleanup/pressure is ineligible, cannot prove the first candidate, cannot fit the atomic unit, or recovers less than the exact deficit.
- [ ] Prove cache/store consistency across success, rejected retry, process reopen, shared content, and physical deletion failure. Include assertions that an evicted completed or pending transfer cannot be served from stale memory.
- [ ] Prove no wire message, supported public Blob API, or CLI shape changes and no additional retry loop is introduced.
- [ ] Run focused node application/runtime tests with repository resource limits.
- [ ] Verify the task-level specification and code-quality criteria; fix findings before Task 5.

## Task 5: Whole-increment verification and integration preparation

**Files:**

- Modify only existing Blob lifecycle/security/architecture documentation that needs to describe implemented pressure behavior.
- Modify: `CHANGELOG.md` if required by repository convention.
- Do not copy non-public inputs into the repository.

- [ ] Update public documentation to match implemented behavior: partition mapping, strict priority, deterministic order, exact completion, atomic/no-skip budget rule, one retry, and resumable deletion. State explicitly that TTL remains inactive and wire/API/CLI are unchanged.
- [ ] Verify the whole increment against the committed Blob lifecycle design and initial product constraints.
- [ ] Verify code quality and security with emphasis on corruption handling, transactional atomicity, bounded work, cache/store lock discipline, and fence preservation.
- [ ] Fix every accepted finding test-first, then rerun the affected focused suites until no actionable findings remain.
- [ ] Run formatting and lint gates using repository commands.
- [ ] Run the full test suite serially with `CARGO_BUILD_JOBS=2`, `RUST_TEST_THREADS=1`, and `tools/with-test-resources.sh`; record exact totals and any intentionally excluded environment-dependent tests.
- [ ] Inspect the complete diff for unrelated changes, non-public material, TTL activation, wire/API/CLI changes, and accidental generated artifacts.
- [ ] Squash the feature work into exactly one signed integration commit for this increment, authored and committed as `Andrii Sirak <a.sirak@astertech.io>`.
- [ ] Verify the commit signature reports good for fingerprint `022F53D3C4DAE8774255EF803E5C1559F09ABC66` before updating the integration branch.
- [ ] Update PR #47's branch and description with the completed increment, verification evidence, non-goals, and remaining increments; wait for all required checks to pass.
