# PR #40 Numbered Publication Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Correct the numbered Event publication recovery, lifecycle, capacity, audit, and SDK defects found during review of PR #40 without broadening its experimental capability claim.

**Architecture:** Preserve the existing numbered ledger and wire schema. Harden the redb store as the source of durable truth, make logical retirement precede physical cleanup, then reconcile the SDK journal against the validated server snapshot through an explicit recovery report. Keep each fix independently tested and reviewable.

**Tech Stack:** Rust, redb, ConnectRPC/buffa, Go conformance client, mise.

**Spec:** The approved PR #40 review findings and remediation order in the 2026-09-23 Clean Room — Privileged review session, grounded in `docs/quickstart/connect-agent.md` and `proto/aster/application/v1alpha1/aster.proto`.

## Global Constraints

- Follow `CONTRIBUTING_CLEANROOM.md`; brief every subagent that the current live guardrail was checked and the repository contains no excluded input.
- Base all work on PR #40 head `c43ebbc88d61a5120e8d9058c9fd6b1d7e5ec530` in `/home/andrii/code/aster/.worktrees/pr40-review`.
- Use TDD: add a focused regression test, observe the expected failure, then implement the minimal fix.
- Preserve the wire schema and numbered-ledger on-disk encodings unless a task explicitly requires otherwise.
- Do not update requirement IDs unless their implementation or evidence boundary genuinely changes.
- Run Cargo with `CARGO_BUILD_JOBS=1`; available memory and swap are constrained.
- Do not run implementation agents or Cargo compilations concurrently.
- Do not push, merge, or modify the original dirty workspace.

## Review Focus

- Corrupt or missing mode/accounting metadata must fail closed without reconstructing persisted corruption.
- Recovery must never change immutable receipt identity or accept a result beyond the server frontier.
- An Event that is logically unavailable must never be reported as `Available`, even while a lease delays byte removal.
- Tombstone publication must use reserved capacity but never exceed total hard record or byte limits.
- SDK callers must retain the assigned sequence after an RPC failure and discover every operation requiring action after restart.

---

### Task 1: Correct numbered source-envelope error classification

**Files:**
- Modify: `crates/aster-node/src/application.rs`
- Test: `crates/aster-node/src/application.rs`
- Test: `crates/aster-agent/src/error.rs` or `crates/aster-agent/src/event_service.rs`

**Interfaces:**
- Consumes: existing `application_error` and public Connect error mapping.
- Produces: numbered source-envelope rejection as `RequestRejected`, yielding `PermissionDenied`/`FailedPrecondition` publicly.

- [ ] Add an application regression test that performs a recovered numbered publication to an unprovisioned topic and expects `ApplicationErrorKind::RequestRejected`.
- [ ] Run the focused test with `CARGO_BUILD_JOBS=1` and record the expected `Integrity` failure.
- [ ] Make source-envelope publication classification cover both `publish` and `publish_numbered` without changing non-publication operations.
- [ ] Add or extend the RPC mapping test to assert `PermissionDenied`, `FailedPrecondition`, and operation `publish_numbered_event`.
- [ ] Run focused node and agent tests, then the affected crate suites with one build job.
- [ ] Commit the task.

### Task 2: Fail closed on numbered ledger metadata and relationship corruption

**Files:**
- Modify: `crates/aster-redb-store/src/numbered_event_operation.rs`
- Test: `crates/aster-redb-store/src/numbered_event_operation.rs`
- Possibly test helpers: `crates/aster-redb-store/src/lib.rs`

**Interfaces:**
- Consumes: existing client/result/reverse encodings and legacy ledger tables.
- Produces: a startup audit that accepts only an absent fresh accounting group or an exact persisted accounting group, and an authoritative mode boundary.

- [ ] Add corruption tests for: explicit all-zero counters over nonempty tables; partial counters; missing mode with numbered rows; unknown mode; mixed ledger rows; missing result owner; result sequence above client frontier; per-client result overflow; and reverse transfer prefix differing from the result receipt.
- [ ] Run each focused test and record the expected pre-fix acceptance or wrong reconstruction.
- [ ] Read accounting metadata as four `Option<u64>` values. Reconstruct only when all are absent, reject partial presence, and compare all-present values exactly even when all are zero.
- [ ] Validate mode as absent legacy/fresh or exact numbered value `1`; reject unknown values, numbered rows without numbered mode, and mixed ledgers independently of marker value.
- [ ] During table audit, build client frontiers and per-client counts; require result ownership, `sequence <= allocated_through`, count at most 4,096, and exact result/reverse identity in both directions.
- [ ] Make `legacy_operation_allowed_write` reject unknown marker values rather than treating them as legacy.
- [ ] Run focused redb-store tests and the complete `aster-redb-store` crate suite with one build job.
- [ ] Commit the task.

### Task 3: Bound recovery and retirement lookups by key prefix

**Files:**
- Modify: `crates/aster-redb-store/src/numbered_event_operation.rs`
- Test: `crates/aster-redb-store/src/numbered_event_operation.rs`

**Interfaces:**
- Consumes: canonical result keys `[client_len, client, sequence]` and reverse keys `[transfer_id, result_key]`.
- Produces: client recovery proportional to that client's result count and Event retirement proportional to that Event's reverse edges.

- [ ] Add focused tests with unrelated clients and transfer IDs that prove the bounded queries return only the requested prefix and retain canonical decoding checks.
- [ ] Run the tests before implementation; use test-only scan instrumentation if needed to demonstrate unrelated rows are not visited.
- [ ] Replace the global result iteration with the exact `(client, 1)..=(client, u64::MAX)` range.
- [ ] Replace the global reverse iteration with a transfer-prefix range using the established successor-bound pattern from the legacy operation ledger; verify decoded transfer identity inside the range.
- [ ] Run focused tests and the complete redb-store crate suite with one build job.
- [ ] Commit the task.

### Task 4: Retire numbered results at logical retirement time

**Files:**
- Modify: `crates/aster-redb-store/src/custody.rs`
- Modify if needed: `crates/aster-redb-store/src/numbered_event_operation.rs`
- Test: `crates/aster-redb-store/src/lib.rs` or `crates/aster-node/src/application.rs`

**Interfaces:**
- Consumes: prefix-bounded `retire_numbered_results_write` from Task 3.
- Produces: `Available -> Retired(reason)` in the same transaction that marks an Event unavailable, while physical bytes may remain leased.

- [ ] Add a regression test that publishes a finite numbered Event, holds an active transfer lease, expires it, runs maintenance, and expects recovery to return the same receipt as `Retired(Expired)` before lease release.
- [ ] Run the focused test and record the pre-fix `Available` result.
- [ ] Invoke numbered-result retirement when an Event custody row is first marked retiring, deriving `Expired` or `QuotaPressure` from the marked row.
- [ ] Preserve transactionality and snapshot-revision invalidation; keep finalization idempotent as a defensive path.
- [ ] Extend the test to release the lease and prove final cleanup preserves the same retired receipt and reason.
- [ ] Run focused custody/application tests and complete affected crate suites with one build job.
- [ ] Commit the task.

### Task 5: Admit numbered tombstones through emergency operation capacity

**Files:**
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-redb-store/src/numbered_event_operation.rs`
- Modify: `crates/aster-node/src/application.rs`
- Modify: `conformance/agent-go/cmd/agent-smoke/main.go`
- Test: redb-store, node status, and Go conformance tests

**Interfaces:**
- Consumes: the existing `tombstone` flag passed through `admit_pending_event_operation_write`.
- Produces: ordinary admission for clients/non-tombstones, total hard-limit admission for numbered tombstone results, and accurate numbered emergency headroom.

- [ ] Add record- and byte-limit tests showing a normal numbered result fails at the ordinary boundary, a tombstone result succeeds inside reserve, exact retry is neutral, and a tombstone fails at total hard limits.
- [ ] Run the focused tests and record the pre-fix ordinary-capacity rejection.
- [ ] Pass `tombstone` into numbered result admission and extend `charge_new_record` with an emergency flag mirroring legacy admission semantics.
- [ ] Keep client creation ordinary-only.
- [ ] Calculate numbered `emergency_remaining` from total versus ordinary headroom using the conservative numbered row size.
- [ ] Update Go status validation and Rust/Go expectations.
- [ ] Run focused Rust and Go tests plus complete affected crate suites with one build job.
- [ ] Commit the task.

### Task 6: Make SDK recovery discoverable, bounded, and fail-closed

**Files:**
- Modify: `crates/aster-agent/src/sdk.rs`
- Modify: `crates/aster-agent/README.md`
- Modify: `docs/quickstart/connect-agent.md`
- Test: `crates/aster-agent/src/sdk.rs`
- Test: `crates/aster-agent/tests/real_node_connect.rs`

**Interfaces:**
- Consumes: the final server recovery/result semantics from Tasks 2-5.
- Produces: an assigned-sequence-aware publication error, a `RecoveryReport` enumerating actionable operations, validated monotonic result reconciliation, and deletion of permanently consumed journal rows.

- [ ] Define and test the public recovery view: sequence-ordered `Pending`, `Committed(result)`, and `Retired` states sufficient to call `publish_journaled`, apply/acknowledge a result, or take no action.
- [ ] Define and test a publication error that distinguishes failure before sequence assignment from failure after assignment and exposes the assigned sequence.
- [ ] Add scripted transport/service tests for RPC loss after journaling, restart discovery of pending and committed work, successful abandonment cleanup, lost abandonment response cleanup, and lost acknowledgement response cleanup.
- [ ] Add malformed snapshot tests for zero/duplicate/unknown/beyond-frontier sequences, missing or invalid receipt fields, immutable receipt replacement, `Retired -> Available`, changed retirement reason, and resurrection of an abandoned operation. Verify rejection leaves the journal unchanged.
- [ ] Run the new tests and record their expected pre-fix failures.
- [ ] Validate the entire response into a sequence-indexed map before opening the journal write transaction. Allow only identical results or `Available -> Retired` with the same receipt.
- [ ] Reconcile entries in linear time, delete rows proven permanently consumed without an outstanding result, and return the post-recovery report only after completion succeeds.
- [ ] Delete the complete journal row after successful/idempotent abandonment instead of retaining its payload. Ensure repeated cancellation does not grow row count or retained logical bytes.
- [ ] Wrap every post-assignment `publish` failure with its sequence while preserving pre-assignment journal errors.
- [ ] Update SDK documentation and examples for recovery enumeration and error handling.
- [ ] Run focused SDK tests, agent integration tests, doctests, and the complete agent crate suite with one build job.
- [ ] Commit the task.

### Task 7: Integration verification and evidence alignment

**Files:**
- Modify only documentation/evidence files whose claims genuinely changed.
- Verify all files changed by Tasks 1-6.

**Interfaces:**
- Consumes: all task commits.
- Produces: one coherent PR #40 remediation branch with verified code, docs, and evidence boundaries.

- [ ] Re-read the review findings and map each to a code path and regression test.
- [ ] Run `git diff --check` against PR #40 head.
- [ ] Run focused Rust and Go suites with `CARGO_BUILD_JOBS=1`.
- [ ] Run `python3 tools/check-implementation-requirements.py` if traceability/evidence changed.
- [ ] Recheck memory and disk, then run `CARGO_BUILD_JOBS=1 mise run check` only when at least 8 GiB disk and adequate process headroom remain.
- [ ] Run `mise run fuzz-smoke` only if parser, encoding, framing, envelope, or hostile-input boundaries changed.
- [ ] Record exact command results and any environmental limitation; do not claim unrun checks.
- [ ] Commit any required documentation/evidence corrections.
