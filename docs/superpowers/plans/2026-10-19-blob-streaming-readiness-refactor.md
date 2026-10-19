# Blob Streaming Readiness Refactor Plan

> **Execution:** Use `superpowers:executing-plans` inline. Use focused local
> verification and CI for the full matrix; prior full local workspace runs were
> killed by the OS.

**Goal:** Turn the semantic-v9/profile-5 implementation from independently
validated mechanisms into one maintainable, measured production-code path from
application ingestion through local durability and selected-contact transfer.

**Authority:**
`docs/superpowers/specs/2026-10-19-aster-data-mesh-streaming-dag-design.md`.
This plan narrows no security, lifecycle, compatibility, durability, or claim
boundary in that design.

## Audit findings that set the order

1. `stream_pipeline` bounds concurrent work, but creates a blocking task per
   partition rather than supervising a fixed worker set. Several validation
   failures abort without explicitly joining every child. Its report records
   only aggregate service time, not queue wait or downstream blocking.
2. The public agent stream does not use the shared DAG. The node actor copies
   each complete plaintext segment, creates fresh scoped OS threads for each
   two-segment batch, and performs pack/checkpoint work synchronously while
   handling the application command.
3. The completed-pack network DAG is exercised by benchmarks and focused tests,
   but normal selected-contact execution still caps Blob operation at semantic
   v8/profile 4. Ten `dead_code` exceptions explicitly defer profile-5 runtime
   activation.
4. Sender and receiver state-machine calls clone every transport extent. Pack
   send reads, decodes, and re-encodes already canonical encrypted records;
   receiver parsing shifts retained bytes after each record.
5. Several central modules mix large production implementations and equally
   large inline test modules. Timing fixtures include real sleeps where a
   controlled clock or explicit event can provide deterministic evidence.
6. Runtime network errors are stringly typed, and duplicated framing/length/
   checkpoint calculations occur across benchmark, validation, and runtime
   paths.

## Task 1: Harden the shared execution engine

**Files:** `crates/aster-node/src/stream_pipeline.rs` and focused tests.

- Add failing tests for fixed worker cardinality, every error-path child join,
  permit reclamation, queue/service/output-blocked accounting, and a slow first
  partition filling only the configured reorder window.
- Replace partition-per-task scheduling with one supervised fixed worker set.
  Keep item and byte permits attached to owned buffers until terminal release.
- Make every early failure close admission, cancel work, join every worker, and
  return all permits before returning.
- Expand bounded observations to distinguish queue wait, active service, and
  downstream/reorder blocking without retaining per-partition history.
- Run `cargo test --locked -p aster-node stream_pipeline --lib`, formatting,
  strict Clippy for `aster-node`, and the 64-MiB release pipeline benchmark.

## Task 2: Move the public application stream onto the engine

**Files:** `crates/aster-node/src/application/blob.rs`,
`crates/aster-node/src/application/blob_stream.rs`, and focused agent tests.

- Add a failing test proving an in-progress large Blob map cannot block an
  unrelated actor command and that worker/thread cardinality is independent of
  segment count.
- Give each admitted publication one bounded pipeline job. Application frames
  feed its source queue; fixed workers seal independent partitions; the ordered
  sink alone appends, checkpoints, and advances durable progress.
- Move plaintext ownership into partitions without `pending.to_vec()` and
  remove `std::thread::scope` batch creation.
- Preserve local publish independence: completion requires only declared local
  sinks; later peer synchronization starts from the completed pack.
- Keep exact operation-key resume, TTL/policy revalidation, cancellation, and
  promotion behavior unchanged.
- Run focused node/agent/CLI Blob stream tests and compare 64-MiB release
  application publish/read throughput, CPU, RSS, worker count, and copies.

## Task 3: Remove transport and pack hot-path copies

**Files:** `stream_transfer.rs`, `runtime/blob_stream.rs`, Blob pack codec, and
transport validation.

- Add ownership tests showing credit rejection returns the original extent and
  receiver validation borrows data it does not retain.
- Move accepted sender extents into frames without cloning and make receiver
  state validation borrow `StreamDataV1`.
- Add a canonical raw-record pack reader so completed-pack forwarding does not
  decode and re-encode ciphertext. Retain bounded structural validation.
- Replace front-draining parser storage with cursor/split ownership so parsing
  work and copies remain linear and bounded.
- Replace duplicated wire-length and attempt-bound calculations with one checked
  profile-5 framing utility.
- Run transfer, pack, runtime Blob, fuzz-smoke, and release transport benchmark
  gates.

## Task 4: Activate profile 5 in selected contacts

**Files:** transfer-profile negotiation, mission protection, runtime contact
driver, Blob stream runtime adapter, and integration tests.

- Add a failing two-node selected-runtime test that publishes locally while
  disconnected, later negotiates semantic v9/profile 5, transfers the completed
  pack, promotes at the receiver, and reads matching plaintext.
- Dispatch the negotiated Blob lane by profile: v7/v8 profile 4 remains
  byte-identical; v9 profile 5 uses the new DAG and never falls back.
- Bind every stream frame to the authenticated mission session, negotiated
  profile digest, direction, attempt nonce, current policy, and source identity.
- Derive work from durable local inventory after contact availability rather
  than coordinating local publication with a destination.
- Remove the profile-5 `dead_code` exceptions and make unsupported semantic/
  profile pairs fail before data I/O.
- Run focused mission/runtime compatibility and real two-process delivery tests.

## Task 5: Refactor module and error boundaries

- Split application stream job/lifecycle logic from the existing 9k-line Blob
  module while retaining one store authority.
- Separate production code from large inline tests where it improves navigation
  without creating public API churn.
- Replace runtime `String` errors with typed stage/context errors and one public
  sanitization boundary.
- Consolidate profile constants, checkpoint policy, framing bounds, and common
  test fixtures; remove stale comments and duplicate helpers.
- Keep APIs transport-blind and keep future data-class adapters dependent only
  on generic pipeline contracts.
- Run focused tests after every mechanical move; require `git diff --check` and
  strict Clippy before a signed commit.

## Task 6: Clean and stabilize tests

- Replace wall-clock sleeps with controlled clocks or event-driven barriers
  wherever the behavior is not specifically real-time expiry.
- Centralize process readiness/shutdown/watchdog helpers and retain watchdogs
  only as failure ceilings.
- Separate protocol/state-machine unit tests, store crash tests, runtime
  integration tests, and ignored performance/CM4 qualification tests.
- Remove compatibility fixtures that target unreleased superseded v9 behavior;
  retain exact v7/v8/profile-4 byte compatibility fixtures.
- Measure focused test duration before/after and ensure cleanup joins all child
  processes/tasks on success and failure.

## Task 7: Requalify the integrated path

- Run formatting, lockfile checks, protocol oracle, focused core/store/node/
  agent/CLI tests, strict Clippy, fuzz-smoke, and CI. Do not run the full local
  workspace suite.
- Build the signed ARM64 artifact through CI.
- On the existing three CM4 devices run warm-up, 256 MiB, exact 800 MiB, exact
  1 GiB, interrupted 1 GiB resume, and three-device fairness/control-lane tests.
- Retain raw-file same-path baseline and per-stage queue/service/blocked metrics.
- Require end-to-end at least 80% of raw transport and each isolated
  non-transport stage at least 125%; otherwise identify and optimize the measured
  bottleneck without claiming readiness.
- Update the PR evidence and exclusions, preserving evaluation-only and
  no-production-deployment boundaries.

## Completion gate

- Normal application and selected-contact paths use the same bounded engine.
- No fresh thread/task is created per segment, no whole-Blob plaintext staging
  exists, and avoidable payload-sized clones are removed.
- Every cancellation/failure joins children and reclaims permits/key-bearing
  buffers before return.
- Durable pack checkpoint remains sole byte-progress authority.
- Semantic v7/v8/profile 4 remains compatible; semantic v9/profile 5 is active
  and fail-closed with no unreleased fallback.
- CI is green, all commits are signed, and retained CM4 evidence meets or
  explicitly fails the declared acceptance ratios.
