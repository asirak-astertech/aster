# Aster Data-Mesh Streaming DAG Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Clean Room — Privileged**

**Goal:** Replace Aster's unreleased serial Blob-stream execution with a reusable, measured, bounded DAG whose Blob adapter pipelines independent crypto, sequential pack durability, transport, verification, and promotion fast enough for CM4 transport to become the limiting qualified stage.

**Architecture:** Semantic v9/profile 5 is redefined in place. A shared node execution engine runs fixed worker pools over independently authenticated partitions, restores canonical order through a bounded merge, reduces deterministic Merkle roots, and advances only checkpoint-authoritative watermarks. Blob is the first adapter; useful negotiation, transport, pack, lifecycle, application-streaming, and resume behavior is ported selectively from `d092cce2`, while chained crypto and synchronous callbacks are not.

**Tech Stack:** Rust 2024, Tokio, AES-256-GCM/HKDF-SHA-256, SHA-256 Merkle reduction, redb 4.2, Iroh/QUIC, ConnectRPC/protobuf, Python conformance oracle, Linux durability primitives, Raspberry Pi CM4 validation.

**Spec:** `docs/superpowers/specs/2026-10-19-aster-data-mesh-streaming-dag-design.md`

## Global Constraints

- Base all work on canonical main `fcf9f1b054f9623b61435659994fad0bc6c51779`; PR 47 lifecycle policy remains authoritative.
- Use semantic v9/profile 5; allocate no new semantic version and retain no fallback for the unreleased old v9 grammar.
- Keep semantic v7/v8/profile 4 byte-identical and never resume profile-4 partial state as profile 5.
- Use the previous streaming branch only as a reference/source of selected behavior; do not merge it wholesale or retain temporary PR packaging changes.
- Sign every commit and keep the branch local until the user explicitly authorizes a push.
- One successful publish reads plaintext once and creates no whole-Blob plaintext staging file.
- No segment depends on the prior segment's ciphertext commitment.
- Streaming memory, descriptors, metadata, traces, and recovery work remain bounded independently of Blob length.
- Only the sequential pack checkpoint is byte-progress authority; no peer acknowledgement precedes recoverable durability.
- Provisional bytes are not inventory-visible, application-readable, or forwardable.
- One transport carries data per attempt; application APIs do not expose selection.
- Do not claim transport-limited operation below 80% of same-path raw transport or unless every isolated non-transport stage sustains 125% of it.
- Use focused local tests. Rely on CI for the full repository matrix because prior full local runs were killed by the OS.

## File Structure

- `crates/aster-core/src/blob_stream.rs`: independent Blob segment format, signed open/final commitment, leaf/subtree hashing, fixed-width reducer frontier, and key-bearing map capabilities.
- `crates/aster-core/src/source_blob.rs`: provider-owned signing, verification, key derivation, and bounded worker-capability construction.
- `crates/aster-core/src/transfer_profile.rs`, `wire.rs`, and `lib.rs`: v9/profile-5 allocation and provider-safe exports.
- `conformance/blob_stream_oracle.py` and `conformance/vectors/blob-stream-records-v2.tsv`: independent canonical vectors.
- `crates/aster-node/src/stream_pipeline.rs`: generic job/partition/result types, byte-bounded queues, fixed worker supervision, ordered merge, cancellation, and stage metrics.
- `crates/aster-node/src/stream_transfer.rs`: transport frames/state machines, absolute credit, durable watermarks, settlement, and async producer/consumer ports.
- `crates/aster-node/src/stream_transport.rs`: transport-neutral attempt interface and Iroh selection seam.
- `crates/aster-node/src/frame.rs` and `mission.rs`: protected control and direct-data dispatch.
- `crates/aster-redb-store/src/blob/pack.rs`: sequential encrypted pack, alternating checkpoints, fixed-width frontiers, recovery, and readers.
- `crates/aster-redb-store/src/blob/stream.rs` and `blob.rs`: provisional reservation, lifecycle/quota integration, checkpoint projection, idempotent finish, and promotion.
- `crates/aster-node/src/application/blob_stream.rs`: local publish/read Blob adapters over the shared pipeline.
- `crates/aster-node/src/runtime/blob_stream.rs`: completed-pack sender and receiver DAG composition.
- `crates/aster-agent/src/blob_service.rs`, `proto/aster/application/v1alpha1/aster.proto`, generated clients, and `crates/asterctl/src/blob_publish.rs`/`blob_read.rs`: resumable application streams.
- `crates/aster-node/examples/blob_benchmark.rs` and `docs/validation/blob-streaming-performance.md`: per-operator benchmark output and CM4 evidence.

## Review Focus

- A slow lowest-index map partition while later partitions complete must fill only the bounded reorder window, stop new admission, and recover without reordering. Covered in Task 2.
- Cancellation or worker panic while buffers are queued must join all children and return every byte permit exactly once. Covered in Task 2.
- Data sync succeeds but the next checkpoint tears: reopen must select the older complete generation and discard the unacknowledged tail. Covered in Task 3.
- A valid signed open followed by a conflicting signed finish must retain bounded conflict evidence and expose no publication. Covered in Task 3.
- A finite stream expires while transport and local pack branches disagree on progress: credit stops, both branches retain only their valid durable prefixes, and promotion fails. Covered in Task 6.

---

### Task 1: Independent Blob partitions and deterministic reduction

**Files:**
- Create: `crates/aster-core/src/blob_stream.rs`
- Modify: `crates/aster-core/src/source_blob.rs`
- Modify: `crates/aster-core/src/transfer_profile.rs`
- Modify: `crates/aster-core/src/wire.rs`
- Modify: `crates/aster-core/src/lib.rs`
- Create: `conformance/blob_stream_oracle.py`
- Create: `conformance/vectors/blob-stream-records-v2.tsv`
- Test: inline unit tests in `crates/aster-core/src/blob_stream.rs`

**Interfaces:**
- Consumes: existing `BlobId`, `BlobMetadata`, `NodeId`, `Topic`, `Scope`, provider crypto, and semantic/profile negotiation.
- Produces: `BLOB_STREAM_SEGMENT_BYTES`, `BlobPublicationStreamId`, `BlobStreamOpen`, `VerifiedBlobStreamOpen`, `BlobStreamPlainPartition`, `EncryptedBlobStreamSegment`, `BlobStreamSegmentLeaves`, `BlobStreamSubtree`, `BlobStreamFrontier`, `BlobStreamCheckpoint`, `BlobStreamFinalCommitment`, `BlobStreamSegmentSealer`, and `BlobStreamSegmentOpener` for Tasks 2-7.

- [ ] **Step 1: Write failing independent-map and reducer tests**

Add tests `blob_stream_segments_seal_and_open_in_any_completion_order`, `blob_stream_reduction_matches_for_one_two_and_four_workers`, `blob_stream_frontier_restores_the_same_final_roots`, and `blob_stream_segment_rejects_every_changed_identity_field`. Assert shuffled completion yields the canonical roots and mutation of stream/open/index/offset/length/epoch/ciphertext/tag fails.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `cargo test --locked -p aster-core blob_stream --lib`

Expected: compile failure because the new types do not exist.

- [ ] **Step 3: Implement independent segment and reduction interfaces**

Implement:

```rust
impl BlobStreamSegmentSealer {
    pub fn seal(&self, partition: BlobStreamPlainPartition) -> Result<(EncryptedBlobStreamSegment, BlobStreamSegmentLeaves), BlobError>;
}

impl BlobStreamSegmentOpener {
    pub fn open(&self, segment: &EncryptedBlobStreamSegment) -> Result<(Zeroizing<Vec<u8>>, BlobStreamSegmentLeaves), BlobError>;
}

impl BlobStreamSubtree {
    pub fn leaf(index: u64, leaves: BlobStreamSegmentLeaves) -> Self;
    pub fn combine(left: Self, right: Self) -> Result<Self, BlobError>;
}

impl BlobStreamFrontier {
    pub fn append(&mut self, subtree: BlobStreamSubtree) -> Result<(), BlobError>;
    pub fn checkpoint(&self) -> BlobStreamCheckpoint;
    pub fn restore(checkpoint: BlobStreamCheckpoint) -> Result<Self, BlobError>;
    pub fn finish(self, total_len: u64) -> Result<([u8; 32], [u8; 32]), BlobError>;
}
```

Use per-stream base nonce plus checked index, bind all canonical fields as AEAD associated data, and serialize a fixed-width Merkle frontier rather than implementation-private hash state. Do not include a previous-segment commitment.

- [ ] **Step 4: Port and redefine v9/profile-5 open/final grammar and vectors**

Port the provider-safe signing/verification and negotiation concepts from `d092cce2`, update them for independent leaves/frontiers, and make the Python oracle independently calculate every literal vector. Keep profile 4 unchanged.

- [ ] **Step 5: Run focused Rust and oracle tests**

Run: `cargo test --locked -p aster-core blob_stream --lib`

Run: `python3 conformance/blob_stream_oracle.py conformance/vectors/blob-stream-records-v2.tsv`

Expected: all tests/vectors pass.

- [ ] **Step 6: Commit signed**

```bash
git add crates/aster-core conformance
git commit -S -m "feat(blob): define independently reducible stream partitions"
```

### Task 2: Shared bounded pipeline engine

**Files:**
- Create: `crates/aster-node/src/stream_pipeline.rs`
- Modify: `crates/aster-node/src/lib.rs`
- Test: inline unit tests in `crates/aster-node/src/stream_pipeline.rs`

**Interfaces:**
- Consumes: Task 1 partition identities only through generic job-owned closures; the engine contains no Blob crypto.
- Produces: `StreamJobId`, `StreamPartition`, `MappedPartition<T>`, `PipelineLimits`, `PipelineStage`, `StageObservation`, `PipelineReport`, `PipelineError`, `PipelineSupervisor`, and `run_ordered_pipeline` for Tasks 4-8.

- [ ] **Step 1: Write failing queue, reorder, and supervision tests**

Add tests `pipeline_never_exceeds_byte_or_item_budget`, `pipeline_reorders_shuffled_worker_results`, `pipeline_slow_first_partition_backpressures_at_reorder_limit`, `pipeline_cancellation_reclaims_all_permits_and_joins_workers`, and `pipeline_worker_panic_is_terminal_not_success`.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-node stream_pipeline --lib`

Expected: compile failure because `stream_pipeline` is absent.

- [ ] **Step 3: Implement the engine interfaces**

Implement a fixed worker set over byte- and item-bounded Tokio channels. `run_ordered_pipeline` accepts async source, synchronous/`spawn_blocking` map, ordered sink, and checkpoint-boundary callbacks. Only the ordered merge advances `next_index`; all permit ownership travels with buffers and returns on drop.

- [ ] **Step 4: Add bounded metrics tests and implementation**

Assert every accepted partition contributes exactly one terminal observation; queue wait, service, output-blocked time, bytes, items, worker, and result are separately accumulated; histogram/sample storage stays constant as partition count grows.

- [ ] **Step 5: Run focused tests**

Run: `cargo test --locked -p aster-node stream_pipeline --lib`

Expected: all pipeline tests pass under normal, cancellation, and panic cases.

- [ ] **Step 6: Commit signed**

```bash
git add crates/aster-node/src/stream_pipeline.rs crates/aster-node/src/lib.rs
git commit -S -m "feat(node): add bounded stream pipeline engine"
```

### Task 3: Sequential pack, checkpoint authority, and provisional lifecycle

**Files:**
- Create: `crates/aster-redb-store/src/blob/pack.rs`
- Create: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/depot.rs`
- Modify: lifecycle/pressure/deletion modules only where provisional/final pack roots require integration
- Test: inline pack and store tests

**Interfaces:**
- Consumes: Task 1 canonical records/frontiers and merged PR 47 lifecycle authorities.
- Produces: `BlobPackWriter`, `BlobPackReader`, `BlobPackCheckpoint`, `BlobStreamReservation`, `BlobStreamResume`, `reserve_blob_stream`, `checkpoint_blob_stream`, `promote_blob_stream`, and cleanup primitives for Tasks 4-7.

- [ ] **Step 1: Write failing crash/frontier tests**

Cover crash before data sync, after data sync, during each alternating checkpoint, corrupt newest checkpoint, uncheckpointed tail, wrong stream/open identity, and restored frontier producing identical final roots.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-redb-store blob_pack --lib`

Expected: compile failure because pack APIs are absent.

- [ ] **Step 3: Port pack foundations and replace checkpoint crypto state**

Port sequential-pack and alternating-journal behavior from `d092cce2`; store Task 1 fixed-width frontiers and exact durable offsets. Enforce append, data sync, checkpoint sync, then publication of durable progress.

- [ ] **Step 4: Write failing provisional/promotion tests**

Cover invisibility, quota reservation, exact reopen, duplicate finish, conflicting finish, TTL expiry, revocation, pressure recovery, deletion fences, and redb never leading the pack checkpoint.

- [ ] **Step 5: Port lifecycle authority and implement atomic promotion**

Reuse PR 47 policy/age/pressure authority and selected previous-stream transaction concepts. Keep redb authoritative for lifecycle/final state but not byte progress.

- [ ] **Step 6: Run focused store tests**

Run: `cargo test --locked -p aster-redb-store blob_stream --lib`

Run: `cargo test --locked -p aster-redb-store blob_pack --lib`

Expected: all named crash, conflict, and lifecycle cases pass.

- [ ] **Step 7: Commit signed**

```bash
git add crates/aster-redb-store
git commit -S -m "feat(store): persist checkpointed Blob stream packs"
```

### Task 4: Local single-pass publish and authenticated read adapters

**Files:**
- Create: `crates/aster-node/src/application/blob_stream.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Test: focused application/runtime tests

**Interfaces:**
- Consumes: Tasks 1-3.
- Produces: actor-owned `BlobPublishStream`, `BlobReadStream`, resume checkpoints, completion receipts, and pipeline reports for Tasks 5-8.

- [ ] **Step 1: Write failing publish/read pipeline tests**

Assert first-byte processing before EOF, each plaintext byte read once, no whole-source staging file, shuffled crypto completion with ordered pack bytes, bounded memory across different total lengths, exact resume offset, and read output matching the final identity.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-node blob_stream --lib`

Expected: local stream types or behavior missing.

- [ ] **Step 3: Port public stream shapes and compose the shared engine**

Port the public request/result semantics from `d092cce2`, but implement source/map/ordered-pack and pack/map/ordered-output through Task 2. Revalidate lifecycle at bounded checkpoints and before success.

- [ ] **Step 4: Run focused application tests**

Run: `cargo test --locked -p aster-node blob_stream --lib`

Expected: all local publish/read/resume/resource tests pass.

- [ ] **Step 5: Commit signed**

```bash
git add crates/aster-node/src/application crates/aster-node/src/runtime.rs
git commit -S -m "feat(blob): pipeline local publish and read streams"
```

### Task 5: Transport grammar, selection, and asynchronous ports

**Files:**
- Create: `crates/aster-node/src/stream_transfer.rs`
- Create: `crates/aster-node/src/stream_transport.rs`
- Modify: `crates/aster-node/src/frame.rs`
- Modify: `crates/aster-node/src/mission.rs`
- Modify: `crates/aster-iroh/src/lib.rs`
- Add/update: stream codec, boundary, and lane tests under `crates/aster-node/src/runtime/`

**Interfaces:**
- Consumes: Tasks 1-2.
- Produces: v9 control/data frames, `StreamAttempt`, async data producer/consumer ports, absolute credit, checkpoint/result settlement, and deterministic one-adapter selection for Task 6.

- [ ] **Step 1: Write failing state-machine and selector tests**

Cover frame bounds, data/control separation, stale/decreasing checkpoints, credit overrun, duplicate settlement, fresh retry nonce, one active adapter, deterministic eligibility ordering, and cancellation while either port is blocked.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-node stream_transfer --lib`

Expected: stream transport interfaces are absent.

- [ ] **Step 3: Port grammar/adapter foundations and replace callbacks**

Port bounded framing, credit, settlement, selector seam, and Iroh attempt behavior from `d092cce2`. Replace synchronous data callbacks with bounded async producer/consumer ports compatible with Task 2; do not embed Blob crypto or store locks.

- [ ] **Step 4: Run focused tests and fuzz-smoke for framing**

Run: `cargo test --locked -p aster-node stream_transfer --lib`

Run: `cargo test --locked -p aster-iroh --lib`

Run at the framing completion gate: `mise run fuzz-smoke`

Expected: tests pass; bounded hostile frames do not panic or allocate beyond declared limits.

- [ ] **Step 5: Commit signed**

```bash
git add crates/aster-node crates/aster-iroh fuzz
git commit -S -m "feat(protocol): drive bounded asynchronous stream attempts"
```

### Task 6: Blob network DAG, durable resume, and promotion

**Files:**
- Create: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/event_pages.rs` only for shared lane scheduling if required
- Test: Blob stream live/boundary/lane tests

**Interfaces:**
- Consumes: Tasks 1-5.
- Produces: provisional live fan-out, completed-pack forwarding, receiver verify/reorder/pack pipeline, durable credit, resume, settlement, and final promotion.

- [ ] **Step 1: Write failing end-to-end and failure-path tests**

Cover multi-worker completion reorder, pack/transport fan-out, transport lag switching to pack, disconnect/resume from receiver checkpoint, bounded replay, settlement without data replay, policy/revocation/TTL loss, finite expiry with divergent branch progress, and Event/control lane fairness.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-node blob_stream --lib`

Expected: completed-pack network DAG is absent.

- [ ] **Step 3: Compose sender and receiver DAGs**

Port only the admission, lifecycle, resume, and settlement behavior from the previous runtime. Sender uses source/pack -> Task 2 -> transport; receiver uses transport parser -> Task 2 independent verification -> ordered pack sink -> Task 3 checkpoint. No receiver-wide processing mutex and no stateful serial decrypt batch.

- [ ] **Step 4: Run focused live and boundary tests**

Run: `cargo test --locked -p aster-node blob_stream --lib`

Run: `cargo test --locked -p aster-node blob_ranges_stream_boundary --lib`

Expected: all v9 DAG tests pass and v7/v8 profile-4 boundary tests remain unchanged.

- [ ] **Step 5: Commit signed**

```bash
git add crates/aster-node/src/runtime crates/aster-node/src/runtime.rs
git commit -S -m "feat(blob): execute network transfers as a measured DAG"
```

### Task 7: Resumable agent and CLI streaming

**Files:**
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: generated Rust/Go descriptor/client files required by repository policy
- Modify: `crates/aster-agent/src/blob_service.rs`
- Modify: `crates/aster-agent/src/config.rs`
- Modify: `crates/asterctl/src/blob_publish.rs`
- Modify: `crates/asterctl/src/blob_read.rs`
- Test: focused agent, generated-client, and CLI tests

**Interfaces:**
- Consumes: Task 4 application streams.
- Produces: declared-length metadata, canonical contiguous frames, monotonic durable checkpoints, exact operation resume, and no-replace atomic output.

- [ ] **Step 1: Write failing disconnect/resume and boundedness tests**

Cover disconnect after accepted-but-undurable bytes, exact operation reopen, changed-intent rejection, nonseekable retry from zero only, frame gap/replay/overrun, EOF before finish, bounded backpressure, and output cleanup/no replacement.

- [ ] **Step 2: Run and verify RED**

Run: `cargo test --locked -p aster-agent blob --lib --tests`

Run: `cargo test --locked -p asterctl blob --lib --tests`

Expected: streaming RPC/CLI behavior missing.

- [ ] **Step 3: Port the public surfaces and connect directly to Task 4**

Reuse previous RPC/CLI compatibility decisions, remove whole-file staging, seek input to the durable offset, and preserve one final output data sync plus no-replace atomic publication.

- [ ] **Step 4: Regenerate clients and run focused tests**

Run the repository's pinned protobuf generation command, then rerun the two focused commands plus generated Go acceptance.

Expected: generated files are clean and all stream/resume cases pass.

- [ ] **Step 5: Commit signed**

```bash
git add proto bindings crates/aster-agent crates/asterctl
git commit -S -m "feat(agent): expose resumable pipelined Blob streams"
```

### Task 8: Critical-path benchmark and CM4 qualification

**Files:**
- Modify: `crates/aster-node/examples/blob_benchmark.rs`
- Modify: Task 2 metrics/reporting code as evidence requires
- Create: `docs/validation/blob-streaming-performance.md`
- Modify requirements trace/status only if the evidence boundary genuinely changes

**Interfaces:**
- Consumes: pipeline reports from Tasks 2, 4, and 6.
- Produces: machine-readable per-stage results, raw transport comparison, warm/cold labeling, limiting-stage diagnosis, and retained validation commands/results.

- [ ] **Step 1: Write failing metric-accounting tests**

Assert byte conservation, exactly one terminal outcome per partition, queue/service/blocked decomposition, bounded histogram state, correct branch completion, and stable stage names/schema.

- [ ] **Step 2: Implement benchmark output and verify locally at 64 MiB**

Emit source/map/reduce/reorder/pack/sync/checkpoint/transport/verify/promotion/read capacity, queue pressure, copies/allocations, RSS/CPU/descriptors, selected adapter, and actual endpoints. Label setup, warm-up, steady state, and drain separately.

- [ ] **Step 3: Run focused local verification**

Run formatting, lockfile checks, focused core/store/node/agent/CLI tests, protocol oracle, strict Clippy for touched crates, and fuzz-smoke. Do not run the full local workspace suite.

Expected: all focused gates pass with no warnings; `git diff --check` is clean.

- [ ] **Step 4: Build through CI and validate the CM4 sequence**

Use CI-built ARM64 artifacts. Run 64 MiB warm-up/instrumentation, 256 MiB steady-state, exact 800 MiB, exact 1 GiB, interrupted 1 GiB resume, then three-CM4 fairness. Retain hashes, Blob IDs, memory plateau, checkpoints, retransmission, route/endpoints, raw transport rate, stage capacities, and critical-path diagnosis.

- [ ] **Step 5: Evaluate acceptance without inflating claims**

Require end-to-end at least 80% of raw selected transport and every non-transport stage at least 125%. If either fails, identify and optimize the measured bottleneck before qualification. Run `python3 tools/check-implementation-requirements.py` only if trace/evidence claims change.

- [ ] **Step 6: Commit signed**

```bash
git add crates/aster-node/examples/blob_benchmark.rs docs/validation
git commit -S -m "test(blob): qualify data mesh streaming pipeline"
```

## Completion Gate

- All commits verify as signed.
- The branch contains no temporary workflow/package modifications from previous PRs.
- Independent segment processing and deterministic roots are proven under reordered completion.
- Memory and retained metrics remain bounded as total length grows.
- Crash recovery and peer resume use only durable checkpoint authority.
- Exact 800-MiB and 1-GiB contents match after publish, replication, and read.
- CM4 evidence either meets the 80%/125% transport-limited ratios or explicitly reports the remaining measured bottleneck without claiming completion.
- Required CI is green before any request to push or open a PR.
