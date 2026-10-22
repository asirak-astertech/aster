# Profile-5 Pack and Blob-Lifecycle Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the proven 1-MiB Profile-5 pack as the directly stored and transferred Blob representation while making PR #95 lifecycle policy its sole semantic authority.

**Architecture:** Keep the existing `ASTRBS02` segment, bounded pipeline, pack, and checkpoint implementation. Replace the active 64-KiB finalization and `ABX1` network projection with lifecycle-owned provisional/final pack records, atomic promotion, pack-aware leases/accounting/deletion, and direct pack-to-pack transfer. Preserve the valid content-proof, route-cache, EOF-settlement, public streaming, and progress-timeout fixes already present in the working tree.

**Tech Stack:** Rust, Tokio, redb, existing Aster source-envelope provider, AES-GCM/HKDF/SHA-256, Iroh/QUIC transport adapter, `mise` verification.

**Spec:** `docs/superpowers/specs/2026-10-22-profile5-pack-lifecycle-integration-design.md`

## Global Constraints

- Semantic v9/profile 5 uses fixed 1-MiB independently authenticated `ASTRBS02` segments.
- Profile-5 storage and wire transfer use the same append-only pack records; no `ASTRBT01` or `ABX1` conversion is permitted.
- PR #95 remains the sole authority for publication identity, visibility, subscriptions, lifecycle, policy, leases, quota, and deletion.
- The pack checkpoint journal remains the sole durable byte-progress authority.
- Local publication completes independently of peer availability.
- The Blob API, native agent RPCs, and `asterctl` remain transport-blind.
- Receiver-checkpoint resume remains in scope; client-side export/download resume remains post-merge.
- Iroh/QUIC remains the first adapter, but Blob semantics cannot depend on that adapter.
- No production migration or Profile-4 Blob fallback is required; incompatible development depots fail with reset/reimport guidance.
- Preserve bounded memory, source authentication, payload-blind relay behavior, zeroization, and fail-closed policy checks.
- Preserve the current uncommitted content-proof, route-cache, terminal-EOF, benchmark, and timeout fixes unless a focused test proves that the restored path replaces them.
- Every commit is signed; do not push until CM4 performance is validated and the user authorizes it.

## Review Focus

- Empty and exact-boundary Blobs must publish, synchronize, and read without manufacturing a segment or confusing EOF with missing content; Task 1 and Task 5 pin this.
- A crash or retry after lifecycle-owned stream-open reservation must reuse the same identity without exposing an incomplete publication or allocating a second counter; Task 2 pins this.
- A torn pack/checkpoint or mismatched open/final commitment must fail closed and resume only from the last durable segment; Task 3 and Task 6 pin this.
- TTL expiry, revocation, quota pressure, or deletion racing an active read/transfer must preserve policy and lease behavior without leaking or deleting bytes in use; Task 4 and Task 6 pin this.
- A healthy transfer lasting longer than 30 seconds must continue while durable progress advances, while a stalled transfer must terminate with a phase-specific error; Task 6 pins this.

---

### Task 1: Re-establish the Profile-5 segment contract

**Files:**
- Modify: `crates/aster-core/src/blob_stream.rs`
- Modify: `crates/aster-core/src/lib.rs`
- Modify: `crates/aster-core/src/transfer_profile.rs`
- Test: `crates/aster-core/src/blob_stream.rs`
- Test: `crates/aster-core/src/transfer_profile.rs`

**Interfaces:**
- Consumes: Existing `BlobStreamOpen`, `VerifiedBlobStreamOpen`, `BlobStreamFinalCommitment`, `EncryptedBlobStreamSegment`, `BlobStreamFrontier`, and `BLOB_STREAM_SEGMENT_BYTES`.
- Produces: Profile-5 segment/open/final types with no canonical-carrier/`ABX1` helpers; semantic-v9 Blob negotiation selects `TransferProfileId::BlobStreamV1` and does not fall back to the Blob range profile.

- [ ] **Step 1: Add failing contract tests**

Add tests named:

- `profile5_segment_is_the_storage_and_wire_partition`
- `profile5_empty_and_exact_boundaries_are_canonical`
- `semantic_v9_blob_selection_requires_profile5`
- `profile5_has_no_legacy_carrier_shape`

Assert 1-MiB full segments, one final short segment, authenticated identity/offset/length fields, deterministic roots, zero-length terminal handling, and no v9 selection of `BlobRangesStreamV1`.

- [ ] **Step 2: Run the focused tests and verify the regression is visible**

Run: `cargo test -p aster-core blob_stream --lib -- --nocapture`

Expected: the no-legacy-shape and v9-selection assertions fail against the current `Profile5CanonicalWireShape`/fallback behavior.

- [ ] **Step 3: Remove the regressed carrier model**

Delete `PROFILE5_CANONICAL_*`, `Profile5CanonicalCheckpoint`, `Profile5CanonicalWireShape`, and `profile5_canonical_wire_shape*`. Keep the existing `ASTRBS02` codec and independently authenticated segment/Merkle implementation. Retain current zero-length support rather than copying the older nonempty-only guard from `b81f4dab`.

- [ ] **Step 4: Make v9 Blob negotiation Profile-5-only**

Update `TransferProfileSelection` so semantic v9 selects `BlobStreamV1` only when authenticated capabilities include it; otherwise the Blob lane is unavailable/fails closed. Do not alter non-Blob lanes merely because a peer negotiates an older semantic version.

- [ ] **Step 5: Run core tests**

Run: `cargo test -p aster-core blob_stream --lib -- --nocapture`

Run: `cargo test -p aster-core transfer_profile --lib -- --nocapture`

Expected: PASS with no Profile-5 reference to `ASTRBT01` or `ABX1`.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-core/src/blob_stream.rs crates/aster-core/src/lib.rs crates/aster-core/src/transfer_profile.rs
git commit -S -m "refactor(blob): restore profile-5 segment contract"
```

### Task 2: Make stream-open reservation lifecycle-owned

**Files:**
- Modify: `crates/aster-redb-store/src/blob/upload.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-core/src/source_blob.rs`
- Test: `crates/aster-redb-store/src/blob/upload.rs`
- Test: `crates/aster-redb-store/src/blob.rs`

**Interfaces:**
- Consumes: `BlobOperationRequest`, `BlobReservation`, `BlobStreamOpen`, `VerifiedBlobStreamOpen`, `BlobUploadReservation`, control policy, custody samples, and operation-key retry rules.
- Produces: `Store::reserve_profile5_upload_with_policy<F>(...) -> Result<(BlobUploadReservation, BlobUploadCheckpoint, VerifiedBlobStreamOpen), StoreError>`, where `F: FnOnce(&BlobReservation, Option<&[u8]>) -> Result<(VerifiedBlobStreamOpen, Vec<u8>), StoreError>` signs a new open or re-verifies exact stored authenticated bytes after retry/restart. The Store never manufactures `VerifiedBlobStreamOpen` authority from persisted fields.

- [ ] **Step 1: Add failing lifecycle-reservation tests**

Add tests named:

- `profile5_open_reservation_is_invisible_until_atomic_promotion`
- `profile5_open_retry_reuses_identity_and_counter`
- `profile5_open_operation_conflict_does_not_mutate_state`
- `profile5_open_crash_before_commit_leaves_no_authority`
- `profile5_open_respects_ttl_policy_quota_and_deletion_fence`

Assert the stored provisional row binds operation intent, exact signed open, stream ID, publisher counter, policy generation, lifetime, capacity reservation, and pack identity while creating no publication/subscription/inventory visibility.

- [ ] **Step 2: Run the failing store tests**

Run: `cargo test -p aster-redb-store profile5_open_ --lib -- --nocapture`

Expected: FAIL because current upload reservations are deliberately nonsemantic and contain no authenticated `BlobStreamOpen`.

- [ ] **Step 3: Extend the upload record and reservation transaction**

Version the durable upload row for the unreleased format and persist the exact sealed open plus its verified projection. Validate that publisher, operation key, topic, scope, priority, TTL, epoch, policy revision, total length, and reserved counter agree with `BlobOperationRequest` and `BlobReservation` before commit.

- [ ] **Step 4: Implement `reserve_profile5_upload_with_policy`**

Reserve the semantic counter/identity and provisional lifecycle state in one immediate redb transaction, but do not accept or expose that identity. Exact retries return the same reservation/open; conflicts and pre-commit faults leave no counter, operation, upload, or capacity mutation. Final promotion converts the reservation into the ordinary semantic publication without allocating a second identity. Do not add application visibility or causal accepted-dot state until that promotion.

Publisher high-water is also the shared cross-data-class allocation fence. Advancing it at open reserves the dot, while accepted-dot and causal-frontier rows remain absent. A later publication may therefore commit at a higher counter before this upload finishes; promotion accepts the older reserved dot without requiring adjacent high-water and never lowers high-water.

- [ ] **Step 5: Run the focused reservation and lifecycle tests**

Run: `cargo test -p aster-redb-store profile5_open_ --lib -- --nocapture`

Expected: PASS, including forced reopen/retry cases.

- [ ] **Step 6: Commit**

```bash
git add crates/aster-core/src/source_blob.rs crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/upload.rs crates/aster-redb-store/src/blob/lifecycle.rs
git commit -S -m "feat(blob): own profile-5 opens in lifecycle"
```

### Task 3: Promote the pack into lifecycle-owned physical storage

**Files:**
- Create: `crates/aster-redb-store/src/blob/pack_lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/pack.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Test: `crates/aster-redb-store/src/blob/pack_lifecycle.rs`
- Test: `crates/aster-redb-store/src/blob/pack.rs`

**Interfaces:**
- Consumes: lifecycle-owned `BlobUploadReservation`, `VerifiedBlobStreamOpen`, `VerifiedBlobStreamFinalCommitment`, `BlobPackCheckpoint`, `PinnedBlobPackRoot`, and store/backing authority.
- Produces: nonconstructible `BlobPackCompletion`; `Store::complete_profile5_upload_pack(...) -> Result<BlobPackCompletion, StoreError>`; `Store::complete_profile5_received_pack(...) -> Result<BlobPackCompletion, StoreError>`; pack open/read helpers gated by completion plus a variant lease.

- [ ] **Step 1: Add failing pack-ownership tests**

Add tests named:

- `completed_profile5_pack_is_exactly_the_uploaded_pack`
- `pack_completion_binds_store_open_finish_roots_and_lengths`
- `pack_promotion_is_restart_safe_at_every_rename_boundary`
- `foreign_or_stale_completion_cannot_open_pack`
- `torn_checkpoint_reopens_at_last_durable_segment`

Assert promotion performs no segment decryption, re-encryption, 64-KiB splitting, or `BLOB_CHUNKS` insertion.

- [ ] **Step 2: Run the failing pack tests**

Run: `cargo test -p aster-redb-store profile5_pack_ --lib -- --nocapture`

Expected: FAIL because the upload pack is currently deleted after legacy depot finalization and no lifecycle-owned pack completion exists.

- [ ] **Step 3: Add `BlobPackCompletion` and physical record encoding**

In `pack_lifecycle.rs`, define the durable record and completion capability around exact store authority, backing identity, variant ID, stream/open identity, total length, segment count, pack length, plaintext/ciphertext roots, final-commitment digest, and physical lineage. Use a new unreleased encoding version; reject old experimental pack rows with reset/reimport guidance rather than migrating them.

- [ ] **Step 4: Implement atomic pack adoption**

Add descriptor-relative, no-follow pack adoption that synchronizes the completed pack/checkpoint, durably renames or rekeys its directory under the lifecycle variant identity, records the physical variant, and returns `BlobPackCompletion`. Recovery must finish or roll back marker/rename boundaries without exposing an incomplete variant.

- [ ] **Step 5: Add completion-gated read and transfer sessions**

Expose pack readers only through a matching `BlobPackCompletion` and the existing lease roles: `BlobLeaseKind::LocalImport` while adopting/finalizing, `BlobLeaseKind::ApplicationPageRead` while serving application plaintext, and `BlobLeaseKind::CarrierRange` while transferring pack records. Recheck exact pack identity/checkpoint before use without rescanning unrelated variants.

- [ ] **Step 6: Run pack tests**

Run: `cargo test -p aster-redb-store profile5_pack_ --lib -- --nocapture`

Run: `cargo test -p aster-redb-store blob::pack --lib -- --nocapture`

Expected: PASS with bounded restart recovery and no legacy chunk rows.

- [ ] **Step 7: Commit**

```bash
git add crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/pack.rs crates/aster-redb-store/src/blob/pack_lifecycle.rs crates/aster-redb-store/src/lib.rs
git commit -S -m "feat(blob): adopt profile-5 packs as physical variants"
```

### Task 4: Apply PR #95 lifecycle policy to pack variants

**Files:**
- Modify: `crates/aster-redb-store/src/blob/pack_lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/blob/pressure.rs`
- Modify: `crates/aster-redb-store/src/blob/deletion.rs`
- Modify: `crates/aster-redb-store/src/blob/lease.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Test: `crates/aster-redb-store/src/blob.rs`
- Test: `crates/aster-redb-store/src/blob/pressure.rs`
- Test: `crates/aster-redb-store/src/blob/deletion.rs`

**Interfaces:**
- Consumes: `BlobPackCompletion`, lifecycle provisional/pending rows, existing publication/reference indexes, lifecycle limits, lease registry, pressure ordering, and deletion manifests.
- Produces: `Store::commit_profile5_upload_once_with_policy(...) -> Result<BlobOnceOutcome, StoreError>` and `Store::apply_verified_profile5_pack_with_policy(...) -> Result<ApplyOutcome, StoreError>`; pack-aware accounting, retirement, pressure, and crash-resumable deletion.

- [ ] **Step 1: Add failing lifecycle integration tests**

Add tests named:

- `profile5_pack_promotion_updates_all_blob_indexes_atomically`
- `profile5_pack_exact_retry_is_idempotent_and_conflict_fails_closed`
- `profile5_pack_ttl_retirement_removes_visibility_before_bytes`
- `profile5_pack_pressure_evicts_only_strictly_lower_priority`
- `profile5_pack_deletion_waits_for_read_and_transfer_leases`
- `profile5_pack_deletion_failure_stays_charged_and_resumes_after_restart`

Each test must assert publication, accepted-dot/high-water, operation, subscription delivery, variant reference, lineage/replay fence, quota, and retirement behavior—not only file deletion.

- [ ] **Step 2: Run the failing lifecycle tests**

Run: `cargo test -p aster-redb-store profile5_pack_ --lib -- --nocapture`

Expected: FAIL because PR #95 lifecycle currently finalizes only manifest/chunk variants.

- [ ] **Step 3: Implement local atomic promotion**

Validate the exact reserved open, signed final commitment, `BlobPackCompletion`, current policy, custody samples, operation intent, and deletion fence. In one transaction, move provisional state to ordinary publication/operation/accepted-dot/subscription/reference indexes and bind the existing physical pack; then retire the provisional upload row without deleting the adopted pack.

- [ ] **Step 4: Implement remote atomic promotion**

Stage the authenticated stream open as ordinary pending source state, bind receiver checkpoint state to it, and promote the completed pack through the same publication/reference/index transaction. Preserve monotone custody age, exact duplicate/equivocation outcomes, route and physical lineage checks, and finite-profile provenance.

- [ ] **Step 5: Generalize quota, pressure, and deletion by physical variant kind**

Charge pack bytes, one variant, bounded checkpoint/metadata rows, and no synthetic 64-KiB chunk rows. Move pack ownership into deletion authority when the final root retires; unlink the exact pack directory under restart-safe markers; release capacity only after durable deletion finalization. Existing chunk-specific code may remain for historical non-v9 tests until Task 8, but no Profile-5 path may enter it.

- [ ] **Step 6: Run focused lifecycle suites**

Run: `cargo test -p aster-redb-store profile5_pack_ --lib -- --nocapture`

Run: `cargo test -p aster-redb-store blob_lifecycle --lib -- --nocapture`

Run: `cargo test -p aster-redb-store blob_pressure --lib -- --nocapture`

Expected: PASS with pack bytes charged through failed deletion and protected by active leases.

- [ ] **Step 7: Commit**

```bash
git add crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/pack_lifecycle.rs crates/aster-redb-store/src/blob/lifecycle.rs crates/aster-redb-store/src/blob/pressure.rs crates/aster-redb-store/src/blob/deletion.rs crates/aster-redb-store/src/blob/lease.rs
git commit -S -m "feat(blob): apply lifecycle policy to profile-5 packs"
```

### Task 5: Publish and read the canonical pack without finalization conversion

**Files:**
- Modify: `crates/aster-node/src/application/blob_stream.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Modify: `crates/aster-node/examples/blob_benchmark.rs`
- Test: `crates/aster-node/src/application/blob_stream.rs`
- Test: `crates/aster-node/src/application/blob.rs`

**Interfaces:**
- Consumes: Tasks 2--4 reservation/completion/promotion APIs, `FixedPartitionMapPool`, provider stream-open/segment/final APIs, and `BlobPackReader`/`BlobPackWriter`.
- Produces: `open_publish_stream`, streamed writes, `finish`, ordinary file publish, and authenticated reads that all operate on the same final 1-MiB pack; `BlobPublishResult` remains unchanged.

- [ ] **Step 1: Add failing application tests**

Add tests named:

- `publish_reads_plaintext_once_and_promotes_same_pack`
- `publish_does_not_create_legacy_chunks_or_run_conversion_finalizer`
- `empty_exact_and_partial_segment_blobs_round_trip`
- `publish_completion_does_not_wait_for_peer`
- `read_uses_bounded_parallel_pack_pipeline_and_rechecks_policy`

Instrument source reads, pack identity, depot operations, buffer peaks, and lifecycle visibility. Assert a 17-MiB test produces 17 segments, not 272 legacy chunks.

- [ ] **Step 2: Run the failing application tests**

Run: `cargo test -p aster-node application::blob --lib -- --nocapture`

Expected: FAIL on the current `BlobFinalizePool` conversion and legacy-depot assertions.

- [ ] **Step 3: Restore direct publication composition**

At stream open, call `reserve_profile5_upload_with_policy`, use the returned verified open to obtain the provider sealer, and write mapped 1-MiB segments to the reservation's pack. On finish, checkpoint/finalize the pack, build and authenticate `BlobStreamFinalCommitment`, obtain `BlobPackCompletion`, and call `commit_profile5_upload_once_with_policy`.

- [ ] **Step 4: Remove the conversion finalizer**

Delete `BlobFinalizePool`, mapped-chunk structures, `UploadPackPlainReader`, canonical-digest sidecar work used only for 64-KiB conversion, and `complete_prepared_local_blob` calls from the Profile-5 application path. Preserve bounded worker/queue metrics on the actual partition/encrypt/pack pipeline.

- [ ] **Step 5: Route reads through the lifecycle-gated pack**

Use the provider opener and ordered bounded read pipeline over exact stored segments. Recheck policy/revocation/TTL before each public page boundary and hold the application-read lease for the active pack reader.

- [ ] **Step 6: Update the benchmark to report real stages**

Keep the current streaming public API benchmark changes, but report reservation/open, source read/map, pack checkpoint, lifecycle promotion, synchronization, verification, and destination read separately. Do not count source-file generation in publication time.

- [ ] **Step 7: Run application and benchmark smoke tests**

Run: `cargo test -p aster-node application::blob --lib -- --nocapture`

Run: `cargo run -p aster-node --example blob_benchmark -- --help`

Expected: PASS; the benchmark exposes the new stage names and no conversion-finalizer metrics.

- [ ] **Step 8: Commit**

```bash
git add crates/aster-node/src/application/blob.rs crates/aster-node/src/application/blob_stream.rs crates/aster-node/examples/blob_benchmark.rs
git commit -S -m "refactor(blob): publish and read canonical profile-5 packs"
```

### Task 6: Transfer exact stored segments through the selected adapter

**Files:**
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/frame.rs`
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-node/src/runtime/blob_progress_test.rs`
- Test: `crates/aster-node/src/runtime/blob_stream.rs`
- Test: `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Consumes: lifecycle-visible stream source/open/final bytes, `BlobPackCompletion`, `StreamTransportAdapter`, `BlobProfile5Receipt`, `BlobStreamResume`, and Task 4 remote promotion.
- Produces: direct `send_profile5_pack(...)` and `receive_profile5_pack(...)` paths; segment-index/pack-offset durable checkpoints; progress-aware transfer deadlines.

- [ ] **Step 1: Add failing runtime tests**

Add tests named:

- `profile5_sends_exact_pack_records_without_legacy_carriers`
- `profile5_receiver_checkpoints_segment_boundaries_and_resumes`
- `profile5_transfer_over_one_mib_uses_selected_adapter`
- `profile5_transfer_preserves_content_proof_route_cache_and_terminal_eof`
- `active_progress_outlives_contact_deadline_but_stall_times_out`
- `ttl_or_revocation_during_transfer_prevents_promotion`

Compare each transmitted DATA body with the corresponding stored `ASTRBS02` record. Assert no call reaches `read_profile5_sender_carrier`, `BlobTransferObject`, `ABX1`, or the range lane.

- [ ] **Step 2: Run the failing runtime tests**

Run: `cargo test -p aster-node runtime::blob_stream --lib -- --nocapture`

Expected: FAIL because current canonical send/receive functions build and parse `ABX1` extents of legacy carriers.

- [ ] **Step 3: Restore the pack sender**

Base the implementation on the bounded sender at `b81f4dab`: read one exact length-prefixed pack segment at a time under a transfer lease, feed it through the selected adapter, and advance credit only from receiver durable checkpoints. Adapter fragmentation is byte transport only and must not alter segment/storage identity.

- [ ] **Step 4: Restore the pack receiver and lifecycle promotion**

Authenticate the signed open/content proof before accepting bytes, resume the exact pending source and pack checkpoint, verify segments in bounded workers, append them in order, checkpoint by configured group, authenticate the final commitment, obtain `BlobPackCompletion`, and call `apply_verified_profile5_pack_with_policy`.

- [ ] **Step 5: Preserve valid post-regression fixes**

Keep the current `BlobStreamSourceOfferV1.content_proof` binding, route-cache update for both inserted and already-present promotion, RESULT_ACK followed by DATA EOF consumption, bounded public error mapping, and the working-tree benchmark/runtime updates that remain applicable.

- [ ] **Step 6: Separate handshake and data deadlines**

Keep a short connection/authentication deadline. Remove the fixed `CONTACT_DEADLINE` wrapper around the full Blob attempt; use the existing 120-second authenticated-progress watchdog and an exact-size-derived hard safety limit. Add deterministic paused-time tests for progress and stall behavior.

- [ ] **Step 7: Run focused runtime and real-adapter tests**

Run: `cargo test -p aster-node runtime::blob_stream --lib -- --nocapture`

Run: `cargo test -p aster-node profile5 --lib -- --nocapture`

Expected: PASS with matching hashes, resumed segment checkpoints, selected-adapter use, and no false terminal close.

- [ ] **Step 8: Commit**

```bash
git add crates/aster-node/src/frame.rs crates/aster-node/src/runtime.rs crates/aster-node/src/runtime/blob_progress_test.rs crates/aster-node/src/runtime/blob_stream.rs crates/aster-node/src/stream_transfer.rs crates/aster-redb-store/src/blob/stream.rs
git commit -S -m "refactor(blob): transfer canonical profile-5 packs"
```

### Task 7: Keep PR #95 agent and CLI workflows correct

**Files:**
- Modify if required: `crates/aster-agent/src/blob_service.rs`
- Modify if required: `crates/asterctl/src/blob_publish.rs`
- Modify if required: `crates/asterctl/src/blob_read.rs`
- Modify if required: `crates/asterctl/src/blob_status.rs`
- Modify: `crates/asterctl/tests/blob.rs`
- Modify: `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs`
- Test: `crates/asterctl/tests/blob.rs`

**Interfaces:**
- Consumes: unchanged public Blob publish/read/status/subscription APIs from Task 5.
- Produces: unchanged operator workflow with accurate local-durable progress/status and no transport or segment controls exposed.

- [ ] **Step 1: Add end-to-end public-surface tests**

Cover file publish, streamed publish, status during provisional/durable/retired phases, authenticated read, subscription delivery/acknowledgement, empty Blob, peer-unavailable local completion, and interrupted client export restarting at byte zero.

- [ ] **Step 2: Run tests before surface changes**

Run: `cargo test -p asterctl --test blob -- --nocapture`

Run: `cargo test -p aster-agent blob --lib -- --nocapture`

Expected: either PASS unchanged or fail only where internal progress/status names still describe carriers/finalization conversion.

- [ ] **Step 3: Make only required compatibility-neutral surface adjustments**

Retain existing RPC and CLI request/response shapes. Translate internal segment/pack progress into accepted/durable/transferred/verified/promoted states. Do not add `--transport`, `--segment-size`, or download-resume flags.

- [ ] **Step 4: Run public-surface tests**

Run: `cargo test -p asterctl --test blob -- --nocapture`

Run: `cargo test -p aster-agent blob --lib -- --nocapture`

Expected: PASS.

- [ ] **Step 5: Commit only if files changed**

```bash
git add crates/aster-agent/src/blob_service.rs crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs crates/asterctl/src/blob_publish.rs crates/asterctl/src/blob_read.rs crates/asterctl/src/blob_status.rs crates/asterctl/tests/blob.rs
git commit -S -m "test(blob): cover profile-5 operator workflow"
```

### Task 8: Remove the regressed active path and update protocol documentation

**Files:**
- Modify: `crates/aster-core/src/blob_stream.rs`
- Modify: `crates/aster-core/src/transfer_profile.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `docs/protocol.md`
- Modify: `docs/validation/blob-streaming-engineering-runbook.md`
- Modify: `docs/validation/blob-streaming-performance.md`
- Modify: `docs/validation/capability-roadmap.md`
- Modify as required: conformance vectors/oracles that encode semantic-v9 Profile-5 frames

**Interfaces:**
- Consumes: completed direct-pack implementation and test evidence from Tasks 1--7.
- Produces: one documented semantic-v9/profile-5 Blob path; obsolete 64-KiB Profile-5 conversion/fallback code and claims removed.

- [ ] **Step 1: Add a repository guard for forbidden Profile-5 concepts**

Add/extend a focused validation script or protocol test so current Profile-5 code/docs cannot describe `ASTRBT01`, `ABX1`, canonical 64-KiB Blob chunks, or pre-profile-5 Blob eligibility as active v9 behavior. Historical evidence may retain those strings only when explicitly labeled superseded.

- [ ] **Step 2: Run the guard and confirm current failures**

Run: `rg -n "ASTRBT01|ABX1|65,536-byte canonical|pre-profile-5 canonical" crates/aster-core/src/blob_stream.rs crates/aster-node/src/runtime/blob_stream.rs docs/validation/blob-streaming-*.md`

Expected: current active-path matches are reported.

- [ ] **Step 3: Remove obsolete active-path code and tests**

Delete Profile-5 carrier codec/batching, upload-to-chunk finalizer code left after Task 5, v9-to-profile4 Blob fallback, legacy Profile-5 eligibility tests, and dead metrics/facades. Keep older semantic code only where another still-supported non-Blob lane or explicit historical fixture requires it; it must be unreachable from semantic-v9 Blob selection.

- [ ] **Step 4: Update protocol, runbook, examples, and evidence boundary**

Document `ASTRBS02`, 1-MiB segments, pack checkpoints, lifecycle ownership, local publication independence, selected-adapter behavior, timeout phases, post-merge CLI download resume, and development-depot reset/reimport. Label the 64-KiB CM4/current-candidate sections superseded rather than presenting them as qualification.

- [ ] **Step 5: Run traceability and hostile-input checks**

Run: `python3 tools/check-implementation-requirements.py`

Run: `mise run fuzz-smoke`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates docs tools
git commit -S -m "docs(blob): cut over profile 5 to canonical packs"
```

### Task 9: Verify the candidate and retain CM4 performance evidence

**Files:**
- Modify: `docs/validation/blob-streaming-performance.md`
- Modify: `docs/validation/blob-streaming-engineering-runbook.md`
- Create: `docs/validation/evidence/2026-10-22-profile5-pack-cm4-validation.md`
- Modify if required: `.github` only for a demonstrated CI defect, never to package or deploy this candidate.

**Interfaces:**
- Consumes: exact signed candidate from Tasks 1--8 and the three existing CM4 devices.
- Produces: retained raw-WLAN and full data-plane evidence for warmed 800-MiB and 1-GiB transfers; final focused/local/CI gate results.

- [ ] **Step 1: Run formatting, lint, focused suites, and repository checks serially**

Run: `cargo fmt --all -- --check`

Run: `cargo clippy --workspace --all-targets --all-features -- -D warnings`

Run the focused commands from Tasks 1--8 serially.

Run: `python3 tools/check-implementation-requirements.py`

Expected: PASS. Do not run repeated full local suites while fixing focused failures.

- [ ] **Step 2: Build the exact ARM64 candidate through CI**

Use the existing temporary build trigger/CI artifact workflow without production deployment or packaging changes. Record commit SHA and SHA-256 for `asterctl`, the acceptance fixture, `blob_benchmark`, and transport benchmark.

- [ ] **Step 3: Distribute once and verify artifact identity on all CM4s**

Download to one CM4 over ZeroTier control access, verify the digest, and distribute to the other two over WLAN. Confirm all three hashes match the CI artifact before testing.

- [ ] **Step 4: Capture topology and raw baselines**

Record interfaces, routes, addresses, RTT/loss, direct/relay result, and raw 800-MiB/1-GiB WLAN throughput. ZeroTier remains SSH/control only; payload uses `192.168.60.0/24` WLAN.

- [ ] **Step 5: Run warmed composite 800-MiB and 1-GiB tests**

Measure reservation/open, source read/map/encrypt, pack durability, lifecycle promotion, discovery, transfer, receiver verify/checkpoint, receiver promotion, and destination read. Capture hashes, errors, CPU, peak RSS, disk usage, checkpoint count, and interface counters.

Expected gates:

- 1-GiB local publication approximately 105--108 seconds, not 620 seconds;
- destination read approximately 90--93 seconds;
- composite 1-GiB no slower than approximately 242 seconds;
- zero active-progress contact timeouts;
- matching source/stored/transferred/exported hashes; and
- bounded RSS independent of Blob length.

- [ ] **Step 6: Investigate measured failures by pipeline stage**

If a gate fails, stop the large test, reproduce on the smallest size showing the same stage bottleneck, and use stage queue/service/blocked/durability metrics before changing concurrency or checkpoint cadence. Do not hide a processing bottleneck by increasing timeouts.

- [ ] **Step 7: Run the complete repository gate once**

Run: `mise run check`

Expected: PASS. CI evidence may substitute for resource-prohibitive duplicate local execution only when the exact commit and artifact are recorded.

- [ ] **Step 8: Retain evidence and commit**

```bash
git add docs/validation/blob-streaming-performance.md docs/validation/blob-streaming-engineering-runbook.md docs/validation/evidence/2026-10-22-profile5-pack-cm4-validation.md
git commit -S -m "docs(blob): retain profile-5 pack CM4 evidence"
```

Do not push until the evidence meets the gates and the user authorizes the push.
