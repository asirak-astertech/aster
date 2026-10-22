# PR 110 Review Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make semantic-v9/profile-5 a bounded streaming transport for the one canonical Blob authority while fixing all 17 findings in the PR 110 review report.

**Architecture:** Local uploads retain only provisional, node-protected staging until finalization allocates the canonical causal identity and commits through the existing Blob publication path. Network profile 5 inventories and transfers canonical source envelopes, manifests, and encrypted chunk records in bounded extents; profile 4 and profile 5 therefore move the same publication and share lifecycle, subscription, quota, and read authorities.

**Tech Stack:** Rust 2024, Tokio, redb, existing `aster-mesh` Blob codecs and custody proofs, Iroh QUIC through `StreamTransportAdapter`, Python protocol/conformance tooling, cargo-fuzz.

**Spec:** `docs/superpowers/specs/2026-10-21-pr110-review-remediation-design.md`

## Global Constraints

- Preserve semantic-v7/v8 profile-4 wire behavior byte-for-byte.
- Semantic v9 uses profile 5 and fails closed on unknown critical records or extents.
- Replace the unreleased PR 95 `PublishBlob` wire exchange with the current
  bidirectional `v1alpha1` stream; require generated-client regeneration and do
  not retain an additive legacy upload method when no production deployment
  depends on it. Keep Blob semantic identity and operation-key recovery intact.
- Keep local publication peer-independent; only network synchronization waits for a destination.
- Bound memory independently of Blob size and keep one checkpoint batch at or below 128 MiB.
- Distinguish canonical plaintext chunk, encoded chunk-record, and batched extent limits; derive encoded limits from the codec.
- Charge provisional, pending, and completed data to the configured canonical Blob limits; do not retain a separate 16-GiB pool.
- Allocate the publisher counter and causal context only in the final canonical publication transaction.
- Keep transport mechanics dependent only on `StreamTransportAdapter`; no Blob semantic/store type may depend on Iroh, QUIC, IP, or MTU types.
- Preserve canonical pre-PR databases. Reject nonempty experimental split-authority state explicitly; never discard or infer it.
- Use test-first increments and signed commits. Do not push or deploy while executing this plan unless separately authorized.
- Run focused tests during implementation; reserve the serial repository suite and CM4 validation for final gates.

## Review Focus

- An upload that loses policy authorization between its last data page and finalization must publish nothing and retain only correctly charged cleanup authority (Task 3).
- A canonical publication shared by multiple publishers or operations must not duplicate physical capacity charge or lose a live reference (Tasks 2 and 5).
- Empty, exact-chunk-boundary, and maximum-size Blobs must produce valid manifests, checkpoints, extents, and terminal settlement without special-case hangs (Tasks 3, 4, and 6).
- A crash between file synchronization and redb projection, or between canonical promotion and provisional cleanup, must reopen to one auditable state and converge idempotently (Tasks 2, 3, and 10).
- Cancellation while the reorder buffer is full and at least one map worker is active must join all workers before returning and release every byte/item permit (Task 8).

---

## File structure

- `crates/aster-redb-store/src/blob/upload.rs`: provisional application-upload reservation, owner-qualified identity, durable checkpoint, unified capacity charge, cleanup, and audit.
- `crates/aster-redb-store/src/blob/stream.rs`: profile-5 network receipt checkpoint only; remove semantic publication, operation, lifecycle, and variant authority.
- `crates/aster-redb-store/src/blob.rs`: canonical publication/operation helpers, migration, quota, pending source, subscription, lifecycle, and finalization integration.
- `crates/aster-redb-store/src/blob/pack.rs`: node-protected provisional upload records and restart journal; it must not represent published content.
- `crates/aster-core/src/blob_stream.rs`: bounded provisional-upload record codec only; remove competing semantic publication identity and roots.
- `crates/aster-node/src/application/blob_stream.rs`: bounded upload pipeline that finalizes into the canonical Blob API.
- `crates/aster-node/src/application/blob.rs`: shared canonical finalization and per-page authorization.
- `crates/aster-node/src/runtime/blob_stream.rs`: canonical profile-5 sender/receiver pipeline.
- `crates/aster-node/src/stream_transfer.rs`: profile-5 record framing and terminal state machine.
- `crates/aster-node/src/stream_transport.rs`: transport selection/attempt boundary and real-adapter integration tests.
- `crates/aster-node/src/stream_pipeline.rs`: cancellation and worker-join guarantees.
- Protocol, fuzz, API, operator, roadmap, and validation documents listed in Tasks 9 and 11.

### Task 1: Canonical operation ownership and atomic causal allocation

**Files:**
- Modify: `crates/aster-redb-store/src/blob.rs`
- Test: `crates/aster-redb-store/src/blob.rs`

**Interfaces:**
- Produces: `BlobOperationOwner { publisher: NodeId, operation: BlobOperationKey }`, `Store::blob_for_owned_operation_with_policy(&self, policy: &ControlPolicySnapshot, owner: &BlobOperationOwner, intent: &BlobPublicationIntent) -> Result<Option<StoredBlob>, StoreError>`, and `Store::commit_prepared_local_blob_once_with_policy<F>(&self, policy: &ControlPolicySnapshot, request: &BlobOperationRequest<'_>, ttl_ms: Option<u64>, initial_sample: Option<CustodySample>, precommit_sample: Option<CustodySample>, completion: &BlobDepotCompletion, build: F) -> Result<BlobOnceOutcome, StoreError>` where `F: FnOnce(&BlobReservation) -> Result<(ContentVerifiedBlobEnvelope, Vec<u8>), StoreError>`.
- Consumes: existing `BlobPublicationIntent`, `BlobReservation`, `BlobDepotCompletion`, lifecycle, acceptance-order, and causal-ledger helpers.

- [ ] **Step 1: Write failing owner and final-allocation regressions**

  Add `blob_operations_are_publisher_qualified_and_migrate_exactly` and `prepared_local_blob_allocates_one_dot_only_at_atomic_commit`. Assert identical operation bytes for two publishers do not collide, no counter/frontier changes occur during preparation, an unrelated publication may commit, final Blob commit gets the next unique dot, and exact retry returns the original result.

- [ ] **Step 2: Run the focused tests and confirm the old raw-key/counter behavior fails**

  Run: `cargo test -p aster-redb-store blob_operations_are_publisher_qualified_and_migrate_exactly -- --nocapture && cargo test -p aster-redb-store prepared_local_blob_allocates_one_dot_only_at_atomic_commit -- --nocapture`

  Expected: FAIL because `BLOB_OPERATIONS` is raw-keyed and final allocation is not exposed atomically.

- [ ] **Step 3: Implement owner-qualified operations and final allocation**

  Key active and retired operation records by a length-delimited `(publisher, operation)` encoding. Migrate predecessor rows by resolving their exact publication publisher; reject orphan or ambiguous rows without mutation. Make `commit_prepared_local_blob_once_with_policy` recheck policy, allocate counter/context, seal the canonical source, and commit operation, acceptance order, subscriptions, lifecycle, and causal ledgers in one transaction.

- [ ] **Step 4: Run focused store tests**

  Run: `cargo test -p aster-redb-store blob_operations_are_publisher_qualified_and_migrate_exactly -- --nocapture && cargo test -p aster-redb-store prepared_local_blob_allocates_one_dot_only_at_atomic_commit -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-redb-store/src/blob.rs && git commit -S -m "fix(blob): allocate canonical upload identity atomically"`

### Task 2: Provisional upload authority and unified capacity

**Files:**
- Create: `crates/aster-redb-store/src/blob/upload.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/pack.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Test: `crates/aster-redb-store/src/blob/upload.rs`

**Interfaces:**
- Consumes: `BlobOperationOwner` and canonical depot/lifecycle capacity helpers from Task 1.
- Produces: `BlobUploadRequest { owner, topic, scope, priority, ttl_ms, media_type, schema_id, total_len }`, `BlobUploadReservation`, `BlobUploadCheckpoint`, `Store::reserve_blob_upload_with_policy(&self, policy: &ControlPolicySnapshot, request: &BlobUploadRequest) -> Result<(BlobUploadReservation, BlobUploadCheckpoint), StoreError>`, `Store::checkpoint_blob_upload(&self, policy: &ControlPolicySnapshot, reservation: &BlobUploadReservation, expected: BlobUploadCheckpoint, durable: BlobPackCheckpoint) -> Result<BlobUploadCheckpoint, StoreError>`, `Store::resume_blob_upload(&self, owner: &BlobOperationOwner) -> Result<Option<(BlobUploadReservation, BlobUploadCheckpoint)>, StoreError>`, `Store::complete_blob_upload(&self, reservation: &BlobUploadReservation, publication: BlobTransferId) -> Result<(), StoreError>`, and `Store::abort_blob_upload(&self, reservation: &BlobUploadReservation) -> Result<bool, StoreError>`.

- [ ] **Step 1: Write failing reservation, restart, and capacity tests**

  Add `upload_restart_restores_exact_request_and_checkpoint`, `upload_capacity_remains_charged_through_canonical_promotion`, and `upload_crash_boundaries_reopen_to_one_authority`. Assert the reservation persists owner, topic, scope, priority, TTL, metadata, declared length, policy/epoch binding, and checkpoint; configured depot limits cover provisional plus completed bytes; promotion transfers rather than drops the charge; each sync/projection fault reopens without invented progress or double ownership.

- [ ] **Step 2: Run and observe missing unified upload authority**

  Run: `cargo test -p aster-redb-store upload_ -- --nocapture`

  Expected: FAIL because the upload module and unified accounting do not exist.

- [ ] **Step 3: Implement provisional authority**

  Keep the pack as node-protected provisional storage, rename its public concepts from semantic stream publication to upload staging, and store canonical-chunk digests/checkpoints needed for final conversion. Reserve worst-case staging bytes against configured Blob limits, synchronize pack data and alternating journal before redb projection, and transfer/release charge only through restart-safe canonical lifecycle transitions.

- [ ] **Step 4: Run upload, depot, and capacity tests**

  Run: `cargo test -p aster-redb-store upload_ -- --nocapture && cargo test -p aster-redb-store physical_depot_byte_chunk_and_variant_caps_are_durable_and_atomic -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-redb-store/src/blob/upload.rs crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/pack.rs crates/aster-redb-store/src/lib.rs && git commit -S -m "refactor(blob): unify upload staging capacity"`

### Task 3: Local streaming finalizes one canonical publication

**Files:**
- Modify: `crates/aster-core/src/blob_stream.rs`
- Modify: `crates/aster-core/src/lib.rs`
- Modify: `crates/aster-node/src/application/blob_stream.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Test: `crates/aster-node/src/application/blob.rs`

**Interfaces:**
- Consumes: Task 2 upload APIs and Task 1 canonical finalization.
- Produces: unchanged `SelectedBlobHandle::open_publish_stream`, `SelectedBlobPublishStream::{write, finish}`, and `BlobPublishResult`; internal `finalize_blob_upload(&mut self, BlobUploadReservation) -> Result<BlobPublishResult, ApplicationError>`.

- [ ] **Step 1: Write failing canonical-local-upload tests**

  Replace split-publication expectations with `stream_upload_finishes_as_canonical_blob_and_exact_retry`, `two_uploads_and_unrelated_publication_get_unique_dots`, `stream_upload_policy_change_before_finish_publishes_nothing`, and `stream_upload_handles_empty_exact_chunk_and_maximum_boundaries`. Assert ordinary read, inspection, operation replay, acceptance order, lifecycle, and capacity APIs see exactly one canonical Blob.

- [ ] **Step 2: Run the focused application tests**

  Run: `cargo test -p aster-node stream_upload_ -- --nocapture && cargo test -p aster-node two_uploads_and_unrelated_publication_get_unique_dots -- --nocapture`

  Expected: FAIL because finish promotes to `BLOB_STREAM_PUBLICATIONS` and the open reserves causal identity.

- [ ] **Step 3: Implement bounded canonical finalization**

  Remove semantic counter/context from the provisional open. During upload, record canonical 64-KiB plaintext chunk digests and node-protected staged records with bounded buffers. At finish, construct the canonical manifest, map provisional decrypt plus canonical chunk encryption through the shared bounded worker pool, write through `BlobDepot`, and call `commit_prepared_local_blob_once_with_policy`. Preserve exact restart and retry behavior.

- [ ] **Step 4: Run focused application and agent contract tests**

  Run: `cargo test -p aster-node stream_upload_ -- --nocapture && cargo test -p aster-node selected_blob_publish_stream_promotes_and_replays_exact_operation -- --nocapture && cargo test -p aster-agent blob -- --nocapture`

  Expected: PASS with unchanged public API shapes.

- [ ] **Step 5: Commit**

  `git add crates/aster-core/src/blob_stream.rs crates/aster-core/src/lib.rs crates/aster-node/src/application/blob_stream.rs crates/aster-node/src/application/blob.rs && git commit -S -m "refactor(blob): finalize streams through canonical publication"`

### Task 4: Profile-5 canonical record codec and sender

**Files:**
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Modify: `crates/aster-core/src/transfer_profile.rs`
- Test: `crates/aster-node/src/stream_transfer.rs`
- Test: `crates/aster-node/src/runtime/blob_stream.rs`

**Interfaces:**
- Consumes: canonical `StoredBlob`, source envelope, manifest, depot chunk records, and `StreamTransportAdapter`.
- Produces: `CanonicalBlobExtentV1 { first_chunk_index: u64, records: Vec<BlobChunkRecord> }`, `CanonicalBlobExtentV1::encode(&self) -> Result<Vec<u8>, StreamError>`, `CanonicalBlobExtentV1::decode(bytes: &[u8]) -> Result<Self, StreamError>`, and `send_canonical_blob_profile5(adapter: &dyn StreamTransportAdapter, store: &Store, policy: &ControlPolicySnapshot, publication: BlobTransferId, session: &MissionSession) -> Result<BlobNetworkReport, BlobNetworkError>`.

- [ ] **Step 1: Write failing codec, inventory, and compatibility tests**

  Add `profile5_extent_batches_complete_canonical_chunk_records`, `pre_profile5_blob_is_profile5_sender_eligible`, and `stream_published_blob_remains_profile4_eligible_for_v8`. Assert codec limits separately cover plaintext chunks, encoded records, and batched extents; existing canonical Blobs appear in v9 inventory; the same new publication selects profile 4 with v8 and profile 5 with v9.

- [ ] **Step 2: Run and confirm split inventory/pack framing fails**

  Run: `cargo test -p aster-node profile5_extent_ -- --nocapture && cargo test -p aster-node pre_profile5_blob_is_profile5_sender_eligible -- --nocapture && cargo test -p aster-node stream_published_blob_remains_profile4_eligible_for_v8 -- --nocapture`

  Expected: FAIL because profile 5 inventories stream publications and emits pack records.

- [ ] **Step 3: Implement canonical sender and extent batching**

  Derive inventory from canonical publications and authenticated interest/lifecycle rules. Bind `StreamOpenV1` to the exact canonical source identity and custody evidence. Batch whole existing encrypted chunk records up to the profile-5 extent ceiling without changing their bytes or Blob identity; retain v7/v8 profile-4 selection unchanged.

- [ ] **Step 4: Run codec, lanes, and negotiation tests**

  Run: `cargo test -p aster-node stream_transfer -- --nocapture && cargo test -p aster-node blob_ranges_stream_lanes -- --nocapture && python3 tools/test-protocol-version-contract.py`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-node/src/stream_transfer.rs crates/aster-node/src/runtime/blob_stream.rs crates/aster-node/src/runtime.rs crates/aster-core/src/transfer_profile.rs && git commit -S -m "refactor(stream): send canonical blobs over profile 5"`

### Task 5: Canonical receiver, subscriptions, lifetime, and network identity

**Files:**
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/depot.rs`
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Test: `crates/aster-redb-store/src/blob/stream.rs`
- Test: `crates/aster-node/src/runtime/blob_stream.rs`

**Interfaces:**
- Consumes: `CanonicalBlobExtentV1` from Task 4 and existing pending-source/apply APIs.
- Produces: `BlobProfile5Receipt`, keyed by `(receiving authority, canonical source transfer id)`, `Store::reserve_profile5_receipt(&self, policy: &ControlPolicySnapshot, source: &VerifiedBlobTransferPlan) -> Result<(BlobProfile5Receipt, BlobStreamResume), StoreError>`, `Store::checkpoint_profile5_receipt(&self, receipt: &BlobProfile5Receipt, expected: BlobStreamResume, durable: BlobStreamResume) -> Result<BlobStreamResume, StoreError>`, and `Store::resume_profile5_receipt(&self, source: BlobTransferId) -> Result<Option<(BlobProfile5Receipt, BlobStreamResume)>, StoreError>`.

- [ ] **Step 1: Write failing receiver regressions**

  Add `independent_publishers_with_same_operation_receive_without_collision`, `profile5_promotion_delivers_existing_subscription_once`, `finite_profile5_transfer_uses_receiver_local_custody_age`, and `profile5_completed_bytes_remain_charged_until_canonical_reclamation`. Assert promotion uses canonical acceptance order, normal acknowledgements/retirement, configured quota, and different receiver clock identities.

- [ ] **Step 2: Run and observe split-authority failures**

  Run: `cargo test -p aster-redb-store profile5_ -- --nocapture && cargo test -p aster-node completed_canonical_blob_crosses_v9 -- --nocapture`

  Expected: FAIL because receipts share application operations and promotion bypasses canonical authorities.

- [ ] **Step 3: Implement canonical receive and promotion**

  Persist only receiver checkpoint/attempt state in `blob/stream.rs`. Stage verified source/manifest/chunks through the canonical pending-source and depot APIs, import authenticated finite age into receiver-local custody continuity, and promote with `apply_verified_blob_with_policy`. Remove network use of application operation keys and all stream publication/variant/retirement behavior.

- [ ] **Step 4: Run receiver, subscription, lifecycle, and quota tests**

  Run: `cargo test -p aster-redb-store profile5_ -- --nocapture && cargo test -p aster-node completed_canonical_blob_crosses_v9 -- --nocapture && cargo test -p aster-node blob_subscription_ -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-redb-store/src/blob/stream.rs crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/depot.rs crates/aster-node/src/runtime/blob_stream.rs && git commit -S -m "fix(stream): promote profile 5 through canonical blob authority"`

### Task 6: Resume terminal settlement and receiver-authoritative checkpoints

**Files:**
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Test: `crates/aster-node/src/stream_transfer.rs`
- Test: `crates/aster-node/src/runtime/blob_stream.rs`

**Interfaces:**
- Consumes: Task 5 receipt checkpoints.
- Produces: `StreamSenderState::accept(...) -> Result<StreamAction, StreamError>` returning `SendFinish` when accepted durable offset equals total; no new public API.

- [ ] **Step 1: Write the failing fully-checkpointed retry test**

  Add `fully_checkpointed_retry_sends_finish_without_waiting_for_data` at state-machine level and `fully_checkpointed_runtime_retry_settles_exactly_once` at runtime level. Assert no data/checkpoint wait, one promotion/result, and idempotent result acknowledgement.

- [ ] **Step 2: Run and confirm the deadlock path**

  Run: `cargo test -p aster-node fully_checkpointed_ -- --nocapture`

  Expected: FAIL because the sender waits for another checkpoint.

- [ ] **Step 3: Implement immediate terminal action**

  Make accepted total-length progress transition directly to Finish while preserving fresh attempt nonce, binding, generation, and final commitment checks. Keep cumulative checkpoints for nonterminal attempts.

- [ ] **Step 4: Run state-machine and runtime resume tests**

  Run: `cargo test -p aster-node fully_checkpointed_ -- --nocapture && cargo test -p aster-node stream_transfer -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-node/src/stream_transfer.rs crates/aster-node/src/runtime/blob_stream.rs && git commit -S -m "fix(stream): settle fully checkpointed retries"`

### Task 7: Reauthorize every read page

**Files:**
- Modify: `crates/aster-node/src/application/blob.rs`
- Modify: `crates/aster-node/src/application/blob_stream.rs`
- Test: `crates/aster-node/src/application/blob.rs`

**Interfaces:**
- Consumes: canonical `BlobReadPlan` and `Store::require_blob_read_plan_with_policy`.
- Produces: one canonical cached-reader path; split stream-publication reader is removed.

- [ ] **Step 1: Write the failing cached-reader revocation matrix**

  Add `cached_blob_reader_rechecks_revocation_epoch_grants_and_lifecycle_each_page`. For each authority mutation after page one, assert page two returns the sanitized public denial, emits no plaintext, and clears the cached reader.

- [ ] **Step 2: Run and reproduce stale cached authorization**

  Run: `cargo test -p aster-node cached_blob_reader_rechecks_revocation_epoch_grants_and_lifecycle_each_page -- --nocapture`

  Expected: FAIL on publisher revocation in the stream-originated path.

- [ ] **Step 3: Route all reads through canonical per-page authorization**

  Delete the split pack reader and revalidate current policy generation, epoch, grants, publisher status, and lifecycle immediately before each nonempty plaintext page. Clear cached readers on denial, retirement, rekey, shutdown, and terminal zeroization.

- [ ] **Step 4: Run read, revocation, and zeroization tests**

  Run: `cargo test -p aster-node cached_blob_reader_ -- --nocapture && cargo test -p aster-node blob_publisher_revocation_closes_retained_and_reopened_facades -- --nocapture && cargo test -p aster-node blob_terminal_zeroization_prevents_facade_reopen -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-node/src/application/blob.rs crates/aster-node/src/application/blob_stream.rs && git commit -S -m "fix(blob): reauthorize every streamed read page"`

### Task 8: Real adapter status and proven worker cancellation

**Files:**
- Modify: `crates/aster-node/src/stream_transport.rs`
- Modify: `crates/aster-node/src/stream_pipeline.rs`
- Modify: `crates/aster-node/src/runtime/blob_stream.rs`
- Test: same files

**Interfaces:**
- Consumes: `StreamTransportAdapter`, canonical publication status API, and fixed worker pool.
- Produces: test-only observable adapter and worker gates; production cancellation remains internal.

- [ ] **Step 1: Replace the two insufficient tests**

  Rewrite `publication_status_survives_small_mtu_interrupt_and_fresh_adapter_instance_resume` to use a small-MTU interruption and a fresh adapter instance reopening the same contact-agreed transport contract, plus real store/API status. Rewrite the runtime cancellation test so failure injection waits on an active-worker barrier and operation completion waits on a worker-exit barrier. Include reorder-buffer saturation from Review Focus.

- [ ] **Step 2: Run and confirm the old implementation cannot satisfy the barriers**

  Run: `cargo test -p aster-node publication_status_survives_small_mtu_interrupt_and_fresh_adapter_instance_resume -- --nocapture && cargo test -p aster-node receive_transport_failure_cancels_and_joins_pipeline -- --nocapture && cargo test -p aster-node pipeline_sink_failure_joins_workers_and_reclaims_permits -- --nocapture`

  Expected: FAIL before cancellation/join and real adapter behavior are wired.

- [ ] **Step 3: Implement deterministic shutdown and integration plumbing**

  On every pipeline failure stop admission, close channels, signal cancellation, join the fixed worker set, zeroize plaintext buffers, release permits, then return. Keep adapter-independent status keyed by canonical publication and receiver checkpoint.

- [ ] **Step 4: Run all pipeline and adapter tests**

  Run: `cargo test -p aster-node stream_pipeline -- --nocapture && cargo test -p aster-node stream_transport -- --nocapture && cargo test -p aster-node receive_transport_failure_cancels_and_joins_pipeline -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-node/src/stream_transport.rs crates/aster-node/src/stream_pipeline.rs crates/aster-node/src/runtime/blob_stream.rs && git commit -S -m "test(stream): prove fresh adapter instance resume and worker shutdown"`

### Task 9: Wire contract, vectors, and fuzz coverage

**Files:**
- Modify: `docs/protocol.md`
- Modify: `docs/wire.cddl`
- Modify: `conformance/blob_stream_oracle.py`
- Modify: `conformance/vectors/blob-stream-records-v1.tsv`
- Modify: `conformance/vectors/profile5-composite-data-record-v1.tsv`
- Modify: `fuzz/src/lib.rs`
- Modify: `fuzz/fuzz_targets/stream_transfer_decode.rs`
- Replace: `fuzz/corpus/stream_transfer_decode/*`
- Modify: `tools/run-fuzz-smoke.sh`
- Modify: `tools/test-run-fuzz-smoke.py`
- Modify: `tools/check-protocol-version-contract.py`
- Modify: `tools/test-protocol-version-contract.py`

**Interfaces:**
- Consumes: Task 4 exact codec constants and records.
- Produces: matching normative prose, CDDL, oracle, vectors, valid corpus, and CI campaign.

- [ ] **Step 1: Add failing contract and fuzz-script assertions**

  Assert v9 registers profile 5, v7/v8 retain profile 4, checkpoint maximum is 128 MiB, the three size classes are distinct, every corpus seed decodes as an actual record (or explicit `HEX:` fixture), and `stream_transfer_decode` appears in the smoke campaign.

- [ ] **Step 2: Run contract tests and observe all documentation/fuzz mismatches**

  Run: `python3 tools/test-protocol-version-contract.py && python3 tools/test-run-fuzz-smoke.py`

  Expected: FAIL on the report's negotiation, size, seed, and campaign findings.

- [ ] **Step 3: Update normative contract and regenerate fixtures**

  Copy numeric limits from executable constants, regenerate all profile-5 vectors from the independent oracle, and replace marker/newline seeds with encoded frames. Extend fuzz validation for truncation, overflow, malformed canonical chunks, attempt binding, rollback, terminal replay, and trailing bytes.

- [ ] **Step 4: Run protocol, oracle, and bounded fuzz smoke**

  Run: `python3 tools/test-protocol-version-contract.py && python3 tools/test-run-fuzz-smoke.py && tools/run-fuzz-smoke.sh`

  Expected: PASS and output explicitly lists `stream_transfer_decode`.

- [ ] **Step 5: Commit**

  `git add docs/protocol.md docs/wire.cddl conformance fuzz tools/run-fuzz-smoke.sh tools/test-run-fuzz-smoke.py tools/check-protocol-version-contract.py tools/test-protocol-version-contract.py && git commit -S -m "fix(protocol): align profile 5 contract and fuzzing"`

### Task 10: Schema cleanup, migration, and audit

**Files:**
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Test: `crates/aster-redb-store/src/blob.rs`

**Interfaces:**
- Consumes: Tasks 1, 2, and 5 final table shapes.
- Produces: `UnsupportedExperimentalBlobStreamSchema` error and current all-or-nothing Blob schema/audit rules.

- [ ] **Step 1: Write failing migration matrix**

  Add `pre_pr110_blob_database_opens_without_content_migration`, `empty_experimental_stream_tables_are_removed_atomically`, `nonempty_experimental_stream_publications_fail_closed`, and `read_only_open_never_migrates_stream_schema`. Add injected-fault cases and audit mismatches for orphan checkpoint, missing charge, duplicate owned operation, and partial removed-table groups.

- [ ] **Step 2: Run and observe old split tables remain authoritative**

  Run: `cargo test -p aster-redb-store experimental_stream_ -- --nocapture && cargo test -p aster-redb-store pre_pr110_blob_database_opens_without_content_migration -- --nocapture`

  Expected: FAIL.

- [ ] **Step 3: Implement atomic cleanup and fail-closed audit**

  Preserve canonical predecessors, create only upload and receipt checkpoint tables, remove empty experimental split tables on writable open, and reject any nonempty stream-only publication/variant/retirement state with the specific development-schema error. Audit live rows against exact charge and ownership totals.

- [ ] **Step 4: Run schema, reopen, and audit tests**

  Run: `cargo test -p aster-redb-store experimental_stream_ -- --nocapture && cargo test -p aster-redb-store blob_schema_ -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/stream.rs crates/aster-redb-store/src/lib.rs && git commit -S -m "fix(store): remove split blob stream authority"`

### Task 11: API, operator, roadmap, and evidence documentation

**Files:**
- Modify: `README.md`
- Modify: `crates/aster-agent/README.md`
- Modify: `crates/asterctl/README.md`
- Modify: `crates/asterctl/asterctl-blob-publish.1`
- Modify: `crates/asterctl/asterctl-blob-read.1`
- Modify: `crates/asterctl/asterctl-blob-status.1`
- Modify: `docs/quickstart/selected-blob-api.md`
- Modify: `docs/operator-guide.md`
- Modify: `docs/validation/capability-roadmap.md`
- Modify: `docs/validation/blob-streaming-engineering-runbook.md`
- Modify: `docs/validation/blob-streaming-performance.md`
- Modify: `docs/validation/requirements-status.md`
- Modify: `docs/validation/requirements-implementation.csv`

**Interfaces:**
- Consumes: final executable behavior and constants from Tasks 1-10.
- Produces: current user/operator contract and honest validation boundary.

- [ ] **Step 1: Add documentation assertions for every D1-D4 correction**

  Extend the protocol/requirements checker so it requires profile-5 negotiation, separate size terms, 128-MiB checkpoint maximum, canonical legacy eligibility, unified configured capacity, agent/CLI capability, and distinct local publication versus peer/convergence status wording.

- [ ] **Step 2: Run documentation checks and capture stale claims**

  Run: `python3 tools/check-protocol-version-contract.py && python3 tools/check-implementation-requirements.py`

  Expected: FAIL until all current-capability wording is reconciled.

- [ ] **Step 3: Update docs without rewriting historical receipts**

  Update examples and runbooks to the canonical authority and current CLI/API behavior. Preserve every historical performance receipt's original commit/environment and label new measurements separately. Document download resume as post-merge work, not current capability.

- [ ] **Step 4: Run documentation and example checks**

  Run: `python3 tools/check-protocol-version-contract.py && python3 tools/check-implementation-requirements.py && cargo test -p asterctl --test blob -- --nocapture && cargo test -p aster-agent --test real_node_connect blob -- --nocapture`

  Expected: PASS.

- [ ] **Step 5: Commit**

  `git add README.md crates/aster-agent/README.md crates/asterctl docs/quickstart/selected-blob-api.md docs/operator-guide.md docs/validation && git commit -S -m "docs(blob): document canonical streaming behavior"`

### Task 12: Local release gates and signed review checkpoint

**Files:**
- Modify only files required by failures attributable to this branch.

**Interfaces:**
- Consumes: all earlier tasks.
- Produces: locally verified candidate commit with no known report finding outstanding.

- [ ] **Step 1: Run formatting and focused aggregate gates**

  Run: `cargo fmt --all -- --check && cargo test -p aster-redb-store upload_ -- --nocapture && cargo test -p aster-redb-store profile5_ -- --nocapture && cargo test -p aster-node stream_upload_ -- --nocapture && cargo test -p aster-node fully_checkpointed_ -- --nocapture && cargo test -p aster-node cached_blob_reader_ -- --nocapture`

  Expected: PASS.

- [ ] **Step 2: Run repository gates serially**

  Run: `CARGO_BUILD_JOBS=1 cargo test --workspace --all-targets -- --test-threads=1`

  Expected: PASS without OS termination or timeout growth attributable to unbounded fixtures.

- [ ] **Step 3: Run the remaining required checks**

  Run: `mise run check && tools/run-fuzz-smoke.sh && python3 tools/check-implementation-requirements.py && git diff --check canonical/main...HEAD`

  Expected: PASS.

- [ ] **Step 4: Request whole-branch code review and fix every actionable result test-first**

  Review against the remediation spec, the 17-row traceability table, and the
  documented unreleased PR 95 `PublishBlob` compatibility break. Repeat
  focused checks for every change.

- [ ] **Step 5: Commit any gate-only corrections**

  Stage only the files changed to resolve attributable failures, review `git diff --cached`, then run `git commit -S -m "fix(blob): satisfy remediation release gates"`. Skip this step when no correction was required.

### Task 13: Three-CM4 correctness and performance validation

**Files:**
- Modify: `docs/validation/blob-streaming-pipeline-cm4-2026-10-19.md` only by appending a separately dated result section, or create a new dated receipt if the existing receipt schema requires immutability.
- Modify: `docs/validation/blob-streaming-performance.md`

**Interfaces:**
- Consumes: CI-built artifact for the exact signed candidate commit and the existing three RPi CM4 devices.
- Produces: raw-file baseline plus Aster publish/sync/read end-to-end evidence with stage timings and exact topology.

- [ ] **Step 1: Build the exact signed candidate in CI and verify artifact identity**

  Record commit, artifact digest, Rust profile, feature set, and workflow run. Do not install a locally built or mismatched binary.

- [ ] **Step 2: Collect network/topology evidence before transfer**

  On all three CM4s record interface addresses/routes, WLAN link details, ZeroTier state, peer-selected endpoints, RTT/loss, and the exact interface used for inter-node traffic. Keep ZeroTier configured for remote access and report if Aster selects it rather than the intended local WLAN path.

- [ ] **Step 3: Run raw 1-GiB transport baseline**

  Measure sender/receiver wall time, bytes, throughput, CPU, memory, disk I/O, retransmission/loss indicators, and artifact digest over the same selected path used by Aster.

- [ ] **Step 4: Run composite Aster 1-GiB test**

  Measure local publication independently, destination availability/sync, destination read, and total end-to-end time. Record every pipeline stage, checkpoint/resume behavior, selected profile/adapter, CPU, RSS, disk I/O, and matching source/destination digests. Repeat warm runs and include all results, not only the best.

- [ ] **Step 5: Compare against the raw baseline and acceptance boundary**

  Attribute remaining overhead by stage. The candidate is performance-ready only when memory stays bounded, no coordination blocks local publish, no timeout is part of normal success, and throughput is close enough to the raw path that transport is the dominant bottleneck. Otherwise return to the owning task with a new failing benchmark/regression.

- [ ] **Step 6: Commit the evidence separately**

  `git add docs/validation/blob-streaming-pipeline-cm4-*.md docs/validation/blob-streaming-performance.md && git commit -S -m "docs(blob): record canonical streaming CM4 evidence"`
