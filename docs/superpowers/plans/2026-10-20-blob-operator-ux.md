# Blob Operator UX Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the profile-5 Blob pipeline observable and safely recoverable for 800-MiB and 1-GiB operator workflows without coupling publication to a destination or exposing transport internals.

**Architecture:** Project exact receiver-local lifecycle and capacity facts from the durable Blob store through the authenticated local-agent API, then add bounded polling and progress rendering in `asterctl`. Publication identity, absolute durable checkpoints, totals, and terminal settlement remain the only cross-layer contract, so a later non-IP adapter can reuse the same UX without changing status semantics or resume behavior.

**Tech Stack:** Rust, redb, Tokio, Connect RPC/Buffa protobuf bindings, Go protobuf conformance fixtures, Clap-style hand-written CLI parsing, roff man pages.

**Spec:** `docs/superpowers/specs/2026-10-20-blob-operator-ux-design.md`

## Global Constraints

- Local publication remains independent of destination availability; no receiver acknowledgement or coordination is added.
- Public status is exact, bounded, receiver-local, and transport-neutral; it exposes no Iroh, QUIC, peer-path, carrier, crypto, or routing-lineage details.
- The tracking identity is the authenticated semantic-v9/profile-5 publication stream ID present before byte zero; `BlobId` remains the post-finalization content/read identity.
- Semantic-v7/v8 profile 4 and its vectors remain byte-compatible and gain no guessed public tracking identity.
- `blob-status --poll-ms` accepts `100..=60000` and defaults to `1000`; one request may be in flight and the global client deadline is authoritative.
- `--progress auto|always|never` defaults to `auto`; progress uses stderr only and is capped at four periodic updates per second plus initial, checkpoint-transition, and terminal records.
- A broken progress sink cancels before success; counter overflow, regression, inconsistent totals, and contradictory durable states fail closed.
- Capacity is a preflight observation, never a reservation or fit guarantee.
- Generated descriptor and Go application-protocol artifacts change in the same commit as the alpha protobuf schema.
- All commits are signed. Do not push until the user requests it.
- Use focused local verification; retain the full suite and physical CM4 composite run as CI/device gates because this host has repeatedly been killed by full local runs.

## Review Focus

- An absent publication and a publication the caller is not currently authorized to inspect both return `MISSING`, without an existence oracle.
- Promotion, abort/retirement, and inspection races return exactly one coherent state; simultaneous or mismatched durable authorities fail as integrity loss.
- A wait deadline reports the last complete state and counters, while terminal retirement exits unsuccessfully without another poll.
- A closed or failing stderr progress sink cancels the operation and cannot be followed by a success receipt or published destination file.
- Maximum counters, exhausted capacity, offset regression, and arithmetic overflow are rendered without wrapping; impossible protocol values are rejected.

---

### Task 1: Durable Publication Inspection and Capacity Projection

**Files:**
- Modify: `crates/aster-redb-store/src/blob.rs`
- Modify: `crates/aster-redb-store/src/blob/stream.rs`
- Modify: `crates/aster-redb-store/src/blob/lifecycle.rs`
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/application/blob.rs`
- Test: inline `#[cfg(test)]` modules in the files above

**Interfaces:**
- Consumes: `aster_mesh::BlobPublicationStreamId`, `BlobStreamReservation`, `BlobStreamResume`, `BlobStreamPublication`, `BlobStoreStats`, and `BlobDepotLimits`.
- Produces: public `BlobStreamPublicationId`, `BlobPublicationPhase`, `BlobPublicationInspection`, and `BlobCapacityStatus`; `SelectedBlobNode::inspect_publication(&BlobPublicationInspectionRequest)` and `SelectedBlobHandle::inspect_publication(BlobPublicationInspectionRequest)`; `SelectedBlobNode::capacity_status()` and `SelectedBlobHandle::capacity_status()`; `BlobPublishResult.publication_id`.

- [ ] **Step 1: Add failing store tests for all exact publication states**

  Add tests named `inspect_stream_publication_reports_every_lifecycle_state`, `inspect_stream_publication_conflates_missing_and_unauthorized`, `inspect_stream_publication_does_not_translate_legacy_identity`, and `inspect_stream_publication_fails_on_contradictory_authority`. Assert direct lookup by stream ID, all six phases including retained `EXPIRED_OR_RETIRED`, monotonic plaintext/pack/unit counters, Blob ID only in `AVAILABLE`, no profile-4 table lookup, and integrity failure when test-only corruption creates two authorities.

- [ ] **Step 2: Run the focused store tests and confirm the inspection API is absent**

  Run: `cargo test -p aster-redb-store inspect_stream_publication -- --nocapture`

  Expected: FAIL because the exact inspection types and method do not exist.

- [ ] **Step 3: Implement the bounded store projection**

  Add `Store::inspect_blob_stream_with_policy(policy, stream_id) -> Result<BlobStreamInspection, StoreError>`. It must perform keyed reads of pending, completed, and retained-retirement authority; validate topic, scope, mission, counters, and mutual exclusion; and return `Missing` for absent or policy-invisible rows. Add the minimum fixed-size retirement record/table keyed by stream ID, create it atomically when an authenticated provisional stream is terminally expired or retired, and account/audit it under the existing bounded Blob lifecycle limits.

- [ ] **Step 4: Run the focused store tests**

  Run: `cargo test -p aster-redb-store inspect_stream_publication -- --nocapture`

  Expected: PASS, including restart and promotion/retirement race coverage.

- [ ] **Step 5: Add failing application tests for identity, capacity, and restart**

  Add tests named `profile5_receipt_preserves_publication_id_through_completion`, `publication_inspection_survives_restart_with_monotonic_progress`, and `blob_capacity_status_handles_zero_and_maximum_counters`. Assert the application wrapper preserves the exact authenticated ID, exposes no transport fields, uses saturating exhausted/remaining presentation, and rejects regressions or overflow.

- [ ] **Step 6: Run the focused application tests and confirm they fail**

  Run: `cargo test -p aster-node publication_inspection -- --nocapture`

  Run: `cargo test -p aster-node blob_capacity_status -- --nocapture`

  Expected: FAIL because the public application types and methods are absent.

- [ ] **Step 7: Implement the application types and live/stopped methods**

  Define `BlobStreamPublicationId([u8; 32])`, `BlobPublicationInspectionRequest { publication_id, topic, scope }`, `BlobPublicationPhase`, and `BlobPublicationInspection` with plaintext total/durable bytes, transfer total/durable bytes, total/durable units, and optional `BlobId`. Define `BlobCapacityStatus` with reserved depot bytes/limit, active-or-deletion-owned variants/limit, active-or-deletion-owned expected chunks/limit, pending source count, network staging bytes, and one exhausted flag per configured limit. Route handle requests through the existing bounded Blob application lane and add `publication_id` to every `BlobPublishResult` constructor, including idempotent completion.

- [ ] **Step 8: Run focused node and store verification**

  Run: `cargo test -p aster-node publication_inspection -- --nocapture`

  Run: `cargo test -p aster-node blob_capacity_status -- --nocapture`

  Run: `cargo test -p aster-node blob_publish_result -- --nocapture`

  Expected: PASS.

- [ ] **Step 9: Commit the durable projection**

  ```bash
  git add crates/aster-redb-store/src/blob.rs crates/aster-redb-store/src/blob/stream.rs crates/aster-redb-store/src/blob/lifecycle.rs crates/aster-redb-store/src/lib.rs crates/aster-node/src/application.rs crates/aster-node/src/application/blob.rs
  git commit -S -m "feat(blob): expose durable publication state"
  ```

### Task 2: Authenticated Agent Status Protocol

**Files:**
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Modify: `crates/aster-agent/src/blob_service.rs`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/error.rs`
- Modify: `crates/aster-agent/src/bin/aster-agent-acceptance-fixture.rs`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.pb.go`
- Modify: `conformance/agent-go/gen/aster/application/v1alpha1/aster.connect.go`
- Test: inline `#[cfg(test)]` modules in the Rust files and generated-artifact checks

**Interfaces:**
- Consumes: Task 1's inspection/capacity methods and types.
- Produces: unary `InspectBlobPublication(InspectBlobPublicationRequest) returns (InspectBlobPublicationResponse)`; protobuf `BlobPublicationPhase`, `BlobCapacityStatus`, and `PublishBlobReceipt.publication_id`; `PublicOperation::InspectBlobPublication`.

- [ ] **Step 1: Add failing protocol and mapping tests**

  Add tests named `inspect_blob_publication_maps_all_states_without_transport_details`, `inspect_blob_publication_hides_unauthorized_as_missing`, `status_response_includes_blob_capacity`, and `publish_receipt_includes_publication_id`. Assert exact 32-byte identifiers, bounded messages, optional Blob ID only for `AVAILABLE`, and public error redaction.

- [ ] **Step 2: Run the focused agent tests and confirm they fail**

  Run: `cargo test -p aster-agent inspect_blob_publication -- --nocapture`

  Run: `cargo test -p aster-agent blob_capacity -- --nocapture`

  Expected: FAIL because the messages and route do not exist.

- [ ] **Step 3: Extend the alpha application schema additively**

  Add the unary method and request/response messages, append `publication_id = 11` to `PublishBlobReceipt`, and append `blob_capacity = 13` to `GetStatusResponse`. Use explicit phase enum values for `MISSING`, `AWAITING_DATA`, `RECEIVING`, `READY_TO_FINALIZE`, `AVAILABLE`, and `EXPIRED_OR_RETIRED`; keep all existing field numbers and meanings unchanged.

- [ ] **Step 4: Implement authenticated service routing and mappings**

  Parse the exact publication ID/topic/scope, call the Task 1 handle, map unauthorized/not-found evidence to `MISSING`, include capacity in `GetStatus`, add `PublicOperation::InspectBlobPublication`, and reuse existing message-size and public-redaction guards.

- [ ] **Step 5: Regenerate and verify checked-in protocol artifacts**

  Run: `buf format -w proto/aster/application/v1alpha1/aster.proto`

  Run: `buf build --as-file-descriptor-set -o proto/aster/application/v1alpha1/aster.fds.bin .`

  Run: `buf generate --template conformance/agent-go/buf.gen.yaml`

  Run: `sh tools/check-agent-proto.sh`

  Run: `sh tools/check-agent-go-generated.sh`

  Expected: all commands exit 0 and generated diffs contain only the additive API.

- [ ] **Step 6: Run focused agent and Go conformance tests**

  Run: `cargo test -p aster-agent inspect_blob_publication -- --nocapture`

  Run: `cargo test -p aster-agent status_response -- --nocapture`

  Run: `go -C conformance/agent-go test ./...`

  Expected: PASS.

- [ ] **Step 7: Commit the agent protocol**

  ```bash
  git add proto/aster/application/v1alpha1 crates/aster-agent conformance/agent-go/gen
  git commit -S -m "feat(agent): report Blob publication lifecycle"
  ```

### Task 3: Blob Status, Wait, and Capacity CLI

**Files:**
- Create: `crates/asterctl/src/blob_status.rs`
- Create: `crates/asterctl/asterctl-blob-status.1`
- Modify: `crates/asterctl/src/args.rs`
- Modify: `crates/asterctl/src/client.rs`
- Modify: `crates/asterctl/src/main.rs`
- Modify: `crates/asterctl/src/output.rs`
- Modify: `crates/asterctl/src/output/text.rs`
- Modify: `crates/asterctl/asterctl.1`
- Modify: `debian/aster.manpages`
- Test: inline `#[cfg(test)]` modules in the Rust files

**Interfaces:**
- Consumes: Task 2's RPC, capacity status, and publication ID receipt field.
- Produces: `blob-status --publication-id ID --topic TOPIC --scope SCOPE [--wait] [--poll-ms N]`; stable text/JSON snapshots; receipt output containing publication ID, Blob ID, and operation key.

- [ ] **Step 1: Add failing parser tests**

  Add `blob_status_requires_exact_selector`, `blob_status_poll_range_is_100_through_60000`, and `blob_status_poll_defaults_to_1000`. Assert `--poll-ms` without `--wait` is rejected and legacy command parsing is unchanged.

- [ ] **Step 2: Run parser tests and confirm they fail**

  Run: `cargo test -p asterctl blob_status -- --nocapture`

  Expected: FAIL because the command does not exist.

- [ ] **Step 3: Implement command parsing and one-request polling**

  Define `blob_status::Status` and `client::inspect_blob_publication(...)`. Snapshot mode performs one RPC and succeeds for every valid state. Wait mode keeps one RPC in flight, sleeps for the selected interval, returns success only on `AVAILABLE`, exits unsuccessfully on `EXPIRED_OR_RETIRED`, and includes the final observed state in a global-deadline error.

- [ ] **Step 4: Add failing output tests**

  Add `blob_status_text_names_transfer_byte_domain`, `blob_status_json_is_stable_for_all_states`, `blob_status_missing_snapshot_succeeds`, `wait_retirement_stops_without_another_poll`, `wait_deadline_contains_final_state`, `publish_output_contains_both_ids_and_operation_key`, and `status_capacity_uses_saturating_remaining_values`. Exercise zero and `u64::MAX` counters.

- [ ] **Step 5: Run output tests and confirm they fail**

  Run: `cargo test -p asterctl output -- --nocapture`

  Expected: FAIL on the new lifecycle, capacity, and receipt fields.

- [ ] **Step 6: Implement stable text and JSON output**

  Keep stdout terminal-only: status output must label plaintext versus authenticated transfer bytes; `asterctl status` must label capacity as observed/preflight; `blob-publish` must print publication ID, Blob ID, and operation key without changing stderr behavior.

- [ ] **Step 7: Add the command man page and top-level registration**

  Document valid states, receiver-local meaning, wait exit behavior, polling bounds, and the absence of remote/transport inference. Register `asterctl-blob-status.1` in the top-level man page and Debian packaging list.

- [ ] **Step 8: Run focused CLI verification**

  Run: `cargo test -p asterctl blob_status -- --nocapture`

  Run: `cargo test -p asterctl output -- --nocapture`

  Expected: PASS.

- [ ] **Step 9: Commit the status CLI**

  ```bash
  git add crates/asterctl debian/aster.manpages
  git commit -S -m "feat(asterctl): inspect and wait for Blob publications"
  ```

### Task 4: Progress Rendering and Actionable Recovery

**Files:**
- Create: `crates/asterctl/src/progress.rs`
- Modify: `crates/asterctl/src/blob_publish.rs`
- Modify: `crates/asterctl/src/blob_read.rs`
- Modify: `crates/asterctl/src/args.rs`
- Modify: `crates/asterctl/src/client.rs`
- Modify: `crates/asterctl/src/main.rs`
- Modify: `crates/asterctl/asterctl-blob-publish.1`
- Modify: `crates/asterctl/asterctl-blob-read.1`
- Test: inline `#[cfg(test)]` modules in the Rust files

**Interfaces:**
- Consumes: existing accepted/checkpoint/complete publish frames and authenticated read pages.
- Produces: `ProgressMode::{Auto,Always,Never}`, a bounded `ProgressReporter<W: Write>`, publish failure snapshots, and read-discard diagnostics.

- [x] **Step 1: Add failing progress policy tests**

  Add `progress_auto_requires_tty`, `progress_always_is_newline_delimited_off_tty`, `progress_never_writes_nothing`, `progress_is_rate_limited_to_four_periodic_updates_per_second`, and `progress_emits_initial_checkpoint_and_terminal_records`. Use a fake clock and memory writer so the tests do not sleep.

- [x] **Step 2: Run the progress tests and confirm they fail**

  Run: `cargo test -p asterctl progress -- --nocapture`

  Expected: FAIL because the reporter does not exist.

- [x] **Step 3: Implement transport-neutral progress rendering**

  Implement `ProgressReporter<W>` using only source/accepted/durable/written offsets, totals, `Instant`, and `Write`. Render current bytes, total bytes, percentage, elapsed time, and interval rate; use carriage-return updates only for a terminal and newline records otherwise; reject overflow, regression, or inconsistent totals.

- [x] **Step 4: Add failing publish/read recovery tests**

  Add `publish_timeout_reports_sent_accepted_durable_total_and_retry`, `publish_retry_uses_agent_resume_offset`, `broken_publish_stderr_prevents_success`, `read_interruption_reports_discarded_bytes`, `broken_read_stderr_does_not_publish_destination`, and `json_stdout_remains_single_terminal_object_with_progress`. Assert the exact operation key appears in the retry instruction.

- [x] **Step 5: Run recovery tests and confirm they fail**

  Run: `cargo test -p asterctl publish_timeout -- --nocapture`

  Run: `cargo test -p asterctl read_interruption -- --nocapture`

  Expected: FAIL because validated counters are not retained outside the timed future and progress errors are not propagated.

- [x] **Step 6: Integrate progress and retained recovery snapshots**

  Add `--progress` to Blob publish/read only. Retain the latest validated sent/accepted/durable counters in shared bounded state outside the transfer future; make the agent's accepted resume offset authoritative; propagate progress write errors; on read failure report authenticated staged bytes and confirm the destination rename did not occur.

- [x] **Step 7: Correct command help and man-page wording**

  Replace “never sent to the agent” with “the path remains local; file contents stream to the local agent.” Document stdout/stderr separation, `auto|always|never`, exact retry, and the lack of download resume.

- [x] **Step 8: Run focused CLI verification**

  Run: `cargo test -p asterctl progress -- --nocapture`

  Run: `cargo test -p asterctl publish_timeout -- --nocapture`

  Run: `cargo test -p asterctl read_interruption -- --nocapture`

  Expected: PASS.

- [x] **Step 9: Commit progress and recovery UX**

  ```bash
  git add crates/asterctl
  git commit -S -m "feat(asterctl): show Blob progress and recovery state"
  ```

### Task 5: Transport-Neutral Evidence, Documentation, and Readiness Gate

**Files:**
- Modify: `crates/aster-node/src/stream_transport.rs`
- Modify: `crates/aster-node/src/stream_transfer.rs`
- Modify: `crates/asterctl/README.md`
- Modify: `crates/aster-agent/README.md`
- Modify: `docs/operator-guide.md`
- Modify: `docs/quickstart/selected-blob-api.md`
- Modify: `docs/validation/blob-streaming-engineering-runbook.md`
- Modify: `docs/validation/requirements-status.md` only if the implementation-evidence boundary changes
- Test: inline fake-adapter tests in `crates/aster-node/src/stream_transport.rs` and documentation command checks

**Interfaces:**
- Consumes: Tasks 1-4's stable publication identity, inspection states, capacity output, progress modes, and recovery wording.
- Produces: a fake-adapter portability test, current operator examples, and the focused pre-CI readiness evidence.

- [x] **Step 1: Add the failing transport-neutral reopen test**

  Add `publication_status_survives_small_mtu_interrupt_and_fresh_adapter_instance_resume`. The fake seam exercises a small-MTU interrupted attempt and a fresh adapter instance resuming from the exact receiver-authoritative offset. Its evidence is transport-neutral reopen of the same single contact-agreed adapter contract, not production cross-transport selection or failover. Assert unchanged publication ID, monotonic common durable counters, final Blob ID/hash equality, and no IP/Iroh type in the status interface.

- [x] **Step 2: Run the fake-adapter test and confirm it fails**

  Run: `cargo test -p aster-node publication_status_survives_small_mtu_interrupt_and_fresh_adapter_instance_resume -- --nocapture`

  Expected: FAIL until status observation is wired solely to the common checkpoint/promotion path.

  Observed: PASS on first execution because the existing common profile-5 state
  and Task 1 inspection shape were already transport-neutral. The test uses the
  real public inspection type and exhaustively destructures it so introducing a
  transport field fails compilation.

- [x] **Step 3: Connect status observation to the common stream contract**

  Keep adapter-local fragments transient and update public durability only after the existing Aster checkpoint commits. Do not add MTU, endpoint, connection-duration, ordered carrier-packet, or Iroh assumptions to the public types or status code.

- [x] **Step 4: Run the portability and unchanged-profile tests**

  Run: `cargo test -p aster-node publication_status_survives_small_mtu_interrupt_and_fresh_adapter_instance_resume -- --nocapture`

  Run: `cargo test -p aster-node semantic_blob_profile_four_resolves_to_version_scoped_contact_mode -- --nocapture`

  Run: `cargo test -p aster-node semantic_v9_profile_five_contact_transfers_completed_blob_stream -- --nocapture`

  Expected: PASS with profile-4 vectors unchanged.

- [x] **Step 5: Update operator and engineering documentation**

  Show separate Event-subscription and Blob-interest prerequisites; publisher/receiver capacity checks; local publish retaining publication ID, Blob ID, and operation key; receiver-local status/wait; read after `AVAILABLE`; hash comparison; and exact retry after interruption. Include a concrete 1-GiB evaluation sizing example, clearly label overhead/reserve assumptions and capacity as non-reserving, and preserve the engineering runbook's per-stage timestamps and raw-transfer baseline.

- [x] **Step 6: Verify documentation commands and requirement evidence**

  Run every new `asterctl` example with `--help`/argument parsing or the existing documentation checker. If `docs/validation/requirements-status.md` changed, run `python3 tools/check-implementation-requirements.py`.

  Expected: examples parse, help matches man pages, and the requirements check exits 0 when applicable.

- [x] **Step 7: Run the focused readiness checks**

  Run: `cargo fmt --all -- --check`

  Run: `cargo clippy -p aster-redb-store -p aster-node -p aster-agent -p asterctl --all-targets -- -D warnings`

  Run: `cargo test -p aster-redb-store inspect_stream_publication -- --nocapture`

  Run: `cargo test -p aster-node publication_ -- --nocapture`

  Run: `cargo test -p aster-agent inspect_blob_publication -- --nocapture`

  Run: `cargo test -p asterctl blob_ -- --nocapture`

  Run: `sh tools/check-agent-proto.sh`

  Run: `sh tools/check-agent-go-generated.sh`

  Expected: all focused checks pass. Record any skipped full-suite evidence explicitly for CI rather than claiming it locally.

- [x] **Step 8: Commit documentation and portability evidence**

  ```bash
  git add crates/aster-node/src/stream_transport.rs crates/aster-node/src/stream_transfer.rs crates/asterctl/README.md crates/aster-agent/README.md docs/operator-guide.md docs/quickstart/selected-blob-api.md docs/validation/blob-streaming-engineering-runbook.md docs/validation/requirements-status.md
  git commit -S -m "docs(blob): make streaming workflow operator-ready"
  ```

- [ ] **Step 9: Preserve the post-CI/device completion gate**

  After a later user-authorized push, require green PR checks and repeat the composite 1-GiB workflow on the three CM4 devices, retaining local-publish, receiver-wait, receiver-read, raw-copy baseline, hashes, and per-stage elapsed times. This evidence is a release-readiness gate, not part of the local implementation commit.
