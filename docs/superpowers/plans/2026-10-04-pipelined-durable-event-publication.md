# Pipelined Durable Event Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add durable Event group commit and a pipelined local publication stream that increases telemetry ingestion without acknowledging before local durability.

**Architecture:** The selected-node actor opportunistically groups only already-buffered ordinary Event commands and commits compatible cohorts in one immediate-durability redb transaction. The additive HTTP/2 bidirectional RPC submits a bounded ordered window through the unchanged actor handle and returns one sanitized durable outcome per input; unary publication remains compatible.

**Tech Stack:** Rust, Tokio bounded channels, redb 4.2, ConnectRPC/Buf Protobuf, existing selected Event store and CM4 telemetry matrix.

**Spec:** `docs/superpowers/specs/2026-10-04-pipelined-durable-event-publication-design.md`

## Global Constraints

- Success remains behind local immediate-durability commit; never acknowledge queued-only work.
- Keep one actor and one redb authority; add no journal, store, worker authority, or mesh semantic-version change.
- Preserve ordinary singleton Event wire representation and independent operation-key semantics.
- Group only already-buffered work; no coalescing timer or wait-for-more delay.
- Keep the application channel capacity 32 and fairness budget 8 as internal implementation bounds, not protocol fields.
- Keep Flash and experimental numbered publication singleton and unchanged.
- Cover durable and finite-TTL ordinary Events.
- Preserve unrelated user work and keep the PR one squashed capability increment.

## Review Focus

- A failed item in a fast-path cohort must not prevent valid siblings from committing through ordered fallback.
- Mixed topic/scope/custody commands must preserve the exact counter, sequence, context, and result order of serial execution.
- Policy, custody-continuity, quota, and reservation races must never partially commit a successful group across generations.
- Stream disconnect, response backpressure, shutdown, and zeroization must never imply success before durability or create unbounded work.
- Browser request-streaming is unavailable; concurrent unary publication must remain the documented compatible pipeline.
- Preserve the existing 10-second default and 30-second maximum stream deadline; native clients recover across bounded sessions by replaying sent-but-unanswered inputs with the same operation keys.
- Emit one bounded, identifier-free structured diagnostic per collected actor group with a monotonic per-invocation sequence and separate exact custody/Event writer-commit counts so commits per Event and group-size receipts come from production behavior rather than inference.

---

### Task 1: Transactional selected-Event group commit

**Files:**
- Modify: `crates/aster-redb-store/src/lib.rs`
- Modify: `crates/aster-redb-store/src/custody.rs`
- Test: `crates/aster-redb-store/src/lib.rs`

**Interfaces:**
- Produces: `Store::reserve_event_group_with_policy(...) -> Result<Vec<EventReservation>, StoreError>` for one topic/scope and ordered predecessors.
- Produces: `ReservedEventOnceCommit::new(...)` and `Store::commit_reserved_event_group_once_with_policy(...) -> Result<EventGroupCommitOutcome, StoreError>`; finite-TTL construction explicitly requires the common commit-adjacent custody checkpoint and exact policy revision, and every success/committed-transition outcome includes its exact Event writer-commit count for diagnostics.
- Produces: refactored custody collection/maintenance outcomes that preserve existing semantics while reporting every writer commit, including committed continuity/policy transitions that are retried.
- Preserves: all singleton commit methods by routing them through the same transaction staging helper.

- [ ] **Step 1: Write failing reservation tests**

  Add tests proving a three-item reservation has contiguous publisher counters and Event sequences, each later context observes the prior local dot, reaction predecessors are observed, and an unchanged store is required at commit.

- [ ] **Step 2: Run the focused reservation tests and verify RED**

  Run: `cargo test --locked -p aster-redb-store event_group_reservation -- --nocapture`

  Expected: compilation/test failure because the group reservation API is absent.

- [ ] **Step 3: Implement `reserve_event_group_with_policy`**

  Derive all reservations from one read transaction, require a nonempty input, one publisher/topic/scope/policy, checked counter/sequence arithmetic, bounded contexts, and exact predecessor lookup. Simulate serial frontier advancement in memory without writing.

- [ ] **Step 4: Run the focused reservation tests and verify GREEN**

  Run: `cargo test --locked -p aster-redb-store event_group_reservation -- --nocapture`

  Expected: all matching tests pass.

- [ ] **Step 5: Write failing atomic commit and isolation-boundary tests**

  Add tests proving one writer commit durably inserts a valid durable cohort, exact retries return original results without new counters, same-group duplicate keys resolve once, same-group conflicting reuse does not consume an extra counter/sequence, finite items share one explicitly supplied fresh checkpoint and policy revision, transaction failure exposes none, restart resolves every committed operation key, and custody maintenance reports zero/one/multiple writer commits exactly across no-pressure, retirement, and committed-policy-transition retry paths.

- [ ] **Step 6: Run the focused commit tests and verify RED**

  Run: `cargo test --locked -p aster-redb-store event_group_commit -- --nocapture`

  Expected: compilation/test failure because the group commit API is absent.

- [ ] **Step 7: Refactor transaction staging and implement group commit**

  Extract a private transaction-scoped Event staging helper from `commit_prepared_event`. Implement `ReservedEventOnceCommit` and `commit_reserved_event_group_once_with_policy` so one immediate-durability writer stages the cohort in order and commits once. Route singleton methods through the same helper without changing outcomes.

- [ ] **Step 8: Run store Event tests and verify GREEN**

  Run: `cargo test --locked -p aster-redb-store event_group -- --nocapture && cargo test --locked -p aster-redb-store event_operation -- --nocapture`

  Expected: all matching tests pass.

- [ ] **Step 9: Commit the store increment**

  Commit: `feat(store): group durable Event publication commits`

### Task 2: Actor-owned opportunistic grouping and fallback

**Files:**
- Modify: `crates/aster-node/src/application.rs`
- Modify: `crates/aster-node/src/runtime.rs`
- Test: `crates/aster-node/src/runtime.rs`

**Interfaces:**
- Consumes: Task 1 reservation and group-commit APIs.
- Produces: `SelectedEventNode::publish_group_with_options(Vec<(EventPublishRequest, EventPublishOptions)>) -> Vec<Result<EventPublishResult, ApplicationError>>`.
- Produces: actor scheduling that drains at most `APPLICATION_COMMAND_BUDGET` adjacent ordinary non-Flash publications and retains the first different command.
- Produces: bounded `EventPublicationGroupDiagnostic` values and one identifier-free structured `event_publication_group` log record per collected group, with a monotonic per-actor `group_sequence` plus separate custody/Event/total writer-commit counts.

- [ ] **Step 1: Write failing actor grouping tests**

  Add tests proving singleton no-wait, two concurrent publications share one durable writer commit, Flash remains singleton, grouping stops before query/State/Record/numbered work, other work runs within the existing fairness budget, sequence values are gap-free within one actor invocation, and the diagnostic reports exact collected/cohort/custody-commit/Event-commit/total-commit/group-size counts without identifiers.

- [ ] **Step 2: Run focused runtime tests and verify RED**

  Run: `cargo test --locked -p aster-node live_event_group --lib -- --nocapture`

  Expected: tests fail because actor grouping and commit instrumentation are absent.

- [ ] **Step 3: Implement ordered actor collection**

  Add a helper that consumes the pending ordinary publication, nonblockingly collects every adjacent ordinary non-Flash publication command, leaves the first non-publication or Flash command pending, never exceeds the current turn's fairness budget, and then splits the ordered group into compatible cohorts.

- [ ] **Step 4: Write failing application group semantics tests**

  Add tests for mixed stream/custody cohort splitting, strict commit-before-reserve sequencing across cohorts, same-group identical and conflicting operation keys, reaction context, quota or malformed sibling isolation, policy/rekey race, reservation retry, finite expiry/continuity, cancellation, shutdown, and restart recovery. Prove a group already collected as the actor turn's synchronous executing unit may finish, while shutdown/zeroization closes admission and rejects commands left queued beyond that group.

- [ ] **Step 5: Run application group tests and verify RED**

  Run: `cargo test --locked -p aster-node selected_event_publish_group --lib -- --nocapture`

  Expected: tests fail because grouped application publication and ordered fallback are absent.

- [ ] **Step 6: Implement group publication and singleton fallback**

  Run one bounded custody-maintenance pass for the collected group. Then process compatible cohorts strictly in order: resolve exact operation-key retries, reserve/seal new Events, commit through Task 1 before reserving the next cohort, cache committed routes, accumulate exact custody/Event writer-commit diagnostics, and map results back to input order. On fast-path failure, replay that cohort in order through the singleton publication primitive after maintenance, without rerunning custody maintenance, and account for the group's one maintenance pass plus every actual fallback Event writer commit. Treat the collected group as the indivisible synchronous actor turn for shutdown purposes.

- [ ] **Step 7: Run node publication/runtime tests and verify GREEN**

  Run: `cargo test --locked -p aster-node live_event_group --lib -- --nocapture && cargo test --locked -p aster-node selected_event_publish_group --lib -- --nocapture`

  Expected: all matching tests pass.

- [ ] **Step 8: Commit the actor increment**

  Commit: `feat(node): coalesce admitted Event publications`

### Task 3: Pipelined local publication RPC

**Files:**
- Modify: `proto/aster/application/v1alpha1/aster.proto`
- Modify: `proto/aster/application/v1alpha1/aster.fds.bin`
- Modify: `crates/aster-agent/src/error.rs`
- Modify: `crates/aster-agent/src/event_service.rs`
- Modify: `crates/aster-agent/src/sdk.rs`
- Modify: `crates/aster-agent/tests/real_node_connect.rs`
- Modify: generated Go client artifacts as required by `tools/check-agent-go-generated.sh`

**Interfaces:**
- Consumes: Task 2 grouping through existing concurrent `SelectedEventHandle::publish_with_options` calls.
- Produces: bidi `PublishEvents(stream PublishEventsRequest) returns (stream PublishEventsResponse)`, where each request wraps one unchanged `PublishEventRequest` publication.
- Produces: ordered `PublishEventsResponse` with `published` or sanitized `failure` outcome.
- Produces: native bounded-session publication helper that reconnects before the existing server deadline and replays sent-but-unanswered requests with unchanged operation keys.

- [ ] **Step 1: Write the failing schema/descriptor test**

  Add the RPC and response message to the source schema first, then run the generated-artifact checks before regenerating artifacts.

- [ ] **Step 2: Verify generated artifacts are RED**

  Run: `sh tools/check-agent-proto.sh && sh tools/check-agent-go-generated.sh`

  Expected: failure because the checked-in descriptor/client artifacts do not match the schema.

- [ ] **Step 3: Regenerate descriptor and Go client artifacts**

  Use the repository's pinned generation commands; do not hand-edit generated output.

- [ ] **Step 4: Verify generated artifacts are GREEN**

  Run: `sh tools/check-agent-proto.sh && sh tools/check-agent-go-generated.sh`

  Expected: both checks pass.

- [ ] **Step 5: Write failing service tests**

  Add tests proving bounded concurrent admission, ordered durable responses, per-item sanitized failures without stream closure, unary/bidi shared group commit, disconnect retry of every sent-but-unanswered operation key, stalled-reader backpressure, the existing 10-second default/30-second maximum deadline behavior, and native Connect plus gRPC HTTP/2 interoperability. Add a real gRPC-Web request-streaming rejection test followed by successful bounded concurrent-unary publication of the same ordinary Events.

- [ ] **Step 6: Run focused agent tests and verify RED**

  Run: `cargo test --locked -p aster-agent publish_events -- --nocapture`

  Expected: tests fail because the bidi handler and in-band outcome mapping are absent.

- [ ] **Step 7: Implement the bounded ordered bidi handler**

  Keep at most the existing application fairness window of publish futures active, preserve input order, emit a result only after its handle future resolves, map application failures to bounded `PublicErrorDetail`, and terminate only for transport/framing/lifecycle failures that cannot be represented per input. Implement bounded native session rotation/reconnect in the SDK without adding a protocol timing field; reuse each original operation key until its durable response is observed.

- [ ] **Step 8: Run focused agent and process tests and verify GREEN**

  Run: `cargo test --locked -p aster-agent publish_events -- --nocapture && cargo test --locked -p aster-agent --test real_node_connect -- --nocapture`

  Expected: all tests pass.

- [ ] **Step 9: Commit the RPC increment**

  Commit: `feat(agent): stream durable Event publications`

### Task 4: Documentation, traceability, and host verification

**Files:**
- Create: `docs/decisions/0044-pipeline-durable-event-publication.md`
- Modify: `docs/decisions/0012-content-committing-pq-batches.md`
- Modify: `crates/aster-agent/README.md`
- Modify: `docs/quickstart/connect-agent.md`
- Modify: `docs/protocol.md`
- Modify: `docs/validation/capability-roadmap.md` only for the exact implemented boundary.
- Modify: `docs/validation/requirements-status.md` and `docs/validation/requirements-implementation.csv` only where exact requirement mappings genuinely change.

**Interfaces:**
- Consumes: implemented behavior and passing tests from Tasks 1-3.
- Produces: adopter and reviewer documentation that distinguishes local durability, pipelining, mesh synchronization, browser fallback, and bounded evidence.

- [ ] **Step 1: Document the implemented contract**

  Explain unary compatibility, bounded-session bidi HTTP/2 publication and reconnect, browser gRPC-Web rejection plus concurrent-unary fallback, durable response timing, operation-key retry after lost responses, internal backpressure, bounded structured group diagnostics, numbered-publication exclusion, and the distinction from cryptographic atomic batch publication. Amend Decision 0012 so no-wait grouping of already-admitted ordinary publishes is explicitly compatible with its immediate/no-silent-buffering rule.

- [ ] **Step 2: Update exact traceability only where justified**

  Keep all physical-performance and release claims bounded. Do not move requirement status based only on implementation or exploratory device results.

- [ ] **Step 3: Run documentation and traceability checks**

  Run: `python3 tools/check-implementation-requirements.py`

  Expected: all requirement IDs and exact mappings validate.

- [ ] **Step 4: Run focused regression and full verification**

  Run: `cargo test --locked -p aster-redb-store event -- --nocapture`

  Run: `cargo test --locked -p aster-node event --lib -- --nocapture`

  Run: `cargo test --locked -p aster-agent -- --nocapture`

  Run: `mise run check`

  Expected: all checks pass. `mise run fuzz-smoke` is not required unless implementation changes framing/decoder code beyond generated Protobuf routing; if it does, run it and retain the result.

- [ ] **Step 5: Commit the documented feature**

  Commit: `docs: explain pipelined durable Event publication`

### Task 5: Existing CM4 performance matrix and evidence

**Files:**
- Add or modify repository evidence only if the repository's validation process accepts it.
- Retain raw engineering receipts outside the source tree until that disposition is known.
- Update the draft PR body with exact results and claim boundaries.

**Interfaces:**
- Consumes: the exact verified candidate commit and the established telemetry harness/scripts.
- Produces: main-versus-candidate durable and finite-TTL device comparison, including isolated group-commit and end-user pipeline effects.

- [ ] **Step 1: Run controller and device resource preflight**

  Confirm controller memory/load/disk, device load/memory/disk/temperature, no competing Aster/test processes, ZeroTier readiness, and exact device identities before any build or matrix.

- [ ] **Step 2: Build exact ARM64 main and candidate artifacts**

  Record commit and binary SHA-256 values. Reuse the established build/deploy path and telemetry probe; do not invent another harness.

- [ ] **Step 3: Run smoke tests before the matrix**

  Verify one durable and one finite-TTL Event in each direction, exact operation-key retry, and remote delivery before sustained rates.

- [ ] **Step 4: Run the established matrix**

  Run durable and finite-TTL `0.2`, `1`, `5`, `10`, and `50` Events/s/device for current DU main and candidate. Measure unary concurrency one, fixed concurrent unary window, and candidate bidi pipeline while keeping payload, duration, sync interval, topology, and correctness checks identical.

- [ ] **Step 5: Analyze and retain exact receipts**

  Pin the exact systemd invocation and before/after journal cursors. Extract bounded `event_publication_group` records, require gap-free `group_sequence`, and reconcile summed `collected` with every matrix-client request frame including reconnect replays; reject any incomplete run. Report accepted/skipped/errors, exactly-once delivery, publication and sync p50/p95/p99, CPU, RSS, separate custody/Event/total writer commits per accepted Event, collected/cohort/max-group-size distribution, singleton fallbacks, device activity, and any contact errors. Separate incremental group-commit effect from end-to-end pipelined effect.

- [ ] **Step 6: Run independent whole-branch review**

  Review the implementation, docs, retained receipts, and claim boundaries against the spec, capability roadmap, original requirements, and current DU main. Resolve Critical/Important findings test-first.

- [ ] **Step 7: Squash and prepare one non-stacked PR**

  Rebase on current DU main if needed, squash the feature to one commit, verify the exact squashed commit, push only to the user's fork, and create one draft PR against `defenseunicorns/aster:main` using `.github/pull_request_template.md`.
