# Task 11 implementation report

## Outcome

Updated the adopter, operator, roadmap, and evidence documentation to match the
canonical semantic-v9/profile-5 implementation completed in Tasks 1–10.

- Documents one canonical durable Blob authority. Profile selection changes
  transfer mechanics, not stored identity or lifecycle authority.
- States exact distinct limits: 65,536-byte canonical plaintext chunk,
  66,215-byte maximum encoded record, 1,048,576-byte maximum `ABX1` extent,
  and 134,217,728-byte (128-MiB) checkpoint batch.
- States that every pre-profile-5 canonical Blob remains profile-5 eligible
  after upgrade, while compatible v7/v8 peers retain profile 4.
- States that provisional uploads, pending receipts, and completed canonical
  variants share configured Blob depot capacity; no 16-GiB stream pool or
  split publication authority is documented.
- Describes Rust, native-gRPC agent, and `asterctl` Blob publish/read as current
  bounded capability while keeping local publication independent of peers.
- Separates receiver-local durable `blob-status` from remote delivery, peer,
  and convergence status.
- Separates implemented node-to-node receipt resume from CLI download resume,
  which is explicitly post-merge work and currently restarts at byte zero.
- Keeps BLE and three-CM4 validation outside the current claim boundary.
- Preserves historical performance receipt numbers and labels them as evidence
  for their original candidate rather than this remediated candidate.
- Corrects stale performance prose that called the 1-MiB extent a canonical
  plaintext segment; the canonical plaintext chunk is 64 KiB.
- Resolves Task 7's deferred Rust API comment: an authenticated empty Blob may
  return exactly one empty terminal EOF page; absence, denial, and out-of-range
  reads do not manufacture empty success.
- Extends the generated requirements trace with the profile-5 runtime,
  transport, upload, agent, and CLI implementation slices.

## TDD evidence

RED observed first:

- The new protocol documentation mutation test failed with
  `AttributeError: ... validate_blob_documentation_contract` before the checker
  existed.
- The new requirement-boundary mutation test failed with
  `AttributeError: ... validate_blob_capability_documentation` before the
  checker existed.
- After adding the Tasks 1–10 implementation slices, the requirements checker
  rejected 50 stale generated `selected_evidence` rows until the CSV was
  regenerated from the authoritative mapping.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 32 tests.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/check-implementation-requirements.py --write` followed by the
  non-writing checker — PASS, 348 rows and 140 exact selected mappings.
- `python3 -m py_compile ...` for both checkers and both focused tests — PASS.
- `cargo fmt --all -- --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- The plan's literal agent command ran zero tests because
  `real_node_connect.rs` is gated by `feature = "client"`. The corrected
  command `cargo test -p aster-agent --features client --test
  real_node_connect blob -- --nocapture` initially failed only because the
  sandbox denied loopback socket creation; the approved non-sandbox rerun
  passed the real Blob test (1 passed, 1 release-only benchmark ignored).
- `git diff --check` — PASS.

No full local suite, push, deployment, or device validation was run.

Signed initial commit: `8174cbfbe15ff7033df42f68d4f69efdb59d288e`
(`docs(blob): document canonical streaming behavior`). `git log
--show-signature` reports a good EDDSA signature from Andrii Sirak.

## Review remediation round 1

All four Important findings in `task-11-review.md` were addressed without
changing runtime behavior.

- The runbook now records the production receiver order exactly:
  authenticated FINISH/content verification, canonical apply/promotion,
  RESULT, ACK, then durable receipt cleanup. It warns that canonical-first
  status may become `AVAILABLE` while settlement or cleanup is pending.
- The durable receipt is documented as keyed by receiving mission authority
  and canonical source, binding the verified plan, depot/store authority, and
  durable checkpoint. It explicitly does not persist the fresh attempt nonce.
- Timeout documentation now reflects the production asymmetry. The sender uses
  exact canonical wire length for its hard deadline; the receiver admits the
  transport before authenticated OPEN using the full 8,679,596,592-byte
  profile wire ceiling. The two-minute authenticated-progress timeout remains
  the shorter stall bound.
- The crate-level Node API, transport guide, and application recipes now state
  that semantic v9 selects profile 5 and v7/v8 retain profile 4, and describe
  64-KiB canonical plaintext chunks as complete ASTRBT01 records batched into
  at-most-1-MiB ABX1 extents.
- Documentation checking now validates those three adopter surfaces
  independently, along with receiver settlement/receipt/timeout claims and the
  performance evidence boundary. A correct phrase in another document can no
  longer mask a stale surface.
- The dated CM4 section again uses its measured legacy ASTRBS02 completed-pack
  and 1-MiB semantic-segment terminology. The entire section is labeled legacy
  and supplies no support for the current candidate. Current 64-KiB/ASTRBT01/
  ABX1 qualification is a separate Task 13 requirement.

RED evidence:

- The expanded documentation mutation test produced eight expected failures:
  the checker did not reject reversed settlement, delayed `AVAILABLE`, an
  attempt-bound receipt, symmetric exact-size receiver timeout, stale Node/
  transport/recipe 1-MiB-segment wording, or reinterpretation of legacy CM4
  evidence.
- After implementing those checks, the live protocol checker rejected the
  still-stale crate-level Node API until its profile and map-unit contract was
  corrected.

GREEN verification:

- `cargo fmt --all -- --check` — PASS.
- `python3 tools/test-protocol-version-contract.py` — PASS, 32 tests.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows and
  140 exact selected mappings.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- `cargo test -p aster-agent --features client --test real_node_connect blob
  -- --nocapture` — PASS, 1 real Blob integration test; 1 release-only
  benchmark ignored.
- `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.

## Review remediation round 2

The remaining Important checker gap in `task-11-rereview-1.md` was closed
without changing documentation or runtime behavior.

- Each current public surface now rejects a coexisting claim that profile 5
  uses independently authenticated 1-MiB segments, even when the correct
  64-KiB/ASTRBT01/ABX1 description remains present.
- The runbook check rejects a coexisting reversed settlement order, a claim
  that the receipt persists an attempt nonce, and a claim that the receiver
  derives its hard deadline from exact content bytes.
- The performance check rejects a claim that legacy 2026-10-20 CM4 evidence
  validates the current ABX1 batching policy. Its contextual rule continues to
  permit the intentionally preserved and explicitly labeled legacy 1-MiB
  ASTRBS02 measurements.

RED evidence:

- Seven coexistence mutation cases retained all required correct text and
  appended one stale contradiction. Before the checker change, all seven
  failed because no `ContractViolation` was raised.

GREEN verification:

- `cargo fmt --all -- --check` — PASS.
- `python3 tools/test-protocol-version-contract.py` — PASS, 32 tests.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows and
  140 exact selected mappings.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- `cargo test -p aster-agent --features client --test real_node_connect blob
  -- --nocapture` — PASS, 1 real Blob integration test; 1 release-only
  benchmark ignored.
- `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.

## Review remediation round 3

The Important paraphrase-bypass finding in `task-11-rereview-2.md` was closed
without changing documentation or runtime behavior.

- Current adopter surfaces now evaluate each sentence as a structured claim:
  1-MiB size, segment unit, authentication, and independence must coexist in
  the same statement. Unrelated transport authentication prose elsewhere in a
  document does not trigger the rule.
- Runbook settlement checks identify both RESULT/ACK-before-promotion and
  promotion-after/following-RESULT/ACK directions. Receipt checks evaluate
  attempt identity and positive storage verbs within a clause, preserving the
  canonical denial and allowing plan/checkpoint bindings. Receiver timeout
  checks recognize receiver, receiving, and incoming roles with exact byte,
  content, or wire inputs.
- Performance evidence checks recognize positive validation, support,
  qualification, proof, demonstration, and establishment claims while
  preserving an explicit denial of support for the current candidate.

RED evidence:

- Seven paraphrase coexistence mutations retained every required correct
  statement. Before this change, all seven failed because the validator
  accepted the contradictory claims.

GREEN and allowance evidence:

- All seven literal coexistence cases and all seven paraphrase cases are
  rejected.
- Explicit denials of the stale segment, settlement, receipt-storage, and
  receiver-deadline claims remain accepted, so ordinary terminology is not
  banned globally.
- Explicitly historical ASTRBS02 support paired with an explicit denial of
  current ABX1 support remains accepted.
- `cargo fmt --all -- --check` — PASS.
- Python compilation of both checkers and focused test modules — PASS.
- `python3 tools/test-protocol-version-contract.py` — PASS, 32 tests.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows and
  140 exact selected mappings.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- `cargo test -p aster-agent --features client --test real_node_connect blob
  -- --nocapture` — PASS, 1 real Blob integration test; 1 release-only
  benchmark ignored.
- `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.

## Review remediation round 4

The two Important findings in `task-11-rereview-3.md` were addressed by
replacing the growing natural-language synonym matcher with a structured,
single-authority documentation contract.

- Node API, transport, application-recipe, runbook, public API, and current
  performance surfaces each contain exactly one JSON capability block. The
  checker owns the typed expected records and rejects missing, duplicate,
  competing, malformed, wrong-typed, extra, or omitted fields.
- The structured fields cover semantic-v7/v8 profile 4 versus semantic-v9
  profile 5, canonical plaintext/ASTRBT01/ABX1 size classes, the 128-MiB
  checkpoint maximum, upgraded legacy eligibility, configured unified depot
  capacity, local peer-independent publish, agent/CLI availability, local-only
  status, absent CLI download resume, settlement order, receipt identity,
  asymmetric deadline inputs, and the pending current CM4 qualification.
- Unstructured coexistence checks no longer enumerate relation synonyms. They
  split adversative clauses and identify competing claims from stable governed
  subjects and objects. Explicit negation must be attached to the governed
  object, so unrelated `not` text does not mask a contradiction.
- All seven fresh reviewer probes are rejected, including `own authentication
  tag`, `on its own`, `separately`, `prior to`, `retains`, `absolute deadline`,
  and `confirm` wording. The four correct clause-level distinction/denial forms
  are accepted.
- The dated ASTRBS02/1-MiB CM4 receipt remains explicitly historical. Its
  original figures and environment were not changed; one duplicate current-
  candidate sentence was replaced by the equivalent historical boundary that
  it supplies no evidence for later candidates.

RED evidence:

- The new structured-contract test failed before implementation because the
  old checker searched for required prose and had no structured block parser.
  Duplicate/malformed field and new contradiction assertions were therefore
  unreachable until the structured contract was implemented.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 33 tests.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows and
  140 exact selected mappings.
- Python compilation of both focused protocol checker modules — PASS.
- `cargo fmt --all -- --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests; existing
  non-test-feature warnings remain unchanged.
- The sandboxed agent integration run failed only because loopback socket
  creation was denied. The approved non-sandbox rerun of `cargo test -p
  aster-agent --features client --test real_node_connect blob -- --nocapture`
  passed 1 real Blob integration test with 1 release-only benchmark ignored.
- `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.

Signed fix commit: `95a1749cdeb6c923a29b653b7ab8f6e767d4ce55`
(`test(docs): structure blob capability contract`). `git log
--show-signature` reports a good EDDSA signature from Andrii Sirak.

## Review remediation round 5

The three Important findings in `task-11-rereview-4.md` are resolved with a
deterministic documentation-authority model rather than another natural-language
synonym matcher.

- `docs/validation/requirements-status.md` now has an independently checked
  semantic-v9/profile-5 record and render. Its current composition, topology,
  selected offer, and selected Blob network sections use default offer
  `[9, 8, 7, 6, 5, 4, 3, 2, 1]`, semantic v9/profile 5, and v7/v8/profile-4
  compatibility. Historical evidence rows and status credit remain unchanged.
- README, agent README, CLI README, selected-Blob guide, operator guide, and
  capability roadmap are six independent governed surfaces. Each contains
  exactly one typed JSON record and one mechanically rendered current-capability
  paragraph; none is hidden behind an aggregate document input.
- The checker rejects case-varied markers and additional marked or unmarked
  capability-shaped JSON while accepting unrelated JSON/code examples.
- Outside the canonical section, stable topic-anchor combinations are rejected
  without interpreting relation verbs or proximity-based negation. Accurate
  alternative wording such as `promotion precedes RESULT and ACK` is governed
  by the same rule and must live in the generated section. Frozen historical
  performance evidence is isolated by explicit legacy delimiters.
- Tests cover all four public API contradictions in every governed public file,
  all unrelated-negation bypasses, `promotion precedes`, `legacy differs`,
  lowercase/unmarked JSON, stale current-v8 requirements wording, explicit
  legacy content, and unrelated examples.

RED evidence:

- The new bypass test produced ten failures before implementation: unmarked and
  lowercase capability blocks, all four public API contradictions, and all four
  unrelated-negation contradictions were accepted.
- The structured requirements test failed against the former presence-only
  prose checker before it was changed to validate the typed roadmap record and
  exact render.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 34 tests.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-implementation-requirements.py` — PASS, 1 test.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows and
  140 exact selected mappings; selected status totals unchanged.
- Python compilation of both checkers and focused test modules — PASS.
- `cargo fmt --all -- --check` and `git diff --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- `cargo test -p aster-agent --features client --test real_node_connect blob
  -- --nocapture` — sandbox run failed only because loopback socket creation was
  denied; approved external rerun passed 1 real Blob test with 1 release-only
  benchmark ignored.

No full suite, push, deployment, or device validation was run.

Signed round-5 fix commit: `4c855a51384f056c2ed46ba41fdabe2bb9e2d2fe`
(`docs(blob): enforce per-surface capability authority`). `git log
--show-signature` reports a good EDDSA signature from Andrii Sirak.

## Review remediation round 6

The three Important findings in `task-11-rereview-5.md` were addressed while
preserving the round-5 single-authority design.

- The requirements ledger now has seven independently named, exact generated
  current-Blob section contracts: selected-lane summary, live mechanism,
  current automation, selected network slice, production network, production
  read, and production lifecycle. The surrounding present-tense prose and
  production rows now describe semantic-v9/profile-5 receiver-authoritative
  checkpoints, complete ASTRBT01 records in bounded ABX1 extents, the 8-GiB /
  131,072-chunk boundary, and v7/v8 profile 4 only as compatibility. Frozen
  profile-4 receipt measurements remain unchanged and explicitly historical.
- The stale hand-maintained totals and second conflicting family table were
  replaced by one generated block derived from the actual trace. The
  requirements checker now binds its current total, every family row, and the
  selected-mapping count. The visible authority is 53
  implemented-uncredited, 84 observed-bounded, 211 open, and 140 exact
  selected mappings.
- Capability-shaped JSON detection now recursively walks mappings and arrays,
  while nested unrelated JSON remains allowed.
- `asterctl-blob-publish(1)`, `asterctl-blob-read(1)`, and
  `asterctl-blob-status(1)` are three separately enumerated surfaces. Each has
  an exact typed record and generated render in roff comments, so the machine
  authority does not leak into rendered manual pages. Tests independently
  reject a missing surface, an extra aggregate surface, a wrong record, and a
  duplicate authority for each manual page.

RED evidence:

- The protocol test initially errored for the missing named-section contract;
  nested-object and array authority probes were newly present and unreachable
  until that production surface was implemented.
- The requirements tests errored because no trace-derived totals renderer or
  validator existed.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 36 tests.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-implementation-requirements.py` — PASS, 3 tests.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows, 140
  exact selected mappings, and exact selected-status totals 53 / 84 / 211.
- Python compilation of all four focused checker/test modules — PASS.
- `cargo fmt --all -- --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- The sandboxed agent integration run failed only because loopback socket
  creation was denied. The approved external rerun of `cargo test -p
  aster-agent --features client --test real_node_connect blob -- --nocapture`
  passed 1 real Blob test with 1 release-only benchmark ignored.

Task 12 diagnostic, intentionally not changed in this documentation task: the
fresh real-node output still prints
`reconciliation_classes=event,state,record,blob-v7-v8-profile4` in READY and
STOP. The stale operator label comes from
`crates/aster-node/src/runtime.rs` (`READY_RECONCILIATION_CLASSES` near line
690 and the literal STOP format near line 18963); the adjacent `with_blob`
API comment also describes only v7/v8 profile 4 near line 1082. Task 12 must
reconcile those v9/profile-5 runtime status strings/comments and their focused
assertions without changing the negotiated compatibility behavior.

No full suite, push, deployment, or device validation was run.

Signed round-6 fix commit: `014011869b66b2d9eb55fe8c1103e0360277e9ed`
(`docs(blob): bind current capability evidence`). `git log --show-signature`
reports a good EDDSA signature from Andrii Sirak.

## Review remediation round 7

The three Important findings in `task-11-rereview-6.md` are addressed without
changing runtime behavior.

- The adjacent current `RunningNode::selected_blobs()` requirements prose now
  states the 8-GiB/131,072-chunk bound, joined two-worker/two-queue canonical
  finalizer, semantic-v9/profile-5 ASTRBT01-in-ABX1 transfer, and
  receiver-authoritative durable checkpoints. The old 16-KiB/profile-4 receipt
  is explicitly historical and does not qualify the current candidate. A new
  exact named current-section authority covers this location.
- Each Blob man page now receives relation-aware competing-prose validation in
  addition to its exact typed/generated capability block. The checker rejects
  peer-dependent local publication, positive CLI byte-resume claims, and
  remote/peer/convergence status claims while accepting the corresponding
  accurate explicit denials in ordinary operational prose.
- Current-section marker recognition is normalized across case and
  hyphen/underscore/whitespace variants before canonical block parsing. Any
  extra or malformed variant is rejected; unrelated historical and Record
  markers remain allowed.

RED evidence:

- The focused requirements/man-page tests produced eight failures before the
  checker changes: four malformed current-marker variants, the stale current
  RunningNode mechanism, and one contradiction in each of the three man pages.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 36 tests.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-implementation-requirements.py` — PASS, 3 tests.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows, 140
  exact selected mappings, and exact selected-status totals 53 / 84 / 211.
- Python compilation of all four focused checker/test modules — PASS.
- `cargo fmt --all -- --check` and `git diff --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests.
- The sandboxed real-node agent test failed only because loopback socket
  creation was denied. The approved external rerun of `cargo test -p
  aster-agent --features client --test real_node_connect blob -- --nocapture`
  passed 1 real Blob test with 1 release-only benchmark ignored.

The stale runtime READY/STOP diagnostic and adjacent `with_blob` comment remain
queued for Task 12, as required by the round-7 brief. No full suite, push,
deployment, or device validation was run.

Signed round-7 fix commit: `91bb8096589abe9ccd1326f7eb59cad3df7d3596`
(`docs(blob): close capability authority gaps`). `git log --show-signature`
reports a good EDDSA signature from Andrii Sirak.

## Review remediation round 8

The two Important findings in `task-11-rereview-7.md` are addressed without
changing runtime behavior.

- The remaining current selected-Blob evidence paragraph is now governed by
  the exact named `current-selected-blob-evidence` section. Its required render
  states semantic v9/profile 5, receiver-authoritative checkpoints, ABX1
  canonical extents, and the 8-GiB/131,072-chunk bound; v7/v8 profile 4 is
  compatibility-only. Semantic-v8 finite-custody, pressure, and GC evidence is
  retained specifically for that compatibility path.
- The three man-page body checks no longer interpret verbs, relations, or
  negation. Outside each exact generated capability section, stable governed
  topic anchors are forbidden regardless of whether the sentence contradicts
  or accurately duplicates the authority: publication plus peer for publish,
  download/blob-read plus resume for read, and blob-status plus
  remote/peer/delivery/convergence for status.
- Duplicate capability paragraphs were removed from the man-page bodies. The
  operational descriptions, flags, progress behavior, file safety, state
  enumeration, and examples remain ordinary body content.
- Tests include all six fresh contradictory review probes, all three accurate
  duplicate probes, the stale current requirements wording, exact omission of
  v9 from the new named section, and three allowed operational flag examples.

RED evidence:

- The two focused tests failed in ten places before implementation: the new
  requirements section name was absent, six fresh contradictions were
  accepted, and three accurate duplicate claims were not consistently
  rejected.

GREEN verification:

- `python3 tools/test-protocol-version-contract.py` — PASS, 36 tests.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-implementation-requirements.py` — PASS, 3 tests.
- `python3 tools/check-implementation-requirements.py` — PASS, 348 rows, 140
  exact selected mappings, and exact selected-status totals 53 / 84 / 211.
- Python compilation of all four focused checker/test modules — PASS.
- `cargo fmt --all -- --check` and `git diff --check` — PASS.
- `cargo test -p asterctl --test blob -- --nocapture` — PASS, 7 tests; existing
  non-test-feature warnings remain unchanged.
- The sandboxed real-node agent test failed only because loopback socket
  creation was denied. The approved external rerun of `cargo test -p
  aster-agent --features client --test real_node_connect blob -- --nocapture`
  passed 1 real Blob test with 1 release-only benchmark ignored.

The stale runtime READY/STOP diagnostic and adjacent `with_blob` comment remain
queued for Task 12. No full suite, push, deployment, or device validation was
run.
