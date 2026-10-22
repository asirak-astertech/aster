# Task 9 implementation report

Planned signed commit: `fix(protocol): align profile 5 contract and fuzzing`.

## Outcome

- Aligned the normative protocol prose and CDDL notes with the executable
  semantic profile registry: semantic v7/v8 select profile 4 and semantic v9
  selects profile 5. This is not a downgrade or migration to v8 and does not
  add a second durable Blob representation.
- Documented the bounded profile-5 grammar as `PLAN -> OPEN -> SOURCE -> ACCEPT
  -> ABX1 DATA -> CHECKPOINT -> FINISH -> RESULT -> ACK`, including the exact
  authenticated empty terminal path with no DATA or CHECKPOINT.
- Derived and locked the distinct executable bounds for canonical 64-KiB
  chunks, complete 66,215-byte carriers, 1-MiB ABX1 extents, 128-MiB checkpoint
  batches, the 2-MiB Iroh frame ceiling, 8-GiB objects, 131,072 chunks, and a
  16-MiB authenticated source. The checker parses the Rust declarations and
  fails if documentation or implementation drifts.
- Removed semantic-v9 ambiguity around `ASTRBS02`: it remains provisional local
  upload staging only. Profile-5 DATA contains byte-identical canonical
  `ASTRBT01` records in `ABX1` extents.
- Extended the independent Python oracle with every profile-5 stream record,
  accepted/rejected vectors, exact composite DATA, and actual decodable `HEX:`
  fuzz seeds. The historical ranges corpus is explicitly profile-4
  compatibility evidence.
- Changed `stream_transfer_decode` from marker-driven generated frames to the
  actual supplied bytes. Accepted frames are canonical-round-tripped and the
  fuzz path exercises truncation, trailing bytes, overflow, malformed ABX1,
  attempt binding, checkpoint rollback, and terminal replay/change rejection.
- Added the stream target to the portable fuzz-smoke inventory and bounded
  10,000-run campaign.
- Updated the public Rust Blob API comments for the authenticated zero-length
  terminal EOF exception.
- Reworked the canonical engineering runbook and affected CLI/agent/API
  examples. They now cover local-first publication, receiver-local status,
  interruption/resume across adapter changes, v8/v9 behavior, protected
  interest/route/content gates, the two-worker/two-queue finalization bound,
  depot overlap, idle/size-derived timeouts, diagnostics, current Iroh and
  future non-IP/BLE adapter scope, and CM4 validation still required.

## Migration and compatibility

There is no durable-content migration. Existing v7/v8/profile-4 bytes and
their 64-MiB / 1,024-chunk / 1-MiB-source bounds remain unchanged. V9 selects
profile 5 and transfers the same canonical durable Blob representation with an
8-GiB / 131,072-chunk / 16-MiB-source envelope. A profile-5 attempt never
downgrades in place. Empty content is profile-5 only and settles through an
authenticated zero-length terminal result.

Receipt resume remains publication-, attempt-, checkpoint-, and commitment-
bound, but adapter-neutral. A later reliable ordered full-duplex adapter can
continue from the receiver's durable receipt. BLE and multi-adapter failover
are deliberately not implemented by this task.

## TDD evidence

Red:

- `python3 tools/test-run-fuzz-smoke.py` failed three tests because the portable
  target list and both platform campaign assertions omitted
  `stream_transfer_decode`.
- `python3 tools/test-protocol-version-contract.py` failed fourteen new
  mutations because the checker did not enforce the profile registry, exact
  numeric bounds, grammar, empty settlement, CDDL relationship, or decodable
  stream corpus.

Green:

- `python3 conformance/blob_stream_oracle.py` — PASS; profile-4 compatibility
  and profile-5 corpora/seeds match the independent construction.
- `python3 tools/check-protocol-version-contract.py` — PASS; semantic versions
  1 through 9 align.
- `python3 tools/test-protocol-version-contract.py` — PASS, 25 tests.
- `python3 tools/test-run-fuzz-smoke.py` — PASS, 3 tests.
- `cargo test -p aster-node stream_transfer -- --nocapture` — PASS, 25 passed,
  1 explicit 1-GiB performance test ignored, 0 failed.
- `cargo test --manifest-path fuzz/Cargo.toml --lib` — PASS, 3 tests.
- `ASAN_OPTIONS=detect_leaks=0 bash tools/run-fuzz-smoke.sh` — PASS; all ten
  bounded 10,000-run campaigns completed, including
  `stream_transfer_decode` with eight generated profile-5 seeds.
- `cargo fmt --all -- --check` — PASS.
- `git diff --check` — PASS.

The first local smoke invocation without `ASAN_OPTIONS=detect_leaks=0`
completed the initial 10,000-run target but LeakSanitizer then rejected the
sandbox's ptrace policy. The rerun disabled only leak discovery for this
ptrace-restricted environment; AddressSanitizer fuzz execution and all bounded
campaigns completed successfully.

## Deferred validation

Per instruction, no full repository suite, push, deployment, or production
device change was performed. The runbook records the remaining three-CM4
validation: raw WLAN baseline, local publication, v9-to-v9 transfer,
interruption/resume, receiver read/hash, resource bounds, and v8/v9 behavior
using the exact CI-built ARM64 artifact. Existing device measurements are not
claimed as qualification for this build.

## Review remediation round 1

The three Important and two Minor findings in `task-9-review.md` are addressed.

- Production semantic-v9 admission, credit rounding, validation, and attempt
  accounting now use the exact 1,048,576-byte encoded ABX1 ceiling. The
  1,048,710-byte ASTRBS02-derived record is confined to `cfg(test)` legacy
  upload-pack fixtures. The canonical sender derives its exact extent count
  from `Profile5CanonicalWireShape`; generic receive-before-authentication
  bounds conservatively budget up to all 131,072 canonical chunks, including
  ASD1/protected-frame and control overhead. Focused tests prove 1 MiB succeeds,
  1 MiB + 1 fails, and a maximum shape cannot exceed its attempt budgets.
- Added `conformance/profile5-wire-schema.json` as the complete
  machine-checkable structured equivalent for the non-CBOR fixed-binary wire.
  It specifies all eight tags, every ordered field and width/bound, enums,
  ABX1 `carrier_len`, ASD1 framing, and empty/nonempty flows. The standalone
  checker binds it to Rust encoder tag/field order and executable constants,
  invokes the independent oracle, and therefore verifies every generated TSV
  and seed. Mutation tests cover every record tag, every field order and
  width/bound, both aggregate bounds, the result-code enum, and independent
  oracle/vector drift.
- The oracle now emits production-valid ASTRBT01 carriers, coherent nonempty
  and empty transcripts, plus rejected rollback, binding, and terminal-change
  transcripts. It independently validates the accepted bindings/sequences and
  proves the named invariant broken by every rejected transcript.
  ACCEPT/DATA/CHECKPOINT/FINISH/RESULT/ACK sequences reflect the actual
  direction-specific state-machine counters.
- Added real ASD1 corpus seeds for a normal valid carrier and an exact 1-MiB
  ABX1 boundary extent, plus complete empty and nonempty transcript seeds.
  Fuzz DATA reaches the production canonical carrier inspector, mutates carrier
  authentication bytes, and feeds input-derived bindings, sequences, offsets,
  generations, and complete settlement transcripts through
  `StreamSenderState`/`StreamReceiverState`. The smoke maximum is 1,052,672
  bytes, above the exact 1,050,632-byte composite ceiling with explicit margin.
- Runbook examples now use the agent's actual 900-second Blob RPC cap and
  explain exact-operation retry, status, receiver receipt resume, and
  download restart. Remaining PR95 “completed-pack” terminology in touched
  documentation was replaced with canonical ABX1/profile-5 language.

Focused verification:

- `python3 conformance/blob_stream_oracle.py` — PASS.
- `python3 tools/check-protocol-version-contract.py` — PASS.
- `python3 tools/test-protocol-version-contract.py` — PASS, 27 tests.
- `python3 tools/test-run-fuzz-smoke.py` — PASS, 3 tests.
- `cargo test -p aster-node stream_transfer -- --nocapture` — PASS, 27 passed,
  1 explicit performance test ignored.
- `cargo test --manifest-path fuzz/Cargo.toml --lib` — PASS, 3 tests.
- Direct `stream_transfer_decode` smoke with the generated twelve-seed corpus,
  `-runs=10000 -max_len=1052672 -seed=2026102201` — PASS, 10,000 runs; maximum
  seed 1,048,673 bytes; peak RSS 403 MiB.
- `cargo fmt --all -- --check` and `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.

## Review remediation round 2

The two Important findings and Minor terminology finding in
`task-9-rereview-1.md` are addressed.

- `StreamOpenV1.total_len` is now explicitly the canonical ABX1 wire length.
  Encoder admission, decoder admission, the receiver ceiling, structured
  schema, protocol prose, checker, oracle, and vectors use the derived exact
  maximum of 8,679,596,592 bytes. The derivation uses the executable 66,215-byte
  carrier maximum, 15 maximum carriers per 1-MiB ABX1 extent, 131,072 chunks,
  and one 16-byte ABX1 header per extent. A focused maximum-shape proof reaches
  the same terminal wire offset; maximum + 1 is rejected. The separate 8-GiB
  plaintext object limit remains on manifest/source fields.
- The standalone checker now binds every record tag, ordered field and
  width/type/bound to both Rust encoder and decoder tokens plus executable
  validators. It also binds every nested attempt field, ABX1 magic/index/count/
  carrier length and aggregate limits, ASD1 magic/header length/protected
  header/extent and aggregate limits, enums/result codes, and both exact flows.
  Mutation tests cover each of these elements, representative decoder offsets,
  executable bound drift, the prior incorrect 8-GiB OPEN bound, and independent
  oracle/vector drift.
- Both ASD1 seeds now contain stable authenticated `ASTRFR01` headers produced
  by a fixed production reference mission/session codec fixture. The fuzz path
  opens those headers through `MissionBlobRecordCodec` and
  `open_v9_blob_data_header` before decoding ABX1. It then calls the production
  route/manifest-bound canonical carrier inspector, proves the valid
  `ASTRBT01` carrier is accepted, and proves an authenticated-byte mutation is
  rejected. The maximum-boundary seed uses the same production path.
- The transcript harness has an independent small phase/state model for
  attempt binding, source/data/control sequences, offsets, cumulative credit,
  checkpoint-generation monotonicity, durable completion, terminal replay,
  terminal change, and ACK binding. Every decoded input is driven through the
  production sender/receiver states and its result is compared with the model.
  Checked-in seeds prove accepted empty/nonempty and rejected binding,
  rollback, DATA replay, and terminal-change branches. An initial direct fuzz
  run exposed and reproduced a mutable seed-label false oracle; replacing that
  label assertion with the independent input-derived model eliminated the
  harness defect.
- Public API and engineering runbook language now calls the residual bytes
  completed provisional upload staging and states that only canonical
  publication is authoritative.

Focused verification:

- `python3 conformance/blob_stream_oracle.py` — PASS.
- `python3 tools/check-protocol-version-contract.py` — PASS; semantic versions
  1 through 9 align.
- `python3 tools/test-protocol-version-contract.py` — PASS, 29 tests.
- `python3 tools/test-run-fuzz-smoke.py` — PASS, 3 tests.
- `cargo test -p aster-core maximum_wire_bound_is_derived_from_executable_carrier_partitioning -- --nocapture`
  — PASS, 1 test.
- `cargo test -p aster-node --features fuzzing stream_transfer -- --nocapture`
  — PASS, 29 passed, 1 explicit 1-GiB performance test ignored.
- `cargo test --manifest-path fuzz/Cargo.toml --lib` — PASS, 3 tests.
- Direct `stream_transfer_decode` campaign with
  `-runs=10000 -max_len=1052672 -seed=2026102202` — PASS, 10,000 runs, 5,000
  executions/second, peak RSS 412 MiB.
- Fresh-copy replay loaded all 17 checked-in seeds, including both production
  ASD1 composites and all six accepted/rejected transcripts, and completed 100
  mutation runs with maximum input 1,048,725 bytes — PASS.
- `cargo fmt --all -- --check` and `git diff --check` — PASS.

No full suite, push, deployment, or device validation was run.
