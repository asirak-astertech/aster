# Task 12 latest-main merge review

Date: 2026-10-22

## Verdict

**APPROVED.** No Critical, Important, or Minor findings were found in signed
merge commit `7294d8e7e051f30616b8262e5bccbf01ba6e3048`, which merges canonical
`main` at `523e87aab5aa8cf661623ec50847bd87a3f44444` into the PR 110 candidate at
`a96c5be7b98972285368b91924b74ad9ae481b5a`.

This is a scoped merge review. It does not replace the full CI suite,
exact-size Blob qualification, network/device testing, or CM4 validation.

## Both-parent review

- The merge has the expected two parents and a good EDDSA signature from
  `Andrii Sirak <a.sirak@astertech.io>` using key
  `022F53D3C4DAE8774255EF803E5C1559F09ABC66`.
- Both parent-to-merge diffs pass `git diff --check`; the index has no
  unresolved stages, and no conflict markers remain outside build artifacts.
- Of the 33 paths changed by latest main, 26 are byte-identical to main in the
  merge. This includes the removed `MeshService` owner implementation and its
  dependency cleanup in `aster-host`/`aster-lab`, the new diagnostic workflow
  and helper, the refactored lab orchestration, protected-runtime coverage, and
  supporting documentation.
- The seven paths that differ from main are legitimate compositions with PR
  110 work: core runtime, the new core batch tests, selected-node runtime,
  selected-node mesh CLI tests, transport documentation, CI documentation, and
  Compose policy tests. Main's additions remain present and focused tests pass.
- The only combined-diff conflict resolution is the generic core Blob batch
  test. It uses explicit semantic-ceiling constructors on both peers and
  asserts semantic version 8. This is the correct boundary: that generic
  `RuntimeDriver` test validates the pre-profile-5 batch Blob path and must not
  silently begin testing selected-node semantic-v9/profile-5 behavior. The
  ceiling rejects zero and values above the implementation maximum, derives a
  descending `ceiling..=1` offer, and is documented as an implementation
  capability rather than application preference. It does not change ordinary
  constructors or the selected-node v9 path.

## Preservation findings

### Latest-main refactor and diagnostics

- No Rust or Cargo source still defines or references `MeshService`.
- `crates/aster-host` and `crates/aster-lab` match latest main byte-for-byte,
  preserving the ownership simplification rather than reintroducing the
  retired wrapper.
- Main's rekey/reopen runtime coverage and public relay/reopen mesh CLI
  coverage remain intact and pass.
- The runtime-volume diagnostic workflow, diagnostic implementation and tests
  are preserved byte-for-byte from main.
- Main's reviewed GitHub Action pin normalization and mutation tests remain in
  the merged Compose policy suite; PR 110's Blob workflow assertions are
  additive.

### PR 110 v9 pipeline, API, and documentation

- Semantic v9/profile 5 remains the default selected-node Blob streaming path;
  the merged selected-node runtime still contains the v9 profile selection,
  sender/receiver pipeline, custody, resume, and lifecycle integration.
- PR 110's stream codec, sender/receiver/finalization pipelines, transport
  registry, generated application API, CLI Blob lifecycle commands, runbook,
  protocol contract, and requirements mappings remain present.
- The protocol and requirements checks still report semantic versions 1-9,
  348 matrix IDs, and 140 exact selected mappings.

### Transport scope

- The merge does not alter `stream_transport.rs`, `stream_transfer.rs`, or
  `stream_pipeline.rs` relative to the approved PR 110 parent.
- Production composition creates one registry and registers exactly one
  `IrohQuicV1Adapter` with authenticated peer-support context.
- Additional adapter implementations and multi-registration occur only in
  tests. Documentation continues to say one contact-agreed production adapter,
  with cross-transport negotiation/failover deferred. No multi-transport
  protocol or product claim was added.

## Fresh focused evidence

The following checks passed at merge commit `7294d8e7`:

```text
git verify-commit 7294d8e7
# Good EDDSA signature

git diff --check 7294d8e7^1 7294d8e7
git diff --check 7294d8e7^2 7294d8e7
# pass

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-core \
  --features adapter-sdk runtime::tests::batch --lib -- --nocapture
# 3 passed, 0 failed

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-node \
  rekey_reopens_all_nodes_before_fresh_event_and_public_visibility \
  --lib -- --nocapture
# 1 passed, 0 failed

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-node --test mesh_cli \
  public_binary_relay_secrecy_and_consumer_ack_survive_reopen -- --nocapture
# 1 passed, 0 failed

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-node \
  stream_transport::tests --lib -- --nocapture
# 8 passed, 0 failed

python3 tools/test_aster_path_diagnostic.py
# 43 passed

python3 tools/test_aster_compose_delivery.py
# 52 passed

CARGO_BUILD_JOBS=1 cargo clippy --locked -p aster-core \
  --all-targets --all-features -- -D warnings
# pass

CARGO_BUILD_JOBS=1 cargo clippy --locked -p aster-node \
  --all-targets --all-features -- -D warnings
# pass

python3 tools/check-protocol-version-contract.py
# semantic versions 1 through 9 align

python3 tools/check-implementation-requirements.py
# 348 matrix IDs, 140 exact selected mappings

cargo fmt --all -- --check
# pass
```

The first sandboxed relay-test attempt could not bind a UDP socket and failed
with `Operation not permitted`; the exact same focused test passed after
granting localhost network permission. This was an execution-sandbox boundary,
not a product failure.

## Deferred gates

Per the user-directed validation policy, this review did not run the full
workspace suite, ignored/exact-size tests, external network tests, deployments,
or device validation. Those remain CI and exact-artifact CM4 gates.
