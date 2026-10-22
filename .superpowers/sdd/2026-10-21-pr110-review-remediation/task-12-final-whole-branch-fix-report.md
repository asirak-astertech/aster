# Task 12 final whole-branch fix report

Date: 2026-10-22

## Status

All five findings in `task-12-final-whole-branch-review.md` are corrected with
focused evidence. The changes do not add multi-transport selection or failover,
restore the old serial Blob API, deploy software, touch devices, or claim
exact-size/full-suite evidence.

## Corrections

### I1: committed fuzz dependency graph

The repository-pinned Cargo 1.97.1 toolchain refreshed the fuzz graph with:

```text
cargo update --manifest-path fuzz/Cargo.toml -p aster-redb-store --offline
```

`fuzz/Cargo.lock` now records `zeroize` in `aster-redb-store`'s dependency
entry. Cargo also normalized four target-specific `windows-sys` dependency
edges from 0.61.2 to the already locked 0.52.0 package while regenerating the
graph. The committed graph passes the repository's locked-manifest checker and
its three regression tests.

### I2: exact upload-capacity fixture

`upload_capacity_remains_charged_through_canonical_promotion` now derives both
pack and digest-sidecar charges from the production reservation helpers. The
one-chunk fixture explicitly asserts the sidecar's exact 118-byte reservation
(86-byte versioned header plus one 32-byte digest) before composing the exact
capacity limit. The production accounting remains unchanged.

### I3: explicit unreleased `PublishBlob` cutover

The approved remediation design, its implementation plan, the earlier Blob UX
design/plan, the selected-Blob quickstart, agent connection guide, agent README,
and engineering runbook now agree on the application API boundary:

- PR 110 deliberately replaces the unreleased PR 95 `v1alpha1`
  client-streaming/unary `PublishBlob` exchange with the bidirectional
  metadata/accepted/data/checkpoint/finish/complete exchange;
- there are no production deployments and therefore no deployed-client
  compatibility promise for the PR 95 generated method;
- clients must stop, upgrade, regenerate bindings, and preserve the original
  operation key and exact intent when resolving an uncertain publication;
- no additive legacy mutation method is retained because that would freeze a
  second upload/recovery grammar without a deployed consumer; and
- this is an application-wire cutover, not a Blob identity, canonical storage,
  operation-key, mesh profile, or stored-content migration.

The governed protocol-version and implementation-requirements checks remain
green. No requirement status or evidence credit changed.

### I4: current upload custody and transport wording

Operator documentation now describes native agent upload as bounded frames
written directly into node-owned durable upload packs/checkpoints on platforms
supported by the selected node/store. It no longer claims a Linux-only,
agent-owned plaintext staging file or fixed unsupported `PublishBlob` response.

The docs separately retain the Linux/qualifying-filesystem boundary for
`asterctl blob-read` destination-file finalization. Resume wording now says a
fresh instance or reopen of the same single contact-agreed adapter; it does not
claim production cross-transport selection or failover.

### M1: default-feature warning

The non-test build now intentionally consumes the test-only
`observe_profile5` argument under the complementary configuration. Default
`cargo check` and warning-denying default-feature clippy are clean.

## Test-first evidence

RED before correction:

```text
sh tools/check-cargo-lockfiles.sh
# failed: fuzz/Cargo.lock could not satisfy fuzz/Cargo.toml under --locked

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-redb-store \
  upload_capacity_remains_charged_through_canonical_promotion --lib -- --nocapture
# failed: incoming=68005, limit=67887 (118-byte omitted sidecar charge)

CARGO_BUILD_JOBS=1 cargo check --locked -p aster-redb-store
# succeeded with an unused-variable warning for observe_profile5
```

GREEN after correction:

```text
sh tools/check-cargo-lockfiles.sh
# pass: root, fuzz, and evaluation-runner committed lockfiles

python3 tools/test-check-cargo-lockfiles.py
# 3 passed

CARGO_BUILD_JOBS=1 cargo test --locked -p aster-redb-store \
  upload_capacity_remains_charged_through_canonical_promotion --lib -- --nocapture
# 1 passed; 660 filtered out

CARGO_BUILD_JOBS=1 cargo check --locked -p aster-redb-store
# pass without warnings

CARGO_BUILD_JOBS=1 cargo clippy --locked -p aster-redb-store --lib -- -D warnings
# pass

sh tools/check-agent-proto.sh
# pass: format, lint, and checked-in descriptor

python3 tools/check-protocol-version-contract.py
# pass: semantic versions 1 through 9 align

python3 tools/test-protocol-version-contract.py
# 36 passed

python3 tools/check-implementation-requirements.py
# pass: 348 matrix IDs and 140 exact selected mappings

python3 tools/test-implementation-requirements.py
# 3 passed

cargo fmt --all -- --check
git diff --check
# pass
```

## Signed commits

- `6b964618607e2d0d1cbc662118b29bcfddf9346d` —
  `fix(blob): close whole-branch readiness blockers` (Good EDDSA signature)
- `docs(blob): record streaming cutover boundary` — the signed documentation
  commit that carries this report.

## Deferred evidence and remaining operational boundary

The full workspace suite, exact-size/ignored Blob gates, physical-device tests,
network deployment, and push were intentionally not run. External clients made
from the PR 95 schema must regenerate and implement the bidirectional recovery
exchange before connecting; compatibility with that unreleased generated
method is intentionally not supplied.
