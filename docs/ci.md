# Continuous integration

The `CI` GitHub Actions workflow runs the repository's established validation
commands on pushes to `main`, pull requests targeting `main`, merge queues, and
manual dispatches. Configure branch protection or a ruleset to require the
single stable check name **`CI / required`**.

## Validation lanes

| Check | Runner | Purpose |
| --- | --- | --- |
| `quality` | `ubuntu-24.04` | Runs `mise run check`: Rust and Go formatting, Apache-2.0-only project-license and package checks, exact 348-row implementation-requirements traceability, the selected-node dependency boundary, vendored netlink source-equivalence and 13-test compatibility gates, the retained-libp2p-oracle boundary, Clippy with warnings denied, the full Rust workspace test suite, C ABI build and C/C++ header checks, Rust/Python conformance, Python/Go binding tests, and the lab-controller tests. |
| `macOS tests` | `macos-14` | Runs all Rust workspace tests on the supported Apple runner with Rust 1.97.1. |
| `Rust 1.91 MSRV` | `ubuntu-24.04` | Checks every workspace target and feature with the declared minimum supported Rust version. |
| `dependency policy` | `ubuntu-24.04` | Enforces the retained-libp2p-oracle boundary, applies `deny.toml` to the root and fuzz dependency graphs, and audits both lockfiles against a freshly downloaded RustSec database. |
| `age reference interoperability` | `ubuntu-24.04` | Installs exact `govulncheck` v1.6.0, runs `mise run age-reference-audit`, then runs `mise run age-reference-interop`: the Go oracle's reachable vulnerability and compiled-module license gates must pass before exact reference Go `filippo.io/age` v1.3.1 and the Rust provider exchange classic-X25519 artifacts in both directions, compare recovered plaintext, and agree on the recipient. |
| `bounded fuzz smoke` | `ubuntu-24.04` | Runs five fixed 10,000-case hostile-input campaigns with the pinned nightly toolchain and `cargo-fuzz`: semantic wire decode, fragment decode, reference-envelope inspection, selected mechanics-frame decode, and selected Negentropy state-machine/bounds exercise. |
| `required` | `ubuntu-24.04` | Fails unless every validation lane completed successfully; this is the branch-protection check. |

The Rust dependency downloads happen before Cargo validation is switched to
offline mode. The dependency-policy job is intentionally different: it obtains
current advisory data once, audits the root lockfile during that refresh, and
reuses the same database without another fetch for the fuzz lockfile. Its
vulnerability result therefore reflects the RustSec database available when
the workflow ran, rather than a permanently reproducible snapshot.

## Selected composition coverage

`aster-profile`, `aster-redb-store`, `aster-negentropy`, `aster-iroh`, and
`aster-node` are workspace members. The quality lane therefore formats, lints,
and runs their unit and integration tests; the macOS lane tests them; the MSRV
lane checks every target and feature; and the dependency-policy lane audits
their locked graph. The MSRV is Rust 1.91 because the selected Iroh 1.0.3
carrier requires it. `aster-node` enables only `aster-core`'s bounded
`reference-session` feature in its normal graph; SQLite and `rusqlite` are not
present in the selected node's normal dependency graph.
`tools/check-selected-node-dependency-boundary.py` enforces that graph
mechanically: required selected crates and `reference-session` must remain
reachable, while `sqlite-store`, `adapter-sdk`, SQLite packages, the legacy
host/IP runtime, the lab, and the libp2p pilot must remain absent.

The 2026-08-24 frozen-tree run passed 336 `aster-core`, 57 redb-store, 48
node-library, six node-binary, and ten node-integration tests plus doc tests.
Formatting, Clippy with warnings denied, current-toolchain workspace validation,
and the Rust 1.91 every-target/every-feature check passed. Five bounded fuzz
targets completed 10,000 cases each (50,000 total) without a finding. These
counts are execution evidence, not release authorization.

The 57th redb-store cell is a Unix writable-open durability adversary. Every
new or existing writer, including a terminal cleanup handle, must synchronize
the exact retained parent directory before becoming usable. An injected sync
failure exposes no Aster application table, and retry must pass a real barrier.
This is bounded host/filesystem evidence, not non-Unix or physical power-loss
assurance.

The `aster-node` integration suite serializes its process-heavy cells and runs
two real four-node mesh scenarios plus local software-zeroization and abrupt
process-loss cells through the full workspace test command in both the quality
and macOS lanes. The omitted-selector Ping/Pong cell is bounded to 120 seconds.
It requires an isolated peerless Ping publication; a separate two-process
transfer cohort for each forward edge; an isolated peerless Pong publication
that observes the already-durable Ping; a separate two-process transfer cohort
for each return edge; and an equal-inventory no-op. Every directed-edge cohort
must move exactly one pre-existing Event difference, emit no application Event,
and retain zero control counters. Every passing no-op contact must retain zero
for all six control and all five Event counters. The generic schedule has
`2N+1` cohorts and `5N-2` child processes: N=4 therefore uses nine cohorts and
18 processes, while the accepted maximum N=32 would use 65 cohorts and 158
processes. A successful integration root is removed; use the equivalent manual
command when logs and a durable
receipt are needed:

```sh
ASTER_DEMO_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 4 --root "$ASTER_DEMO_PARENT/mesh"
```

A pass must finish with
`DEMO_RESULT status=pass scenario=ping-pong nodes=4 processes=18`,
`contacts=real-iroh`, `mission_auth=hybrid-pq`,
`provisioning=unprotected-reference`, `stores=independent-redb`,
`reconciliation=negentropy`, `producer_process_absent=true`,
`emitted_by=running-node-processes`, `restarts=pass`, `atomic_reaction=pass`,
`equal_inventory_noop=pass`, `transfers_each=2`,
`semantics=source-authenticated-event`, `payload_blind_relays=pass`, and
`ttl=durable-none`. The 2026-08-24 frozen-tree N3, default N4, and N8 observed
loopback results and their exact claim boundaries are recorded in
the [mesh CLI quickstart](quickstart/mesh-cli.md) and [requirements
status](implementation/requirements-status.md). Unit-test or demo success does
not override dependency-policy failure and does not authorize a production
release.

The explicit control cell is bounded to 120 seconds and runs:

```sh
ASTER_CONTROL_PARENT="$(mktemp -d)"
cargo run --locked -p aster-node --bin aster -- \
  demo --nodes 4 --scenario control --root "$ASTER_CONTROL_PARENT/mesh"
```

It requires two short-lived authority processes, source-authenticated chained
Flash controls, durable commit before activation, payload-blind control/Event
forwarding while the authority processes and authority carrier node are absent,
recipient-filtered epoch-two access, two denied captured-node cohorts,
epoch-two Ping/Pong among eligible members, restart replay, and an
equal-inventory no-op. The deterministic 23-process sequence is a causal
barrier: after the two-process control-forward cohort converges, node 2 runs
alone with zero peers and contacts to commit epoch-two Ping; only a later
two-process cohort moves that exact Event into node 1's route-only cache. Four
additional stopped-state barriers move that already-durable Ping to node 0,
commit causal Pong in a one-process zero-peer/zero-contact cohort, move Pong to
the relay, and return Pong to node 2. Every passing contact in the final no-op
must report zero for all six control and all five Event reconciliation counters.
Its terminal invariants include
`CONTROL_RESULT status=pass nodes=4`, `controls=2`,
`captured_epoch2_read=denied`, `captured_mesh_publication=denied`,
`captured_rejoin=denied`, `captured_local_signing=stale-only`, and
`DEMO_RESULT status=pass scenario=control nodes=4 processes=23`. The stale-only
field proves that this is exclusion, not local zeroization. A separate
cross-process test requires the exact-path redb writer lock to reject an
authority command while a node owns the same state and permit it after the node
stops.

The Unix zeroization cells are separate from that control scenario. One
same-UID CLI process requests destruction from a live child node. The node must
drain owned work, close its endpoint, terminally lock the redb store, invalidate
derived secret holders, and overwrite/synchronize/truncate the exact retained
mission-bundle and carrier-identity inodes to owner-only zero-length tombstones.
The receipt must say `mode=live state=complete`,
`data_rows_preserved=true`, `assurance=bounded-software`, and
`physical_sanitization=not-claimed`; the node must say
`STOP lifecycle=zeroized sync_status=terminal-lockout`. The test restores the
credential bytes into those same tombstone inodes and requires normal reopen of
the retained database to remain denied. An idempotent retry must report the
external change without erasing the restored data.

A second real child commits the Immediate-durability terminal marker and exits
abruptly before either artifact is erased. The CLI must resume the exact
recorded inode cleanup, preserve the existing data row, and finish both
zero-length tombstones. Additional library/store cells cover wrong mission
authority, path/inode replacement, symlink, hard-link, owner/mode, corrupt or
partial marker, phase ordering, and normal-open lockout. These checks establish
only a same-UID Unix software hook. They do not prove inode deletion,
deterministic remote observation of mid-flight stream teardown, physical or
copy-on-write sanitization, snapshot/swap/backup destruction, redb
rollback/replacement resistance, non-Unix support, remote triggering, or
independent platform assurance.

A separate retained same-tree probe exercised the Event/mission boundary across
eight loopback nodes and 38 child processes in 17 causal cohorts. It is a manual
receipt, not a CI lane; seven nonempty stderr files preserve ten transient
duplicate-contact or connection-loss lines from the final no-op despite the
exact terminal convergence pass. All 228 passing no-op contacts reported all
11 counters zero. The command, root, artifact digest, and claim boundary are
recorded in the
[requirements status](implementation/requirements-status.md).

The node tests establish the existing `aster-core` four-flight hybrid session
over real loopback Iroh and exercise it in the selected runtime before
inventory. They require exact carrier-to-mission binding, protected mechanics
frames, plaintext and replay rejection, tamper rejection, wrong-carrier,
wrong-mission and cross-mission failure, and rejection of Fetch/Offer identifiers
outside the authenticated contact's independently negotiated difference. They
also cover the Event source-envelope seam, the control-envelope and
recipient-filtered-rekey seams, exact-versus-semantic identity, content versus
route capability, mission-bound redb acceptance, strict chained-control
ordering and pending gaps, atomic commit-before-activate, restart activation
replay, stale/revoked rejection, peer scope-route filtering, and durable
reaction replay. The real-process tests require successful protected contacts
on every eligible line edge and the expected failure on captured-node edges.
They remain bounded to Event, one control family/scope, and loopback; they do not
claim State/Record/Blob, generalized subscriptions/applications or control
administration, finite-TTL custody, protected provisioning, platform-complete
zeroization assurance, admitted release cryptography, independent review, or
physical-network acceptance.

One explicit `cargo deny` advisory ignore covers a bounded active pilot graph.
`RUSTSEC-2026-0173` covers unmaintained build-time `proc-macro-error2` 2.0.1 in
the non-production age-provider pilot. RustSec reports no vulnerability and no
patched release; current Rust separately emits future-incompatibility `E0365`.
The ignore permits that exact informational finding only. It does not suppress
other advisories, change exact package checksums, permit online execution after
the acquisition step, or authorize the provider for production.

The former `RUSTSEC-2024-0436` exception is retired. A path-patched exact
`netlink-packet-core` 0.8.2 preserves its API while resolving the dependency
key `paste` to maintained `pastey` 0.2.2. [Decision 0027](decisions/0027-libp2p-pilot-dependency-policy.md)
and the vendored [`ASTER-PATCH.md`](../third-party/netlink-packet-core-0.8.2-aster/ASTER-PATCH.md)
record the provenance and removal gate. CI now requires `paste` to be absent
from the lock, workspace, and fuzz graphs. It also verifies every retained
upstream file hash, reconstructs and checks the two exact manifest-only deltas,
rejects extra vendored files, and reruns all 13 upstream library unit tests from
a disposable dependency-minimized copy. The decision continues to admit
`BSD-2-Clause`, `ISC`, and `Zlib` for the reviewed external dependency graph;
first-party packages and distributed project files remain subject to the
separate byte-identical Apache-2.0 gate.

The companion scope gate fails if the remaining ignored package's reverse graph
drifts, if it appears in the separately excluded fuzz graph, or if any `paste`
version reappears. Any change to a package chain or advisory disposition
requires a recorded pilot review.

The current Iroh-first dependency-policy run is expected to remain red until an
owner disposition is recorded for exact licenses: `webpki-root-certs` and
`webpki-roots` 1.0.9 use `CDLA-Permissive-2.0`, while all-target browser-WASM
packages `async_io_stream` 0.3.3, `pharos` 0.5.3, and `ws_stream_wasm` 0.7.5 use
the `Unlicense`. No waiver was added. Green tests or a successful artifact build
do not override this release-admission failure.

An advisory-independent retained-oracle gate separately parses locked,
offline, all-feature Cargo metadata. It requires
`aster-libp2p-provider` to remain unpublished and allows no dependency consumer
other than `aster-lab`'s optional `libp2p-candidate` feature. It also rejects
default or aliased activation, renamed or remote provider dependencies, and
local intermediary consumers outside the workspace. The provider remains
directly buildable as a workspace test package so explicit and workspace-wide
validation can exercise the retained oracle without activating it in a default
or shipping consumer. Mutation tests cover each escape route in both the
primary and dependency-policy lanes.

The root lockfile also contains `hickory-proto` and `hickory-resolver` 0.25.2
because the `libp2p` 0.56.0 aggregate manifest exposes DNS and mDNS as optional
features. Aster disables libp2p default features and enables neither optional
feature, so neither Hickory package is present in the resolved workspace graph,
including with every Aster workspace feature and target enabled. They are also
absent from the independent fuzz graph. The raw-lock tools cannot represent
that reachability distinction, so only the root raw-lock `cargo audit` command
narrowly ignores `RUSTSEC-2026-0118` and `RUSTSEC-2026-0119`. Feature-aware
`cargo deny` sees neither inactive package and carries no Hickory ignore.

This is a lock-only tooling disposition, not a runtime vulnerability waiver or
admission of DNS, mDNS, or Hickory. Before either ignore can be used,
`tools/check-dependency-exception-scope.sh` requires the affected lock-only
package set to remain exactly `hickory-proto`/`hickory-resolver` 0.25.2 and
permits the separately resolved, fixed 0.26.1 versions used by Iroh. It proves
that the affected 0.25.2 versions are absent from the full workspace and fuzz
dependency graphs. Its adversarial regression injects an active vulnerable
Hickory version and requires the gate to fail. Package/version drift or future
feature activation therefore blocks CI before the audit suppression is
applied. Remove both ignores when the aggregate libp2p lock no longer contains
the affected optional versions.

The age interoperability lane keeps its independent Go module in
`tools/age-reference/go.mod` and `go.sum`. Its acquisition step canonicalizes
the module with `go mod tidy`, downloads the complete locked graph, and fails if
the final module files differ from the committed files. Exact `govulncheck`
v1.6.0 then performs canonical non-CGO Linux/amd64 source-mode analysis.
Reachable vulnerabilities fail; imported-but-unreachable findings remain
visible as upstream informational output and do not fail, and there is no local
Go suppression list. Offline interoperability execution resolves with
`-mod=readonly`, runs `go mod verify`, and fails unless the selected module is
exactly `filippo.io/age@v1.3.1`. It also enumerates the external modules
compiled for canonical non-CGO Linux/amd64, requires their coordinates to match
the committed receipt set, permits only Apache/BSD/MIT-compatible expressions,
and verifies each reviewed license file's SHA-256. Every resolved module
replacement is rejected before this comparison, so a local or alternate source
cannot inherit an admitted coordinate. It does not install or discover an
ambient age CLI.

Because `deny.toml` expresses an active advisory exception at workspace scope,
both the primary and dependency-policy gates also run
`tools/check-dependency-exception-scope.sh`. Its exact reverse-graph assertions
fail unless `proc-macro-error2` 2.0.1 remains reachable only through the
isolated age-provider pilot and `paste` remains absent from the root lock and
resolved workspace/fuzz graphs. The
ignored package must be absent from fuzz. The same gate proves the vulnerable
raw-lock Hickory pair remains inactive while allowing Iroh's fixed 0.26.1
packages. Adversarial wrappers force a fuzz graph command failure, an active
vulnerable Hickory package, and reintroduced `paste` versions; each must fail
closed.

## Security posture

The workflow is safe to run for pull requests from forks:

- It uses `pull_request`, never `pull_request_target`.
- Its only workflow permission is read-only repository contents.
- It runs exclusively on GitHub-hosted, fixed-version runner labels.
- It does not receive secrets, persist checkout credentials, execute
  submodules, upload artifacts, or use shared Actions caches.
- Every third-party action is pinned to a full commit SHA.
- Concurrency cancels superseded runs for the same pull request or ref, and
  every job has a timeout.

The action and tool pins are:

| Component | Pin |
| --- | --- |
| `actions/checkout` | `3d3c42e5aac5ba805825da76410c181273ba90b1` (`v7.0.1`) |
| `jdx/mise-action` | `3c2e0cf82a5b2e5249f0d3635a4d83d0ae861518` (`v4.2.5`) |
| mise | `2026.4.28` |
| Rust | `1.97.1` |
| Minimum supported Rust | `1.91.0` |
| Go | `1.26.7` |
| Python | `3.13.7` |
| ripgrep | `15.2.0` |
| Reference Go age oracle | `filippo.io/age v1.3.1` |
| `govulncheck` | `golang.org/x/vuln v1.6.0` |
| Fuzz nightly | `nightly-2026-08-18` |
| `cargo-fuzz` | `0.13.2` |
| `cargo-deny` | `0.20.2` |
| `cargo-audit` | `0.22.2` |

Dependabot is configured separately to propose updates to action, Cargo, and
the isolated Go oracle module pins. The exact govulncheck workflow pin remains a
manual reviewed update. An update remains untrusted until these checks pass and
a maintainer reviews the upstream release and the resulting dependency changes.

## Running checks locally

Install the repository toolchain and run the primary gate:

```sh
mise install
mise run check
```

The primary gate runs `tools/check-project-license.py`. It requires every
first-party Cargo package to declare exactly `Apache-2.0`, carry a byte-identical
copy of the canonical `LICENSE`, and include that text in its package archive.
The C, Go, and Python binding roots and the lab runtime image must carry the same
text. The gate also rejects alternate root license files or changed license
text.

Run the independent Go-oracle audit and classic-X25519
provisioning-artifact interoperability gates separately:

```sh
GOBIN=/tmp/aster-go-tools go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
GOVULNCHECK=/tmp/aster-go-tools/govulncheck mise run age-reference-audit
mise run age-reference-interop
```

Keeping these commands outside `mise run check` makes the separately maintained
Go implementation, live vulnerability database, and network-fetched Go
dependency graph explicit. The required CI aggregator still fails unless the
combined lane succeeds. A pass covers the oracle's currently reachable known
vulnerabilities, reviewed compiled-module license receipts, and the outer age
file profile only; it is not independent Aster mesh interoperability,
persistent-custody evidence, or production authorization.

Run the bounded fuzz campaigns separately:

```sh
rustup toolchain install nightly-2026-08-18 --profile minimal
cargo +nightly-2026-08-18 install --locked cargo-fuzz --version 0.13.2
mise run fuzz-smoke
```

The five target names and their exact mechanics-only claim boundaries are
documented in [`fuzz/README.md`](../fuzz/README.md). Fuzz success is not mission,
semantic-conformance, or release authorization by itself.

Check the declared MSRV with:

```sh
rustup toolchain install 1.91.0 --profile minimal
cargo +1.91.0 check --locked --workspace --all-targets --all-features
```

The online advisory scan is time-sensitive. To reproduce that lane's mechanics,
install the pinned tools, refresh the databases, and then apply the same policy
to both lockfiles:

```sh
cargo install --locked cargo-deny --version 0.20.2
cargo install --locked cargo-audit --version 0.22.2
cargo deny fetch all
CARGO_NET_OFFLINE=true sh ./tools/check-dependency-exception-scope.sh
cargo audit --ignore RUSTSEC-2026-0118 --ignore RUSTSEC-2026-0119 --file Cargo.lock
cargo deny --locked --offline check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked --offline check
cargo audit --no-fetch --file fuzz/Cargo.lock
```
