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

The retained parent PR-A/pre-subscription 2026-08-24 frozen-tree run passed 336
`aster-core`, 57 redb-store, 48 node-library, six node-binary, and ten
node-integration tests plus doc tests.
Formatting, Clippy with warnings denied, current-toolchain workspace validation,
and the Rust 1.91 every-target/every-feature check passed. Five bounded fuzz
targets completed 10,000 cases each (50,000 total) without a finding. These
counts are execution evidence for that parent snapshot, not PR-B/current-tree
evidence or release authorization.

PR B adds a separate selected Event subscription gate. Store tests cover
partial/wrong-kind migration, corrupt and terminal-open handling, canonical
Consume/Carry projection and selector generation, idempotent subscription replay
and conflict, attempts across reopen, idempotent semantic-ID acknowledgement,
gap delivery, zero-match cursor advance, inactive-pending retirement, and stale
plan/policy rejection. Frame tests enforce a maximum of 256 canonical selectors
and empty-as-receive-none. Application/runtime tests freshly source/content
verify poll candidates and prove that protected receiver interest transfers
subscribed `beta`, withholds authorized-unsubscribed `alpha`, and transfers
nothing when the durable selector set is empty. These are current code/test
claims only; no retained real-process PR-B root is identified here.

PR C extends that current-code gate through the running node's sole actor.
`SelectedEventHandle` covers async publish/query/subscribe/poll/ack,
idempotent unsubscribe, bounded authenticated gap inspection, and sanitized
peer/last-contact status. The selected store adds atomic selector removal,
delivery-ledger purge, monotonic selector generations, and policy-bound gap
plans that are freshly verified and race-rechecked before exposure. The
compiled `live_event_application` example exercises the public surface while
no peer is configured.

The PR-C validation set includes all of the following:

```sh
cargo check -p aster-node --all-targets
cargo test -p aster-node --all-targets --no-run
cargo clippy -p aster-node --all-targets -- -D warnings
cargo test -p aster-node application::tests
cargo test -p aster-node oversized_run_for_is_rejected_before_readiness_or_state_mutation
cargo test -p aster-node queued_live_zeroization_outranks_an_elapsed_run_for_deadline
cargo test -p aster-node run_for_preempts_a_saturated_application_queue_and_closes_every_caller
cargo test -p aster-node authenticated_contact_status_progresses_with_saturated_application_queues
cargo test -p aster-node live_selected_event_actor_is_peerless_durable_and_closes_admission
cargo test -p aster-node live_zeroization_closes_selected_event_admission_before_erasure
cargo test -p aster-node --test mesh_cli \
  offline_publish_later_real_process_sync_poll_ack_and_restart -- --exact
```

The application module has seven passing tests. Focused runtime cells prove
peerless live operations, reject an overflowing `run_for` before readiness or
state mutation, ensure a queued zeroization request outranks an already elapsed
deadline, preserve a nonzero operational interval under saturated application
callers, allow authenticated contact/status progress despite saturated callers
and continuously overdue one-nanosecond ticks, and close admission during
shutdown/zeroization. The focused Unix integration cell uses separate processes
and stores to publish with no configured peer, restart into a later
authenticated contact, poll and acknowledge at the receiver, and verify the
acknowledgement after receiver restart. The current-toolchain selected-code
suite passed 499 of 499 tests: 336 core, 68 node-library, six node-binary, 13
`mesh_cli`, and 76 selected-store tests; the examples had no tests.

A later timeout-only hardening gave the offline cell one shared 40-second
cold-start deadline across retries and kill/reap cleanup on publisher spawn
failure.
Against the final test bytes, that focused cell then passed twice on the current
toolchain and three times on Rust 1.91.

The separate exact-tree Rust 1.91.0 matrix then passed 499 of 499: core 336/336
(126.48s), node library 68/68 (28.43s), node binary 6/6 (0.02s), `mesh_cli`
13/13 (148.26s), and selected store 76/76 (31.81s); the examples had no tests.
These are separate executions; their timings are not pooled. No individual
offline-cell elapsed time or retained execution root is claimed.

The frozen SHA-256 identities are:

- `crates/aster-node/src/application.rs`: `2ad1b080bfed2ba654b0d29c0cd6eab5f1eb6f4799dbb09203dc18a085b713d0`
- `crates/aster-node/src/runtime.rs`: `81021e226bd413826e3afcea6adf7e8c6e0f22f547f59631a30238e1a015c6c2`
- `crates/aster-node/src/lib.rs`: `b3a684b32b474c5ee22d1c24e0e7bdb19ff2f9613ca42cf3cdf3ebda5262476c`
- `crates/aster-node/examples/live_event_application.rs`: `e31a456a98950d5439b3b6ecd6492f0cbdfb50ad827856c97041b9645d278f82`
- `crates/aster-node/tests/mesh_cli.rs`: `59c858c0bc559944546e88eefee550523fd64905e4b2779a9a3d1a7eb2b8ce0e`
- `crates/aster-redb-store/src/lib.rs`: `364e5a1d8d7f7b24ab75afe8ec2791023db83b11997bd07722c7d107a16a6a00`

This is current-code automated loopback evidence only: no retained PR-C
execution root or log artifact, physical system, independent implementation,
or release artifact is claimed.

The later stopped/local State, Record, and Blob gates are additive to that Event
surface and do not change its wire. Record validation covers the typed
source-envelope seam, bounded mission-bound tables and operation ledger,
shared Event/State/Record causal high-water, independent conflict-reducer
recomputation, explicit exact-sibling resolution guards, and the public stopped
facade/example. Representative focused commands are:

```sh
cargo test --locked -p aster-core source_record
cargo test --locked -p aster-redb-store record
cargo test --locked -p aster-node application::record::tests
cargo run --locked -p aster-node --example record_application -- \
  STATE_DIR MISSION_BUNDLE
```

The exact focused Record suites passed on both the pinned current toolchain and
Rust 1.91.0: core 7/7, selected store 7/7, and selected-node 8/8. The node tests
cover independently authenticated N-way heads, ordinary-publish conflict bypass
rejection, stale and changed guards without mutation, exact restart/rekey retry,
visible tombstones without delete-wins, post-rekey inactive-row verification,
valid metadata tamper with unchanged sealed bytes, sanitized errors, and writer
exclusion. Store tests additionally cover arrival independence, both complete-
ID directions, shared causal ledgers with disjoint class indexes, collision,
quota, schema/reopen, and terminal-state invariants. No test invokes a
registered application merge policy during ingest.

The final frozen-tree matrix passed 539 of 539 on each toolchain. The current
run comprised core 349/349 (44.44s), node library 81/81 (5.19s), node binary
6/6 (0.00s), `mesh_cli` 13/13 (135.87s), and selected store 90/90 (8.75s).
The separate Rust 1.91.0 run comprised the same counts in 45.77, 5.42, 0.01,
135.76, and 8.61 seconds respectively. Each run also had five zero-test targets;
their test-harness sums were 194.25 and 195.57 seconds. The executions and
timings are not pooled.

Strict all-target/all-feature Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 10.32 and 10.30 seconds. Formatting passed on both
in 0.73 and 0.85 seconds, and `git diff --check` passed in 0.03 seconds. The
complete dual-toolchain validation used 463.76 seconds wall time. After a
27.21-second disposable two-node fixture, the compiled Record example returned
`moving`, counter 3, one superseded revision, no concurrent head, no conflict,
and both insert flags true in 1.26 seconds; an exact 0.84-second rerun returned
the same semantic ID and projection with both insert flags false.

The exact Record source/dependency hashes are pinned in the
[requirements evidence](implementation/requirements-status.md#current-selected-record-automated-evidence).
This is stopped/local automated evidence, not a Record contact, disconnected-
process acceptance result, retained execution receipt, or release artifact.
Record has no live handle or reconciliation frames; automatic registered-policy
merge, finite TTL, expiry/garbage collection, selected-node bindings, physical
systems, mixed implementations, and scale remain open.

The subsequent stopped/local Blob gate adds a typed source-manifest capability,
mission-bound redb publication/operation/read-plan authority, a bounded
encrypted sibling depot, and synchronous `SelectedBlobNode` publish/read
streaming. Representative focused commands are:

```sh
cargo test --locked -p aster-core source_blob
cargo test --locked -p aster-redb-store blob
cargo test --locked -p aster-node application::blob::tests
cargo run --locked -p aster-node --example blob_application -- \
  STATE_DIR MISSION_BUNDLE INPUT OUTPUT
```

The core tests distinguish route-only from content authority, reject wrong
class/mission/source/epoch/group/route root, tampered manifest or envelope,
empty/flexible-chunk inputs, and a forged store completion whose wrong records
and final digest are mutually consistent. Store tests cover crash boundaries,
marked-file corruption without repair, schema migration/nonrepair, exact
operation conflict/caps/replay, policy/revocation/epoch ordering, cross-class
causal and identity collisions, aggregate quota rollback, terminal-before-
depot ordering, unfinished import handling, and bounded reopen audit. Node tests
cover multi-chunk bounded streaming, exact retry and changed-source conflict,
same-variant no-growth, rekey variant separation, source-valid wrong key/variant
claims, fresh inactive-candidate verification, stale read-plan rejection,
revocation, exclusive writer ownership, depot tamper, and terminal zeroization.

`BlobId` is exact object identity over plaintext bytes, the canonical chunk
profile, and media/schema identity metadata; it is not a metadata-independent
whole-byte identity. `BlobDepotLimits` count redb-marked ciphertext-file bytes,
all durable per-chunk metadata rows, and all import variants. Unfinished rows
remain charged pending explicit GC; untracked hostile filesystem entries and
complete physical allocation are outside the counters. The public peak-buffer
field reports the core Blob engine's capacity; generic store adapters may use
additional independently chunk-bounded buffers, so it is not a whole-operation
memory measurement. No test in this gate is a Blob contact, remote/any-peer
resume, maximum-size acceptance, physical-storage result, retained execution
receipt, or release artifact.

The database is pinned to one fixed local depot owner on its first successful
Store open, not treated as a portable backup. Redb persists a domain-separated
commitment over a random owner token, canonical store path, and Unix
device/inode when available; the depot marker must carry the same binding
before any chunk/variant scan or reclaim. The first database to initialize a
parent’s depot wins, and another cannot adopt it. Moving/copying even an empty
bound database to another path fails on reopen. On Unix, a new inode also
fails, moving the depot with the database does not preserve the binding, and a
same-path replacement cannot adopt an existing depot. No supported
depot-rebind/restore path is claimed. Non-Unix keeps token-plus-canonical-path
binding but cannot distinguish a copied database restored over that same path,
so equivalent inode/rollback resistance is not claimed.
The owner-token/binding migration is all-or-none and admits missing fields only
for canonical empty Blob rows/counters with no fixed depot root; partial
fields, any logical Blob state, or any fixed depot root fail without repair.

On the final frozen bytes, focused current-toolchain runs passed the six typed
source-Blob tests, the dedicated core reader retry-state adversary, all 28
selected-store Blob tests, and all seven selected-node Blob tests. The current
tracked-Cargo-target matrix passed 576 of 576 tests: core library 351/351
(44.68s), node library 88/88 (11.29s), node binary 6/6 (0.00s), `mesh_cli`
13/13 (153.69s), and selected store 118/118 (12.33s). The separate exact Rust
1.91.0 matrix passed the same 576 tests in 45.57, 28.63, 0.01, 153.99, and
12.44 seconds respectively. The core basic example and five node examples had
no tests. These totals count only the listed tracked Cargo targets; no
auxiliary non-workspace scratch harness is counted.

Strict workspace all-target Clippy with warnings denied passed on the current
and Rust 1.91 toolchains in 28.36 and 34.71 seconds. Current-toolchain Rustdoc
with warnings denied, `cargo fmt --all -- --check`, and `git diff --check`
also passed. A loopback-enabled current-toolchain `cargo test --workspace`
passed every runnable workspace suite; one performance experiment remained
explicitly ignored. The process-heavy node cells required loopback permission;
an earlier sandboxed attempt was denied by the host before those socket tests
could run and is not counted as a test failure or success.

The exact Blob source identities are pinned in the
[requirements evidence](implementation/requirements-status.md#current-selected-blob-automated-evidence).
A disposable provisioned fixture then ran the compiled Blob example twice over
18,783 input bytes. The 4.792-second first run returned one chunk,
`inserted=true`, and Blob ID
`85c3f98504cc9e671212256c994698ce2d8c1e947aa5b3841d61a943d3660fde`;
the 0.714-second exact rerun returned the same ID with `inserted=false`. Both
outputs matched the input byte-for-byte at SHA-256
`f3d9ba32b0825abfec157aadf8c16581608220f48dd2a8f0a3a39bef29bdd966`.
The fixture is not retained, and this is local executable evidence rather than
a Blob contact, remote-resume result, physical-storage measurement, or release
receipt.

The 57th test in that parent redb-store receipt is a Unix writable-open
durability adversary. Every new or existing writer, including a terminal
cleanup handle, must synchronize
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
`ttl=durable-none`. The retained parent PR-A/pre-subscription 2026-08-24 N3,
default N4, and N8 observed loopback results and their exact claim boundaries
are recorded in
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

A separate retained parent PR-A/pre-subscription probe exercised the
Event/mission boundary across eight loopback nodes and 38 child processes in 17
causal cohorts. It is a manual
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
They remain bounded to Event, one control family/scope, and loopback. The
current code additionally has durable Event Consume/Carry selectors, live and
stopped-state poll/ack, idempotent unsubscribe, verified gap inspection,
bounded last-contact status, protected receiver-directed filtering, and
separate stopped/local State and Record projections plus local Blob streaming;
it does not turn the retained parent roots into PR-B, PR-C, State, Record, or
Blob receipts. The tests do not claim networked State/Record/Blob, remote Blob
chunks, global convergence, generalized control
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
