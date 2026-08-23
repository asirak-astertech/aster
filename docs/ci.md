# Continuous integration

The `CI` GitHub Actions workflow runs the repository's established validation
commands on pushes to `main`, pull requests targeting `main`, merge queues, and
manual dispatches. Configure branch protection or a ruleset to require the
single stable check name **`CI / required`**.

## Validation lanes

| Check | Runner | Purpose |
| --- | --- | --- |
| `quality` | `ubuntu-24.04` | Runs `mise run check`: Rust and Go formatting, Apache-2.0-only project-license and package checks, Clippy with warnings denied, the full Rust workspace test suite, C ABI build and C/C++ header checks, Rust/Python conformance, Python/Go binding tests, and the lab-controller tests. |
| `macOS tests` | `macos-14` | Runs all Rust workspace tests on the supported Apple runner with Rust 1.97.1. |
| `Rust 1.90 MSRV` | `ubuntu-24.04` | Checks every workspace target and feature with the declared minimum supported Rust version. |
| `dependency policy` | `ubuntu-24.04` | Applies `deny.toml` to the root and fuzz dependency graphs and audits both lockfiles against a freshly downloaded RustSec database. |
| `age reference interoperability` | `ubuntu-24.04` | Installs exact `govulncheck` v1.6.0, runs `mise run age-reference-audit`, then runs `mise run age-reference-interop`: the Go oracle's reachable vulnerability and compiled-module license gates must pass before exact reference Go `filippo.io/age` v1.3.1 and the Rust provider exchange classic-X25519 artifacts in both directions, compare recovered plaintext, and agree on the recipient. |
| `bounded fuzz smoke` | `ubuntu-24.04` | Runs the three fixed 10,000-iteration decoder campaigns with the pinned nightly toolchain and `cargo-fuzz`. |
| `required` | `ubuntu-24.04` | Fails unless every validation lane completed successfully; this is the branch-protection check. |

The Rust dependency downloads happen before Cargo validation is switched to
offline mode. The dependency-policy job is intentionally different: it obtains
current advisory data once, audits the root lockfile during that refresh, and
reuses the same database without another fetch for the fuzz lockfile. Its
vulnerability result therefore reflects the RustSec database available when
the workflow ran, rather than a permanently reproducible snapshot.

Two explicit `cargo deny` advisory ignores cover bounded active pilot graphs.
`RUSTSEC-2026-0173` covers unmaintained build-time `proc-macro-error2` 2.0.1 in
the non-production age-provider pilot. RustSec reports no vulnerability and no
patched release; current Rust separately emits future-incompatibility `E0365`.
The ignore permits that exact informational finding only. It does not suppress
other advisories, change exact package checksums, permit online execution after
the acquisition step, or authorize the provider for production.

`RUSTSEC-2024-0436` covers unmaintained `paste` 1.0.15 only through the exact
`netlink-packet-core` → `if-watch` → `libp2p-tcp` path in the non-production
libp2p-provider pilot. [Decision 0027](decisions/0027-libp2p-pilot-dependency-policy.md)
records the 2026-11-23 review deadline, upstream-removal gate, and production
prohibition. The same decision admits `BSD-2-Clause`, `ISC`, and `Zlib` for the
reviewed external dependency graph; first-party packages and distributed
project files remain subject to the separate byte-identical Apache-2.0 gate.

The companion scope gate fails if either ignored package's reverse graph drifts
or if either package appears in the separately excluded fuzz graph. Any change
to a package chain or advisory disposition requires a recorded pilot review.

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
`tools/check-dependency-exception-scope.sh` requires the lock-only package set
to remain exactly `hickory-proto`/`hickory-resolver` 0.25.2 and proves that both
names are absent from the full workspace and fuzz dependency graphs. Its
adversarial regression injects an active Hickory package and requires the gate
to fail. Package/version drift or future feature activation therefore blocks
CI before the audit suppression is applied. Remove both ignores when the
aggregate libp2p lock no longer contains the affected optional versions.

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

Because `deny.toml` expresses active advisory exceptions at workspace scope,
both the primary and dependency-policy gates also run
`tools/check-dependency-exception-scope.sh`. Its exact reverse-graph assertions
fail unless `proc-macro-error2` 2.0.1 remains reachable only through the
isolated age-provider pilot and `paste` 1.0.15 remains limited to the reviewed
libp2p-provider path. Both must be absent from the fuzz graph. The same gate
proves the raw-lock Hickory pair remains inactive. Adversarial wrappers force a
fuzz graph command failure, an active Hickory package, an expanded `paste`
graph, and a second active `paste` version; each must fail closed.

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
| Minimum supported Rust | `1.90.0` |
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

Check the declared MSRV with:

```sh
rustup toolchain install 1.90.0 --profile minimal
cargo +1.90.0 check --locked --workspace --all-targets --all-features
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
