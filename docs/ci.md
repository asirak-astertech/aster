# Continuous integration

The `CI` GitHub Actions workflow runs the repository's established validation
commands on pushes to `main`, pull requests targeting `main`, merge queues, and
manual dispatches. Configure branch protection or a ruleset to require the
single stable check name **`CI / required`**.

## Validation lanes

| Check | Runner | Purpose |
| --- | --- | --- |
| `quality` | `ubuntu-24.04` | Runs `mise run check`: formatting, Clippy with warnings denied, the full Rust workspace test suite, C ABI build and C/C++ header checks, Rust/Python conformance, and Python/Go binding tests. |
| `macOS tests` | `macos-14` | Runs all Rust workspace tests on the supported Apple runner with Rust 1.97.1. |
| `Rust 1.90 MSRV` | `ubuntu-24.04` | Checks every workspace target and feature with the declared minimum supported Rust version. |
| `dependency policy` | `ubuntu-24.04` | Applies `deny.toml` to the root and fuzz dependency graphs and audits both lockfiles against a freshly downloaded RustSec database. |
| `bounded fuzz smoke` | `ubuntu-24.04` | Runs the three fixed 10,000-iteration decoder campaigns with the pinned nightly toolchain and `cargo-fuzz`. |
| `required` | `ubuntu-24.04` | Fails unless every validation lane completed successfully; this is the branch-protection check. |

The Rust dependency downloads happen before Cargo validation is switched to
offline mode. The dependency-policy job is intentionally different: it obtains
current advisory data once, audits the root lockfile during that refresh, and
reuses the same database without another fetch for the fuzz lockfile. Its
vulnerability result therefore reflects the RustSec database available when
the workflow ran, rather than a permanently reproducible snapshot.

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
| `actions/checkout` | `de0fac2e4500dabe0009e67214ff5f5447ce83dd` (`v6.0.2`) |
| `jdx/mise-action` | `3c2e0cf82a5b2e5249f0d3635a4d83d0ae861518` (`v4.2.5`) |
| mise | `2026.4.28` |
| Rust | `1.97.1` |
| Minimum supported Rust | `1.90.0` |
| Go | `1.26.5` |
| Python | `3.13.7` |
| Fuzz nightly | `nightly-2026-08-18` |
| `cargo-fuzz` | `0.13.2` |
| `cargo-deny` | `0.20.2` |
| `cargo-audit` | `0.22.2` |

Dependabot is configured separately to propose updates to action and Cargo
pins. An update remains untrusted until these checks pass and a maintainer
reviews the upstream release and the resulting dependency changes.

## Running checks locally

Install the repository toolchain and run the primary gate:

```sh
mise install
mise run check
```

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
cargo audit --file Cargo.lock
cargo deny --locked --offline check
cargo deny --manifest-path fuzz/Cargo.toml --config deny.toml --locked --offline check
cargo audit --no-fetch --file fuzz/Cargo.lock
```
