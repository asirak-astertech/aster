# Aster hostile-input fuzzing

This is an isolated test workspace. It is not a release dependency and does not
change the protocol or application API. The pinned nightly is used only because
`cargo-fuzz` requires unstable compiler instrumentation.

Install the exact tool and run bounded smoke campaigns:

```sh
cargo install cargo-fuzz --version 0.13.2 --locked
mise run fuzz-smoke
```

The task selects `nightly-2026-08-18` explicitly and runs all targets from the
isolated `fuzz/` workspace. `wire_decode` and `fragment_decode` require accepted
input bytes to equal their deterministic canonical encoding. `envelope_inspect`
uses only the public `adapter-sdk` provisioning and reference-envelope APIs. It
tests arbitrary hostile bytes and structured mutations of a freshly sealed valid
envelope carrying exactly 4,096 causal predecessors. Its retained `M` seed is a
nonsecret mutation recipe; credentials and generated envelope bytes are never
written to the retained corpus.

Each smoke campaign runs 10,000 cases with a fixed seed and a 262,144-byte
maximum input. Retained corpora are copied to a temporary directory before each
campaign, so libFuzzer cannot mutate the checked-in seed corpus. The root release
workspace excludes this package, so neither libFuzzer nor its compiler
instrumentation enters shipped artifacts.

Release assurance should run longer campaigns on Linux and macOS, retain each
minimized crashing input and seed corpus, and record toolchain, target, command,
elapsed time, corpus hash, and result in the release test report.
