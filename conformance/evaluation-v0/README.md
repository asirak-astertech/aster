# Candidate-neutral conformance seed

This directory contains a requirements-shaped, non-product evaluation profile
and a small golden/negative vector corpus. It intentionally does not inherit an
Aster wire, store, API, or compatibility constraint.

The executable derives the same semantic profile twice: once through a manual
`minicbor` decoder and once through `ciborium::Value`. Both paths validate
bounds and re-encode through one deterministic encoder. Their agreement is an
oracle check, not independent implementation interoperability.

Authoritative local reproduction:

```sh
cargo build --release --locked --offline \
  --manifest-path conformance/evaluation-v0/runner/Cargo.toml
conformance/evaluation-v0/runner/target/release/mesh-eval-conformance \
  conformance/evaluation-v0/vectors
```

Review `profile-v0.cddl`, `summary.json`, `MANIFEST.sha256`, and the report at
`docs/evaluations/0005/conformance-profile-seed.md`. Build products and repeated
execution evidence remain ignored locally.

