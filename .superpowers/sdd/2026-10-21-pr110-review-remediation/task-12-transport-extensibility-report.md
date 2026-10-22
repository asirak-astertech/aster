# Task 12 transport-extensibility remediation report

## Status

Complete. The production Blob-stream composition now selects from an
adapter-neutral registry rather than constructing a one-element Iroh candidate
array inside the selector. Iroh QUIC v1 remains the only adapter registered by
the shipped production composition.

Signed implementation commit:

- `be45f99b59ae7db3a86841af6986f3977c2c2b00` — `refactor(node): make stream transport composition extensible`
- `git show --show-signature` reports a good EDDSA signature from
  `Andrii Sirak <a.sirak@astertech.io>`.

## Implemented boundary

- Replaced the closed one-variant `StreamTransportId` enum with a nonzero,
  ordered stable-ID value type. `1` remains reserved for `IROH_QUIC_V1`.
- Added `StreamTransportRegistry`, which accepts independently owned
  `Arc<dyn StreamTransportAdapter>` registrations and rejects duplicate stable
  IDs.
- Added `AuthenticatedTransportContext` for composition-owned local enablement,
  policy, authenticated peer support, and configured priority.
- Added `StreamTransportCapabilities`, reported by each adapter independently
  for reliable-ordered and full-duplex behavior. Eligibility derives from those
  independent flags; it is not projected from one aggregate boolean.
- Kept adapter-owned attempt creation. The registry/selector never accepts or
  depends on an Iroh `Connection`; the Iroh adapter alone owns that connection.
- Split runtime composition into:
  - `production_stream_transport_registry(Connection)`, which currently
    registers exactly Iroh QUIC v1;
  - `select_stream_transport(&StreamTransportRegistry)`, which accepts any
    registered adapter set; and
  - the existing-production convenience boundary that builds the Iroh registry
    and selects from it.
- Preserved one selected adapter per logical attempt, receiver-authoritative
  resume, adapter-neutral cancellation through `StreamAttempt::cancel_data`,
  and the existing single persistence/authentication/reconciliation authority.
- Updated `docs/transports.md` to distinguish “only currently shipped adapter”
  from an architectural one-adapter limitation. The documentation continues to
  make no cross-transport selection or failover claim.

## Strict TDD evidence

### RED 1: missing production registry seam

The first production-composition test registered several adapters, required an
authenticated/policy/health/priority/stable-ID selection, and opened the
selected adapter's own in-memory attempt without an Iroh connection.

Command:

```text
cargo test -p aster-node production_registry_selects_an_independent_adapter_by_authenticated_requirements_and_rank --lib
```

Observed RED:

```text
error[E0422]: cannot find struct, variant or union type `AuthenticatedTransportContext`
error[E0599]: no variant, associated function, or constant named `new` found for enum `StreamTransportId`
error[E0433]: failed to resolve: use of undeclared type `StreamTransportRegistry`
error: could not compile `aster-node` (lib test) due to 3 previous errors
```

This failed on the missing extensibility boundary, before production code was
added.

### RED 2: independent capability modeling

Controller review identified that the first GREEN projected one aggregate
eligibility result into both capability fields. A second test pinned
reliable-only and full-duplex-only adapters independently.

Command:

```text
cargo test -p aster-node registry_keeps_reliable_and_full_duplex_capabilities_independent --lib
```

Observed RED:

```text
assertion failed: !reliable.candidate.full_duplex
test result: FAILED. 0 passed; 1 failed
```

The implementation was then changed to explicit adapter capability descriptors.
Both reliable-only and full-duplex-only selection passed afterward.

## Focused verification

Fresh focused test command (run with loopback socket permission for the Iroh
integration test):

```text
cargo test -p aster-node 'stream_transport::tests' --lib
```

Result:

```text
running 8 tests
test stream_transport::tests::registry_keeps_reliable_and_full_duplex_capabilities_independent ... ok
test stream_transport::tests::stream_iroh_adapter_reports_one_production_transport ... ok
test stream_transport::tests::stream_transport_coordinator_retries_only_from_authenticated_durable_progress ... ok
test stream_transport::tests::stream_transport_ranking_is_deterministic_and_authenticated ... ok
test stream_transport::tests::stream_transport_selector_returns_best_eligible_adapter ... ok
test stream_transport::tests::stream_transport_terminal_cancel_and_checkpoint_rules_are_typed ... ok
test stream_transport::tests::registry_selects_independent_adapter_by_authenticated_requirements_and_rank ... ok
test stream_transport::tests::stream_iroh_adapter_reopens_a_fresh_concurrent_pair ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 650 filtered out
```

Additional checks:

```text
rustfmt --edition 2024 --check crates/aster-node/src/stream_transport.rs crates/aster-node/src/runtime/blob_stream.rs
git diff --check -- crates/aster-node/src/stream_transport.rs crates/aster-node/src/runtime/blob_stream.rs crates/aster-node/src/runtime.rs docs/transports.md
```

Both completed successfully. The full workspace suite and `mise run check` were
not run, per the explicit instruction not to run the full suite. No parser,
framing, envelope, or fragmentation behavior changed, so `mise run fuzz-smoke`
was not applicable. Requirements evidence/traceability did not change, so the
implementation-requirements checker was not required.

The focused build emitted one pre-existing warning from concurrent
`application/blob.rs` finalization work about unread `BlobFinalizeMetrics`
fields. No warning originated in the transport files.

## Files in the implementation commit

- `crates/aster-node/src/stream_transport.rs`
- `crates/aster-node/src/runtime/blob_stream.rs`
- `crates/aster-node/src/runtime.rs`
- `docs/transports.md`

Concurrent uncommitted changes in `aster-core` Blob, redb pack,
`application/blob`, `application/blob_stream`, and `stream_pipeline` were not
staged or committed.

## Remaining concerns and truthful exclusions

- Only Iroh QUIC v1 is shipped and registered in production today. The test
  adapters prove the composition seam, not BLE or other product transport
  support.
- No cross-transport selection, cross-transport resume, or failover scenario
  has been physically or operationally validated; no such claim was added.
- The broader selected contact bootstrap and mission-session establishment are
  still Iroh-centric. A future non-Iroh contact path must authenticate the peer
  and supply the same narrow `AuthenticatedTransportContext` before registering
  its stream adapter. That integration work no longer requires changes to the
  stream protocol, pipeline, registry, or selector.
- Stable transport IDs require project-level allocation discipline. The
  registry rejects duplicate IDs in one composition, but this task did not add
  a global allocation document or ship another ID.
