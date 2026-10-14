# Blob range streaming loopback measurement

This diagnostic compares upstream main with the optional receipt-free Blob
range-stream profile on one host. It adds no requirements credit, WAN
qualification, or production throughput guarantee. The Rust fixture is copied
unchanged from the prior ACK experiment; no ACK production code is imported.

## Reproduce

Build the identical `crates/aster-node/examples/blob_benchmark.rs` in separate
baseline and feature checkouts with separate Cargo targets:

```sh
CARGO_NET_OFFLINE=true mise exec -- sh tools/with-test-resources.sh \
  cargo build --release --offline --locked -p aster-node --example blob_benchmark
python3 tools/test_blob_benchmark.py
python3 tools/blob_benchmark.py \
  --variant baseline /absolute/baseline /absolute/baseline-binary \
  --variant stream /absolute/feature /absolute/feature-binary \
  --output /durable/new-results --state /scratch/new-state
```

The campaign is exactly one run per variant at 16 KiB, 64 KiB, 256 KiB, and
1 MiB: eight real runs, alternating baseline then feature at each size. A
300-second receive bound applies per run, plus an outer 180-second allowance.
`--sizes` restricts the campaign without adding repetitions. Finish all builds
and tests before timing; do not edit measured sources during the campaign.

## Timing and verification boundaries

- Two real node actors in one process, two Tokio workers, independent stores,
  synthetic reference identities, and explicit direct-loopback Iroh addresses.
  Production `NodeConfig` defaults retain the 500 ms scheduler interval.
- Deterministic SplitMix64-counter fixture generation makes aligned 64-KiB
  chunks distinct, avoiding a repeating-data deduplication bias. Source file
  generation, SHA-256, and fsync precede publication.
- `publication_ns` brackets awaited peerless local file publication. Successful
  publication means local durable acceptance, not remote delivery.
- `transfer_until_ready_ns` brackets connected-node startup through first
  successful receiver read, polled every 20 ms. It excludes publication.
- `transfer_ns` additionally includes a fixed 600 ms receipt-accounting settle,
  both node shutdowns, and receiver Store reopen with invariant checks. It is
  not pure network time.
- `verification_ns` includes a new peerless receiver actor and full paged
  plaintext read/SHA-256 verification. Every page's identity, publisher, length,
  and offset is checked; no network repair is possible after reopen.
- `total_ns` spans publication through full verification, including intermediate
  shutdown, but excludes fixture setup and final verification-node shutdown.
- Successful runs require only direct contacts, no contact errors, no pending
  source, no residual carrier prefix or staging bytes, and exact final full
  plaintext SHA-256. Timeouts remain incomplete observations, never throughput.

The runner persists each stdout/stderr and fsynced JSON receipt immediately.
It records read-only AC/battery/profile/governor snapshots before and after
individual runs. Source and binary identities must remain unchanged before
normal summaries are published; mismatch retains raw evidence without summary.
Inspect power stability before comparing samples. Default release builds use
`opt-level=z`, thin LTO, and one codegen unit. Normal OS caches and desktop load
remain; neither idle-host nor cold-cache conditions are claimed.

Report local publication, synchronization readiness, settle-inclusive transfer,
and verification separately. One sample is an observation, not a distribution.
The harness's unit tests use explicitly synthetic subprocess receipts solely to
test summary validation; these are not performance measurements.
