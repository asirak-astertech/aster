# Blob streaming performance evidence

This file records development evidence for semantic v9/profile 5. It is not
device qualification and does not replace the three-CM4 acceptance run.

## 2026-10-16 local loopback ceilings

The merged semantic-v8/profile-4 selected-stack benchmark transferred 64 MiB
at approximately 0.475 MiB/s, reaching receiver readiness in 134.725 seconds.
Linear extrapolation is about 28 minutes for 800 MiB and 36 minutes for 1 GiB.
That result rejects profile 4 for the requested large-object operating range.

Two optimized measurement-only profile-5 ceiling tests were then run:

| Measurement | Bytes | Elapsed | Rate |
| --- | ---: | ---: | ---: |
| Canonical StreamData encode plus decode, 1-MiB bounded extents | 1,073,741,824 | 1.145 s | 894.3 MiB/s |
| Direct loopback Iroh long-lived data stream with concurrent reverse 8-MiB checkpoints | 1,073,741,824 | 2.818 s | 363.4 MiB/s |

The Iroh test sent 1,024 bounded 1-MiB extents and observed the final cumulative
checkpoint on the reverse stream. Resident transfer buffers were independent of
the 1-GiB total. The transport result is roughly 75 times the corrected
profile-4 payload rate and puts the loopback transport-only projection near 2.2
seconds for 800 MiB and 2.8 seconds for 1 GiB.

These are ceilings, not end-to-end claims. They exclude source authentication,
Blob encryption/decryption, carrier verification, lifecycle checks, durable
files/redb checkpoint batches, application promotion, lossy links, and CM4
hardware. The production driver must be measured with those costs before an
operational deadline is claimed.

Reproduction commands:

```text
cargo test --offline --locked --release -p aster-node stream_codec_ceiling_processes_one_gib_in_bounded_extents --lib -- --ignored --nocapture
cargo test --offline --locked --release -p aster-iroh concurrent_stream_ceiling_transfers_one_gib_with_reverse_checkpoints -- --ignored --nocapture
```

## 2026-10-17 production-driver loopback

The semantic-v9/profile-5 production path was measured with source metadata,
mission/profile negotiation, receiver-authored pre-open planning, whole-carrier
verification, 4-MiB durable checkpoint batches, redb/file persistence,
promotion, result acknowledgement, and authenticated Iroh transport enabled.
Fixture publication is outside the reported contact elapsed time.

| Payload | Contact elapsed | Payload rate | Linear 800-MiB projection | Linear 1-GiB projection |
| ---: | ---: | ---: | ---: | ---: |
| 16 MiB | 2.167 s | 7.38 MiB/s | 108 s | 139 s |
| 64 MiB | 5.301 s | 12.07 MiB/s | 66 s | 85 s |
| 256 MiB | 23.342 s | 10.97 MiB/s | 73 s | 93 s |

The first 256-MiB run failed before carrier I/O because three metadata/load
boundaries still applied profile 4's fixed 64-MiB/1,024-chunk ceiling after
profile-5 projection admission had correctly used configured depot limits. The
same focused run passed after all three boundaries were routed through the
authenticated contact mode and configured profile-5 limits. This is retained
as a size-dependent regression finding, not discarded as benchmark noise.

An 8-MiB checkpoint-batch experiment was rejected. Carrier-boundary alignment
can make an 8-MiB absolute receive window slightly smaller than an 8-MiB batch,
so neither endpoint reaches the transition that grants more credit. The driver
retains 4-MiB batches and now has a compile-time invariant requiring room for a
maximum extent beyond the batch threshold. The experiment also exposed that
the inbound wrapper still used the legacy 30-second total deadline; inbound and
outbound Blob contacts now select the same bounded Blob-aware deadline. A final
256-MiB rerun passed in 23.514 seconds after both corrections.

These results demonstrate the production driver's local feasibility and are
roughly 19–25 times faster than the measured profile-4 baseline. They do not
qualify UAS radio behavior or Raspberry Pi CM4/Jetson performance. The required
three-CM4 run remains the device acceptance authority.

The deterministic test defaults to 16 MiB. Development measurements can select
a bounded 1–256 MiB payload through `ASTER_TEST_BLOB_STREAM_MIB`; the cap avoids
turning an accidental environment value into an unbounded local allocation.
The production receiver now retains bounded completed-contact metrics for the
selected transport, attempt count, authenticated received bytes, greatest
absolute receive limit and durable checkpoint, maximum checkpoint commit
latency, and writer-commit count. Reopen is not counted as cross-transport
failover while Iroh is the only production adapter. These counters make the
same quantities observable during the eventual three-CM4 procedure without
placing transport details in the public Blob application API.

A post-instrumentation 256-MiB release rerun completed in 23.721 seconds
(10.79 MiB/s), within one percent of the preceding 23.514-second run. The
bounded per-checkpoint observations therefore showed no material loopback
throughput regression in this fixture.

```text
ASTER_TEST_BLOB_STREAM_MIB=256 cargo test --release --locked -p aster-node live_blob_stream_v9_completes_retained_sixteen_mib_shape_in_one_contact --lib -- --nocapture
```
