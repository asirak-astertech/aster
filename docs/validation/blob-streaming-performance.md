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
