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

## Selected-contact measurement fields

Semantic-v9/profile-5 contacts emit bounded measurements in their `CONTACT`
receipt. `blob_stream_sent_bytes` and `blob_stream_received_bytes` are the
canonical pack bytes carried in the current attempt; `blob_stream_resumed_bytes`
is the durable prefix skipped across local send and receive directions.
`blob_stream_checkpoints` and `blob_stream_partitions` count checkpoint
settlement and receiver pipeline completion.

`blob_stream_pipeline` is a semicolon-delimited value. Its capacity prefix is
`workers`, `peak_items`, `peak_bytes`, and `peak_reorder`. Each subsequent stage
has the form `name:items:bytes:queue_wait_ns:service_ns:output_blocked_ns` for
`admission`, `map`, `reorder`, and `sink`. These cumulative, bounded counters
make a CM4 run attributable without retaining per-partition histories or Blob
identifiers. A sender-only direction has no receiver pipeline samples.

## 2026-10-20 mission-record hot-path isolation

An optimized 256-MiB, 1,024-extent measurement of the original profile-5
composition took 7.450 seconds, or 34.362 MiB/s. That rejected composition
mission-encrypted and decrypted every complete 256-KiB StreamData frame even
though each body was already a source-encrypted and independently authenticated
canonical Blob-pack segment. The result identified the outer mission envelope
as a non-transport bottleneck on the local x86 host.

Semantic v9/profile 5 now uses a composite record: the mission layer protects
the fixed canonical StreamData header, while the adjacent canonical pack
segment retains its existing end-to-end source AEAD. The same optimized
256-MiB sender-encode plus receiver-decode measurement completed in 0.017359
seconds, or 14,747.147 MiB/s. This is approximately 429 times the rejected
full-envelope rate and includes bounded frame construction and receiver body
materialization. It establishes only that profile-5 record processing is no
longer the local throughput ceiling; it excludes transport, pack I/O, source
segment verification, checkpoints, and CM4 effects.

Reproduction command:

```text
cargo test --release -p aster-node composite_profile5_records_process_256_mib_in_bounded_extents --lib -- --ignored --nocapture
```
