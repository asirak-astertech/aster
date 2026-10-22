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

The public application-RPC publish/read path has a separate ignored benchmark.
It uses the real node, native bidirectional gRPC upload, durable publication,
and authenticated streaming read; it is not part of default correctness CI.
Run it serially with a release build and place temporary state on a filesystem
large enough for the selected payload and durable overhead:

```text
df -B1 "${TMPDIR:-/tmp}"
/usr/bin/time -v -o /var/tmp/aster-blob-application-rss.txt \
  env ASTER_BLOB_BENCH_BYTES=1073741824 \
  cargo test --offline --locked --release -p aster-agent --all-features \
  --test real_node_connect real_node_blob_bidi_stream_benchmark \
  -- --ignored --exact --nocapture --test-threads=1
df -B1 "${TMPDIR:-/tmp}"
```

For 1 GiB, budget at least 2 GiB of free temporary storage, 2 GiB of available
memory, two CPU cores, and 20 minutes as a conservative timeout. Retain the
binary commit, payload bytes, publish/read elapsed time and MiB/s, checkpoint
count, temporary-filesystem capacity before and after the run, and the GNU
`time` peak-RSS report. This local loopback result
is engineering evidence only; it does not replace same-path raw transport or
CM4 end-to-end qualification.

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
segment retains its existing end-to-end source AEAD. After aligning each
StreamData extent with one complete canonical pack record, the same optimized
256-MiB sender-encode plus receiver-decode measurement used 256 extents and
completed in 0.014036 seconds, or 18,238.555 MiB/s. This is approximately 531
times the rejected full-envelope rate and includes bounded frame construction
and receiver body materialization. The aligned boundary also removes sender
slicing and receiver reassembly from the integrated path. This establishes only
that profile-5 record processing is no
longer the local throughput ceiling; it excludes transport, pack I/O, source
segment verification, checkpoints, and CM4 effects.

Reproduction command:

```text
cargo test --release -p aster-node composite_profile5_records_process_256_mib_in_bounded_extents --lib -- --ignored --nocapture
```

## Open qualification: extent batching policy

The remediated profile uses the existing 64-KiB canonical plaintext chunk and
an encoded canonical chunk record of at most 66,215 bytes. `ABX1` batches whole
records into an extent of at most 1 MiB. The extent target is transfer policy,
not the canonical plaintext chunk size and not a second Blob identity format.

Before changing batching policy, run the same warmed CM4 workload with smaller
extent targets. Retain end-to-end throughput and latency, CPU, peak RSS and
in-flight bytes, checkpoint cost, retransmitted bytes, resume amplification,
and behavior under loss and constrained MTU. A peer may negotiate a smaller
extent without changing canonical Blob identity.

## 2026-10-20 CM4 checkpoint and sender-copy requalification

The completed-pack sender now writes the small protected record prefix and the
owned canonical pack body as one carrier frame without first copying the body
into a second payload-sized allocation. The receiver's absolute-credit window
also rounds up to a whole canonical extent. That rule fixes the deadlock where
an exact byte window admitted too few slightly-over-1-MiB pack records to reach
the next checkpoint.

The checkpoint batch is a durability/performance policy, independent of the
64-KiB canonical chunk and 1-MiB maximum batched extent. A receiver may
negotiate a smaller batch;
the profile-5 implementation caps the current batch at 128 MiB. Larger batches
reduce synchronization and reverse-control overhead but increase the maximum
uncheckpointed suffix that an interrupted attempt may replay. The attempt's
control allocation therefore uses the bounded worst case of one checkpoint per
admitted extent rather than assuming that every peer selects the maximum batch.

Successive 256-MiB CM4 runs on `rpi4-2 -> rpi4-1` showed:

| Candidate | Checkpoints | Aster MiB/s | Adjacent raw MiB/s | Raw ratio |
| --- | ---: | ---: | ---: | ---: |
| 8-MiB batch, instrumented pipeline | 32 | 6.147 | 9.400 | 65.4% |
| 64-MiB batch and split-frame sender | 4 | 7.376 | 9.400 retained sample | 78.5% |
| 128-MiB batch and split-frame sender | 2 | 8.317 | 9.561 | 87.0% |

These are integrated candidate measurements, not an isolated single-variable
benchmark; they support the selected combination but do not attribute all gain
to checkpoint cadence. The exact 1-GiB confirmation transferred 1,073,879,040
wire bytes in 126.445 seconds at 8.099 MiB/s, with eight checkpoints and
matching terminal roots. The immediately adjacent 1-GiB raw TCP run sustained
9.344 MiB/s, so the integrated path achieved 86.7% of available throughput and
passed the 80% floor. Receiver occupancy remained bounded at four items and
4,194,840 bytes.

This historical requalification does not prove that the 1-MiB extent target is
optimal. It shows that changing the canonical 64-KiB chunk was not required to
remove the observed transport gap: the retained batching policy exceeded the
acceptance floor after credit, durability cadence, and sender ownership were
corrected. These measurements predate the current canonical-authority
remediation and are not validation of this candidate.
