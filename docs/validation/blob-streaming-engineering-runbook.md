# Blob streaming engineering runbook

This runbook exercises the semantic-v9/profile-5 Blob pipeline from local
application publication through selected-contact transfer. It is engineering
validation, not a production deployment procedure or release qualification.
Use CI-built artifacts for retained qualification evidence.

## Know the three independent lifecycles

1. `blob-publish` streams the source into the local node and succeeds after a
   local durable commit. It does not wait for a destination.
2. The node's sync scheduler opens a bounded transfer attempt when an eligible
   configured destination is available or content is requested. An unavailable
   destination does not fail local publication.
3. The receiver promotes the publication only after authenticated segment
   verification, ordered durable pack writes, terminal-root verification, and
   settlement. A later attempt resumes from the receiver's durable checkpoint.

Do not keep an application publish RPC open to coordinate peer availability.
Do not treat a successful local publish, a carrier connection, or a `CONTACT`
line alone as proof that one exact Blob reached a peer.

Event and Blob receive prerequisites are independent. An Event transfer needs
a matching receiver-created Event subscription. A profile-5 Blob transfer
needs the receiver's exact Blob interest plus authenticated peer/mission policy;
an Event subscription does not authorize Blob custody, and a Blob interest does
not subscribe to Events.

## Current bounded profile

| Boundary | Current value | Meaning |
| --- | ---: | --- |
| Object | 8 GiB maximum | Application stream admission ceiling |
| Application RPC frame/page | 512 KiB | Local agent transport bound |
| Canonical Blob segment | 1 MiB plaintext | Authenticated format boundary, not a throughput setting |
| Local application checkpoint | 64 segments / 64 MiB | Local publish/read durability cadence |
| Completed-pack network checkpoint | up to 128 MiB | Receiver-selected durability/control cadence |
| Receiver working set in the CM4 profile | 2 workers, 4 items, about 4 MiB | Independent of object and checkpoint-batch size |

The 1-MiB segment size is intentionally not configurable. Changing it changes
AEAD records, offsets, Merkle leaves, pack layout, resume indices, and Blob
identity. The required 256-KiB, 512-KiB, 1-MiB, 2-MiB, and 4-MiB device matrix
must justify any future size, which must be a negotiated protocol profile.

The 128-MiB checkpoint value is a maximum, not a framing size. A receiver may
select a smaller batch. Credit is rounded to whole canonical records so record
overhead cannot deadlock the extent that crosses a checkpoint threshold. A
larger batch reduces sync/control overhead while increasing the uncheckpointed
suffix that may be replayed after interruption.

## Publish and read a large local Blob

Check capacity and record the source identity before publication. The state and
pack filesystems need room for the object plus database, journal, temporary,
quota, and operational reserve; logical Blob limits do not include filesystem
overhead.

For an exact 1-GiB plaintext object, the current 1-MiB format produces 1,024
segments. Each segment adds 130 authenticated-format bytes plus the 4-byte
network record prefix, for 1,073,879,040 transfer bytes before database,
journal, temporary-file, filesystem-allocation, and safety reserve. As an
evaluation assumption—not a protocol requirement—provision at least 20% beyond
the logical object and then verify actual free bytes on both state and pack
filesystems. Capacity status is observational and non-reserving: another
operation can consume it after the check.

```sh
TOKEN_FILE=/run/aster/client.token
SOURCE=/data/imagery-1g.bin
OUTPUT=/data/received-imagery-1g.bin

stat --format='bytes=%s' "$SOURCE"
sha256sum "$SOURCE"
df -B1 /var/lib/aster-agent /data
asterctl --token-file "$TOKEN_FILE" --json status

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-publish \
  --file "$SOURCE" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key imagery-flight-2026-10-20 \
  --priority immediate \
  --media-type application/octet-stream \
  --progress always \
  2>publish-progress.log
```

Save the returned Publication ID, Blob ID, and operation key. Progress is on
stderr and JSON remains the single stdout result. Success means the publication
is durable on this node even if no peer is running. If the outcome is unknown,
repeat the exact bytes, metadata, TTL, and operation key; do not invent a new
key. A retry resumes from the local durable frontier.

On the receiver, repeat `asterctl --json status`, then wait for the exact
publication. This observes receiver-local durable state; it neither coordinates
the source nor requires one particular carrier:

```sh
PUBLICATION_ID='PASTE_BASE64_PUBLICATION_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-status \
  --publication-id "$PUBLICATION_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --wait
```

The terminal `AVAILABLE` response contains the receiver's Blob ID. Read it to a
path that does not already exist and compare the application-level hash:

```sh
BLOB_ID='PASTE_BASE64_BLOB_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 blob-read \
  --id "$BLOB_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output "$OUTPUT" \
  --progress always \
  2>read-progress.log

sha256sum "$OUTPUT"
```

Compare that digest with the source digest recorded before publication; the
source and receiver need not share a filesystem.

`blob-read` requires Linux, an owner-controlled destination directory, and a
filesystem supporting named sibling staging, atomic no-replace rename, and
directory synchronization. It never replaces an existing path. Filesystem
errors or abrupt process or host failure can leave a hidden owner-only staging
file for operator cleanup; after a reported post-publication directory-sync
failure, verify the destination before retrying.
An interrupted `blob-read` discards authenticated staged bytes and restarts at
byte zero; this is separate from resumable node-to-node publication transfer.

## Configure and confirm the data path

Use a concrete local-interface address in `NodeConfig::bind` when an evaluation
must prove the payload path. A ZeroTier address may remain available for SSH
and artifact control while the Aster endpoints bind WLAN. The receiver must
also opt in to the exact Blob topic and scope; peer configuration alone does
not create Blob receive intent:

```rust
let mut config = NodeConfig::new(
    state,
    "192.168.60.80:8183".parse()?,
    mission,
);
config.peers = vec![MissionExpectedPeer {
    carrier: ExpectedPeer {
        id: expected_carrier_id,
        address: "192.168.60.79:8183".parse()?,
    },
    mission: expected_mission_id,
}];
config.mutable_interests = MutableSourceInterests::default().with_blob(vec![
    SourceInterestSelector::new(topic.clone(), scope.clone(), false),
]);
```

Carrier identity and path selection do not grant mission or Blob
authorization. Keep each node's durable state and credentials separate.

Aster deterministically selects one eligible production stream adapter for an
attempt. Today that adapter is `IrohQuicV1`; this is automatic single-adapter
selection, not cross-transport failover. The common protocol retains
publication identity, absolute durable offset, checkpoint generation, totals,
and terminal result independently of carrier fragmentation, so a later BLE or
other reliable ordered full-duplex adapter can resume without changing the
operator status contract. Iroh may establish a direct or
operator-pinned relay path. Confirm the observed endpoint and `carrier_path`
instead of inferring them from SSH reachability:

The production sender and receiver consume only the selected stream-adapter
contract after selection; Iroh is constructed at the outer composition edge.
The receiver runs transport ingestion and verification/checkpoint work in one
scoped operation. Any transport, framing, verification, or sink failure drops
admission and joins the fixed verification workers before the attempt returns,
so no failed attempt leaves a detached pipeline holding pack or key material.

```sh
rg 'CONTACT .*blob_stream_(sent|received)_bytes=[1-9]' /path/to/node.log
```

Relevant receipt fields are:

- `blob_stream_sent_bytes`, `blob_stream_received_bytes`, and
  `blob_stream_resumed_bytes` for current-attempt accounting;
- `blob_stream_checkpoints` and `blob_stream_partitions` for durable progress;
- `blob_stream_pipeline` for bounded capacity and stage counters; and
- `carrier_path` for the observed Iroh path.

`blob_stream_pipeline` begins with `workers`, `peak_items`, `peak_bytes`, and
`peak_reorder`, followed by admission/map/reorder/sink counters in the form
`items:bytes:queue_wait_ns:service_ns:output_blocked_ns`. Stage service values
are cumulative and overlap; do not add them to derive wall time.

## Reproduce the CM4 completed-pack measurement

Build the validation example for ARM64 and retain its hash:

```sh
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc \
  cargo build --locked --release --target aarch64-unknown-linux-gnu \
  -p aster-node --example blob_stream_transport_benchmark

sha256sum \
  target/aarch64-unknown-linux-gnu/release/examples/blob_stream_transport_benchmark
```

Create one fixture and signed Open on one engineering host, then copy those
exact two files and the binary to both devices:

```sh
BIN=/var/tmp/blob_stream_transport_benchmark
FIXTURE=/var/tmp/blob-stream.fixture
OPEN=/var/tmp/blob-stream-1g.open
BYTES=1073741824

"$BIN" fixture-init "$FIXTURE"
"$BIN" open-init "$FIXTURE" "$OPEN" "$BYTES"
sha256sum "$BIN" "$FIXTURE" "$OPEN"
```

Do not create fixtures independently: provisioning contains fresh secret
material, so independently generated files are different even when the
benchmark uses the same seed. The fixture is unprotected test material and
must never be installed as a production credential.

On the source, prepare and start a 1-GiB attempt. CM4 images used in this
campaign mount `/tmp` as a 463-MiB tmpfs, so direct benchmark packs to a
filesystem with sufficient capacity:

```sh
BIN=/var/tmp/blob_stream_transport_benchmark
FIXTURE=/var/tmp/blob-stream.fixture
OPEN=/var/tmp/blob-stream-1g.open
BYTES=1073741824

env TMPDIR=/var/tmp "$BIN" pack-send \
  "$FIXTURE" "$OPEN" 192.168.60.80:0 192.168.60.79:18293 "$BYTES"
```

The standalone sender constructs its local authenticated pack before it
connects. When it prints `ASTER_BLOB_PACK_READY`, start the standalone receiver
promptly in the other terminal:

```sh
BIN=/var/tmp/blob_stream_transport_benchmark
FIXTURE=/var/tmp/blob-stream.fixture
OPEN=/var/tmp/blob-stream-1g.open
BYTES=1073741824

env TMPDIR=/var/tmp "$BIN" pack-receive \
  "$FIXTURE" "$OPEN" 192.168.60.79:18293 "$BYTES"
```

That timing is only a property of this one-shot benchmark. A running Aster node
owns a long-lived contact listener and schedules transfer independently of
local publication.

Require matching plaintext and ciphertext roots, `path:"Direct"`, eight
checkpoints for the selected 128-MiB batch, 1,024 segments, and bounded peak
occupancy. The retained candidate transferred the exact 1-GiB object at
8.099/8.100 MiB/s in 126.445 seconds versus a same-size 9.344-MiB/s raw WLAN
baseline (86.7%). The PR acceptance floor is 80% of an adjacent same-path raw
measurement; one historical or differently routed baseline is insufficient.

Retain one timestamped evidence row per stage rather than only an aggregate:

| Stage | Required evidence |
| --- | --- |
| Local publish | start/end UTC, elapsed, source bytes/hash, Publication ID, Blob ID, operation key, final sent/accepted/durable counters |
| Receiver wait | start/end UTC, each durable checkpoint transition, final state and Blob ID |
| Receiver read | start/end UTC, elapsed, written/discarded bytes, destination hash |
| Raw baseline | immediately adjacent start/end UTC, exact interface/address pair, bytes, elapsed, MiB/s |
| Environment | binary/config hashes, node IDs, interface addresses, route/path evidence, CPU/storage snapshots |

For a same-size raw TCP comparison, discard the receiver bytes and measure the
sender wall time on the same addresses immediately before or after Aster:

```sh
# Receiver
nc -l -s 192.168.60.79 -p 18294 > /dev/null

# Sender
start_ns=$(date +%s%N)
dd if=/dev/zero bs=1048576 count=1024 status=none \
  | nc -N 192.168.60.79 18294
end_ns=$(date +%s%N)
elapsed_ns=$((end_ns - start_ns))
awk -v ns="$elapsed_ns" \
  'BEGIN { printf "raw_mib_s=%.3f\n", 1024 / (ns / 1000000000) }'
```

## Failure interpretation

| Symptom | Check first |
| --- | --- |
| Local publish succeeds while peer is absent | Expected; inspect later contact and receiver state |
| `Timeout("accept")` followed by `Timeout("connect")` in the example | One-shot benchmark started before source pack readiness |
| `SinkFailed("No space left on device")` while `/var/tmp` has space | Benchmark used a small `/tmp` tmpfs; set `TMPDIR` explicitly |
| Transfer stops immediately below a checkpoint threshold | Verify whole-extent credit rounding and negotiated batch |
| Low Aster/raw ratio | Pair measurements, then inspect map queue, sink service, blocked time, path, retransmission, CPU, and storage sync |
| Retry starts at zero | Receiver had no authenticated durable checkpoint, or identity/open changed |
| Different terminal roots | Fail the run; do not publish, rename, or compare throughput as success |

Do not tune the canonical segment size to mask a storage, credit, route, or
checkpoint bottleneck. Measure the pipeline stage that owns wall time first.
