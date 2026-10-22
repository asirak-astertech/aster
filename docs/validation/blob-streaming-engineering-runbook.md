# Blob streaming engineering runbook

This runbook validates the semantic-v9/profile-5 Blob pipeline from a local
application publish through selected-contact transfer and receiver-local read.
It is engineering validation, not a production deployment or release
qualification procedure.

## Understand the selected profile

Profile 5 is the semantic-v9 selection. It is not a migration back to v8 and
does not introduce a second durable Blob representation. Semantic v7/v8 peers
retain profile 4 for compatibility; a semantic-v9 peer selects profile 5.
`ASTRBT01` canonical records and the Blob manifest remain the durable
representation. The former `ASTRBS02` provisional upload-pack format is local
staging only and has no semantic-v9 wire meaning.

| Selection | Object maximum | Canonical chunks | Authenticated source |
| --- | ---: | ---: | ---: |
| semantic v7/v8, profile 4 | 64 MiB | 1,024 | 1 MiB |
| semantic v9, profile 5 | 8 GiB | 131,072 | 16 MiB |

Both profiles use canonical 64-KiB plaintext chunks. A complete length-prefixed
`ASTRBT01` carrier is at most 66,215 bytes. Profile-5 DATA packs one or more
whole carriers into one `ABX1` extent no larger than 1 MiB, below Iroh's 2-MiB
exchange-frame ceiling. SOURCE is sent in records no larger than 1 MiB, with a
16-MiB authenticated-open maximum. The receiver selects a checkpoint batch no
larger than 128 MiB.

The bounded exchange is:

```text
PLAN -> OPEN -> SOURCE -> ACCEPT -> ABX1 DATA -> CHECKPOINT
     -> FINISH -> RESULT -> ACK
```

An authenticated empty Blob uses exactly `PLAN -> OPEN -> SOURCE -> ACCEPT ->
FINISH(0) -> RESULT -> ACK`: it has no DATA or CHECKPOINT. A successful read of
that publication returns exactly one authenticated empty terminal page at
offset zero. Missing content, denied access, or an offset beyond nonempty
content must never be converted into that EOF.

## Keep publication and synchronization independent

Local publish succeeds after the local durable commit and does not wait for a
peer. Synchronization starts when an eligible destination becomes available or
requests the content. Receiver promotion occurs only after authenticated
canonical records, terminal-root verification, RESULT, and ACK settlement.

Every attempt is gated independently by authenticated peer identity, current
Blob interest, route authorization, content proof, and nonrevocation. Status is
canonical-first: `blob-status` reports receiver-local durable publication
state, not carrier connectivity or source-side intent. Resume uses the
receiver's durable receipt (publication/attempt binding, canonical offset,
checkpoint generation, and commitment). A later selected adapter therefore
resumes the same publication without translating durable state.

The current adapter is Iroh QUIC. The adapter interface is carrier-independent
and retains the bindings needed by a reliable ordered full-duplex non-IP
adapter. That keeps a future BLE adapter possible; this change does not
implement BLE or multi-adapter failover.

## Capacity and timeout bounds

The local canonical finalization pool has two workers and two queued jobs.
That bound limits concurrent finalization, not disk consumption. Depot
reservations, completed-but-unpublished packs, database/journal allocation,
and finalizers may overlap. Check both state and depot filesystems and leave
operational reserve; an observed capacity snapshot is not a reservation.

Profile-5 transfer has two different liveness bounds:

- two minutes without authenticated progress is a retryable idle stall; and
- the hard attempt deadline is `ceil(bytes / 128 KiB/s) + 20 minutes`.

The legacy ten-minute attempt constant is not the normal-success deadline for
profile 5. CLI/agent RPC deadlines are a separate local application concern;
set them long enough for the local upload or read and recover an unknown
publish outcome with the same operation key.

## Publish, observe, and read

The CLI accepts nonempty regular files. Publication is local and remains valid
with no configured peer:

```sh
TOKEN_FILE=/run/aster/client.token
SOURCE=/data/imagery-1g.bin
OUTPUT=/data/received-imagery-1g.bin

stat --format='bytes=%s' "$SOURCE"
sha256sum "$SOURCE"
df -B1 /var/lib/aster-agent /var/lib/aster-depot /data
asterctl --token-file "$TOKEN_FILE" --json status

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-publish \
  --file "$SOURCE" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --operation-key imagery-flight-2026-10-20 \
  --priority immediate \
  --media-type application/octet-stream \
  --progress always 2>publish-progress.log
```

Save the publication ID, Blob ID, and operation key. If the command is
interrupted or its result is unknown, repeat the exact bytes, metadata, TTL,
and operation key. A different key means a different application operation.
The agent caps a Blob RPC at 15 minutes, so a larger client `--timeout` cannot
extend one local upload. If the cap is reached, retry the exact publication;
operation-key idempotency returns or resumes its durable local outcome. Peer
synchronization is separate and resumes from the receiver receipt.

Run status on the destination node. It is safe to start this after local
publication and before or after a peer becomes reachable:

```sh
PUBLICATION_ID='PASTE_BASE64_PUBLICATION_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 --json blob-status \
  --publication-id "$PUBLICATION_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --wait
```

Read the returned Blob ID to a path that does not exist, then compare the
application-level hashes:

```sh
BLOB_ID='PASTE_BASE64_BLOB_ID'

asterctl --token-file "$TOKEN_FILE" --timeout 900 blob-read \
  --id "$BLOB_ID" \
  --topic imagery.maps \
  --scope mission/team/alpha \
  --output "$OUTPUT" \
  --progress always 2>read-progress.log

sha256sum "$OUTPUT"
```

An interrupted CLI download removes its staged bytes and currently restarts at
zero. That is independent of node-to-node receipt resume, which continues from
the receiver's authenticated durable checkpoint even when adapter selection
changes. If the 15-minute read RPC cap is reached, confirm `blob-status` still
reports `AVAILABLE`, remove any owner-only abandoned staging file after
inspection, and retry the read; the CLI download itself does not resume.

The Rust streaming API also admits an empty Blob. Open a
`BlobPublishStreamRequest` with `total_len: 0`, perform no `write`, and call
`finish`. Read it with `BlobReadPageRequest { offset: 0, ... }`; the result must
be empty and complete. The file-based CLI deliberately rejects empty sources.

For a nonempty Rust upload, call `open_publish_stream`, begin at
`stream.durable_offset()`, pass absolute offsets to `write`, and call `finish`
only after exactly `total_len` bytes. Reopening the exact operation returns the
durable local frontier. Do not infer progress from bytes merely submitted by
the caller.

## Check peer compatibility and policy

- A v9-to-v9 contact selects profile 5 and can transfer empty through 8-GiB
  publications.
- A v7/v8 contact selects profile 4. It can receive only compatible nonempty
  publications up to 64 MiB / 1,024 chunks / a 1-MiB authenticated source.
- A profile-5 attempt does not fall back in place to profile 4. Content outside
  profile-4 bounds remains local for that older peer.
- Peer configuration alone grants nothing. Confirm exact Blob interest plus
  current route/content authorization on the receiver.

## Diagnose an operational run

Record the source length/hash, both node IDs, semantic/profile selection,
bind/listen addresses, selected carrier path, free bytes on state and depot
filesystems, publication/Blob IDs, operation key, and wall-clock timestamps.
Keep progress logs and the source/receiver node logs.

```sh
rg 'CONTACT .*blob_stream_(sent|received|resumed)_bytes=[1-9]' /path/to/node.log
rg 'profile|carrier_path|checkpoint|interest|route|content|revok|timeout' \
  /path/to/node.log
```

`blob_stream_sent_bytes`, `blob_stream_received_bytes`, and
`blob_stream_resumed_bytes` are attempt accounting. Checkpoints and partitions
show durable progress. Pipeline service counters overlap; do not add them to
derive elapsed time. A CONTACT line alone is not proof of publication receipt.

## Measure transport and end-to-end performance

Build the current transport example and retain its hash:

```sh
cargo build --locked --release -p aster-node \
  --example blob_stream_transport_benchmark
BIN=target/release/examples/blob_stream_transport_benchmark
sha256sum "$BIN"
```

Run a local 1-GiB control:

```sh
"$BIN" loopback 1073741824
```

Run the receiver first on one device and the sender on another. Bind Aster to
the network under test; retaining ZeroTier for remote administration does not
prove that payloads used WLAN.

```sh
# receiver
./blob_stream_transport_benchmark receive 192.168.60.80:18293 1073741824

# sender
./blob_stream_transport_benchmark send \
  192.168.60.79:0 192.168.60.80:18293 1073741824
```

Capture an adjacent raw-file baseline on the same selected interface, for
example with `iperf3` or an audited `nc` plus source/receiver `sha256sum`.
Compare raw throughput, the transport example, local publish, network
replication, and receiver read separately; do not collapse those stages into
one unexplained rate.

Before device work, run the focused contract checks:

```sh
python3 conformance/blob_stream_oracle.py
python3 tools/check-protocol-version-contract.py
python3 tools/test-protocol-version-contract.py
python3 tools/test-run-fuzz-smoke.py
tools/run-fuzz-smoke.sh
```

The oracle/vectors and fuzz smoke validate the protocol grammar and decoder;
they do not establish CM4 throughput. A CI-built ARM64 binary still needs the
three CM4 devices to validate raw WLAN baseline, one-node local publication,
v9-to-v9 transfer, interruption/resume, receiver read/hash, memory/disk bounds,
and v8/v9 compatibility. Record exact commands, hashes, selected paths, and
receipts. Do not carry earlier device numbers forward as qualification for a
new binary.
