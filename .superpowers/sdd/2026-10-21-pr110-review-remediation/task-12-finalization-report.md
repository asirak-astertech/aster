# Task 12 Phase B — local Blob finalization report

## Status and scope

Implemented the remaining local finalization performance remediation in signed commit
`ff6bc04f8b561b2cf91d600bb077dfb5a1b8e755` (`perf(blob): pipeline local
finalization`). The change preserves the two-job finalizer admission/lifetime model while
replacing each job's whole-Blob prepare replay and serial canonical encryption with a
restart-safe digest artifact and a bounded canonical-chunk pipeline.

No device, deployment, push, full workspace test suite, or ignored 800-MiB/1-GiB
measurement run was performed.

## Test-first evidence

The production-path occupancy regression was written before the implementation.

RED command:

```text
cargo test -p aster-node stream_upload_finalization_occupies_multiple_chunk_workers --lib -- --nocapture
```

RED result: exit 101. The old whole-Blob/serial implementation failed at
`application::blob::tests::stream_upload_finalization_occupies_multiple_chunk_workers`
with `one Blob occupied only 0 map worker`.

After implementing the durable digest path and fixed-worker finalizer, the same command
passed: 1 passed, 0 failed, 657 filtered out. The final focused group passed 9 runnable
upload tests with 2 exact-size gates ignored by design.

## Design and execution DAG

### Existing upload pass

```text
caller bytes
  -> canonical 64-KiB incremental digest state (no extra plaintext chunk buffer)
  -> fixed-stride 32-byte digest sidecar append
  -> existing 1-MiB provisional segment seal/pack append
  -> sidecar sync
  -> pack sync
  -> alternating combined checkpoint v3 sync
  -> one redb upload-frontier projection
```

The sidecar is private to the owner-qualified upload pack and starts with a versioned
header containing the upload ID, immutable request digest, total length, and canonical
chunk size. Its body is exactly one 32-byte digest per canonical chunk, bounded by
`MAX_BLOB_CHUNKS`. The checkpoint records the digest count, exact projected file length,
SHA-256 commitment, and incremental whole-plaintext SHA-256 state. This is O(n) durable
data and avoids rewriting a growing digest vector into redb at every checkpoint.

### Finalization

```text
projected v3 checkpoint + sidecar
  -> validate identity/count/length/commitment/SHA state
  -> reconstruct PreparedBlob and canonical manifest without plaintext replay
  -> open one projected provisional-pack reader
  -> partition: read/decrypt one canonical 64-KiB chunk
  -> bounded fixed map pool: canonical digest check + in-place canonical AEAD seal
  -> bounded deterministic index reorder
  -> ordered depot commit of complete canonical chunk records
  -> finish manifest
  -> existing single atomic publication transaction
  -> existing cleanup/retry convergence
```

There is no serial compatibility fallback in normal v3 finalization. Every provisional
segment is opened once and each plaintext byte is read/decrypted once during
finalization. The map closure uses a provider-bound sealer rather than exporting key or
algorithm controls. The ordered sink retains the existing depot and publication
authorities.

## Durability, format, and crash boundaries

Pack data remains format v2. Sidecar-free pack checkpoints remain actual checkpoint v2
records, preserving supported pre-sidecar rows. Combined pack-plus-digest checkpoints
are v3 records. Decoding retains the checkpoint version, and a nonzero one-time digest
rebuild is authorized only by a genuine v2 checkpoint; a v3 checkpoint never receives
that migration path.

The one-time v2 migration decrypts and rereads exactly the already-durable staged prefix,
constructs the sidecar, writes a combined v3 checkpoint, and projects it. A focused
counter assertion proves:

- normal v3 resume replays 0 bytes;
- v2 migration replays exactly its durable prefix once;
- the first resume after that v3 projection again replays 0 bytes.

At a normal checkpoint, durability is ordered sidecar sync, pack sync, alternating
combined checkpoint sync, then redb projection. A crash before redb projection leaves
only unprojected tails; resume validates every projected identity/count/length/hash/SHA
field before truncating either artifact back to the projected boundary. A truncated,
misbound, mismatched, or corrupt sidecar fails closed.

The persisted SHA-256 snapshot is explicitly artifact format v1 and is not the raw sha2
serialization. It consists of eight big-endian chaining words, a big-endian compressed
64-byte-block count, one buffered-byte count, and a zero-padded 64-byte partial block.
Restore rejects buffered counts at or above 64, nonzero padding, arithmetic overflow,
state/offset disagreement, dependency deserialization failure, and non-canonical
round-trips before caller-side truncation or mutation. The pinned sha2 representation is
confined to an adapter at the artifact boundary.

## Ownership, cancellation, and resource bounds

One finalizer job uses 2 persistent map workers, at most 4 admitted canonical chunks,
and at most 4 reorder entries. There is no per-chunk thread creation, unbounded queue,
detached worker, or whole-object buffer. Worker map panics are caught as terminal pipeline
errors. Success, source/map/sink failure, cancellation, and panic all close admission,
signal cancellation, drain owned queued/results/reorder values, join every worker, and
zeroize plaintext/ciphertext vectors through their owners.

The plaintext vector reserves the AEAD tag in advance and becomes the ciphertext vector
in place. The explicit production accounting is:

```text
canonical owned bytes/chunk = 65,536 + 16 = 65,552
per-job pipeline bound       = 4 * 65,552 = 262,208 bytes
two-job pipeline bound       = 2 * 262,208 = 524,416 bytes
one staged segment/job       = 1,048,576 bytes
aggregate sensitive bound    = 2 * (1,048,576 + 262,208)
                             = 2,621,568 bytes
```

Digest metadata is separately bounded by `MAX_BLOB_CHUNKS` and contains digests rather
than retained plaintext. Upload-side fragmented chunk hashing is incremental, so the
sidecar writer does not own another 64-KiB plaintext copy.

Across the two existing finalizer jobs, the execution topology is 2 coordinator threads
plus 2 map workers per job. A shared four-permit production CPU budget covers both staged
segment open/decrypt/read and canonical encryption. Therefore no more than four
cryptographic CPU phases can execute concurrently on a four-core CM4, even though
coordinators may concurrently block on I/O, ordering, or the sink. The regression asserts
the two-job formula and the global budget value.

## Measurements and operation counts

`BlobFinalizeMetrics` retains real observations for admission, map, reorder, and sink
items/bytes/queue-wait/service/output-blocked durations; partition count; configured and
peak active workers; peak admitted items/bytes, owned bytes, encoding bytes, and reorder
items; plaintext bytes read; encrypted bytes; provisional segment opens; depot calls; and
store orchestration calls.

For N canonical chunks on the successful measured path, the focused regression observes:

```text
plaintext bytes read = exact Blob length
encrypted bytes      = Blob length + 16N
provisional opens    = ceil(Blob length / 1 MiB)
depot operations     = 4N + 2
store operations     = 6 (including successful cleanup)
```

The depot count is measured around the actual `BlobStore` implementation, not inferred
from a codec helper. A serial reference publication is installed first in the same
provider/epoch; the pipelined publication produces the same canonical Blob ID and must
idempotently match the already-stored canonical ciphertext/records.

Ignored gates
`stream_upload_finalization_measurement_800_mib` and
`stream_upload_finalization_measurement_1_gib` compile locally and emit schema
`aster.local_blob_finalization.measurement.v1`, including every metric above plus the
aggregate CPU and byte bounds. They were intentionally not executed locally.

## Compatibility analysis

- Public application API shapes are unchanged.
- Canonical chunk size, manifest encoding, Blob identity, content verification, and
  canonical ciphertext construction are unchanged.
- The existing two-job admission queue, caller-independent completion lifetime,
  policy/epoch replay and recheck, exact-operation retry, capacity credit and limits,
  atomic publication, cleanup-gap authority, and restart convergence remain in place.
- Empty, exact-chunk, maximum-boundary, policy change, retry, cleanup-authority,
  admission saturation, caller-drop, closed-pool, responsiveness, and worker-panic
  focused regressions pass.
- Existing v2 projected uploads are readable and are upgraded once. New normal uploads
  project combined v3 checkpoints. No provisional data becomes readable.

## Verification evidence

All commands below completed successfully unless explicitly described as RED above.

```text
cargo fmt --all -- --check
git diff --check
cargo test -p aster-node stream_upload_ --lib -- --nocapture
  9 passed; 0 failed; 2 ignored
cargo test -p aster-node selected_blob_publish_stream_ --lib -- --nocapture
  2 passed; 0 failed
cargo test -p aster-node stream_finalize_ --lib -- --nocapture
  5 passed; 0 failed
cargo test -p aster-node stream_pipeline::tests --lib -- --nocapture
  14 passed; 0 failed
cargo test -p aster-redb-store pack::tests --lib -- --nocapture
  7 passed; 0 failed
cargo test -p aster-node --lib --no-run
  success; ignored 800-MiB and 1-GiB gates compiled
cargo check --locked --workspace --all-targets
  success
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
  success
sh tools/check-cargo-lockfiles.sh
  success for the workspace, fuzz, and evaluation-v0 lockfiles
python3 tools/check-implementation-requirements.py
  valid: 348 matrix IDs; 140 exact selected mappings
python3 tools/check-protocol-version-contract.py
  passed: semantic versions 1 through 9 align
python3 tools/test-protocol-version-contract.py
  36 passed
python3 tools/check-selected-node-dependency-boundary.py
  passed
python3 tools/check-project-license.py
  passed for 18 packages
```

The full `mise run check` was not run because this task explicitly prohibited the full
workspace test suite. Its required formatting, strict all-feature/all-target Clippy,
all-target compile, relevant foundation/contract checks, and focused regressions were run
individually instead.

## Remaining concerns

- The exact-size 800-MiB and 1-GiB gates are compiled but have no local runtime/throughput
  receipt; they still require an authorized measurement host.
- `cargo check --workspace --all-targets` reports a pre-existing configuration-specific
  unused `SessionKeys` import and Cargo reports the existing future-incompatibility notice
  for `proc-macro-error2 v2.0.1`. Strict all-feature Clippy passes, and neither warning is
  introduced by this commit.
- A future sha2 upgrade must keep or deliberately update the small dependency adapter;
  the persisted artifact codec itself is versioned and canonical.

The report is committed separately with a signed documentation commit; its exact ID is
the commit containing this file in the branch history.
