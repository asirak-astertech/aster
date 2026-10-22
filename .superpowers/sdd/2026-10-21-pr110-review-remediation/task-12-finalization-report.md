# Task 12 Phase B — local Blob finalization report

## Status and scope

The original Phase B implementation is in signed commit
`ff6bc04f8b561b2cf91d600bb077dfb5a1b8e755`. Review round 1 corrected the
durability, worker mapping, capacity, v3 validation, and zeroization findings.
Review round 2 corrects the two remaining measurement findings from
`task-12-finalization-rereview.md`: observed allocation peaks are now distinct
from conservative bounds, and the selective Store phase counter is removed.
Review round 3 satisfies the original Task 12 Store-count requirement with a
complete private finalizer boundary rather than restoring that selective
counter.

No transport file, device, deployment, push, full workspace test suite, or
ignored 800-MiB/1-GiB measurement run was touched or executed.

## Test-first evidence

The review fixes began with regressions that failed against the signed
candidate:

```text
cargo test -p aster-redb-store upload_digest_v2_resume_recreates_a_torn_unprojected_sidecar --lib -- --nocapture
  RED: UnexpectedEof while opening the torn final-name sidecar

cargo test -p aster-redb-store checkpoint_v3_rejects_missing_digest_projection --lib -- --nocapture
  RED: v3 without a digest projection decoded successfully

cargo test -p aster-redb-store upload_capacity_charges_the_exact_canonical_digest_artifact --lib -- --nocapture
  RED: charged 196743 bytes, expected 196925 bytes (86 + 3*32 absent)

cargo test -p aster-node stream_upload_finalization_occupies_multiple_chunk_workers --lib -- --nocapture
  RED: the probe observed canonical encryption workers but no worker-owned
       provisional decrypt/read
```

The same tests are GREEN after the implementation. Additional crash/reopen,
legacy-capacity pressure, privacy-boundary, one-pass, parity, cancellation, and
zeroization regressions are listed under verification.

Round 2 added its measurement/schema regression before implementation:

```text
cargo test -p aster-node stream_upload_finalization_is_one_pass_bounded_and_canonical --lib -- --nocapture
  RED: exit 101; observed worker/publication/whole-buffer fields and the v2
       measurement schema did not exist, while the old peak and selective
       Store counter remained
```

The focused test is now GREEN and rejects JSON keys named `peak_owned_bytes`,
`store_operations`, or `store_phase_calls`.

Round 3 first added exact boundary-trace expectations to the one-pass and
cleanup-gap regressions:

```text
cargo test -p aster-node stream_upload_finalization_is_one_pass_bounded_and_canonical --lib -- --nocapture
  RED: exit 101; BlobFinalizeMetrics had no store_boundary_operations or
       store_boundary_trace fields
```

After the private boundary was implemented, the successful finalization test
was GREEN at 10 attempted operations. The synchronous cleanup-gap regression
initially exposed that its test helper discarded the measured report; the
helper now returns that report directly and the regression is GREEN at the
exact nine-operation prefix without `CompleteUpload`.

## Durable digest artifact and crash recovery

The fixed-stride artifact remains:

```text
86-byte versioned header
  + 32 * ceil(total_len / 64 KiB) canonical plaintext digests
```

The header canonically binds the upload ID, immutable request digest, total
length, and canonical chunk size. A v3 combined checkpoint binds the projected
digest count, exact projected file length, SHA-256 artifact commitment, and a
versioned/canonical whole-plaintext SHA-256 state. The SHA state is eight
big-endian chaining words, a big-endian compressed-block count, one buffered
length, and a zero-padded 64-byte partial block. Decode rejects impossible
counts, lengths, padding, arithmetic, state/offset combinations, dependency
round-trip disagreement, and identity mismatch before truncation or mutation.

First creation now uses the existing pinned-directory atomic writer: a
same-directory private `O_NOFOLLOW`, `0600`, `CREATE|EXCL` temporary file is
written completely, synchronized, atomically renamed, and followed by parent
directory synchronization. Test path roots use the same create/write/sync/
rename/parent-sync discipline. Partial private temporaries are invisible.

If the authoritative checkpoint has no digest projection (`None` or genuine
pack v2), an invalid unprojected final-name artifact can be discarded and
atomically reconstructed. Pack audit permits such a torn unprojected artifact
only after enforcing the private regular-file/owner/link/no-follow boundary.
Once a v3 projection exists, header, commitment, length, count, and SHA state
remain fail-closed. Unprojected tails after combined-checkpoint sync but before
redb projection are validated and truncated back to the redb-authoritative
frontier on resume.

The one-time durable-v2 migration rereads/decrypts its already durable prefix
exactly once to construct and project v3. A counter regression distinguishes
that migration from normal operation: v3 resume/finalization rereads zero
plaintext for digest reconstruction, v2 migration rereads its prefix once,
and the next v3 reopen again rereads zero.

## Exact capacity and legacy migration

Fresh reservations now charge the provisional pack reservation plus the exact
digest artifact size, including the 86-byte header for an empty Blob. Durable
upload encoding is versioned: legacy row v1 validates with the legacy formula;
current row v2 validates with the sidecar-inclusive formula.

Before a legacy row can create a sidecar, its reserve transaction calculates
the additional physical bytes and atomically checks/reserves them. Capacity
pressure returns without changing the durable row or artifacts, so a later
retry can succeed. The migration regression proves byte-for-byte unchanged
state after failure, exact-limit success after reopening with sufficient
capacity, audit equality, and cleanup returning to the baseline.

## Finalization execution DAG

```text
coordinator: validate projected v3 checkpoint + load one zeroizing digest vector
  -> submit bounded segment descriptors only

two persistent map workers per Blob:
  -> independently open exact projected provisional segment
  -> decrypt/read that segment once under the global CPU permit
  -> split into canonical 64-KiB chunks
  -> borrow retained digest, validate, canonical-encrypt
  -> return one ordered segment bundle

ordered sink:
  -> deterministic bounded reorder by segment index
  -> commit canonical records/chunks
  -> build measured manifest and route
  -> existing atomic publication and cleanup convergence
```

The coordinator never calls `UploadPackPlainReader::read_exact`. A production
probe records decrypt observations from the named map workers, and the focused
test requires multiple provisional segments, more than one worker, exact
segment-read count, one read/decrypt per byte, and canonical identity/ciphertext
parity with the serial reference. There is no whole-object plaintext buffer.

Two finalizer jobs remain admitted. Each has two persistent map workers and at
most two admitted/reorder segment bundles. A shared four-permit budget covers
provisional open/decrypt/read plus canonical encryption, so the four-core CM4
cannot run more than four cryptographic CPU phases across both jobs. All
success, source/map/sink failure, cancellation, and panic paths close
admission, drain owned queues/results/reorder values, join workers, and rely on
zeroizing plaintext/ciphertext owners.

## Whole-finalizer memory and operation measurements

Measurement schema `aster.local_blob_finalization.measurement.v2` separates
observations from configuration:

- `observed_worker_buffer_peak_bytes` is maintained by a shared live-capacity
  tracker across both map workers and queued/reorder results. Each guard reports
  actual `Vec::capacity()` and container capacity while the encoded pack record
  and decoded ciphertext overlap, while decoded ciphertext and plaintext
  overlap, while each canonical plaintext copy is sealed, and while mapped
  ciphertext bundles wait for the ordered sink.
- `observed_publication_buffer_peak_bytes` observes the post-manifest phase. It
  explicitly includes the simultaneously live retained manifest, sealed
  envelope, and opened manifest, then the retained manifest, durable outcome
  envelope, and stored-verification manifest through route caching.
- `observed_buffer_peak_bytes` is the maximum of the observed preparation,
  worker/queue, manifest/route, and publication buffer phases. It is an
  observed capacity total for the named buffers, not a process allocator RSS
  claim.
- `conservative_owned_byte_bound` and
  `aggregate_conservative_owned_byte_bound` are explicitly configured bounds,
  never labeled as measured peaks.

The old JSON keys `peak_owned_bytes` and `pipeline_peak_owned_bytes` are gone.
`peak_in_flight_accounted_bytes` and
`aggregate_pipeline_accounting_bound` retain the distinct admission-accounting
meaning.

The conservative two-job ownership bound is exported separately and asserted
against the same production formula:

```text
worker_peak = 3 * 1 MiB
            + 16 * sizeof(BlobFinalizeMappedChunk)

per_job = (MAX_BLOB_CHUNKS * 32)                  digest material
        + 2 * worker_peak                         two inner workers
        + 4 * MAX_BLOB_MANIFEST_BYTES             publication overlap bound
        + (2 * MAX_BLOB_CHUNKS * 32
           + 32 * sizeof(Vec<[u8; 32]>))          route levels
        + 1 MiB                                    provider-envelope overhead
        + 3 * (MAX_MEDIA_TYPE + MAX_SCHEMA_ID)    owned metadata

aggregate_conservative_owned_byte_bound = 2 * per_job
aggregate_pipeline_accounting_bound     = 2 jobs * 2 bundles
                                          * segment accounting
aggregate_cpu_budget                    = 4
```

The reorder peak now subtracts the expected next item only when it is actually
present, so one genuinely out-of-order result reports one rather than zero.

The finalizer now moves its `Arc<Store>` into a private `BlobFinalizeStore`
facade at the start of `run_measured`. The facade deliberately implements no
`Deref`, `AsRef<Store>`, or raw Store getter, and the moved raw binding cannot
be reused. Verification that does not request completion checking is split
into a Store-free path, so every top-level Store-backed action in the finalizer
is a named facade operation.

`store_boundary_operations` counts attempted top-level operations on entry to
that facade; it intentionally does not count nested redb calls inside those
helpers. The successful trace is exactly:

```text
ReplayAuthority, ReadControlHead, RefreshPolicy, ReserveUpload, OpenPackRoot,
OpenUploadDepot, CompletePreparedBlob, CommitPublication, CacheRoute,
CompleteUpload
```

The cleanup-gap path is the exact nine-operation prefix ending at `CacheRoute`.
The measurement JSON exposes `store_boundary_operations` and continues to
reject the obsolete `store_phase_calls` and `store_operations` keys. Separately,
`MeasuredBlobStore` still observes every canonical chunk-depot API call and the
exact `4N + 2` assertion detects added or removed depot-boundary work. The same
successful path observes exact plaintext bytes, `Blob length + 16N` encrypted
bytes, and `ceil(Blob length / 1 MiB)` provisional reads.

## Digest ownership and privacy boundary

Sidecar material, SHA snapshots/commitments, and the single retained digest
vector use zeroizing ownership. `PreparedBlob` and map workers share one
`Arc<Zeroizing<Vec<[u8; 32]>>>`; the earlier plain-vector clone is gone, and
workers borrow each digest rather than creating a temporary copy. SHA-256
state has a compile-time `ZeroizeOnDrop` assertion. Canonical chunk records
necessarily retain their authenticated plaintext digest as part of the
existing record format.

The artifact is not cryptographically protected at rest. The store layer has
no provider/node/mission content key without introducing a second authority,
so this increment deliberately keeps the reviewed filesystem boundary:
pinned owner-qualified directory, `O_NOFOLLOW`, private `0600` file,
same-owner regular-file validation, and link count one. This prevents broader
filesystem disclosure and link/symlink substitution, but it does not protect
against the same Unix account or offline disk access; raw unkeyed digests permit
equality and dictionary attacks. Tests assert the boundary and symlink
rejection without claiming encryption.

## Verification evidence

Fresh focused gates after review correction:

```text
cargo fmt --all -- --check
  passed
git diff --check
  passed
cargo clippy -p aster-core -p aster-redb-store -p aster-node --lib --tests -- -D warnings
  passed

cargo test -p aster-node stream_upload_finalization_ --lib -- --nocapture
  5 passed; 0 failed; 2 ignored exact-size gates; 657 filtered
cargo test -p aster-redb-store blob_pack_reader_observes_encoded_and_decoded_capacity_overlap --lib -- --nocapture
  1 passed; 0 failed

cargo test -p aster-redb-store upload_digest_ --lib -- --nocapture
  3 passed; 0 failed
cargo test -p aster-redb-store checkpoint_v3_rejects_missing_digest_projection --lib -- --nocapture
  1 passed; 0 failed
cargo test -p aster-redb-store upload_capacity_charges_the_exact_canonical_digest_artifact --lib -- --nocapture
  1 passed; 0 failed
cargo test -p aster-redb-store legacy_upload_capacity_upgrade_is_atomic_under_pressure_and_reopen --lib -- --nocapture
  1 passed; 0 failed
cargo test -p aster-redb-store store_reopen_accepts_and_new_upload_recreates_torn_unprojected_sidecar --lib -- --nocapture
  1 passed; 0 failed
cargo test -p aster-redb-store digest_sidecar_enforces_the_documented_local_private_boundary --lib -- --nocapture
  1 passed; 0 failed
cargo test -p aster-redb-store upload_sync_and_projection_faults_reopen_without_invented_progress --lib -- --nocapture
  1 passed; 0 failed
```

Round 2 reran the formatting/diff checks, the same node finalization group, and
strict Clippy for `aster-core`, `aster-redb-store`, and `aster-node` after the
metric changes. The one-pass regression additionally proves:

- the worker observation contains at least the concurrently live encoded/
  decoded or decoded/plaintext segment buffers and real mapped-container
  capacity;
- the publication observation contains at least three live manifest-sized
  buffers;
- the observed peak does not exceed the separately named conservative bound;
- `depot_operations == 4N + 2` at the instrumented `BlobStore` boundary; and
- the measurement JSON contains neither the old peak key nor obsolete
  Store-counter keys.

Round 3 reran the same focused node finalization group and strict Clippy. The
one-pass regression additionally requires the exact ordered ten-operation
Store-boundary trace and JSON count; the cleanup-gap regression requires the
exact ordered nine-operation trace. Because the facade owns the only Store
authority in `run_measured` and has no escape hatch, adding a top-level Store
action requires a named, observed facade method or fails to compile.

```text
cargo test -p aster-node stream_upload_finalization_ --lib -- --nocapture
  5 passed; 0 failed; 2 ignored exact-size gates; 657 filtered
cargo test -p aster-node stream_upload_prefers_canonical_result_over_residual_cleanup_authority --lib -- --nocapture
  1 passed; 0 failed; 663 filtered
cargo clippy -p aster-core -p aster-redb-store -p aster-node --lib --tests -- -D warnings
  passed
cargo fmt --all -- --check
  passed
git diff --check
  passed
```

The redb group covers partial atomic create, v2 torn-final recreation, header
and combined-checkpoint durability states, pre-redb-projection tails, projected
resume truncation, Store reopen, exact capacity pressure/retry/reopen, cleanup
baseline, v3 canonical rejection, and the stated local-private boundary.

The ignored `stream_upload_finalization_measurement_800_mib` and
`stream_upload_finalization_measurement_1_gib` gates still compile but were not
run. No full workspace suite or broad check script was run in this fix round.

## Signed commits

- `ff6bc04f8b561b2cf91d600bb077dfb5a1b8e755` — initial Phase B implementation
- `cb3822839d73cb178b6ab04a09aca4d65d7079c5` — initial Phase B report
- `071c65ce97e26584897a74612ff1c94d4f5e4060` — review-round implementation corrections
- `3640f492b504744ae4dab44e9f3b321d6efccde0` — review-round 2 measurement corrections
- `b1721b3e588db0ed9606af03d35c78970f7c4f6a` — review-round 3 Store-boundary implementation
- the signed documentation commit containing this report

## Remaining concerns

- The exact-size 800-MiB and 1-GiB runtime/throughput receipts still require an
  authorized measurement host.
- The sidecar intentionally exposes unkeyed digest equality to the same Unix
  account or offline disk access, as documented above; protecting it would
  require a new Store-layer authority design.
- Opening an independent pinned reader per segment repeats bounded checkpoint
  validation metadata I/O; it does not reread provisional plaintext, but a
  future measured optimization could pass a prevalidated pinned segment view.
- `store_boundary_operations` is an orchestration-boundary attempt count, not a
  count of nested redb transactions or physical I/O. Depot work retains its
  independent complete `4N + 2` API-boundary instrumentation.
