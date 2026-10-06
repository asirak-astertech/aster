# PR 25 bounded Event maintenance measurements

**Date:** 2026-10-06 (`Europe/Kyiv`)  
**Measured source:** implementation tree `960798f9df423236e9fc4a713fd1801180f3309d`
**Final verified source:** tree `90115910c62b9baf52e5a9ab0a9c43c4e3637f16`
**Evidence boundary:** current-code engineering observations on the local development host

## Claim boundary

These observations characterize the focused store fixtures and one attempted
10,000-item laboratory workload. They are not target-device results, retained
qualification evidence, a protocol limit, or evidence that the provisional
Tier-2 memory brackets are met. No roadmap, requirements-status, or atomic
trace row changes follow from this report.

The implementation controls measured here remain internal:

- one maintenance pass examines at most 1,024 dependency units;
- the maintained retirement scan examines at most 5,120 rows;
- pressure selection scans all retained custody rows while retaining at most
  1,024 candidate entries; and
- startup inspection remains O(total retained state), although the custody
  reverse-reference audit uses constant data-dependent scratch per row.

## Host preflight

Immediately before Task 7 work, the host reported:

| Resource | Observation |
| --- | --- |
| Workspace filesystem | 468 GiB total, 222 GiB available, 51% used |
| `/tmp` | 6.4 GiB total, 4.1 GiB available |
| RAM | 12 GiB total, approximately 5.1 GiB available |
| Swap | 4.0 GiB total, effectively fully consumed |
| Competing build/test process | none observed |

The initial Task 7 gate required at least 5.5 GiB available RAM, with no
competing build or test, before the full node suite or `mise run check`.
Available RAM remained approximately 5.0–5.2 GiB, so neither command was
started during that initial attempt. After the host reboot, the final preflight
reported approximately 10 GiB available RAM, 2.7–2.8 GiB free swap, 208 GiB
free on the workspace filesystem, 6.4 GiB free on `/tmp`, and no competing
build or test; the deferred gates then ran to completion.

## Focused maximum-constructed fan-out fixture

The existing numbered-retirement fixture constructs 1,025 results for one
Event, one more than a maintenance page, and exercises cleanup across reopen.
It is the largest valid per-object fan-out constructed by this fixture; it is
not described as a protocol maximum.

```text
umask 0077
/usr/bin/time -v \
  target/debug/deps/aster_redb_store-3434c5e50ccce99b \
  --exact \
  tests::event_operation_retirement::numbered_cleanup_rewrites_raw_pages_and_persists_client_revision \
  --nocapture --test-threads=1
```

| Metric | Observation |
| --- | ---: |
| Result | 1 passed, 0 failed |
| Exact numbered-result fan-out | 1,025 |
| Cleanup passes | 2 |
| First pass | 1,024 examined and rewritten results |
| Second pass | 1 examined and rewritten result; retirement completed |
| Wall time | 0.88 s |
| User CPU | 0.87 s |
| System CPU | 0.00 s |
| Peak RSS | 21,888 KiB (21.38 MiB) |
| Major page faults | 0 |
| Minor page faults | 998 |

The peak is below the provisional 32 MiB preferred and 64 MiB steady-state
Tier-2 brackets, but this short-lived, debug-profile, 1,025-result test is not a
10,000-item node and has no steady-state phase. It therefore cannot establish
either bracket. Steady RSS and allocator high-water are not exposed by this
fixture. Redb transaction and byte/I/O counters are also not exposed; GNU
`time` reported zero filesystem input/output for the cached run, which is not a
redb I/O measurement.

The same focused suite also asserts, using production-shared instrumentation,
that the victim heap peaks at exactly 1,024 entries and the retirement scan
stops after 4,096 lease-blocked rows plus one 1,024-row page.

## Advancing no-op continuity cadence

The existing advancing-GC fixture creates a fresh store, commits the initial
continuity observation, commits one advancing same-clock no-work observation,
and verifies the durable tick. It was invoked 100 times without introducing a
new harness:

```text
umask 0077
/usr/bin/time -v bash -c \
  'for i in $(seq 1 100); do
     target/debug/deps/aster_redb_store-3434c5e50ccce99b \
       --exact tests::custody_gc_advancing_noop_persists_continuity \
       --quiet --test-threads=1 >/dev/null || exit 1
   done'
```

| Metric | Observation |
| --- | ---: |
| Successful fixture invocations | 100 |
| Verified advancing no-op durable updates | 100 |
| Wall time | 21.47 s |
| User CPU | 20.98 s |
| System CPU | 0.48 s |
| Peak RSS | 20,816 KiB (20.33 MiB) |

This is 4.66 complete fixture invocations per second. Each invocation includes
process startup, store creation, the initial continuity commit, the advancing
commit, and verification, so the result must not be presented as isolated
commit latency or storage throughput. The implementation intentionally writes
one durable high-water update for every advancing observation; equal and stale
same-clock observations remain read-only.

## Existing 10,000-item working-set fixture

The repository's existing one-node scale fixture was rebuilt from the current
branch and run without changing its workload or inventing a substitute:

```text
cargo build --locked -p aster-lab
/usr/bin/time -v target/debug/aster-lab scale \
  --root /tmp/aster-pr25-task7.cv2bGE/run \
  --nodes 1 --shards 1 --items 10000 --payload-bytes 64 --max-pumps 100000
```

The debug-profile run did not finish within the repository resource scenario's
20-minute boundary and was stopped with `SIGINT` (exit 130). It produced no
final `metrics.json`. This stopped run is accepted as the bounded engineering
result for this increment, not as a successful scale or resource result.
Before removal of the Task 7 scratch directory, the partial state contained a
130,723,840-byte SQLite database, a 4,268,352-byte WAL, and a 32,768-byte SHM
file (129 MiB directory total).

Because the signal terminated the GNU `time` wrapper together with the
workload, final peak RSS, steady RSS, wall/CPU totals, allocator high-water,
transaction counts, and I/O counters were unavailable. The partial database
size is not used to infer an item count, completion percentage, or memory
result. The generated scratch directory was removed after these sizes were
recorded.

The existing 10,000-item scale workload also does not construct the focused
Event retirement dependency fan-out. Consequently, this run and the focused
fan-out run must not be combined into an unmeasured claim about simultaneous
10,000-item plus maximum-fan-out behavior.

## Verification completed

The complete store suite was rerun serially with the lockfile gate and secure
backing-file umask:

```text
umask 0077
CARGO_BUILD_JOBS=1 cargo test --locked -p aster-redb-store -- --test-threads=1
```

Result: 324 tests passed, 0 failed; doc tests passed; test execution time was
175.21 seconds.

After the reboot and healthy resource preflight, the deferred node suite ran
serially with the lockfile gate and secure backing-file umask:

```text
umask 0077
cargo test --locked -p aster-node --features nearby-discovery -- --test-threads=1
```

Result: 376 tests passed, 0 failed.

The complete repository gate then ran:

```text
mise run check
```

Result: exit 0. The workspace nextest summary was `1734 tests run: 1734
passed (1 slow), 1 skipped`; workspace Clippy, doc tests, real-process mesh
integrations, conformance, Python, Go, C, and C++ checks passed. The
requirements checker retained 348 matrix IDs and 137 exact mappings; no
requirements evidence or maturity boundary changed.

Formatting and whitespace checks are recorded in the Task 7 report. `mise run
fuzz-smoke` is not applicable because this change does not modify parser,
framing, envelope, fragmentation, or related hostile-input boundaries.

## Result

The focused evidence supports the implementation-level claims that dependency
cleanup is page-bounded and resumable, the candidate and retirement-scan bounds
are asserted, and advancing no-work continuity observations commit durably.
For this increment, the stopped 20-minute run is the accepted bounded
10,000-item engineering result and limitation: the workload did not finish and
did not expose final resource metrics. It does not establish simultaneous
10,000-item plus maximum-fan-out behavior, Tier-2 qualification, or a protocol
limit. DM-9/DM-14 resource status and all roadmap/requirements maturity
therefore remain unchanged.
