# Task 1 equal/stale no-writer regression red receipt

## Exact source under test

- Baseline commit: `8181367b948c068f2d2961fa1497866f6d730591`
  (`fix: persist custody continuity on no-op maintenance`)
- Worktree: `/home/andrii/code/aster/.worktrees/pr25-review-fixes`
- Uncommitted test-only addition: the shared held-writer assertion helper plus
  `custody_gc_equal_sample_does_not_enter_write_queue`,
  `custody_gc_stale_sample_does_not_enter_write_queue`,
  `custody_pressure_equal_sample_does_not_enter_write_queue`, and
  `custody_pressure_stale_sample_does_not_enter_write_queue` in
  `crates/aster-redb-store/src/lib.rs`.

The test-only addition was present for both runs. The production predicate in
`crates/aster-redb-store/src/custody.rs` was then changed only locally and
reversibly for each run, before being restored exactly to its baseline
`sample.tick_ms > current.sample.tick_ms` condition. Neither temporary
production mutation was committed.

## Equal samples

Temporary predicate: `sample.tick_ms >= current.sample.tick_ms`.

```text
$ cargo test --locked -p aster-redb-store equal_sample_does_not_enter_write_queue -- --nocapture
running 2 tests
test tests::custody_gc_equal_sample_does_not_enter_write_queue ... FAILED
test tests::custody_pressure_equal_sample_does_not_enter_write_queue ... FAILED

failures:
    tests::custody_gc_equal_sample_does_not_enter_write_queue
    tests::custody_pressure_equal_sample_does_not_enter_write_queue

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 295 filtered out
error: test failed, to rerun pass `-p aster-redb-store --lib`
```

Both failed at the assertion that an equal same-clock sample must not wait for
redb's single-writer queue. Exit status: `101`.

## Stale samples

Temporary predicate: `sample.tick_ms != current.sample.tick_ms`.

```text
$ cargo test --locked -p aster-redb-store stale_sample_does_not_enter_write_queue -- --nocapture
running 2 tests
test tests::custody_gc_stale_sample_does_not_enter_write_queue ... FAILED
test tests::custody_pressure_stale_sample_does_not_enter_write_queue ... FAILED

failures:
    tests::custody_gc_stale_sample_does_not_enter_write_queue
    tests::custody_pressure_stale_sample_does_not_enter_write_queue

test result: FAILED. 0 passed; 2 failed; 0 ignored; 0 measured; 295 filtered out
error: test failed, to rerun pass `-p aster-redb-store --lib`
```

Both failed at the same blocked-writer assertion. Exit status: `101`.
