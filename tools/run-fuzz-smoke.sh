#!/bin/sh
# Run bounded fuzz campaigns without mutating the retained seed corpus.
set -eu

project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fuzz_smoke_dir=$(mktemp -d "${TMPDIR:-/tmp}/aster-fuzz-smoke.XXXXXX")

cleanup_fuzz_smoke() {
    if [ -n "${fuzz_smoke_dir:-}" ] && [ -d "$fuzz_smoke_dir" ]; then
        rm -rf -- "$fuzz_smoke_dir"
    fi
}
trap cleanup_fuzz_smoke 0 1 2 3 15

wire_corpus="$fuzz_smoke_dir/wire-corpus"
fragment_corpus="$fuzz_smoke_dir/fragment-corpus"
envelope_corpus="$fuzz_smoke_dir/envelope-corpus"
wire_artifacts="$fuzz_smoke_dir/wire-artifacts"
fragment_artifacts="$fuzz_smoke_dir/fragment-artifacts"
envelope_artifacts="$fuzz_smoke_dir/envelope-artifacts"
mkdir -p "$wire_corpus" "$fragment_corpus" "$envelope_corpus" \
    "$wire_artifacts" "$fragment_artifacts" "$envelope_artifacts"
cp -R "$project_dir/fuzz/corpus/wire_decode/." "$wire_corpus/"
cp -R "$project_dir/fuzz/corpus/fragment_decode/." "$fragment_corpus/"
cp -R "$project_dir/fuzz/corpus/envelope_inspect/." "$envelope_corpus/"

cd "$project_dir"
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz wire_decode "$wire_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081901 \
    -artifact_prefix="$wire_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz fragment_decode "$fragment_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081902 \
    -artifact_prefix="$fragment_artifacts/" -print_final_stats=1
cargo +nightly-2026-08-18 fuzz run --fuzz-dir fuzz envelope_inspect "$envelope_corpus" -- \
    -runs=10000 -max_len=262144 -seed=2026081903 \
    -artifact_prefix="$envelope_artifacts/" -print_final_stats=1
