#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cargo_command=${CARGO:-cargo}

tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --workspace \
    --invert proc-macro-error2@2.0.1 \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
packages=$(printf '%s\n' "$tree" | awk '{ print $1 " " $2 }')
expected='proc-macro-error2 v2.0.1
i18n-embed-fl v0.9.4
age v0.11.5
aster-provisioning-age v0.1.0'

if [ "$packages" != "$expected" ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected reverse dependency graph' >&2
  printf '%s\n' 'expected:' "$expected" 'actual:' "$packages" >&2
  exit 1
fi

fuzz_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/fuzz/Cargo.toml" \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
fuzz_packages=$(printf '%s\n' "$fuzz_tree" | awk '{ print $1 " " $2 }')
if printf '%s\n' "$fuzz_packages" | awk '$1 == "proc-macro-error2" { found = 1 } END { exit !found }'; then
  printf '%s\n' 'dependency-exception scope failed: ignored proc-macro-error2 is present in the excluded fuzz graph' >&2
  exit 1
fi

printf '%s\n' 'dependency-exception scope passed: RUSTSEC-2026-0173 is isolated to aster-provisioning-age and absent from fuzz'
