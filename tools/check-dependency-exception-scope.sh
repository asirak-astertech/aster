#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cargo_command=${CARGO:-cargo}

lock_hickory_packages=$(
  awk '
    /^\[\[package\]\]$/ { package = ""; version = "" }
    /^name = "hickory-(proto|resolver)"$/ {
      package = $3
      gsub(/"/, "", package)
    }
    /^version = / && package != "" {
      version = $3
      gsub(/"/, "", version)
      print package " " version
      package = ""
    }
  ' "$repository_root/Cargo.lock"
)
expected_lock_hickory_packages='hickory-proto 0.25.2
hickory-resolver 0.25.2'

if [ "$lock_hickory_packages" != "$expected_lock_hickory_packages" ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected lock-only Hickory package set' >&2
  printf '%s\n' 'expected:' "$expected_lock_hickory_packages" 'actual:' "$lock_hickory_packages" >&2
  exit 1
fi

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

paste_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --workspace \
    --all-features \
    --invert paste@1.0.15 \
    --edges normal,build,dev \
    --target all \
    --prefix depth \
    --format '{p}'
)
paste_graph=$(printf '%s\n' "$paste_tree" | awk '{ print $1 " " $2 }')
expected_paste_graph='0paste v1.0.15
1netlink-packet-core v0.8.2
2if-watch v3.2.2
3libp2p-tcp v0.44.1
4libp2p v0.56.0
5aster-libp2p-provider v0.1.0
6aster-lab v0.1.0
2netlink-packet-route v0.28.0
3if-watch v3.2.2
3rtnetlink v0.20.0
4if-watch v3.2.2
2netlink-proto v0.12.2
3if-watch v3.2.2
3rtnetlink v0.20.0
2rtnetlink v0.20.0'

if [ "$paste_graph" != "$expected_paste_graph" ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected paste reverse dependency graph' >&2
  printf '%s\n' 'expected:' "$expected_paste_graph" 'actual:' "$paste_graph" >&2
  exit 1
fi

active_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/Cargo.toml" \
    --workspace \
    --all-features \
    --edges normal,build,dev \
    --target all \
    --prefix none \
    --format '{p}'
)
active_packages=$(printf '%s\n' "$active_tree" | awk '{ print $1 " " $2 }')
active_paste_packages=$(
  printf '%s\n' "$active_packages" |
    awk '$1 == "paste" { print $1 " " $2 }' |
    LC_ALL=C sort -u
)
if [ "$active_paste_packages" != 'paste v1.0.15' ]; then
  printf '%s\n' 'dependency-exception scope failed: unexpected active paste package set' >&2
  printf '%s\n' 'expected:' 'paste v1.0.15' 'actual:' "$active_paste_packages" >&2
  exit 1
fi

if printf '%s\n' "$active_packages" | awk '
  $1 == "hickory-proto" || $1 == "hickory-resolver" { found = 1 }
  END { exit !found }
'; then
  printf '%s\n' 'dependency-exception scope failed: ignored Hickory package is active in the workspace graph' >&2
  exit 1
fi

fuzz_tree=$(
  "$cargo_command" tree \
    --locked \
    --manifest-path "$repository_root/fuzz/Cargo.toml" \
    --all-features \
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

if printf '%s\n' "$fuzz_packages" | awk '$1 == "paste" { found = 1 } END { exit !found }'; then
  printf '%s\n' 'dependency-exception scope failed: ignored paste is present in the fuzz graph' >&2
  exit 1
fi

if printf '%s\n' "$fuzz_packages" | awk '
  $1 == "hickory-proto" || $1 == "hickory-resolver" { found = 1 }
  END { exit !found }
'; then
  printf '%s\n' 'dependency-exception scope failed: ignored Hickory package is present in the fuzz graph' >&2
  exit 1
fi

printf '%s\n' 'dependency-exception scope passed: RUSTSEC-2026-0173 is isolated to aster-provisioning-age; RUSTSEC-2024-0436 is isolated to the exact libp2p-provider pilot path; RUSTSEC-2026-0118 and RUSTSEC-2026-0119 are exact lock-only inactive Hickory entries; all four are absent from fuzz'
