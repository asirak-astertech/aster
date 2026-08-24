#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
source_root="$repository_root/third-party/netlink-packet-core-0.8.2-aster"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/aster-netlink-patch.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM

cp -R "$source_root/." "$test_root/"

# The published crate's sole dev dependency exercises examples rather than the
# library unit tests and resolves a historical netlink graph. Remove it only in
# the disposable test copy so the 13 upstream library tests exercise the exact
# production-patched library without introducing an unrelated old `paste`.
awk '
  $0 == "[dev-dependencies.netlink-packet-route]" { skipping = 1; next }
  skipping && $0 == "" { skipping = 0; print; next }
  !skipping { print }
' "$source_root/Cargo.toml" > "$test_root/Cargo.toml"

CARGO_TARGET_DIR="$test_root/target" \
  cargo test --offline --manifest-path "$test_root/Cargo.toml" --lib
