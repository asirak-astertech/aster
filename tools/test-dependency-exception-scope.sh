#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
checker="$repository_root/tools/check-dependency-exception-scope.sh"
failing_cargo="$repository_root/tools/testdata/fail-fuzz-cargo.sh"
active_hickory_cargo="$repository_root/tools/testdata/inject-active-hickory-cargo.sh"
expanded_paste_cargo="$repository_root/tools/testdata/inject-expanded-paste-cargo.sh"
second_paste_version_cargo="$repository_root/tools/testdata/inject-second-paste-version-cargo.sh"
real_cargo=$(command -v "${CARGO:-cargo}")

if ASTER_TEST_REAL_CARGO="$real_cargo" CARGO="$failing_cargo" \
  sh "$checker" >/dev/null 2>&1; then
  printf '%s\n' 'dependency-exception regression failed: fuzz cargo-tree failure passed' >&2
  exit 1
else
  status=$?
fi

if [ "$status" -ne 97 ]; then
  printf 'dependency-exception regression failed: expected status 97, got %s\n' "$status" >&2
  exit 1
fi

if ASTER_TEST_REAL_CARGO="$real_cargo" CARGO="$active_hickory_cargo" \
  sh "$checker" >/dev/null 2>&1; then
  printf '%s\n' 'dependency-exception regression failed: active Hickory graph passed' >&2
  exit 1
else
  status=$?
fi

if [ "$status" -ne 1 ]; then
  printf 'dependency-exception regression failed: expected active-Hickory status 1, got %s\n' "$status" >&2
  exit 1
fi

if ASTER_TEST_REAL_CARGO="$real_cargo" CARGO="$expanded_paste_cargo" \
  sh "$checker" >/dev/null 2>&1; then
  printf '%s\n' 'dependency-exception regression failed: expanded paste graph passed' >&2
  exit 1
else
  status=$?
fi

if [ "$status" -ne 1 ]; then
  printf 'dependency-exception regression failed: expected expanded-paste status 1, got %s\n' "$status" >&2
  exit 1
fi

if ASTER_TEST_REAL_CARGO="$real_cargo" CARGO="$second_paste_version_cargo" \
  sh "$checker" >/dev/null 2>&1; then
  printf '%s\n' 'dependency-exception regression failed: second active paste version passed' >&2
  exit 1
else
  status=$?
fi

if [ "$status" -ne 1 ]; then
  printf 'dependency-exception regression failed: expected second-paste-version status 1, got %s\n' "$status" >&2
  exit 1
fi

printf '%s\n' 'dependency-exception regression passed: fuzz cargo-tree failure propagates; active Hickory, expanded paste graph, and second paste version fail closed'
