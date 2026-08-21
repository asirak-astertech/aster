#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
oracle_root="$repository_root/tools/age-reference"
go_command=${GO:-go}
govulncheck_command=${GOVULNCHECK:-govulncheck}
GOCACHE=${GOCACHE:-"${TMPDIR:-/tmp}/aster-age-reference-go-cache"}
CGO_ENABLED=0
GOARCH=amd64
GOOS=linux
go_path=$(command -v "$go_command")
go_bin=$(dirname "$go_path")
PATH="$go_bin:$PATH"
export CGO_ENABLED GOCACHE GOARCH GOOS PATH

govulncheck_path=$(command -v "$govulncheck_command")
tool_metadata=$("$go_path" version -m "$govulncheck_path")
tool_module=$(
  printf '%s\n' "$tool_metadata" |
    awk '$1 == "mod" && $2 == "golang.org/x/vuln" { print $2 "@" $3 }'
)
if [ "$tool_module" != "golang.org/x/vuln@v1.6.0" ]; then
  printf 'unexpected govulncheck module: %s\n' "${tool_module:-not reported}" >&2
  exit 1
fi

# Source-mode govulncheck fails for vulnerabilities reachable from this oracle.
# Imported-but-unreachable findings remain visible as upstream informational
# output and are non-blocking; Aster maintains no local suppression list.
(
  cd "$oracle_root"
  GOWORK=off "$govulncheck_path" -test -show verbose ./...
)
