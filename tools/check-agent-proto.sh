#!/bin/sh
set -eu

ASTER_BUF_CACHE_DIR="${BUF_CACHE_DIR:-${TMPDIR:-/tmp}/aster-buf-cache}"
mkdir -p "$ASTER_BUF_CACHE_DIR"
export BUF_CACHE_DIR="$ASTER_BUF_CACHE_DIR"

descriptor="$(mktemp "${TMPDIR:-/tmp}/aster-agent-descriptor.XXXXXX")"
trap 'rm -f "$descriptor"' EXIT

buf format -d --exit-code
buf lint
buf build --as-file-descriptor-set -o "$descriptor" .
cmp "$descriptor" proto/aster/application/v1alpha1/aster.fds.bin
