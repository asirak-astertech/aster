#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu

: "${ASTER_STATE_DIR:=/state}"
: "${ASTER_DISCOVER_LAN:=1}"
: "${ASTER_NEARBY_WINDOW:=3}"
: "${ASTER_SYNC_MS:=500}"

case "$ASTER_DISCOVER_LAN" in
    0|1) ;;
    *)
        echo "aster-lan-mvp-agent: ASTER_DISCOVER_LAN must be 0 or 1" >&2
        exit 2
        ;;
esac

set -- \
    /usr/local/bin/aster-agent \
    --state "$ASTER_STATE_DIR" \
    --mesh-bind 0.0.0.0:4433 \
    --listen 127.0.0.1:8181 \
    --mission-bundle-unprotected-reference \
        "$ASTER_STATE_DIR/mission.unprotected-reference.bundle" \
    --client-token-file "$ASTER_STATE_DIR/client.token" \
    --sync-ms "$ASTER_SYNC_MS"

if [ "$ASTER_DISCOVER_LAN" = 1 ]; then
    set -- "$@" --discover-lan --nearby-window "$ASTER_NEARBY_WINDOW"
fi

exec "$@"
