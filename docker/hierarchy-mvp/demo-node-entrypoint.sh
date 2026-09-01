#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu

: "${ASTER_STATE_DIR:=/state}"
: "${ASTER_DISCOVER_LAN:=1}"
: "${ASTER_NEARBY_WINDOW:=3}"
: "${ASTER_SYNC_MS:=500}"

mode=${1:-}
case "$mode" in
    init)
        shift
        exec /usr/local/bin/aster-hierarchy-demo-node init "$@"
        ;;
    run)
        shift
        : "${ASTER_HIERARCHY_ROLE:?ASTER_HIERARCHY_ROLE is required}"
        case "$ASTER_HIERARCHY_ROLE" in
            publisher|bridge-alpha|bridge-bravo|consumer|outsider) ;;
            *)
                echo "aster-hierarchy-mvp: unknown hierarchy role" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        echo "aster-hierarchy-mvp: expected init or run mode" >&2
        exit 2
        ;;
esac

case "$ASTER_DISCOVER_LAN" in
    0|1) ;;
    *)
        echo "aster-hierarchy-mvp: ASTER_DISCOVER_LAN must be 0 or 1" >&2
        exit 2
        ;;
esac

set -- \
    /usr/local/bin/aster-hierarchy-demo-node \
    run \
    --role "$ASTER_HIERARCHY_ROLE" \
    --state "$ASTER_STATE_DIR" \
    --bind 0.0.0.0:4433 \
    --sync-ms "$ASTER_SYNC_MS"

if [ "$ASTER_DISCOVER_LAN" = 1 ]; then
    : "${ASTER_NEARBY_IPV4_INTERFACES:?ASTER_NEARBY_IPV4_INTERFACES is required when discovery is enabled}"
    set -- \
        "$@" \
        --discover-lan \
        --nearby-window "$ASTER_NEARBY_WINDOW" \
        --discovery-ipv4-interfaces "$ASTER_NEARBY_IPV4_INTERFACES"
fi

exec "$@"
