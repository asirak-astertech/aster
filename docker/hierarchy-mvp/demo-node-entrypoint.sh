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
    init-scale)
        shift
        if [ "$#" -ne 4 ] || [ "$1" != "--root" ] || [ "$2" != "/provision" ] || [ "$3" != "--publishers-per-leaf" ]; then
            echo "aster-hierarchy-mvp: init-scale requires --root /provision --publishers-per-leaf N" >&2
            exit 2
        fi
        case "$4" in
            1|2|3|4|5|6|7|8) publishers_per_leaf=$4 ;;
            *)
                echo "aster-hierarchy-mvp: publishers-per-leaf must be within 1..=8" >&2
                exit 2
                ;;
        esac

        # The initializer intentionally has CAP_CHOWN but no DAC-bypass
        # capability. A fresh named volume mounted on a legacy 0700 image
        # directory retains that ownership. Change the mount root first so the
        # recursive pass can traverse it, then return the exact generated scale
        # mounts to the runtime UID below.
        expected_publishers=$((8 * publishers_per_leaf))
        publisher_index=0
        while [ "$publisher_index" -lt "$expected_publishers" ]; do
            child="/provision/$(printf 'p%03d' "$publisher_index")"
            if [ ! -d "$child" ]; then
                echo "aster-hierarchy-mvp: scale publisher mount is missing" >&2
                exit 2
            fi
            chown 0:0 "$child"
            chmod 0700 "$child"
            chown -R 0:0 "$child"
            publisher_index=$((publisher_index + 1))
        done
        for role in l00 l01 l02 l03 l04 l05 l06 l07 r00 r01 root-consumer outsider; do
            child="/provision/$role"
            if [ ! -d "$child" ]; then
                echo "aster-hierarchy-mvp: scale role mount is missing" >&2
                exit 2
            fi
            chown 0:0 "$child"
            chmod 0700 "$child"
            chown -R 0:0 "$child"
        done
        /usr/local/bin/aster-hierarchy-demo-node init-scale "$@"

        actual_nodes=0
        actual_publishers=0
        actual_leaves=0
        actual_regions=0
        actual_root=0
        actual_outsider=0
        for child in /provision/*; do
            if [ ! -d "$child" ] || [ -L "$child" ]; then
                echo "aster-hierarchy-mvp: unexpected scale provisioning entry" >&2
                exit 2
            fi
            role=${child##*/}
            case "$role" in
                publisher|bridge-alpha|bridge-bravo|consumer)
                    legacy_empty=1
                    for legacy_entry in "$child"/* "$child"/.[!.]* "$child"/..?*; do
                        if [ -e "$legacy_entry" ] || [ -L "$legacy_entry" ]; then
                            legacy_empty=0
                            break
                        fi
                    done
                    if [ "$legacy_empty" -ne 1 ]; then
                        echo "aster-hierarchy-mvp: legacy provisioning directory is not empty" >&2
                        exit 2
                    fi
                    continue
                    ;;
            esac
            actual_nodes=$((actual_nodes + 1))
            case "$role" in
                l00|l01|l02|l03|l04|l05|l06|l07)
                    actual_leaves=$((actual_leaves + 1))
                    ;;
                r00|r01)
                    actual_regions=$((actual_regions + 1))
                    ;;
                root-consumer)
                    actual_root=$((actual_root + 1))
                    ;;
                outsider)
                    actual_outsider=$((actual_outsider + 1))
                    ;;
                p0[0-5][0-9]|p06[0-3])
                    expected_role=0
                    publisher_index=0
                    while [ "$publisher_index" -lt "$expected_publishers" ]; do
                        if [ "$role" = "$(printf 'p%03d' "$publisher_index")" ]; then
                            expected_role=1
                            break
                        fi
                        publisher_index=$((publisher_index + 1))
                    done
                    if [ "$expected_role" -ne 1 ]; then
                        echo "aster-hierarchy-mvp: scale publisher is outside the requested bound" >&2
                        exit 2
                    fi
                    actual_publishers=$((actual_publishers + 1))
                    ;;
                *)
                    echo "aster-hierarchy-mvp: unexpected scale provisioning role" >&2
                    exit 2
                ;;
            esac
        done
        for hidden_child in /provision/.[!.]* /provision/..?*; do
            if [ -e "$hidden_child" ] || [ -L "$hidden_child" ]; then
                echo "aster-hierarchy-mvp: unexpected hidden scale provisioning entry" >&2
                exit 2
            fi
        done
        expected_nodes=$((expected_publishers + 12))
        if [ "$actual_nodes" -ne "$expected_nodes" ] || \
            [ "$actual_publishers" -ne "$expected_publishers" ] || \
            [ "$actual_leaves" -ne 8 ] || \
            [ "$actual_regions" -ne 2 ] || \
            [ "$actual_root" -ne 1 ] || \
            [ "$actual_outsider" -ne 1 ]; then
            echo "aster-hierarchy-mvp: scale provisioning role count mismatch" >&2
            exit 2
        fi
        publisher_index=0
        while [ "$publisher_index" -lt "$expected_publishers" ]; do
            chown -R 10001:10001 "/provision/$(printf 'p%03d' "$publisher_index")"
            publisher_index=$((publisher_index + 1))
        done
        for role in l00 l01 l02 l03 l04 l05 l06 l07 r00 r01 root-consumer outsider; do
            chown -R 10001:10001 "/provision/$role"
        done
        exit 0
        ;;
    run)
        shift
        : "${ASTER_HIERARCHY_ROLE:?ASTER_HIERARCHY_ROLE is required}"
        case "$ASTER_HIERARCHY_ROLE" in
            publisher|bridge-alpha|bridge-bravo|consumer|outsider|p0[0-5][0-9]|p06[0-3]|l0[0-7]|r0[0-1]|root-consumer) ;;
            *)
                echo "aster-hierarchy-mvp: unknown hierarchy role" >&2
                exit 2
                ;;
        esac
        ;;
    *)
        echo "aster-hierarchy-mvp: expected init, init-scale, or run mode" >&2
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
