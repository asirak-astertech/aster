#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077

: "${ASTER_SCALE_NODES:=8}"
: "${ASTER_SCALE_OUTSIDERS:=1}"

case "$ASTER_SCALE_NODES" in
    ''|*[!0-9]*)
        echo "aster-lan-scale-init: ASTER_SCALE_NODES must be an integer" >&2
        exit 2
        ;;
esac
case "$ASTER_SCALE_OUTSIDERS" in
    ''|*[!0-9]*)
        echo "aster-lan-scale-init: ASTER_SCALE_OUTSIDERS must be an integer" >&2
        exit 2
        ;;
esac
if [ "$ASTER_SCALE_NODES" -lt 2 ] || [ "$ASTER_SCALE_NODES" -gt 32 ]; then
    echo "aster-lan-scale-init: ASTER_SCALE_NODES must be between 2 and 32" >&2
    exit 2
fi
if [ "$ASTER_SCALE_OUTSIDERS" -lt 1 ] || [ "$ASTER_SCALE_OUTSIDERS" -gt 4 ]; then
    echo "aster-lan-scale-init: ASTER_SCALE_OUTSIDERS must be between 1 and 4" >&2
    exit 2
fi

index=0
while [ "$index" -lt "$ASTER_SCALE_NODES" ]; do
    service="$(printf 'n%03d' "$index")"
    state_dir="/nodes/$service"
    if [ ! -d "$state_dir" ]; then
        echo "aster-lan-scale-init: missing state volume: $state_dir" >&2
        exit 2
    fi
    if [ -n "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "aster-lan-scale-init: state volume is not empty: $state_dir" >&2
        exit 2
    fi
    index=$((index + 1))
done

index=0
while [ "$index" -lt "$ASTER_SCALE_OUTSIDERS" ]; do
    service="$(printf 'o%03d' "$index")"
    state_dir="/nodes/$service"
    if [ ! -d "$state_dir" ]; then
        echo "aster-lan-scale-init: missing state volume: $state_dir" >&2
        exit 2
    fi
    if [ -n "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "aster-lan-scale-init: state volume is not empty: $state_dir" >&2
        exit 2
    fi
    index=$((index + 1))
done

/usr/local/bin/aster playground-init \
    --nodes "$ASTER_SCALE_NODES" \
    --root /seed/mission

outsider_seed_nodes="$ASTER_SCALE_OUTSIDERS"
if [ "$outsider_seed_nodes" -lt 2 ]; then
    outsider_seed_nodes=2
fi
/usr/local/bin/aster playground-init \
    --nodes "$outsider_seed_nodes" \
    --root /seed/outsider

index=0
while [ "$index" -lt "$ASTER_SCALE_NODES" ]; do
    service="$(printf 'n%03d' "$index")"
    state_dir="/nodes/$service"
    cp -a "/seed/mission/node-$index/." "$state_dir/"
    python3 /usr/local/libexec/aster/aster_lan_mvp.py token \
        --file "$state_dir/client.token"
    chmod 0700 "$state_dir"
    chown -R 10001:10001 "$state_dir"
    index=$((index + 1))
done

index=0
while [ "$index" -lt "$ASTER_SCALE_OUTSIDERS" ]; do
    service="$(printf 'o%03d' "$index")"
    state_dir="/nodes/$service"
    cp -a "/seed/outsider/node-$index/." "$state_dir/"
    python3 /usr/local/libexec/aster/aster_lan_mvp.py token \
        --file "$state_dir/client.token"
    chmod 0700 "$state_dir"
    chown -R 10001:10001 "$state_dir"
    index=$((index + 1))
done

sync
printf '%s\n' \
    "INIT status=pass authorized=$ASTER_SCALE_NODES outsiders=$ASTER_SCALE_OUTSIDERS authorities=2 state=owner-only"
