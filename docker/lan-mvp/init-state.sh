#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077

for state_dir in /nodes/a /nodes/b /nodes/c /nodes/d; do
    if [ -n "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
        echo "aster-lan-mvp-init: state volume is not empty: $state_dir" >&2
        exit 2
    fi
done

/usr/local/bin/aster playground-init --nodes 3 --root /seed/mission
/usr/local/bin/aster playground-init --nodes 2 --root /seed/outsider

cp -a /seed/mission/node-0/. /nodes/a/
cp -a /seed/mission/node-1/. /nodes/b/
cp -a /seed/mission/node-2/. /nodes/c/
cp -a /seed/outsider/node-0/. /nodes/d/

for state_dir in /nodes/a /nodes/b /nodes/c /nodes/d; do
    python3 /usr/local/libexec/aster/aster_lan_mvp.py token \
        --file "$state_dir/client.token"
    chmod 0700 "$state_dir"
    chown -R 10001:10001 "$state_dir"
done

sync
printf '%s\n' 'INIT status=pass nodes=4 authorities=2 state=owner-only'
