#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    echo "macOS compatibility lane requires macOS" >&2
    exit 2
fi

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

run_cargo_test() {
    sh tools/with-test-resources.sh cargo +1.97.1 test --locked --offline --all-features "$@"
}

sh tools/with-test-resources.sh \
    cargo +1.97.1 test --locked --offline --workspace --all-features --no-run

run_cargo_test -p aster-node --lib platform_compat_
run_cargo_test -p aster-agent platform_compat_
run_cargo_test -p asterctl platform_compat_
run_cargo_test -p aster-compose-credentials platform_compat_
run_cargo_test -p aster-systemd-credentials platform_compat_
