#!/bin/sh

set -eu

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
scenario="$script_dir/testdata/aster-hello-real.commands"

if [ ! -r "$scenario" ]; then
  echo "hello smoke scenario is not readable: $scenario" >&2
  exit 2
fi

# Invitation is the reliable, zero-idle route for the real-process smoke. The
# nearby route remains an explicit local-network evaluation with no fallback.
exec sh "$script_dir/aster-hello.sh" \
  --network invitation \
  --view raw \
  --script "$scenario"
