#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

invert_target=
previous_argument=
for argument do
  if [ "$previous_argument" = "--invert" ] || [ "$previous_argument" = "-i" ]; then
    invert_target=$argument
  fi
  previous_argument=$argument
done

if [ "$invert_target" = "basic-toml@0.1.10" ]; then
  "${ASTER_TEST_REAL_CARGO:?}" "$@"
  printf '%s\n' 'unexpected-basic-toml-consumer v9.9.9'
  exit 0
fi

exec "${ASTER_TEST_REAL_CARGO:?}" "$@"
