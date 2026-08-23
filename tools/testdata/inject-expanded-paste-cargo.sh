#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

previous_argument=
for argument do
  if { [ "$previous_argument" = "--invert" ] || [ "$previous_argument" = "-i" ]; } &&
    [ "$argument" = "paste@1.0.15" ]; then
    "${ASTER_TEST_REAL_CARGO:?}" "$@"
    printf '%s\n' 'unexpected-paste-consumer v9.9.9'
    exit 0
  fi
  previous_argument=$argument
done

exec "${ASTER_TEST_REAL_CARGO:?}" "$@"
