#!/bin/sh
# Copyright 2026 Defense Unicorns, Inc.
# SPDX-License-Identifier: Apache-2.0

set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
oracle_root="$repository_root/tools/age-reference"
temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/aster-age-reference.XXXXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM

go_command=${GO:-go}
cargo_command=${CARGO:-cargo}
python_command=${PYTHON:-python3}
GOCACHE=${GOCACHE:-"${TMPDIR:-/tmp}/aster-age-reference-go-cache"}
CGO_ENABLED=0
export CGO_ENABLED GOCACHE
oracle="$temporary_root/age-reference"
identity="$temporary_root/identity.txt"
go_recipient="$temporary_root/go-recipient.txt"
rust_recipient="$temporary_root/rust-recipient.txt"
plaintext="$temporary_root/plaintext.bin"
rust_ciphertext="$temporary_root/rust-to-go.age"
go_recovered="$temporary_root/go-recovered.bin"
go_ciphertext="$temporary_root/go-to-rust.age"
rust_recovered="$temporary_root/rust-recovered.bin"

GOWORK=off "$go_command" -C "$oracle_root" mod verify
"$python_command" -m unittest discover -s "$oracle_root" -p 'test_*.py'
"$python_command" "$oracle_root/check_licenses.py"
reference_module=$(GOWORK=off "$go_command" -C "$oracle_root" list -mod=readonly -m -f '{{.Path}}@{{.Version}}' filippo.io/age)
if [ "$reference_module" != "filippo.io/age@v1.3.1" ]; then
  printf 'unexpected Go age reference module: %s\n' "$reference_module" >&2
  exit 1
fi
go_root=$(GOWORK=off "$go_command" env GOROOT)
unformatted=$("$go_root/bin/gofmt" -l "$oracle_root/main.go" "$oracle_root/main_test.go")
if [ -n "$unformatted" ]; then
  printf 'Go age reference files require formatting:\n%s\n' "$unformatted" >&2
  exit 1
fi
GOWORK=off "$go_command" -C "$oracle_root" vet -mod=readonly ./...
GOWORK=off "$go_command" -C "$oracle_root" test -mod=readonly ./...
GOWORK=off "$go_command" -C "$oracle_root" build -mod=readonly -trimpath -o "$oracle" .

"$oracle" generate "$identity" "$go_recipient"
"$oracle" fixture "$plaintext"

"$cargo_command" run --quiet --locked --manifest-path "$repository_root/Cargo.toml" \
  -p aster-provisioning-age --example reference_interop -- \
  public-key "$identity" >"$rust_recipient"
cmp -s "$go_recipient" "$rust_recipient"

recipient=$(tr -d '\r\n' <"$go_recipient")
"$cargo_command" run --quiet --locked --manifest-path "$repository_root/Cargo.toml" \
  -p aster-provisioning-age --example reference_interop -- \
  encrypt "$recipient" "$plaintext" "$rust_ciphertext"
"$oracle" decrypt "$identity" "$rust_ciphertext" "$go_recovered"
cmp -s "$plaintext" "$go_recovered"

"$oracle" encrypt "$go_recipient" "$plaintext" "$go_ciphertext"
"$cargo_command" run --quiet --locked --manifest-path "$repository_root/Cargo.toml" \
  -p aster-provisioning-age --example reference_interop -- \
  decrypt "$identity" "$go_ciphertext" "$rust_recovered"
cmp -s "$plaintext" "$rust_recovered"

plaintext_size=$(wc -c <"$plaintext")
plaintext_size=$(printf '%s\n' "$plaintext_size" | tr -d ' ')
printf 'age X25519 interoperability passed: Rust->Go, Go->Rust, %s-byte binary plaintext\n' "$plaintext_size"
