# Official Go age interoperability oracle

This test-only helper uses the official Go `filippo.io/age` implementation at
exact version `v1.3.1` as an implementation-independent oracle for the
experimental Rust X25519 provisioning provider. `check.sh` verifies:

- the Go module resolves to exactly `filippo.io/age@v1.3.1`;
- no resolved Go module uses a `replace` directive;
- the canonical non-CGO Linux/amd64 compiled module set and reviewed BSD-3-Clause
  license-file hashes match `dependency-licenses.tsv`;
- Go and Rust derive the same public recipient from one X25519 identity;
- Rust-produced age ciphertext decrypts to byte-identical plaintext in Go; and
- Go-produced age ciphertext decrypts to byte-identical plaintext in Rust.

The binary fixture is exactly Aster's 125,877-byte unprotected provisioning
ceiling and crosses age's 64 KiB streaming-chunk boundary. The wrapper rejects
larger plaintext, artifacts over one MiB, empty input, malformed key text, and
failed authentication without retaining partial output. It creates new files
only and never overwrites an existing path.

Run it with:

```sh
GOBIN=/tmp/aster-go-tools go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
GOVULNCHECK=/tmp/aster-go-tools/govulncheck mise run age-reference-audit
mise run age-reference-interop
```

The first task verifies the scanner binary was built from exact
`golang.org/x/vuln@v1.6.0` and then runs source-mode govulncheck, including test
code for canonical non-CGO Linux/amd64. A configured `GO` executable is placed
first on the scanner's subprocess path. Reachable vulnerabilities fail.
Imported-but-unreachable findings remain visible as upstream informational
output and are non-blocking; this repository maintains no Go vulnerability
suppression list. Because the scanner consults the live Go vulnerability
database, that result is time-sensitive.

This harness is not a provisioning CLI, key-custody system, production runtime,
post-quantum claim, FIPS claim, or independent security review. It exercises
the classic age X25519 recipient profile only. The helper's first-party source
is Apache-2.0; the separately admitted Go dependency remains under its upstream
BSD-3-Clause license.

Primary sources consulted:

- [age v1.3.1 release](https://github.com/FiloSottile/age/releases/tag/v1.3.1)
- [official Go age package](https://pkg.go.dev/filippo.io/age@v1.3.1)
- [age v1 format specification](https://age-encryption.org/v1)
- [upstream license](https://github.com/FiloSottile/age/blob/v1.3.1/LICENSE)
- [govulncheck v1.6.0](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck@v1.6.0)
- [Go vulnerability database](https://go.dev/doc/security/vuln/database)
