# Decision 0002: Dependency admission and rejections

- Status: accepted with recorded gates
- Date: 2026-08-18

## Adopted

- RustCrypto `aes-gcm`, `hkdf`, `sha2`, `p256`, `ml-kem`, `ml-dsa`, and
  `zeroize`, exactly pinned, for the non-validated conformance provider.
- `getrandom`, exactly pinned with only its OS `sys_rng` feature, to bridge the
  operating system random source into the private provider.
- `rusqlite`, exactly pinned with only bundled SQLite, behind `RecordStore`.
  The Rust wrapper is MIT. SQLite 3.53.2 is public-domain software rather than
  code under an OSI-approved license; because the binding requirement literally
  says dependencies use OSI-approved licenses only, legal/release review must
  confirm that license-free public-domain software satisfies that policy. It is
  not treated as a silently approved exception.

The IP adapter directly reuses the already admitted `getrandom`, `hkdf`, and
`sha2` packages for unlinkable authenticated local-discovery proofs. All other
adapter and binding code uses the standard library and `aster-core`; this adds
no component or version beyond the admitted workspace graph.

## Evaluated but not adopted

- `redb` 4.2.0 was considered as a pure-Rust ACID store. It was not adopted
  because the reference's multi-index transactional/query workload mapped more
  directly to SQLite; replacing SQLite remains possible behind `RecordStore`.
- Tokio 1.51.4 LTS was considered for adapter scheduling. The MVP adapters use
  nonblocking standard-library I/O and require no runtime dependency.
- `bluer` 0.17.4 was considered for a Linux-specific BTLE implementation. The
  shipped adapter is platform-neutral; a concrete driver remains a hardware
  integration gate and `bluer` is not in the lockfile.
- `minicbor` 2.3.0 was considered. BlueOak-1.0.0 is OSI-approved, but the narrow
  deterministic decoder needed strict non-minimal, ordering, duplicate, depth,
  and critical-extension behavior. The protocol-owned bounded subset is used
  and tested byte-for-byte instead.

## Rejected

Iroh 1.0.3 was evaluated because it is explicitly permitted as a public example
in the requirements. It is not admitted: the audited public project page did not
provide the required vulnerability-reporting policy, and its default presets use
hosted discovery/relay services. Reconsideration requires security-process
evidence and a locally controlled configuration.

No dependency owns data semantics, causality, key hierarchy, or synchronization
correctness. All versions and transitive sources are locked and audited.
