# Decision 0013: Separate provisioning artifact protection from mesh semantics

- Status: accepted boundary; operational provider pending
- Date: 2026-08-20

## Context

The canonical `ASTRPB03` bundle contains a node identity seed, routing grants,
content grants, and sometimes the mission control-route key. Its checksum
detects accidental damage; it provides no confidentiality, authenticity, or
at-rest key custody. Passing those bytes directly to a node is useful for public
fixtures and controlled migration, but it is not an operational provisioning
workflow.

Artifact protection is generic security infrastructure rather than a mission
mesh differentiator. Implementing a new encrypted-file construction in the
core would add custom cryptographic risk and couple local custody to the mesh
wire profile. Conversely, choosing a library before defining the boundary would
let one package's API determine Aster's application and host contracts.

Protecting the provisioning artifact before node open and protecting long-lived
keys after ingestion are different problems. An encrypted file does not become
a platform keystore merely because both hold secret bytes.

## Decision

`ASTRPB03` remains the canonical **unprotected inner representation**. It is a
local reference format, never a mesh message or cross-implementation custody
protocol. Its exact maximum is 125,877 bytes under the v3 key, signature, grant,
and name bounds; the parser rejects larger input before checksum work. One
provider-owned protected artifact is capped at one MiB.

Separate public traits own the outer artifact operations so an issuing authority
does not need node/private-key capability and a node does not need authority
recipient-encryption capability:

- `ProvisioningProtector::protect` receives a non-cloneable, redacted,
  zeroizing plaintext container;
- `ProvisioningUnprotector::unprotect` authenticates before returning the same
  bounded container;
- providers receive the plaintext limit and must enforce it while reading;
- the core independently bounds both the protected artifact and recovered
  plaintext;
- errors preserve fixed typed categories with no paths, recipients, key
  identifiers, or provider strings;
- each top-level protect/open operation completes its local, size, and magic
  prechecks before provider invocation; a precheck failure makes zero provider
  calls, and passing all prechecks makes exactly one protector or unprotector
  attempt; and
- provider failure never falls back to parsing the protected bytes as
  `ASTRPB03`.

`ApplicationNode::open_protected` and `MeshService::open_protected` validate
local options and outer bounds before opening durable state. Aster does not
retry or select a fallback provider internally; a caller may explicitly begin
a new top-level operation. `ProvisioningBundle` exposes provider-backed
import/export to adapter and provisioning tooling. The outer format is
deliberately absent from the protocol specification.

The existing raw-byte open methods remain temporarily for checked-in fixtures,
language bindings, and migration. Their documentation now identifies them as
unprotected compatibility paths. They will not be described as an operational
default, and this decision does not deprecate them until the bindings and lab
have a protected replacement.

A persistent `SecretStore` is a separate future boundary: opaque handle-based
seal/load/destroy, platform or hardware custody, recovery policy, backup policy,
and rollback behavior. The current host retains a zeroizing in-process copy of
the canonical bundle for backend restarts. Artifact protection does not change
that fact.

## Provider admission

Provider selection uses total assurance cost: code and cryptographic
construction deleted, adoption and maintenance, public vulnerability handling,
independent review, interoperability, dependency surface, target support,
operational recovery, and fit with offline deployment. A missing formal
security-policy file is an assurance cost, not by itself an automatic veto;
wide adoption is evidence, not by itself automatic approval.

The next isolated pilot will evaluate an exact-pinned, age-compatible artifact
provider against this boundary. It must use a published format and upstream
implementation rather than recreate file encryption. Platform keyring and
hardware-backed stores remain separate pilots behind the future secret-store
boundary.

## Consequences and open gates

- No new dependency or graph component, wire byte, credential, NodeID,
  cryptographic suite, database schema, or `ASTRPB03` byte changes in this
  boundary batch. Host secret ownership moves into the core wrapper, removing
  the host's redundant direct `zeroize` dependency declaration.
- Mock-provider tests establish capability separation, bounded invocation,
  echo-provider rejection, bounds, redaction, zeroization, checksum
  revalidation, and fail-closed behavior. They do not establish encryption at
  rest.
- No operational provider is shipped yet. C, Go, and Python still accept the
  raw fixture/compatibility path and must not claim protected provisioning.
- Full process or root compromise, unlocked-memory inspection, swap, DMA,
  backups, crash dumps, and physical flash erasure remain outside this
  boundary unless a selected platform and deployment explicitly address them.
- Operational artifact protection, persistent key custody, recovery, and
  independently reviewed provider integration remain production gates.

## Public sources considered

Accessed 2026-08-20:

- [age format specification](https://age-encryption.org/v1)
- [reference age implementation](https://github.com/FiloSottile/age)
- [keyring-rs platform credential-store interface](https://github.com/open-source-cooperative/keyring-rs)
- [rust-tss-esapi TPM interface](https://github.com/parallaxsecond/rust-tss-esapi)
- [`zeroize` crate](https://github.com/RustCrypto/utils/tree/master/zeroize)

These public inputs inform replaceable boundaries only. No candidate is admitted
by this decision.
