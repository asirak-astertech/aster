# Decision 0013: Separate provisioning artifact protection from mesh semantics

- Status: accepted boundary; live/stopped Rust composition present; operational backend/workflow pending
- Date: 2026-08-20
- Updated: 2026-08-25

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

The selected-production Rust surfaces now compose the same boundary.
`NodeConfig`, stopped `SelectedEventNode`, and stopped `SelectedControlAdmin`
can open a protected file or byte slice through a caller-owned
`ProvisioningUnprotector`, or load a provider-owned opaque reference through a
caller-owned `ProvisioningSecretLoader`. Live construction first validates one
private bounded `NodeConfigOptions` value and terminal state, then invokes the
provider or loader once without creating state. Errors are sanitized and
provider rejection cannot fall back to plaintext parsing. The stock CLI and
C/Go/Python bindings do not use these opens.

The existing raw-byte open methods remain temporarily for checked-in fixtures,
language bindings, and migration. Their documentation now identifies them as
unprotected compatibility paths. They will not be described as an operational
default, and this decision does not deprecate them until the bindings and lab
have a protected replacement.

A persistent `SecretStore` remains a separate capability, but its
provider-neutral API is now defined. A versioned bounded
`ProvisioningSecretRef` holds a redacted opaque backend locator or bearer
capability. Separate caller-chosen install, load, and destroy operation IDs bind
idempotent retry. The checked install helper validates the exact operation;
load and destroy validate both the exact operation and caller-supplied
reference. Install/load transfer an owned zeroizing
plaintext value at the in-process capability boundary. A destroy receipt
records only the trusted backend's logical tombstone assertion; `NotFound` is
indeterminate and no provider-independent physical-erasure claim is made.

No production SecretStore backend, platform or hardware custody policy,
unattended-start decision, recovery/backup/rollback procedure, operation-ledger
retirement rule, or coordinated live-drain-plus-destroy workflow is selected.
The current host and selected live/stopped surfaces retain a zeroizing
in-process copy of the canonical bundle while operating. Artifact protection
and opaque references do not change that fact. Protected and secret-reference
live nodes can shut down gracefully, but the selected local software-erasure
path has no provider destroyer and cannot destroy provider custody.

## Provider admission

Provider selection uses total assurance cost: code and cryptographic
construction deleted, adoption and maintenance, public vulnerability handling,
independent review, interoperability, dependency surface, target support,
operational recovery, and fit with offline deployment. A missing formal
security-policy file is an assurance cost, not by itself an automatic veto;
wide adoption is evidence, not by itself automatic approval.

An isolated exact-pinned age-compatible artifact pilot now evaluates the
protection boundary using a published format and upstream implementation rather
than recreating file encryption. It is not an operational default or a
SecretStore backend. Platform keyring and hardware-backed stores remain
separate future pilots behind the persistent-custody boundary. Exact age pilot
admission limits are recorded in
[Decision 0018](0018-age-provisioning-provider.md).

## Consequences and open gates

- The boundary changes no mesh wire byte, credential, NodeID, cryptographic
  suite, or `ASTRPB03` byte. Host secret ownership moved into the core wrapper;
  later selected composition adds only local provider capabilities, typed
  operation receipts, and stopped entry points.
- Mock-provider tests establish capability separation, bounded invocation,
  echo-provider rejection, bounds, redaction, zeroization, checksum
  revalidation, and fail-closed behavior. They do not establish encryption at
  rest.
- The in-memory SecretStore fixture establishes operation binding, canonical
  opaque references, zeroizing ownership, tombstone semantics, and checked
  receipt rejection only. It does not establish backend authentication,
  durability, at-rest secrecy, hardware custody, recovery, or erasure.
- The age pilot is shipped but is not an operational provider. No production
  SecretStore backend is shipped. Caller-provided Rust live startup is
  protected-capable; the stock selected CLI and C, Go, and Python still accept
  the raw fixture/compatibility path and must not claim protected operational
  provisioning.
- Relative state and protected-artifact paths for the live config and stopped
  selected opens are lexically bound to one captured current directory before
  provider or loader callbacks. The live state witness is only the exact
  absolute lexical pathname; it does not bind an inode, parent directory,
  symlink resolution, rename history, or rollback state. Unix protected-file
  no-follow/opened-file checks remain stronger than the non-Unix path-swap
  boundary; parent-directory rename/symlink races, persistent inode/rollback
  identity, and supported restore/rebind remain open.
- `SelectedControlAdmin` and the running actor's `SelectedControlHandle` are
  consumers of this boundary, not part of the outer artifact format. They
  provide one bounded live/stopped revocation/rekey family. Live commands use a
  one-command queue, yield after at most four controls, and may commit after
  caller cancellation; recovery is exact retry, with lost self-revocation
  responses recovered through stopped admin after teardown. Automatic or atomic
  revoke-plus-rekey, generalized policy governance, cross-process admin IPC,
  issuer and registry recovery, protected stock CLI/bindings, and repeated
  multi-scope acceptance remain separate work.
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

## Semantic-v4 mutable-lineage amendment (2026-08-25)

The selected semantic-v4 State/Record path consumes the same authenticated
mission/source provider boundary; it does not select a production provisioning
or SecretStore backend and does not make the stock CLI or language bindings
protected by default. Caller-provided protected `NodeConfig` construction is a
local bootstrap seam, not a wire or custody change. The `[4, 3, 2, 1]` offer and
v4 mechanics frames therefore do not broaden the custody claims of this
decision.

Semantic v5 later changes the default offer to `[5, 4, 3, 2, 1]` and adds
provider-owned Blob peer-content, current-lineage, transfer-plan, and
full-content-completion capabilities. Those values expose no content key and do
not select a production provisioning/SecretStore backend. The stock CLI,
selected-node bindings, issuance/recovery, and protected operational custody
remain outside this decision.

Route-key identity is now an explicit data-exposure boundary. Startup proves a
bounded union of retained State/Record source route lineages before sockets
open. After a same-epoch key replacement, old-lineage rows remain durable but
are withheld from ordinary current projection/query and from network inventory
or transfer. Exact idempotent State publish and Record publish/resolution
retries may recover the committed historical result only through the strict
cached/projection/historical verification path. This exception is not general
read or forwarding authority.

The durable peer/class/local-mode fairness cursor contains only mission peer
identity and exact transfer digest metadata; it is not secret-key storage or an
authorization grant. It is bounded to 256 configured peers/1,024 rows, audited
under mission binding, and pruned for removed configured peers before sockets
open. Operational backend selection, recovery, rollback resistance, and
physical erasure remain unchanged open gates.
