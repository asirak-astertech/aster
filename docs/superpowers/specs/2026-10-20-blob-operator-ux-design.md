# Blob Operator UX Design

Date: 2026-10-20

Status: proposed amendment to the approved data-mesh streaming design

Extends:
`docs/superpowers/specs/2026-10-19-aster-data-mesh-streaming-dag-design.md`

## Purpose and release boundary

The semantic-v9/profile-5 pipeline can publish a large Blob locally, transfer it
later during an eligible contact, resume receiver-authoritative durable progress,
and stream the completed object to an application. The current operator surface
does not make that lifecycle usable: long-running commands are silent, local
publication exposes no destination progress, and the destination has no public
way to distinguish missing work from partial durable receipt.

This increment makes the existing asynchronous design operable for the selected
800-MiB and 1-GiB evaluation workflow. It does not add coordination between local
publication and a destination. Publication still succeeds independently, and
network synchronization still begins only when an eligible destination and
contact are available.

This remains evaluation-stage work. It does not claim global convergence,
production monitoring, durable fleet-wide history, arbitrary remote inspection,
BTLE implementation, or release authorization.

## Decisions

### 1. Exact local lifecycle inspection

Add one authenticated local-agent unary operation, `InspectBlobPublication`,
addressed by exact publication ID, topic, and scope. The publication ID is the
transport-neutral, source-authenticated profile-5 stream identity present in the
open before any data bytes. It is distinct from the immutable content `BlobId`,
which is derived only after the final plaintext root exists. `blob-publish`
returns both identities: publication ID tracks this publication through the
mesh, while Blob ID remains the read and deduplication identity.

The response reports only facts the queried node can prove from its current
authorized durable state:

- `MISSING`: no current authorized pending or completed object is visible;
- `AWAITING_DATA`: authenticated source metadata is durable and no carrier or
  profile-5 pack bytes are durable;
- `RECEIVING`: a nonzero durable prefix exists and work remains;
- `READY_TO_FINALIZE`: all data is durable but atomic promotion is unfinished;
- `AVAILABLE`: this publication is complete and its returned Blob ID can be
  read; and
- `EXPIRED_OR_RETIRED`: retained lifecycle evidence proves the object is no
  longer readable.

Pending states include plaintext total bytes, transfer total bytes, durable
transfer bytes, total units, and durable units. The byte domain is named
explicitly: transfer bytes are authenticated encrypted pack/carrier bytes, not
plaintext. Available state includes the authenticated plaintext length and Blob
ID.

Inspection performs direct bounded lookup in the existing profile-5 reservation
or completed-publication authority keyed by publication ID. A bounded durable
retirement record keyed by the same ID preserves only the minimum state needed
to distinguish `EXPIRED_OR_RETIRED` from `MISSING`; it follows the existing Blob
lifecycle retention and capacity policy. Promotion atomically replaces pending
state with completed state, and retirement atomically replaces visible state
with retirement evidence. Contradictory simultaneous states fail closed.

The operation is exact rather than a list so its response is bounded regardless
of depot size. It does not expose peer identities, paths, carrier object IDs,
lineages, cryptographic material, or transport-selection internals. It does not
claim that any other node has or lacks the object.

`asterctl blob-status --publication-id ID --topic TOPIC --scope SCOPE` prints one snapshot.
`--wait` polls the same local operation until `AVAILABLE`,
`EXPIRED_OR_RETIRED`, or the global client deadline. `--poll-ms` is accepted in
`100..=60000` and defaults to `1000`. A wait deadline reports the final observed
state and durable progress. Snapshot output exits successfully for every valid
state, including `MISSING`; wait succeeds only for `AVAILABLE`.

Operators inspect the receiving node to observe destination durability. A sender
does not infer receiver completion from its own local publication receipt.

This first public lifecycle query covers semantic-v9/profile-5 publication IDs.
Semantic-v7/v8 profile-4 remains byte-compatible but does not gain a new public
tracking identity in this increment. Unsupported legacy identities fail as
invalid input rather than being guessed or translated.

Lifecycle state is derived from Aster store and stream-checkpoint authority, not
from an IP connection, QUIC stream, endpoint, or transport callback. A future
non-IP adapter such as BTLE therefore produces the same local states and durable
byte counters. `AWAITING_DATA` means no authenticated data is durable locally;
it does not diagnose link availability. Transient adapter-local bytes that have
not reached an Aster durable checkpoint are never reported as durable progress.

### 2. Blob capacity in node status

Extend `GetStatusResponse` with a bounded `BlobCapacityStatus` containing:

- reserved depot bytes and the configured byte limit;
- active or deletion-owned variants and the configured variant limit;
- active or deletion-owned expected chunks and the configured chunk limit;
- pending source count and network-staging bytes; and
- a boolean indicating whether each configured limit is already exhausted.

All counters are local durable observations. They are not a promise that a
particular object will fit: deduplication, lifecycle changes, concurrent work,
filesystem free space, and framing overhead remain relevant. The CLI and runbook
must label this as an admission preflight signal, not a reservation.

Before a large evaluation transfer, operators run `asterctl status` on the
publisher and every intended receiver and compare the configured byte limit and
current reservation against the object size plus documented overhead and
operational reserve. The example configuration must provide a concrete 1-GiB
evaluation sizing example while stating that production sizing is inventory-
and retention-dependent.

### 3. Live application-stream progress

`blob-publish` and `blob-read` accept `--progress auto|always|never`, defaulting
to `auto`. Auto enables progress only when stderr is a terminal. Progress is
written exclusively to stderr; stdout remains one stable human or JSON terminal
result.

Publish progress distinguishes:

- source bytes sent to the local agent; and
- bytes durably checkpointed by the local agent.

Read progress reports authenticated bytes written to the staging output. Every
progress record includes current bytes, total bytes, percentage, elapsed time,
and an interval transfer rate. Human output is rate-limited to at most four
updates per second, plus the initial state, durable-checkpoint transitions, and
terminal state. `always` uses newline-delimited records when stderr is not a
terminal, so logs are readable without carriage-return control sequences.

Progress is observational. A closed stderr or formatting failure must cancel the
command before falsely reporting success; it must not weaken protocol validation
or durability semantics.

### 4. Actionable interruption and resume

The publish client retains the latest validated accepted and durable offsets
outside the timed transfer future. Any timeout, disconnect, or unknown outcome
reports:

- source bytes sent;
- agent-accepted bytes;
- agent-durable bytes;
- total bytes; and
- the exact operation key and identical retry instruction.

Retrying the same file metadata and operation key remains the only publication
resume action. The agent remains authoritative for the resume offset; the client
never asks it to trust a client checkpoint.

`blob-read` interruption reports the authenticated byte count written before the
temporary output was discarded and states that the destination path was not
published. Download resume is not added in this increment: local read begins
only after complete node-local availability and is not the DDIL network path.

### 5. Documentation and wording

The CLI help must say that the source path remains local while file contents are
streamed to the local agent. Event subscription prerequisites and Blob network
interest prerequisites must be documented separately. The operator guide must
show the complete workflow:

1. inspect capacity on publisher and receiver;
2. publish locally and retain publication ID, Blob ID, and operation key;
3. inspect or wait on the receiver by exact publication identity;
4. read only after receiver-local `AVAILABLE`;
5. compare hashes; and
6. use the reported durable offset and exact retry instruction after an
   interruption.

The engineering runbook retains detailed pipeline and contact evidence. The
operator workflow must not require reading internal logs or benchmark receipts
to determine ordinary lifecycle state.

## Protocol and compatibility

`InspectBlobPublication`, `BlobCapacityStatus`, and the publication-ID field in
`PublishBlobReceipt` are additive fields and methods in the alpha application
protocol. The subsequently selected PR 110 implementation intentionally
replaces the unreleased PR 95 `PublishBlob` client-streaming/unary exchange with
the current bidirectional `v1alpha1` stream. No production deployment depends
on the older generated method; clients must regenerate and migrate, and an
additive legacy upload method is not retained. `GetStatus` and `ReadBlob`
retain their field meanings. Generated Rust and Go artifacts and descriptor
fixtures are regenerated in the same change.

Semantic-v9/profile-5 mesh framing does not change. Semantic-v7/v8 profile 4 is
unchanged. This increment adds no peer acknowledgement, coordination message,
or durable transport-specific state.

The status and progress implementation may depend only on transport-neutral
stream identities, absolute durable offsets, canonical totals, and terminal
settlement. It must not import Iroh endpoint/path types or assume an IP MTU,
continuous connection, ordered carrier packet delivery, or a minimum attempt
duration. A later BTLE adapter may fragment and reorder its own carrier units,
but it must present the existing ordered Aster stream-attempt producer/consumer
contract and resume from the same receiver-authoritative absolute checkpoint.
Reopening a fresh instance of the same single contact-agreed adapter must not
change the Blob identity, lifecycle state meanings, CLI output schema, or
safe-retry procedure. Cross-transport selection and failover remain outside
this increment.

## Security and privacy

- Every new operation uses the existing authenticated loopback agent boundary.
- Exact topic and scope validation and current-policy checks happen before a
  state is returned.
- `MISSING` deliberately conflates absent and unauthorized data.
- Retired state is returned only when existing authorized lifecycle evidence can
  support it; otherwise the result is `MISSING`.
- Status contains no plaintext, keys, nonces, filesystem paths, peer-specific
  fetch cursors, or protected routing lineage.
- Error and progress output retain the existing public redaction boundary.

## Resource and failure behavior

- Exact inspection performs one bounded lookup/projection and never enumerates
  the complete Blob inventory.
- `blob-status --wait` has one request in flight, sleeps between polls, obeys
  the client deadline, and never busy-polls.
- Progress tracking retains only current counters and timestamps; it does not
  retain per-frame history.
- Counter overflow, impossible regressions, inconsistent totals, or a state that
  contradicts durable storage fail closed as data loss/integrity errors.
- Capacity counters use saturating remaining-value presentation while preserving
  exact usage and limits in the protocol response.

## Validation

Focused automated evidence must cover:

- all six lifecycle states by exact publication ID, including
  missing/unauthorized conflation;
- stable publication ID from local receipt through interrupted receiver progress
  and final Blob-ID availability;
- monotonic durable progress across restart and interrupted contact;
- exact bounded status responses at zero and maximum counters;
- wait success, terminal retirement, and deadline with final-state reporting;
- TTY, non-TTY, forced, disabled, JSON, and broken-stderr progress behavior;
- publish timeout diagnostics and exact-operation resume;
- read interruption cleanup diagnostics;
- Blob capacity output and exhausted-limit flags;
- unchanged profile-4 vectors and profile-5 transfer behavior; and
- a transport-neutral fake-adapter test using a small MTU and a fresh instance
  of the same contact-agreed adapter after interruption, proving that status
  observes only common durable checkpoints and contains no IP/Iroh fields; and
- updated CLI help, man pages, operator guide, and engineering runbook examples.

The composite CM4 validation must retain timestamps and terminal outputs for
local publication, receiver wait, receiver read, and hash comparison so the
operator-observed end-to-end duration is separable from local upload, peer
transfer, and local download.

## Completion gate

- An operator can determine receiver-local Blob state without trial downloads
  or internal logs.
- A 1-GiB local publish or read never appears silent while progress is enabled.
- An interrupted publish reports the authoritative durable checkpoint and an
  exact safe retry.
- Publisher and receiver capacity are visible before the evaluation run.
- The public status/progress implementation remains usable by a future BTLE
  adapter without protocol, state-machine, or CLI changes.
- Documentation does not confuse Event subscriptions with Blob interests or a
  local path with streamed file contents.
- Existing protocol compatibility, lifecycle, security, and bounded-memory
  tests remain green.
