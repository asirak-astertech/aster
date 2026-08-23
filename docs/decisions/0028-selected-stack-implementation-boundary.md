# Decision 0028: Start the selected-stack implementation behind an isolated profile

> ****

- Status: accepted — implementation migration lane; no selected dependency admitted
- Date: 2026-08-23
- Authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Related: [Decision 0002](0002-dependency-admission.md),
  [Decision 0025](0025-requirements-first-foss-architecture-evaluation.md),
  [Proposal 0006](../proposals/0006-selected-foss-reference-stack.md), and
  [Proposal 0006 result](../evaluations/0006/README.md)

## Context

Proposal 0006 retained Iroh 1.0.3, Negentropy 0.5.1, and redb 4.2.0 as a
bounded engineering baseline. That result stops broad whole-stack substitution
research, but it explicitly does not admit the dependency graph or select a
production stack.

The existing `aster-core` owns a large SQLite schema and custom sparse-inventory
and synchronization implementation. Adding redb and Negentropy inside that
crate now would create overlapping persistence and reconciliation authorities.
Wrapping Iroh behind the existing IP seam would also preserve a boundary that
had zero selection weight in the requirements-first evaluation.

Decision 0002 still records redb as evaluated but not adopted and Iroh as
rejected pending a bounded exception. Iroh 1.0.3 also declares Rust 1.91 while
the workspace minimum remains Rust 1.90. A proposal result does not supersede
those dependency-admission and toolchain gates.

## Decision

Begin the selected-stack implementation as an isolated migration lane:

1. Add dependency-free `aster-profile` as the requirements-owned semantic
   vocabulary shared by future replica, storage, reconciliation, policy, and
   security implementations.
2. Define stable item and publisher identifiers, the four current extensible
   data classes, the four current provisional priorities, topic, scope,
   perishability, a causal
   publisher-counter context, and a
   reconciliation ordering key derived only from the full item identifier.
3. Keep wall-clock time, replica-local insertion order, wire encoding,
   evaluator behavior, databases, and carriers outside this crate.
4. Introduce future `aster-redb-store` and Negentropy reconciliation crates as
   siblings that depend inward on the profile. A profile-agnostic Iroh carrier
   remains a separate sibling; the composition root depends on both layers.
   Each requires its own exact-graph dependency admission and evidence.
5. Permit only one selected durable acceptance/effect authority at a node.
   redb cutover must replace, not duplicate, the corresponding SQLite owner.
6. Treat the current SQLite/custom-sync/IP and pilot libp2p paths as legacy
   experimental implementations during migration. This decision neither
   removes them nor grants them compatibility weight.

The evaluation profile-v0 wire corpus is seed material, not a product format.
No product encoder or decoder may copy its undeclared extension behavior.
The crate's initial ASCII name syntax and size ceilings are implementation work
bounds, not a frozen protocol or stakeholder limit. Item metadata remains
separate from its opaque identifier until a normative encoding and source
verifier define and test that binding.
Data-class and priority vocabularies are opaque and extensible; they assign no
numeric wire discriminants, preserving later registry evolution.

## Cutover gates

Before any selected mechanism becomes the default, a later decision must bind:

- the exact admitted dependency graph, Rust minimum, licenses, advisories,
  security process, SBOM, and support owner;
- the normative profile and an independently implemented conformance corpus;
- schema migration, rollback, mixed-version, and data-preservation behavior;
- parity for restart, duplicate delivery, crash boundaries, any-peer resume,
  bounded fallback, and hostile input;
- deletion of the displaced store, reconciliation, and carrier machinery; and
- the remaining security, Blob, policy, physical-carrier, target, and release
  gates recorded by Proposal 0006.

## Consequences

- The first implementation PR can establish a stable semantic dependency
  direction without expanding the runtime graph or weakening the MSRV.
- The dependency-free slice adds no committed package SBOM. Generation and
  review are explicitly deferred to the cutover/dependency-admission gate
  before any selected runtime dependency is admitted.
- Stable full-ID ordering is a profile prerequisite. The later Negentropy
  adapter must additionally prove that no timestamp or replica-local ordinal
  can override it before the selected-stack defect is considered prevented.
- Restart, crash-atomic effect, and provider-identity tests remain deferred
  until the real redb and Iroh implementations exist; mocks must not freeze
  invented production seams.
- Existing behavior and public APIs remain unchanged in this phase.
