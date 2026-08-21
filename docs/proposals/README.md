# Aster proposals and experiments

> ****

Proposals describe bounded investigations that may inform a later architecture
decision. They complement the accepted records in [`docs/decisions`](../decisions/)
without changing them.

A proposal is deliberately non-normative. It does not, by itself:

- change the Aster protocol, application API, or production behavior;
- admit a dependency or authorize a deployment profile;
- satisfy a requirement or conformance scenario;
- supersede an architecture decision; or
- turn an experimental result into a product claim.

## Lifecycle

Proposal statuses are:

- **draft** — incomplete and not ready to schedule;
- **proposed** — ready for review, but not authorized for execution;
- **accepted for experiment** — scope, owner, timebox, and evidence plan are
  approved;
- **completed** — the bounded work and retained result are finished;
- **superseded** — a later proposal replaces the investigation; and
- **withdrawn** — the investigation will not proceed.

Every accepted experiment must state a falsifiable question, common controls,
quantitative exit criteria, an early-abort rule, and a fixed evidence plan. A
dependency comparison must allow **one winner or none per replaceable boundary
or profile** and must not leave multiple overlapping production stacks behind.
Multiple winners require a later decision to define their non-overlapping
platform or operator purposes.

When an experiment finishes:

1. append a dated outcome to the original proposal; do not rewrite its original
   hypothesis or erase failures;
2. preserve exact sources, versions, configurations, commands, measurements,
   failures, and receipts under the project evidence process;
3. record any resulting design choice in a new architecture decision record;
4. update requirements traceability only when product behavior actually
   changes; and
5. remove rejected experimental integrations unless a separate record retains
   one as a bounded test-only oracle.

Proposal files use an independent four-digit sequence:
`NNNN-short-description.md`.

## Index

| Proposal | Status | Decision sought |
|---|---|---|
| [0001 — Operational IP mesh vertical-slice experiment](0001-ip-mesh-vertical-slice.md) | proposed | Select or reject an IP mesh host/connectivity profile after a controlled bake-off |
