# Aster public development provenance record

- Record date: 2026-08-26
- Repository: `defenseunicorns-partnerships/aster`
- Reviewed repository baseline: `4268201d16d79c0c5814763735de7bd755b01029`
- Product-intent authority: [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
- Product-intent SHA-256: `e88bcc6c717a5175a460205fdc084aaa2e1f020a142a84087f9881677da02987`
- Public source index: [`public-source-register.csv`](public-source-register.csv)

## Purpose and scope

This record gives an external reviewer a public, repository-native path through
the materials that ground Aster's development: the supplied product-intent
document, public standards and upstream projects, Aster's decisions and
evaluations, the implementation and tests, and the version-control history that
joins them.

It is a review aid rather than a reconstruction of every development activity.
It contains only information suitable for the public repository and does not
replace the project's other retained records.

## Development basis

The repository identifies the following record chain:

1. **Product intent.** [`data-mesh-requirements.md`](../../data-mesh-requirements.md)
   defines the target outcomes. Its hash above binds this record to the exact
   requirements baseline used by the project.
2. **Public inputs.** The [public source register](public-source-register.csv)
   lists the standards, guidance, selected components, bounded pilots, and
   evaluated alternatives that materially informed public repository work.
3. **Reasoning and dispositions.** The
   [architecture decisions](../reference-index.md#architecture-decisions),
   [proposals and results](../reference-index.md#proposals-and-results), and
   [requirements-first evaluation](../evaluations/0005/README.md) record what
   was considered, what was selected or rejected, and the limits of each
   conclusion.
4. **Implementation and verification.** Source, tests, lockfiles, dependency
   policy, third-party notices, and retained public evidence show what was
   actually built and exercised. The
   [capability roadmap](../implementation/capability-roadmap.md) gives the
   outcome-level view; the
   [requirements status](../implementation/requirements-status.md) and
   [atomic trace](../implementation/requirements-implementation.csv) preserve
   the detailed claim boundaries.
5. **Chronology.** Commits and pull requests preserve the public change sequence
   and the exact repository state associated with each merged increment.

The 348-row atomic requirements trace is an evidence map, not a flat backlog or
a completion percentage. The capability roadmap is the intended planning and
merge-review view, while the atomic trace remains available for exact claims
and open gates.

## Public source register boundary

The public source register is a reviewed disclosure set, not a software bill of
materials or a complete activity log. It contains:

- normative standards and official security guidance used by the design;
- upstream projects selected for the active implementation or a bounded pilot;
- material alternatives retained as comparisons, interoperability oracles, or
  documented non-selections; and
- a repository evidence path for every row.

It does not list transient searches, failed retrievals, duplicate visits, local
evidence, or every transitive package. Exact runtime versions are controlled by
[`Cargo.lock`](../../Cargo.lock); direct dependency intent is visible in
[`Cargo.toml`](../../Cargo.toml); distribution notices and exceptional license
dispositions are in [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md)
and [`deny.toml`](../../deny.toml).

`tools/check-public-provenance.py` validates the public register's schema,
stable identifiers, HTTPS-only source locations, allowed dispositions,
repository evidence paths, ordering, and exclusion of operational-only fields.

## How to review this record

An external reviewer can:

1. hash the requirements document and compare it with the value above;
2. inspect the public source row relevant to a capability and follow its
   `repository_evidence` path;
3. read the cited decision or evaluation for the source's actual disposition
   and limitations;
4. inspect the implementing commits, tests, `Cargo.lock`, and dependency
   notices rather than inferring implementation from a research citation; and
5. compare capability claims with the roadmap and detailed requirements status
   before drawing a completeness or readiness conclusion.

Absence from the selected runtime is not evidence that a project was never
considered; evaluated alternatives are deliberately retained. Conversely, a
public citation is not evidence that its code was copied, adopted, or granted
production authority. The `disposition` column and cited repository record set
that boundary.

## Maintenance and corrections

Future changes should be made through reviewed commits. Existing public source
IDs remain stable; corrections update the affected row and are explained by the
commit or pull request. New sources receive new IDs. A material change to the
requirements authority, disposition vocabulary, or public-register scope
requires a dated update to this document.
