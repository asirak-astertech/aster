# Decision 0011: Bounded recipient-filtered fresh rekey

- Status: accepted for reference
- Date: 2026-08-18

## Decision

An authority issues a monotonic ScopeEpoch control containing one bounded,
sorted set of packages for the remaining recipients. Each epoch creates a fresh
scope routing key and fresh per-topic content keys. Every recipient package
combines authenticated static P-256 ECDH with ML-KEM-768, derives a labeled
AES-256-GCM wrapping key, and binds mission, authority, scope, epoch, recipient,
credential, package-set hash, and hidden grant commitment. A package contains
no key for an omitted or revoked node.

The single-control limit is 128 recipients, which covers the draft 100-node
per-scope baseline while remaining within the authenticated control-size bound.
Activation occurs only after the full dual-signed control is durably committed;
out-of-order controls remain pending, and replay/reopen applies the identical
committed package without advancing or mutating keys twice.

Authorities maintain recipient public credentials through a canonical,
authority-signed `ASTRRKR1` registry artifact. It contains public material only,
is strictly sorted, version/mission/authority/suite bound, and imports
atomically. Generation is append-only; equal-generation replacement, rollback,
and a newer non-superset are rejected. A deployment persists an external
registry-generation high-water value and supplies it on import after restart.

## Consequences

- A captured node excluded from the package set cannot learn the new route or
  content keys, while remaining recipients receive only their declared topics.
- Grant commitments use a hidden random salt so a captured nonrecipient cannot
  test guessed topic lists offline.
- ScopeEpoch format 0 remains a pre-provisioned-epoch compatibility form;
  format 1 is the fresh recipient-package form. Both are explicitly versioned.
- The registry import/export seam solves authority-process restart when its
  signed artifact and external high-water witness survive. Total deletion of
  all local state and every external witness remains undetectable locally.
- The high-level application/binding administration workflow and a policy for
  scopes larger than 128 recipients remain release work; unsafe partial epoch
  activation is not permitted.

This is a bounded static-recipient mechanism for the draft profile, not an
implementation of MLS or another external group-state protocol. It uses only
the already admitted NIST algorithms and provider boundary.
