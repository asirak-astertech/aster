## Summary

Describe the behavior changed and why.

## Capability outcome and claim boundary

- Roadmap outcome advanced (or maintenance rationale):
- Demonstrated/implemented behavior after this PR:
- Important exclusions and remaining gaps:
- Exact requirement IDs whose evidence boundary changes, if any:

- [ ] The PR is a coherent increment toward the named outcome; it does not need
  to close every associated atomic requirement.
- [ ] Claims are no broader than the code, tests, environment, and retained
  evidence.
- [ ] `docs/implementation/requirements-status.md` and its generated trace were
  updated when requirement evidence changed, or no evidence boundary changed.

## Security and compatibility

- [ ] Wire/API compatibility is unchanged or explicitly versioned.
- [ ] Resource limits and failure behavior were considered.
- [ ] No credentials, mission data, local artifacts, or generated binaries are included.
- [ ] Dependency and tool changes are exact-pinned and justified.

## Verification

- [ ] `mise run check`
- [ ] Relevant regression tests
- [ ] `mise run fuzz-smoke` when parser/framing/envelope behavior changed
