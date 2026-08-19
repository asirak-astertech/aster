## Summary

Describe the behavior changed and why.

## Security and compatibility

- [ ] Wire/API compatibility is unchanged or explicitly versioned.
- [ ] Resource limits and failure behavior were considered.
- [ ] No credentials, mission data, local artifacts, or generated binaries are included.
- [ ] Dependency and tool changes are exact-pinned and justified.

## Verification

- [ ] `mise run check`
- [ ] Relevant regression tests
- [ ] `mise run fuzz-smoke` when parser/framing/envelope behavior changed
