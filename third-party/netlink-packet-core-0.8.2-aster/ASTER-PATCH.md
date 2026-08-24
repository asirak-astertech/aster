# Aster patch provenance

- Upstream package: `netlink-packet-core` 0.8.2 from crates.io.
- Crate archive SHA-256: `b897d7bd4f0af82e68d40d0344cf37e97f9c97ddf74a098de3e4da05e96ca395`.
- Upstream VCS revision: `571d8bb5fa1dbaa875e8aede3f214c87f70b955b`.
- License: MIT; see `LICENSE-MIT`.
- Per-file upstream receipt: `ASTER-UPSTREAM.sha256`.

The only upstream-code delta aliases the dependency key `paste` to exact
`pastey` 0.2.2. This preserves the public macro API while removing the
unmaintained `paste` package identified by RUSTSEC-2024-0436. No Rust source
files are modified. Remove this patch after the active netlink consumers can
move to an upstream release that no longer depends on `paste`.

`tools/check-netlink-packet-core-patch.py` verifies the retained upstream file
set and hashes, reconstructs both original manifests from the exact allowed
delta, and rejects every other source or file-set change. The quality gate also
runs the 13 upstream library tests from a disposable dependency-minimized copy.
