# Semantic-v9 Blob streaming pipeline CM4 evidence — 2026-10-19

## Scope and build identity

This evidence covers two independently measured parts of the unreleased semantic-v9/profile-5 design:

1. the authenticated Blob map/reduce and sequential-pack pipeline on each of the three CM4s; and
2. the complete v9 stream state machine over the selected Iroh transport between two CM4s.

It does **not** yet claim that the runtime composes those parts into one encrypted network Blob operation. The product runtime/lifecycle adapter remains an implementation task.

All device binaries were cross-built from signed local branch `perf/data-mesh-stream-pipeline`. The relevant signed commits are:

- `cbbfabbe8c2f569c67bf9de06637b6d819244b9e` — stable content-addressed plaintext roots;
- `47d0a11769434e9c7b058bb92796040a00b02295` — end-to-end v9 transfer driver; and
- `7a7f8a4dffb40063524bc2bfdd29eccdf90e684a` — transport-only validation source without synthetic CPU cost.

ARM64 artifact identities:

| Artifact | SHA-256 |
| --- | --- |
| Blob pipeline benchmark | `2e7558bfc74f052bf0d3038b403d96201c9b9f574edcd49fd4b1aa627a5bd6e3` |
| v9 network benchmark | `ace6abbdfa91e07238b4ccf8e7cbd3025f033c7634aa2982a0b22e8228714222` |

## Device inventory

| Device | WLAN | ZeroTier | RAM | Root bytes available before validation |
| --- | --- | --- | ---: | ---: |
| `rpi4-1` | `192.168.60.79/24` | `10.244.155.147/16` | 927,444 KiB | 4,718,387,200 |
| `rpi4-2` | `192.168.60.80/24` | `10.244.158.173/16` | 927,444 KiB | 5,828,931,584 |
| `rpi4-3` | `192.168.60.81/24` | `10.244.219.86/16` | 927,444 KiB | 10,595,069,952 |

All three ran Linux `6.18.39+rpt-rpi-v8` on `aarch64`.

## Local authenticated Blob pipeline

The benchmark reads deterministic plaintext once, maps independent 1 MiB AES-GCM/SHA-256 segments on four fixed workers, restores order through a bounded merge, appends one sequential encrypted pack, checkpoints it, then reads, authenticates, and reduces the pack back through the same bounded pipeline. Each run removes only its exact temporary root afterward.

| Size | Device | Publish MiB/s | Read MiB/s | Peak in-flight bytes | Result |
| ---: | --- | ---: | ---: | ---: | --- |
| 64 MiB | `rpi4-1` | 23.390 | 24.512 | 4,194,824 | pass |
| 64 MiB | `rpi4-2` | 23.703 | 24.739 | 4,194,824 | pass |
| 64 MiB | `rpi4-3` | 25.290 | 26.516 | 4,194,824 | pass |
| 256 MiB | `rpi4-1` | 20.198 | 24.232 | 4,194,824 | pass |
| 256 MiB | `rpi4-2` | 21.941 | 25.189 | 4,194,824 | pass |
| 256 MiB | `rpi4-3` | 22.342 | 26.679 | 4,194,824 | pass |
| 800 MiB | `rpi4-1` | 23.667 | 24.927 | 4,194,824 | pass |
| 800 MiB | `rpi4-2` | 23.744 | 25.134 | 4,194,824 | pass |
| 800 MiB | `rpi4-3` | 24.543 | 26.637 | 4,194,824 | pass |
| 1 GiB | `rpi4-1` | 23.959 | 24.833 | 4,194,824 | pass |
| 1 GiB | `rpi4-2` | 24.209 | 25.138 | 4,194,824 | pass |
| 1 GiB | `rpi4-3` | 25.390 | 26.814 | 4,194,824 | pass |

The three devices produced identical roots for each identical input:

- 64 MiB: `fa07e020b965cd6d8907704a7304146907e5a8e0335c8aee6908097cfb1c99fe`;
- 256 MiB: `6d12fbe42064f7d0e41863b2117f157228b5ab2a945a49d4bddb0140436a1797`;
- 800 MiB: `468f1c1bbcdf471af919c1a38b6434fb35259500241b17db47a7ba7b0c8e0b5e`; and
- 1 GiB: `81f4cbd7babf24a8fe0464ff13ee0d676e7703fb19721cc1db2a5af1a8b33eb0`.

The exact 1 GiB publish-plus-authenticated-read cycle took 78.6–84.0 seconds. Map service dominated sink and reorder service. The processing stage is 2.7–3.1 times faster than the measured same-path raw network baseline below, exceeding the design's 125% isolation threshold.

## Direct WLAN semantic-v9 transfer

The network driver exercised `Open → Accept → Data → Checkpoint → Finish → Result → ResultAck` over one bounded Iroh stream pair. It used 256 KiB extents, an 8 MiB absolute durable-credit window, SHA-256 terminal verification, and no payload-sized allocation.

Endpoints were explicitly bound to WLAN:

- sender: `rpi4-3`, `192.168.60.81`;
- receiver: `rpi4-1`, `192.168.60.79:18191`.

The 64 MiB warm-up transferred at 8.540 MiB/s. A same-address raw TCP transfer of 64 MiB took 7.325 seconds, or 8.737 MiB/s. The v9 driver therefore achieved approximately 97.7% of the available same-path raw throughput.

The exact 1 GiB run produced:

| Role | Elapsed | Throughput | Durable checkpoints | Selected path | SHA-256 |
| --- | ---: | ---: | ---: | --- | --- |
| send | 121.9469 s | 8.397 MiB/s | 128 | Direct | `99cba42a6d9842b5a6c304c4c553be69f95328f15c01e8246b44ec4d9b07c0c8` |
| receive | 121.9537 s | 8.397 MiB/s | 128 | Direct | `99cba42a6d9842b5a6c304c4c553be69f95328f15c01e8246b44ec4d9b07c0c8` |

Interface counters around only this run changed as follows:

| Interface | RX delta | TX delta |
| --- | ---: | ---: |
| `rpi4-1 wlan0` | 1,168,369,510 B | 7,601,829 B |
| `rpi4-1 ZeroTier` | 42,987,591 B | 488,606 B |
| `rpi4-3 wlan0` | 4,107,034 B | 1,136,278,055 B |
| `rpi4-3 ZeroTier` | 12,111 B | 13,307 B |

The payload-sized WLAN deltas, explicit WLAN binds, and `Direct` Iroh witness establish the data path. ZeroTier remained enabled for remote management.

## Network issues observed

The workstation-to-CM4 ZeroTier path has a repeatable MTU/fragmentation symptom: SSH stdin payloads up to 1,024 bytes completed, while 1,200 bytes and larger stalled. HTTP and SCP requests connected but delivered zero body bytes. A bounded 900-byte acknowledged UDP artifact transfer succeeded. This affects deployment/control and is not the measured Aster WLAN path.

After the local three-device matrix, `rpi4-2` continued answering ZeroTier ICMP (92–276 ms in one five-packet sample) but could not complete a small SSH command within 20 seconds. It therefore did not participate in the final network pair. Its local 64 MiB through 1 GiB authenticated pipeline results remain valid.

## Qualification boundary

This evidence establishes that:

- the independent authenticated Blob pipeline is bounded and fast enough that the tested WLAN is slower;
- the semantic-v9 transport state machine carries 1 GiB at approximately the raw WLAN rate; and
- the previous 1.5 MiB/s serial processing path is no longer the limiting design.

It does not yet qualify production deployment. Remaining implementation includes the runtime adapter that feeds encrypted segment records from the parallel pipeline into the v9 driver, receiver-side provisional lifecycle/promotion, application RPC streaming, resume/fault injection, and CI/full-matrix evidence.
