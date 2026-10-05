# Pipelined Event publication CM4 comparison — 2026-10-05

Status: **bounded physical engineering evidence; not qualification or release
authorization**.

## Outcome

The exact candidate preserved durable local publication and exactly-once
observed peer delivery for every admitted Event in the two-device matrix. At
offered rates through 5 Events/s/device, upstream main and the candidate both
admitted the entire workload. Under saturation, the candidate admitted and
delivered more Events:

- durable: +3.1% at 10 Events/s/device and +11.1% at 50;
- finite TTL: +3.5% at 10 Events/s/device and +4.3% at 50.

The candidate does not establish a general latency, synchronization, CPU, or
capacity improvement. Publication and synchronization percentiles were mixed.
Peak RSS stayed within -468 to +524 KiB of the baseline observations. After
normalizing CPU to each receipt's actual process-observation window, candidate
CPU ranged from 10.7% lower to 2.7% higher than the corresponding baseline
row. These are single-run observations, not an efficiency threshold; the
stream is additive and existing unary publication remains available.

## Exact comparison boundary

| Item | Upstream baseline | Candidate |
| --- | --- | --- |
| Source revision | `2dd022f9c6cb453b6cc22896aecfb3449270be88` | `ffbd26d1a7fe99c7577b02b076bda14532defb8f` |
| `aster-agent` SHA-256 | `dd60b5f5b9ce9af7ecf7eaa60142f70685ecd9e5a205300227705b6a2e5d33c9` | `d4e5d198fbe185cd8ec536b1c7f9747165a7f0ac1999861f8af0e32b83f2b183` |
| Local publication API | concurrent unary, window 8 | native HTTP/2 bidirectional stream, window 8, healthy-session rotation |
| Probe SHA-256 | `e23e88255bc4508df1cab18bdcbc1c3a261f7dcb40f73f4e810dc124b0e54071` | `cea8a45ca8b37e2fd4073f9190a94eaf2ae8f330ce978d6b4df38a609573fae5` |
| Durable driver SHA-256 | `08c430d4aaab51e24cf65895ab70d5ec738295ec38fd92277b0f20831cf2263f` | same |
| Finite driver SHA-256 | `60f79ae8fb5129df1c219819b1e75b6c050bc693d0e0383d5278da0af275e7a5` | same |

The physical nodes were the two mandatory ARM64 CM4 engineering devices
`cm4-a` and `cm4-b`. The installed candidate hash matched on both devices.
Before the final matrix both agents were ready, the probe was executable as the
`aster` service account, packet loss was zero in the three-packet preflight,
and no other probe, matrix, or transfer process was active. CPU conversion uses
the measured `CLK_TCK=100` on both devices.

Each cell reset local state while retaining the provisioned mission identity,
created the same Event subscription, exchanged one seed Event in each
direction, and ran the established 256-byte two-device workload. Rates were
0.2, 1, 5, 10, and 50 Events/s/device. Durable Events used no TTL; finite Events
used 600,000 ms. Configured durations and drain-window arguments were unchanged
from the baseline drivers. The candidate probe remained alive for the complete
30-second drain at 0.2--5 Events/s/device while the baseline probe completed
earlier after satisfying its receive condition, so raw accumulated CPU seconds
are not directly comparable. `publish_skipped` is client-window admission
pressure, not mesh loss.

## Correctness and latency matrix

All rows had zero publication errors, query errors, duplicates, invalid Events,
and negative-clock samples. In every row, each node's unique remote receive
count equaled the peer's accepted count.

| Class | Rate | Main accepted/delivered | Candidate accepted/delivered | Admission delta | Main publish p95 A/B (ms) | Candidate publish p95 A/B (ms) | Main sync p95 A/B (ms) | Candidate sync p95 A/B (ms) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| durable | 0.2 | 24/24 | 24/24 | +0.0% | 166.9/180.8 | 153.5/159.8 | 2027.9/2212.0 | 2032.8/2208.9 |
| durable | 1 | 60/60 | 60/60 | +0.0% | 181.2/178.1 | 131.6/152.9 | 2373.4/2297.6 | 2536.2/2348.9 |
| durable | 5 | 200/200 | 200/200 | +0.0% | 194.6/214.5 | 263.9/211.2 | 5820.3/5912.8 | 7376.0/6280.7 |
| durable | 10 | 258/258 | 266/266 | +3.1% | 1119.8/1175.4 | 1012.7/1087.0 | 16344.0/12035.7 | 10376.0/14337.6 |
| durable | 50 | 180/180 | 200/200 | +11.1% | 1206.0/1213.0 | 1362.9/1429.4 | 8889.4/10799.1 | 13784.4/11820.6 |
| finite | 0.2 | 24/24 | 24/24 | +0.0% | 178.5/183.9 | 204.6/163.6 | 2093.7/2340.9 | 1964.4/2164.4 |
| finite | 1 | 60/60 | 60/60 | +0.0% | 140.7/291.8 | 147.9/130.4 | 2435.1/2217.9 | 2662.0/2394.1 |
| finite | 5 | 200/200 | 200/200 | +0.0% | 223.9/182.9 | 296.7/221.1 | 7803.0/6135.8 | 7054.9/6399.4 |
| finite | 10 | 256/256 | 265/265 | +3.5% | 1156.0/1281.4 | 1140.2/1086.5 | 10458.4/13492.1 | 14066.0/14915.0 |
| finite | 50 | 185/185 | 193/193 | +4.3% | 1216.8/1225.7 | 1240.1/1315.1 | 11760.5/9763.3 | 9060.1/11453.9 |

The candidate skipped 34, 800, 35, and 807 planned offers in the durable-10,
durable-50, finite-10, and finite-50 rows respectively. The other rows skipped
none. No skipped offer was counted as a mesh delivery failure.

## Durable-group reconciliation

The candidate emitted one fixed-field, identifier-free diagnostic for every
collected publication group. Diagnostics were partitioned by systemd process;
each cell therefore had a fresh sequence beginning at one. Across all 20
node/cell invocations:

- every group sequence was contiguous and gap-free;
- `sum(collected)` and `sum(accepted_new)` equaled that node's measured
  accepted count plus its one seed publication;
- `exact_retries=0` and `failures=0` everywhere;
- measured probe delivery equaled peer acceptance everywhere.

| Class | Rate | Collected including seeds | Groups | Writer commits | Singleton-equivalent commits | Commit reduction | Maximum cohort |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| durable | 0.2 | 26 | 26 | 52 | 52 | 0.0% | 1 |
| durable | 1 | 62 | 62 | 124 | 124 | 0.0% | 1 |
| durable | 5 | 202 | 202 | 404 | 404 | 0.0% | 1 |
| durable | 10 | 268 | 137 | 274 | 536 | 48.9% | 5 |
| durable | 50 | 202 | 69 | 138 | 404 | 65.8% | 7 |
| finite | 0.2 | 26 | 26 | 52 | 52 | 0.0% | 1 |
| finite | 1 | 62 | 62 | 124 | 124 | 0.0% | 1 |
| finite | 5 | 202 | 202 | 404 | 404 | 0.0% | 1 |
| finite | 10 | 267 | 133 | 266 | 534 | 50.2% | 5 |
| finite | 50 | 195 | 66 | 132 | 390 | 66.2% | 7 |

The observed maximum cohort of seven is an observation, not a protocol limit,
rate limit, capacity claim, or recommendation. The actor fairness budget of
eight remains a private implementation bound and was not derived from this
measurement.

## Resource observations

Normalized CPU is aggregate process CPU across both agents divided by the sum
of both receipts' actual process-observation time. This corrects the different
effective observation windows described above. Peak RSS is the larger of the
two agents' sampled maxima.

| Class | Rate | Main peak RSS (KiB) | Candidate peak RSS (KiB) | Main normalized CPU | Candidate normalized CPU | Relative CPU delta |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| durable | 0.2 | 19344 | 19560 | 28.57% | 29.03% | +1.6% |
| durable | 1 | 19988 | 20196 | 37.03% | 36.87% | -0.4% |
| durable | 5 | 22356 | 22620 | 68.89% | 61.53% | -10.7% |
| durable | 10 | 23564 | 23756 | 70.44% | 70.75% | +0.4% |
| durable | 50 | 22384 | 22684 | 59.35% | 60.93% | +2.7% |
| finite | 0.2 | 19440 | 19528 | 28.41% | 29.01% | +2.1% |
| finite | 1 | 19992 | 20068 | 36.83% | 36.35% | -1.3% |
| finite | 5 | 22160 | 22684 | 68.07% | 61.95% | -9.0% |
| finite | 10 | 23760 | 23760 | 70.61% | 71.87% | +1.8% |
| finite | 50 | 22616 | 22148 | 59.37% | 59.77% | +0.7% |

These single-run observations do not establish variance, a CPU acceptance
threshold, or a supported physical rate. They support neither a general CPU
regression nor a general CPU-efficiency claim.

## Receipt custody and claim boundary

The controller retained the complete engineering receipts under the unique
result root `/tmp/aster-pipelined-validation-20261005/final-ffbd26d1` for this
review. Full service journals were not exported. Only the explicitly bounded
publication-group fields, service PID, and timestamp were extracted:

- `cm4-a.publication-groups.tsv` SHA-256
  `326682f3aed013cd2bf8ed9d1ef6f338253e3bcfd7ba9c2a4e208d7c81b65604`;
- `cm4-b.publication-groups.tsv` SHA-256
  `6fbc82953bd7116aea2acb30b453caff490eb180777c837ccd6cd2c4b25e28a3`.
- exact preflight, deployment, invocation, cursor, and result provenance
  SHA-256
  `dce88311734c01b33e3127bc13d8da51415354e6aa6c398959e4a5ff472d1381`;
- reconciled matrix report SHA-256
  `58b35c4291f1b72859143a9ad5b3099fcb1250e78828fe3608c8581361a154f9`;
- reconciliation program SHA-256
  `e29fe9efda8c5bc8d11436cd68e0dff7b552aa06c098785a7fb4b6c327f32c2d`.

This record demonstrates one exact two-device comparison on one observed
network path. It does not establish a production threshold, supported target,
variance envelope, long-duration behavior, impaired-network behavior,
multi-hop/relay behavior, energy result, mixed implementation, release
qualification, or requirement completion. It changes no atomic requirement
status. Mesh synchronization remains independent of local durable publication;
the mixed synchronization percentiles are therefore not represented as a V7
sync improvement.
