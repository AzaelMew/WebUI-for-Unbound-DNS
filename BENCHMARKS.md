# Filter scalability measurements

## Scope and production safety

Target Unbound **1.17.1**, 2 GiB container RAM, 512 MiB swap, existing WebUI
service `MemoryMax=512M`. The host reports two available CPUs, not the requested
one; isolated workers/checkers/resolvers were pinned to **CPU 21** to test one CPU.
Every config/filter tree was separate and temporary; direct DNS queries used
owned high loopback ports, never port 53. Production resolver identity remained
PID **5338**, start ticks **70036930**, throughout. No production config/state,
resolver reload/restart, client settings, firewall or resource allocation changed.

Representation comparison predates the final durability/gzip/canary fixes. The
`post-review-*` artifacts measure the final shipped backend/storage separately.
Raw timestamps, source hashes, executable source hashes, sample counts, process
ownership and cleanup results are retained in `benchmarks/2026-09-30/*.json`.
This directory name identifies the feed/test cohort even if local time passed
midnight during the work.

Latency uses a deterministic loopback upstream and socket nanosecond timers,
not a single `dig` and not WAN/DNSSEC performance. Upstream request counts
confirm cache hits/misses and filtering; zero reported successful-run query errors.
Baseline “blocked” group has no filter and measures upstream NXDOMAIN responses;
it is not evidence of baseline blocking. Fast baseline checkers may finish
between RSS samples; a recorded zero sample is **not zero memory usage**.

## Exact feeds

| Feed | Exact source | Download bytes | Unique domains |
|---|---|---:|---:|
| Mini | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt` | 4,243,028 | 199,618 |
| Full | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt` | 48,926,475 | 2,389,473 |
| Full RPZ part 1 | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-1.txt` | 65,020,258 | logical union below |
| Full RPZ part 2 | `https://raw.githubusercontent.com/hagezi/dns-blocklists/main/rpz/tif-2.txt` | 61,506,522 | logical union below |

Full Adblock/RPZ version **2026.0930.1431.55**, modified 30 Sep 2026 14:31 UTC.
Mini version **2026.0930.1450.01**, modified 14:50 UTC. RPZ parts contain a total
4,778,946 apex/wildcard CNAME policies, yielding the same **2,389,473** domains
as Adblock, zero unsupported entries. Canonical domain SHA-256:
`10ad0151b5f1a7c801e73f99507e506d55fc2d530412dc4e2d048e8202382882`.
The downloaded-byte total for the logical RPZ subscription is **126,526,780**.

Source SHA-256:
- Full Adblock: `b8b539f0e1927ce42beb3c77566c628cb84dcb58c850c4a1aff4f73f2b0242bc`
- Mini Adblock: `52713a597419d81fb98f059bf040542a6a1e7d496e2bc55dede9e0199726e9c4`
- RPZ part 1: `335b3abd45697a50a2703c1c568e7c25a006513a735ac48460c1d0881d84bdbc`
- RPZ part 2: `85c3cba3367262b7df2ae7a76c0e6c76c02bf7c29e42460c73febd9d19d07611`

## Representation and resolver measurements

| Representation | Checkconf seconds | DNS-ready startup seconds | Peak startup RSS MiB | Steady RSS MiB | Isolated reload seconds |
|---|---:|---:|---:|---:|---:|
| Baseline | 0.009 | 0.126 | 16.12 | 16.12 | 0.070 |
| Mini local-zone | 0.596 | 0.585 | 94.66 | 94.91 | 0.740 |
| Mini native RPZ | 3.330 | 2.924 | 252.58 | 252.58 | 3.290 |
| Full local-zone, final backend | 8.162 | 6.838 | 1003.36 | 1003.36 | 9.763 (representation run) |
| Full native RPZ | 13.648, failed | — | — | — | — |

Final Full staged main/fragment/live validation took respectively
**8.162 / 8.574 / 8.160 s**,
maximum sampled checker RSS **1000.17 MiB**.
Final activation includes a live TXT canary check and a blocked query before
metadata commit. Actual config/state rollback and old canary verification passed
on a small separate resolver fixture; Full hot-update overlap was not attempted.

Full native RPZ failed allocation during `unbound-checkconf` under the deliberately
imposed **1 GiB address-space cap**, at **1009.55 MiB sampled checker RSS**. Thus
there are no Full RPZ startup/reload/latency results and no assertion of its exact
uncapped memory. Mini RPZ used roughly 2.7 times local-zone steady RSS and slower
validation/startup. Both representations passed actual DNS allowlist subtree
semantics, including a parent exception overriding explicit blocked children.
The shipped multi-source RPZ importer also passes its own actual wire-DNS test.

**Decision:** retain local-zones as production output; support RPZ as strictly
validated input. Exact ancestor pruning found **zero redundant domains** in both
actual feeds, so equivalent parent-domain pruning does not solve Full memory.

## Importer and API memory

Python `ru_maxrss` below belongs to fresh Python workers; it is not child Unbound
RSS, total container RAM, page cache or production Unbound memory.

| Import path | Import/parse seconds | Python peak MiB | Notes |
|---|---:|---:|---|
| Original Mini algorithm | 2.55 parse + 2.15 render | 117.46 | temporarily raised limits for isolated comparison |
| Original Full algorithm | 31.16 parse + 27.00 render | 983.39 | full set/sort/string materialization |
| Standalone file-backed Full | 40.11 parse | 28.55 | benchmark parser, not the app backend |
| Final Full FilterManager | 65.75 disabled refresh; 57.90 parse/build | 50.93 | includes normal backend imports/union/durability |
| Final two-source Full RPZ | 165.21 disabled refresh | 49.45 | 126.5 MB input, 4.78M policies, one logical cache |

Final Full enable preparation/validation/cold activation took
**70.33 s**, including **2.89 s**
of extra service-cap diagnostics. Subtracting those separately timed diagnostics
gives **67.44 s**, not a separate run.
Snapshot JSON: **893 bytes**, mean serialization
**43.27 µs**; state JSON
**638 bytes**, no subscription domain arrays.
RPZ snapshot **965 bytes**, state
**711 bytes**. Cache bytes differ slightly with
insertion order (Adblock 56,635,392; RPZ 57,040,896), while domain digests match.

## Repeated direct-query latency

| Resolver | Query group | Count | Errors | Median ms | p95 ms | Max ms |
|---|---|---:|---:|---:|---:|---:|
| Baseline | cached | 150 | 0 | 0.0370 | 0.0595 | 0.2143 |
| Baseline | uncached | 50 | 0 | 0.1412 | 0.1755 | 0.3388 |
| Baseline | blocked | 150 | 0 | 0.1423 | 0.2304 | 0.3724 |
| Baseline | descendant_blocked | 150 | 0 | 0.0360 | 0.0676 | 0.2151 |
| Full local-zone | cached | 150 | 0 | 0.0360 | 0.0691 | 0.2399 |
| Full local-zone | uncached | 50 | 0 | 0.1403 | 0.1972 | 0.3835 |
| Full local-zone | blocked | 150 | 0 | 0.0361 | 0.0693 | 0.2105 |
| Full local-zone | descendant_blocked | 150 | 0 | 0.0337 | 0.0592 | 0.2046 |
| Mini local-zone | cached | 150 | 0 | 0.0360 | 0.0524 | 0.1910 |
| Mini local-zone | uncached | 50 | 0 | 0.1330 | 0.2019 | 0.3446 |
| Mini local-zone | blocked | 150 | 0 | 0.0343 | 0.0565 | 0.2083 |
| Mini local-zone | descendant_blocked | 150 | 0 | 0.0332 | 0.0614 | 0.2284 |
| Mini native RPZ | cached | 150 | 0 | 0.0363 | 0.0573 | 0.0761 |
| Mini native RPZ | uncached | 50 | 0 | 0.1307 | 0.2384 | 0.2939 |
| Mini native RPZ | blocked | 150 | 0 | 0.0330 | 0.0517 | 0.1801 |
| Mini native RPZ | descendant_blocked | 150 | 0 | 0.0326 | 0.0586 | 0.2459 |

These measurements show local policy overhead in this controlled setup; they
cannot predict real external cache misses, upstream delays or production load.

## Disk and backup impact

Final Full fragment with canary: **125,388,923 bytes**; without
canary: **125,388,648**. Final compressed rollback blob:
**13,168,484 bytes**, created in **26.97 s**.
Repeated unchanged backup revalidated gzip/hash integrity and reused the blob
with zero additional blob allocation;
its small new archive allocated one 4 KiB block.

Ten **distinct synthetic minor-change variants of the actual Full RPZ feed**
retained ten real copied/modified immutable caches, ten compressed fragments and
ten metadata/config archives. This is not ten identical hardlinks or ten remote
feed versions. Actual measurements:
- Compressed blobs: **131,683,420 bytes**.
- Retained caches: **570,408,960 bytes**.
- Total allocated filter data/backups: **702,144,512 bytes
  (669.62 MiB)**.
- Minimum disk free sampled during import/copy/decompression/retention:
  **476.05 MiB**.
- Streaming restored policy hash matched exactly; all temporary trees cleaned.

The discarded raw-blob design would retain about **1.82 GB** for ten Full
fragments/caches before active/staged/transient data. Compression materially
reduces this, but changes to list size/count and other backup trees still require
monitoring. Disk preflight reserves 256 MiB plus estimated operation space.
Archives are not standalone: retain `filter-data` and `filter-backups` together.

## Practical conclusion for the target

Full **does start and answer DNS** on the measured one-CPU/2 GiB test allocation;
latency alone is not the problem. Routine safe validated refresh is **not practical
with the current 512 MiB WebUI cap and 2 GiB total RAM**: an old Full resolver plus
a new validator consumes about 2,004 MiB before Python/other services/reserve.
The original 983 MiB importer made that worse; the new approximately 51 MiB
importer fixes that component but cannot remove Unbound's validation cost.

A real separate transient systemd service with `MemoryMax=512M` rejected Full
before spawning a validator (507 MiB remaining actual cgroup budget versus
1,108 MiB conservative requirement). The checker independently failed at a
512 MiB address-space cap; address space is not the same as cgroup memory.
The final isolated run's minimum resolver headroom was
**762.06 MiB** because it did not overlap
large resolver/validation processes. Earlier representation runs reached 543.85
MiB minimum and swap increased 28.24→64.98 MiB. Neither certifies production hot
refresh. Cache/page-cache and other workloads can narrow headroom further.

Use Mini under current budgets. For Full, review a **4 GiB container and a 2 GiB
WebUI service budget** as starting recommendations, update the container-memory
override and rerun actual deployment validation/reload/load measurements. Those
budgets were **not deployed or measured as a 4 GiB system**. Do not merely raise
service limits on the 2 GiB container or bypass preflight. No Full policy was
enabled in production. See `DEPLOYMENT.md` and `SCALABLE_FILTERS.md` for exact
upgrade/migration/recovery steps.

## Verification and remaining limitations

The final integrated target suites passed **127 Python tests** in 43.293 seconds.
The original suites remain green; all new backend/storage probes are included. Node UI suite:
**12 passed**. Import-isolation PASS and the real TLS launcher smoke verified
HTTPS login, Secure cookies, CSRF rejection and disabled unsafe saves. Existing
Starlette/httpx deprecation warning remains; no package changes were made.

Tests cover migration and post-rename/fsync failure, malformed state/cache,
source/aggregate limits, duplicate sources, every-source SSRF/redirect pinning,
failed multi-source refresh, activation/verification rollback, journal recovery,
compressed artifact corruption/path attacks, disabled state, scheduler exclusion,
and actual DNS allowlist contracts for shipped RPZ imports. Generated 300,017-
domain scaling fixtures remain temporary; no giant literal fixtures are tracked.

Real-browser pixel verification was blocked by the installed nightly browser's
real-profile tool restriction and native-window capture limitation; no browser
switch or X11 workaround was introduced. DOM behavioral/safe-text tests and
actual Jinja page rendering passed. The Hermes fan-out re-review workers were provider-rate-limited; independent
standalone Codex CLI review found archive/rollback-durability issues, which a
separate fix context addressed and regression tests verified. Final independent
verdict is recorded separately in `final-verification.json`. Production hot refresh/loaded cache growth,
WAN latency and a 4 GiB deployment remain unmeasured.

The post-review measurements include atomic archive publication, safe tar member
handling and complete cache validation before archive publication. That cache
check costs about 23 seconds per Full archive; the measured first/repeated Full
backup operations take about 27/24 seconds, not merely gzip compression time.
The final two small durability adjustments (new-blob CRC verification and durable
missing-original deletion) are covered by the final 127-test suite; artifact
source hashes identify the precise measurement revision. They do not alter
parsing, canonical domain rules, resolver RSS or retained data sizes.

Final fresh independent CLI review: **PASS**, no important security/logic gaps.
A non-blocking suggestion to strengthen GC-expiration directory durability is
retained in `independent-review.json`. Active/state/journal references remain
protected; offline recovery refuses missing/corrupt expired artifacts.
The four hash-verified feed inputs were copied to operator scratch for optional
reproduction and removed from the resolver development area, freeing 179,696,283
bytes. All isolated processes/temporary trees were cleaned.

## 4 GiB update and deployment — 2026-10-01

The original 2 GiB conclusion above is historical. After the operator increased
the same container to4GiB, a new isolated test placed the WebUI/validator worker
and resolver in separate2GiB-limited service cgroups **inside that one container**.
No second container or production Full policy was used. The source snapshot
remained2,389,473 domains for a like-for-like comparison.

- Initial disabled import: **65.98s**.
- Cold enable: **64.04s**.
- **Live refresh while the old Full resolver remained running: 132.16s, passed.**
- Isolated reload-to-DNS-readiness: **8.69s**;
  the resolver PID stayed unchanged. This does not imply answers never pause
  during parsing/reload.
- Steady resolver RSS: **1003.64MiB**, sampled peak
  **1003.86MiB**. Python peak **48.63MiB**.
- Minimum sampled container headroom: **1764.92MiB**
  (1.72GiB).
- Candidate canary/block verification, staged/live validation and cleanup passed.
  Production resolver PID5338/start identity was unchanged.

This supports using Full on the measured4GiB/service2GiB budgets, subject to
normal growth/load/resource admission checks. It does not prove a WAN speedup
versus an AdGuard forwarding chain. The committed feature was then deployed
without activating Full: the existing230,960-domain subscription was preserved
and schema-migrated, listeners/auth/TLS retained, scheduler kept off. Raw test
and deployment results are in `benchmarks/2026-10-01/`.
