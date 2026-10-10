# AGENTS.md

Guidance for AI agents working on this project.

## What this is

WebUI for an Unbound DNS resolver — a FastAPI app that administers a live,
production DNS server as root. Bugs don't just crash the app; they can take
down DNS for an entire LAN. Treat every change as high-stakes.

Upstream is [mayur-454/WebUI-for-Unbound-DNS](https://github.com/mayur-454/WebUI-for-Unbound-DNS);
this fork (AzaelMew) layers a safety module, domain filters, container-aware
memory reporting, and responsive UI fixes on top of upstream commit
`233433be9565eba67d88d78401c44d917a33e5cd`. Read the current fork, not just upstream.
Subscriptions now use versioned metadata and immutable file-backed caches;
multi-million-domain support must preserve the existing safety architecture.

## Repository layout

| Path | Role |
|---|---|
| `app.py` | Upstream FastAPI application (pinned upstream code; avoid editing) |
| `auth.py`, `ssl_utils.py` | Upstream auth and TLS certificate helpers |
| `run.py` | **The launcher.** Installs safety, memory, filters and opt-in refresh lifecycle hooks, then serves TLS-only uvicorn. Listener env defaults to `127.0.0.1:8443`; preserve deployment-specific bind/bootstrap/redirect settings via drop-ins. |
| `safety.py` | Deployment policy layer. Disables upstream's lossy form saves, re-implements raw save/restore as validated transactions, adds login/setup CSRF, HTTPS-only cookies, rate limiting. |
| `filters.py` | Auth/CSRF-protected filter API, strict source parsers, schema migration and transactional updates. Writes only `unbound.conf.d/webui-filters.conf` plus owned filter data/backups. |
| `filter_store.py` | Immutable SQLite cache generations and bounded disk-backed unions/rendering. No subscription domain arrays in state/API snapshots. |
| `filter_resources.py` | Container/service/disk admission checks and finite validator address-space cap through a fresh interpreter/exec wrapper. |
| `filter_activation.py` | Bounded wire-DNS verification of the loaded fragment's reserved TXT canary and representative blocked query. |
| `filter_refresh.py` | Global opt-in scheduler; starts/stops through application lifecycle, refreshes enabled lists serially. |
| `filter_recovery.py` | Explicit offline validation/restore of managed fragment/state. Never activates DNS automatically. |
| `rewrites.py`, `rewrites_recovery.py` | Dedicated A/AAAA rewrite API, revisioned drafts, own managed fragment/transactions and explicit offline recovery. Never modify filter policy or unmanaged overrides implicitly. |
| `server_config.py` | Config page backend: schema-driven, line-preserving edits of the real config files, same transactional/rollback contract, raw editor, offline recovery CLI. Replaces upstream `/config`. |
| `dashboard.py` | Read-only metrics dashboard: light-tree `stats_noreset` sampler, SQLite history (`dashboard-data/`), `/dashboard` + `/api/dashboard`. See `DASHBOARD.md`. Never changes config or enables logging. |
| `container_memory.py` | Reports container cgroup working-set memory instead of host `/proc/meminfo` (LXC hides the parent limit; override via `WEBUI_CONTAINER_MEMORY_BYTES`). |
| `templates/`, `static/` | Jinja/assets; fork-owned filter page/JS and responsive CSS. Keep remote values in safe DOM text/value APIs. |
| `unbound-webui.service` | Reference systemd unit for the deployed service. |
| `DEPLOYMENT.md` | Operator-facing install/maintenance notes for the live deployment. |
| `SCALABLE_FILTERS.md` | Exact schema, formats, configurable bounds, transaction/backup/recovery contract. |
| `SERVER_CONFIG.md` | Config editor semantics, invariants, transaction and recovery. |
| `DNS_REWRITES.md` | Rewrite editor semantics, conflicts, backup scope and offline recovery. |
| `BENCHMARKS.md`, `benchmarks/` | Measured comparisons and raw results; distinguish historical 2 GiB runs from successful 4 GiB live-refresh tests. |
| `filter_benchmark.py` | Guarded isolated benchmark harness; also imported by several suites, so it stays in the root. |
| `tools/` | `probe_tif_*.py`, `probe_filter_*.py`, legacy `verify_filter_routes.py` and the probe tests. Guarded isolated helpers, not production filter toggles. Run tests with `python -m unittest discover -s tools`. |

## Golden rules

1. **Never run the upstream `app.py` directly against a real resolver.** Its
   form Save/Apply rebuilds `unbound.conf` from a limited key list, silently
   dropping includes, repeated directives, and the remote-control block. Only
   `run.py` (through `safety.py`) is safe to expose.
2. **Never edit `/etc/unbound` files in tests.** Tests must construct a
   temporary config tree and assert the app's resolved paths stay beneath it.
3. **Tests must load the app via `importlib.util.spec_from_file_location`
   with a unique module name** — never `import app`. Python caches modules;
   if any suite imports the production app first, later environment overrides
   (`DEFAULT_CONFIG_FILE` etc.) silently don't apply and a test can overwrite
   the live config. This exact failure happened once; `test_import_isolation.py`
   guards it. Keep that guard green. Its deliberate pre-import is an exception
   for cache-poisoning coverage, run only from the isolated development copy.
4. **Don't commit secrets or host-specific state.** `users.json`, `.secret_key`,
   `ssl_cert.pem`/`ssl_key.pem`, `backups/`, `.env`, and any live resolver
   configuration are gitignored — keep them that way. Do not commit live
   `filter-data/`, `filter-backups/` or literal giant feed fixtures; retain small
   benchmark metadata/hashes, not private policy/config dumps.
5. **Don't hardcode operator addresses** (IPs, LAN subnets, hostnames) into
   source. They belong in env vars, systemd drop-ins, or deployment docs.
6. **Do not enable Full, change client DNS or reload/restart production Unbound
   as part of development/testing.** SSH access is not implicit rollout approval.
   A requested WebUI deployment must preserve existing policies/auth/listeners.

## Filter invariants

- Keep state schema 2 metadata-only for subscriptions; manual arrays remain
  separate. Immutable cache references must stay confined beneath `filter-data`.
  Migrate valid v1 data without dropping metadata, rules, caches or enabled flags,
  retaining the exact v1 backup and never activating DNS during migration.
- Preserve allowlist subtree precedence against every managed source. Local-zone
  output remains `always_nxdomain` with more-specific `transparent` exceptions;
  RPZ is strict QNAME NXDOMAIN input, not arbitrary remote Unbound configuration.
  Test omitted-owner/multiline metadata and split-feed boundaries using actual
  publisher syntax. Unsupported RPZ actions must reject the whole generation.
- New subscriptions start disabled and require a successful refresh. Multiple
  sources are one logical generation: validate every source/redirect, reject
  duplicates, and preserve the entire last-good generation if any source fails.
- Retain HTTPS/443, no URL userinfo, public/global-only DNS answers, TLS hostname
  verification, numeric-address pinning, redirect revalidation and bounded reads.
  Never weaken SSRF protection to make a feed work.
- Do not recreate large arrays, sets, deep copies or whole-file fragment reads in
  the manager. Snapshot/API response size must stay independent of feed size.
  Defaults are 96 MiB/source, 192 MiB/refresh combined, 3M aggregate cached/manual
  domains including disabled lists, 25 subscriptions and 8 sources; enforce actual
  configured finite values and show them in UI/errors.
- Preserve preparation → staged full-tree/fragment validation → complete rollback
  data → atomic managed replacement → live validation → activation and actual DNS
  verification → metadata commit. Failed activation must verify restored policy.
  A service being `active` is not proof that the candidate loaded.
- Fault-inject before/after rename and directory fsync. A failed write may already
  be visible: never delete a generation referenced by persisted state, retained
  archives, an active refresh or an uncertain recovery journal. GC must not race
  cache preparation outside the transaction lock.
- Publish backups from hidden temporary archives only after close/fsync, gzip CRC,
  safe tar member and manifest/state/cache checks. Reject symlink/special config
  entries before staging; serialize regular hardlinks as regular data. Verify both
  new and reused compressed blobs before live changes. Durably sync rollback
  deletions before clearing journals.
- Ten retained archives depend on shared gzip blobs and cache generations: a
  `.tgz` alone is not a complete recovery set. Test distinct changing generations,
  not only repeated identical backups. Offline recovery defaults to dry-run,
  requires the operator to stop the WebUI, restores only managed data and never silently
  activates DNS. Do not delete a journal or reset malformed state to force startup.
- Automatic refresh is off by default; no import-time downloads. Preserve explicit
  lifecycle hooks, same-list exclusion, bounded operations and failed-attempt
  metadata. Test hooks with a real FastAPI/TestClient lifespan, not only fake apps.

## DNS rewrite invariants

- Manage only `webui-rewrites.conf` plus private `rewrite-data`/`rewrite-backups`;
  disabled drafts must not activate DNS. Apply enabled changes once per batch,
  with strict hostname/IP/TTL validation and optimistic revision conflict checks.
- Permit private IPs as A/AAAA RDATA without relaxing subscription download SSRF
  checks. Reject IPv6 scope IDs, URLs/wildcards, duplicate hosts and invalid TTLs.
- Use an independent reserved rewrite canary alongside the filter canary; verify
  actual A/AAAA answers and missing-family NoData. Keep UDP verification bounded
  while advertising EDNS space for long names/multiple IPv6 addresses.
- Do not silently adopt/delete existing local-data or modify the filter allowlist.
  Exact managed NXDOMAIN conflicts require explicit allowlisting; unmanaged
  overrides require explicit migration. Other config/filter bytes stay intact.
- Rewrite backups omit the giant generated filter fragment, recording its hash
  as context. Recovery restores only the small rewrite policy/state and requires
  the stopped WebUI; never claim it restores the complete filter backup set.
- Keep operator-provided mappings out of source/tests. If importing requested
  mappings during rollout, store them as private disabled drafts unless activation
  has been explicitly authorized. Initialize an empty fragment only as an approved
  deployment operation, never during module import or route installation.

## Server config invariants

- The config files are the only state: never add a shadow state file or rebuild
  `unbound.conf` from a key list (that is the upstream bug). Edit the defining line
  in place; keep comments, includes, repeated directives, remote-control and every
  unknown directive byte-identical. Never parse/edit `webui-*.conf` here.
- Read effective/running values through light trees (generated fragments emptied):
  `unbound-control`/`checkconf` against the real tree load ~134 MB of local-zones
  (~1.7 s and ~1 GiB per call). Only full-tree validation uses the real fragments.
- Every new schema key must exist in the installed Unbound
  (`RealToolTests.test_every_schema_key_is_known_to_the_installed_unbound`).
- Keep the lock-out invariants (loopback access/interface/UDP) and the
  acknowledgement requirement for disruptive applies; verify after reload against the
  candidate, not just `systemctl is-active`.
- Tests use a fake Unbound reading the temp tree; never point the manager at
  `/etc/unbound` except for read-only snapshots (`snapshot()` only reads).

## Capacity and benchmark gates

The documented target is now **4 GiB RAM**, with a **2 GiB WebUI/validator service
cap**. The reference unit's conservative 512 MiB default is overridden on the
host; do not bake operator resources/addresses into generic source.

- Unbound's Full local-zone resolver and validator each measured about 1 GiB.
  The old 2 GiB/512 MiB budget failed admission; the same container upgraded to
  4 GiB passed an isolated live refresh with about 1.72 GiB minimum headroom.
  Separate service cgroups in that test did **not** mean separate containers.
- Account for the old resolver, validation child, Python, page cache and reload
  transients. `MemoryMax` includes service children. Measure actual cgroup limits
  and use the true container allocation override when LXC hides its parent limit.
  Keep conservative admission checks, 384 MiB memory reserve and 256 MiB disk
  reserve; don't bypass them merely because one isolated startup fits.
- Native RPZ was worse in the measured comparison; do not change representation
  without new installed-version/configuration measurements and actual allowlist
  wire-DNS proof through the shipped importer.
- Use separate temporary config/filter trees, private control sockets and high
  loopback ports. Never bind/query port 53 in benchmark helpers, include production
  config, mutate live filters, or call production service activation.
- Require an expected DNS response for readiness, not just a TCP-open port. Own
  and reap isolated children on success, exceptions, timeout and Ctrl-C; remove
  temporary trees. Use finite resource/headroom guards and one heavy workload at
  a time unless explicitly measuring safe overlap.
- Record exact URLs/bytes/domain hashes and code revision. Separate fresh Python
  peak RSS, child resolver/validator RSS, container memory and file cache. Report
  repeated cached/uncached/blocked query counts, median/p95/max and errors. Do not
  present mock-upstream latency as WAN performance or missing metrics as success.
- Full reload readiness measured about 8.7 seconds; do not promise continuous
  answering during reload or a client speedup without measuring it. Feed growth,
  workload/cache growth and backup/staging disk use still need admission checks.

## Testing

Tests require the deployment venv (FastAPI/Pydantic v2/httpx) and target Unbound
tools. Run from a separate development copy on that host, **not** the live
`/opt/unbound-webui` directory. The integrated rewrite/filter/config suite is 199 Python
cases plus 44 Node UI cases; keep import-isolation and the real TLS launcher smoke green.

```bash
<deployment-venv>/bin/python -m unittest \
  test_container_memory test_safety test_filters test_filters_scaling \
  test_filter_recovery test_filter_activation test_filter_resources \
  test_filter_regressions test_filter_refresh test_filter_benchmark \
  test_filter_semantics \
  test_rewrites test_rewrite_semantics test_server_config -v
<deployment-venv>/bin/python -m unittest discover -s tools  # probe/benchmark-wrapper tests
<deployment-venv>/bin/python test_import_isolation.py  # must print PASS
node --test test_filters_ui.js test_rewrites_ui.js test_server_config_ui.js
node --check static/js/filters.js
node --check static/js/rewrites.js
node --check static/js/server_config.js
git diff --check
```

`tools/verify_filter_routes.py` is a legacy live-mutating script: do not run it on the
deployment. Current `tools/probe_tif_mini.py`/`tools/probe_tif_full.py` wrap the isolated
`filter_benchmark.py`; `tools/probe_filter_backend.py` and `tools/probe_filter_storage.py`
measure actual backend/retention behavior with controlled cached sources.
Inspect their guards/`--help` before use, and keep workspace/output/source paths
outside production. Never treat `TMPDIR` alone as authorization for a path.

Use generative fixtures, not millions of literal repository domains. For launcher
smokes, explicitly set temporary config/backup paths, loopback/nonproduction TLS
port and refresh off; do not import the live launcher. Exercise real framework
lifecycle APIs and confirm Secure cookies/CSRF/auth boundaries.

## Deployment model

The live instance runs from `/opt/unbound-webui` on the resolver LXC as a
systemd service (`unbound-webui.service`), synced from this repo by scp —
it is not a git checkout. Deploy by editing here, testing on the target,
then copying files. Production config is validated (`unbound-checkconf`)
and backed up before every filter or raw-config change, with automatic rollback
and explicit offline recovery for uncertain publication failures.

The scalable feature is deployed on the documented target, preserving its existing
230,960-domain enabled subscription. **Production Full was not added/enabled;
automatic refresh remains off.** Do not infer activation permission from passing
benchmarks. Keep `main` unmerged until the user explicitly requests integration;
commit/publish feature work only within the requested branch scope.

Before an approved rollout, snapshot configs and policies, back up the private
application/filter state, preserve secrets/TLS/`.configured`/firewall and bind/
bootstrap/redirect drop-ins, stop only the WebUI, copy the approved modules/assets,
then verify migration, hashes/policy counts, HTTPS/auth and unchanged resolver
PID/config. Read-only deployment checks may query production DNS; isolated
benchmarks may not. No new dependency or client DNS change is needed for filtering
inside the same Unbound container. See `DEPLOYMENT.md` for the full procedure.

## Style

- Match the existing dark/orange dashboard aesthetic; layout fixes belong in
  `static/css/responsive.css`, not inline styles in upstream templates.
- Keep upstream files (`app.py`, upstream templates) byte-stable where
  possible — patch them minimally so upstream diffs stay reviewable.
- Test-first for behavior changes: watch the test fail, then implement.
