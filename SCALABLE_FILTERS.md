# Scalable filter subscriptions

## Storage and policy

The renderer remains Unbound `always_nxdomain` local-zones. Native RPZ is
available in the target's Unbound 1.17.1, but the isolated comparison measured
higher memory and slower validation/startup for RPZ. RPZ **input** is supported;
it is parsed into the same canonical domain cache, not installed as remote
Unbound configuration. No `respip` module is added to the production config.

Schema 1 embedded subscription `domains` arrays in `state.json`. Schema 2 keeps
manual `blocked` and `allowed` arrays, subscription metadata and a stored
`effective_count`. Each subscription has `sources`, `format`, `count`,
`downloaded_bytes`, a relative `cache/<generation>.sqlite` reference and existing
success/attempt/error/parser metadata. `url` remains the first source for API
compatibility. Domains are deduplicated in immutable SQLite generations and
merged using a temporary disk-backed SQLite index. API snapshots do not traverse
or embed subscription domains. Ordinary mutations copy only metadata/manual
rules, not millions of subscription strings.

On first load, schema 1 is validated, caches are prepared, the old state is saved
as `filter-data/state.v1.backup.json`, then schema 2 replaces the state atomically.
Migration retains enabled status, names/IDs, URLs, manual rules, cached domains,
timestamps, errors, unsupported counts and samples. Historical download sizes
are unknown and initially recorded as zero. Migration does not rewrite active
DNS configuration or reload Unbound. Invalid state, missing/malformed caches,
symlinks and conflicting migration backups fail closed: do not delete them to
make the application start. Restore known-good data instead.

## Formats and sources

- `auto`: inspect each source independently; recognize supported domain/hosts/
  Adblock content and RPZ metadata.
- `domains`: fully-qualified plain domains.
- `hosts`: blocking hosts addresses `0.0.0.0`, `127.0.0.1`, `::`, `::1`.
- `adblock`: simple `||domain^` domain rules, not cosmetic rules, options,
  regular expressions or remote exceptions.
- `rpz`: QNAME NXDOMAIN policies (`CNAME .`), with supported `$ORIGIN`, `$TTL`,
  apex SOA/NS metadata, standard omitted owners (including HaGeZi's indented NS
  record), multiline SOA metadata and wildcard owners. Wildcards normalize to the blocked
  apex to preserve the manager's existing apex-and-descendants contract.
  Unsupported RPZ actions/triggers/directives or malformed records reject the
  **whole generation**, rather than silently weakening a policy.

A subscription combines all its HTTPS sources into one generation. Every source
and redirect is independently checked for public HTTPS/443, credential-free URLs
and global-only resolved addresses. TLS hostname checks use the URL hostname;
connections use the validated pinned numeric address. Duplicate source URLs are
rejected after canonicalizing hostname/default port. One failing or empty source
rejects the entire refresh and preserves the previous generation.

New subscriptions are disabled. A successful explicit refresh is required before
enabling. Editing sources/format disables the old policy and invalidates its
cache using the validated transaction; renaming alone retains policy and cache.
Allowlist subtrees win over every managed source, including RPZ inputs, while a
blocked parent continues blocking other descendants.

## Settings

The launcher reads the following environment settings. Invalid/nonpositive limits
fail closed. No new dependency is required (SQLite is in Python's standard
library).

| Environment variable | Default | Meaning |
|---|---:|---|
| `WEBUI_FILTER_MAX_BYTES` | `100663296` (96 MiB) | Maximum downloaded bytes per source |
| `WEBUI_FILTER_MAX_TOTAL_BYTES` | `201326592` (192 MiB) | Aggregate downloaded bytes per logical subscription refresh |
| `WEBUI_FILTER_MAX_ENTRIES` | `3000000` | Unique aggregate domains across manual rules and **all** caches, including disabled subscriptions |
| `WEBUI_FILTER_MAX_SUBSCRIPTIONS` | `25` | Logical subscriptions |
| `WEBUI_FILTER_MAX_SOURCES` | `8` | URLs per logical subscription |
| `WEBUI_FILTER_DOWNLOAD_TIMEOUT` | `120` | Seconds per source, including redirects/resolution |
| `WEBUI_FILTER_REFRESH_TIMEOUT` | `600` | Cooperative total refresh deadline through preparation/validation/commit |
| `WEBUI_FILTER_REFRESH_INTERVAL_SECONDS` | `0` | Off by default; opt-in global interval, 300–604800 seconds |
| `WEBUI_FILTER_CHECKCONF_MAX_BYTES` | `1342177280` (1280 MiB) | Maximum validator child address space; actual budget also respects available container/service memory |
| `WEBUI_FILTER_VERIFY_HOST` | `127.0.0.1` | Numeric address of the actual Unbound listener, not another filtering proxy |
| `WEBUI_FILTER_VERIFY_PORT` | `53` | Actual Unbound DNS port; isolated tests always use separate high ports |
| `WEBUI_FILTER_VERIFY_TIMEOUT` | `10` | Bounded post-activation wire-DNS verification, maximum 60 seconds |

The UI reports the actual running bounds. Automatic refresh starts only through
application startup, not module import. One worker refreshes due **enabled**
subscriptions serially. Successful and failed attempts are throttled; per-list
manager exclusion prevents overlapping manual/scheduled refreshes. Downloads,
parsing and validation are bounded. Shutdown signals the scheduler; the manager
retains transaction/crash protection.

## Transactions and backups

Enabled changes prepare and validate a separate complete Unbound config tree,
create rollback data, atomically replace only `webui-filters.conf`, validate the
live tree, activate Unbound, verify the fragment's SHA-256 TXT canary and an actual
blocked query, then atomically commit metadata. The canary is a private reserved
underscore-label name beneath `.invalid`; it does not count as a filtering rule.
Failures restore the previous fragment/state and verify reactivation of the old
configuration (including legacy policies without a canary). Refresh
errors preserve last-known-good contents/success time and record attempt/error.
Disabled refreshes commit cache/metadata only and never activate DNS.

A transaction journal (`filter-data/transaction.json`) identifies interrupted
changes. Startup refuses further filter writes while this journal exists; it
never guesses or activates DNS automatically. Preserve the journal and referenced
backup until administrator recovery has validated both the restored configuration
and state. Metadata-only saves and migration also journal their previous state;
post-rename/fsync failures restore it before deleting candidates. If restoration
fails, visible metadata, caches and journal are preserved and further writes are
blocked rather than leaving state references pointing to deleted files.

The ten retained `filter-backups/filters_*.tgz` archives contain the other Unbound
configuration, state metadata and `filter-manifest.json`. Each archive is
published under its retained archive name only after a hidden temporary archive
is closed, fsynced and checked for gzip CRC, safe members, manifest and valid
state/cache references. Interrupted writes cannot consume a retained generation.
Config-tree symlinks/special files are refused before staging; ordinary hardlinked
regular files are archived as regular data, matching the recovery validator.
The managed fragment is stored once per content hash as an immutable streaming
gzip `.conf.gz` blob in
`filter-backups/blobs/`. Restore streams decompression and validates CRC, hash and
managed header before replacement. Older uncompressed `.conf` blobs remain
readable. Immutable cache generations referenced by retained backups
are checked again when publishing an archive; this bounded full-cache validation
has a measurable CPU cost for million-domain feeds. New and reused gzip blobs
are both CRC/hash/header/size-verified before live replacement. Missing-original
rollback deletions fsync their parent directory before clearing the journal.
Immutable cache generations referenced by retained backups
are also retained. **A `.tgz` alone is not a complete backup**: copy the entire
`filter-backups` and `filter-data` directories together (e.g. `cp -a` or a full
`tar` archive). Repeated unchanged fragments reuse the same compressed blob.
Distinct large policies still consume disk; garbage collection
only removes generations/blobs no longer referenced by state or retained
backups and never runs over pending refresh candidates.

## Benchmark evidence and deployment

Raw representation-comparison measurements are in
`benchmarks/2026-09-30/mini-result.json` and `full-result.json`. Both use the exact
reported feed bytes/hashes, separate loopback high ports, a deterministic
loopback upstream and a one-CPU affinity. They do not measure WAN/DNSSEC latency.
Resolver/validator RSS and fresh Python worker `ru_maxrss` are separate metrics.
Full native RPZ validation failed under the imposed 1 GiB safety cap, so there
are no Full RPZ startup/latency measurements.

Final backend measurements and disk retention are in
`post-review-backend-full.json` and `post-review-rpz-storage-full.json`, with an
operator summary in `BENCHMARKS.md`. The actual split RPZ subscription produces
the exact same canonical domain digest as the Adblock source. Ten distinct minor
Full variants retained ten caches and gzip rollback blobs using about 670 MiB of
allocated data, not the approximately 1.82 GB raw-blob design.

Memory preflight reserves 384 MiB of container headroom and accounts for the
WebUI's actual service/ancestor cgroup limits. It conservatively budgets 32 MiB
plus nine times managed-fragment bytes for validation; this is a refusal heuristic,
not a reported RSS prediction. The validator uses a fresh interpreter/exec wrapper
to impose finite address space without thread-unsafe `preexec_fn`. Disk preflight
reserves 256 MiB plus operation-specific staging/cache space on both filesystems.

**Full is not recommended for routine validated refresh on the current 2 GiB
LXC/512 MiB WebUI service.** The isolated Full resolver starts and answers quickly,
but it and `unbound-checkconf` each use approximately 1 GiB. Their overlap leaves
no realistic room for other workloads. The real dedicated 512 MiB development
service test refused Full before launching a validator. Retain Mini on these
budgets; if Full is required, review a larger container (4 GiB recommended) and
WebUI service budget, then remeasure the real deployment. Do not bypass preflight
or stop production DNS to fit a validation run. Production resources were not
changed by this work.

## Offline backup/journal recovery

1. Stop **only the WebUI**, leaving Unbound running: `systemctl stop unbound-webui`.
   Preserve `filter-data`, `filter-backups`, current Unbound config and the journal
   together in a separate administrator backup before recovery.
2. Run a validation-only dry run from `/opt/unbound-webui`:

   ```sh
   venv/bin/python filter_recovery.py --base /opt/unbound-webui \
     --main /etc/unbound/unbound.conf \
     --target /etc/unbound/unbound.conf.d/webui-filters.conf --journal
   ```

   To select a retained archive rather than an interrupted transaction, replace
   `--journal` with `--backup filters_<retained-name>.tgz`. Supply only a basename.
3. If validation succeeds, repeat the same command with **`--restore`**. This
   restores only the managed fragment and metadata, creates a safety backup,
   validates staged/live current configuration, and clears the journal after a
   successful commit. It never extracts unrelated archived configuration or
   activates/restarts DNS. Missing/corrupt caches, unsafe archive paths, symlinks,
   invalid gzip/hash/header, policy/cache disagreement or inadequate resources
   cause refusal before replacement. Metadata migration recovery preserves exact
   v1 bytes to avoid a conflicting migration backup.
4. Decide whether DNS activation is needed: metadata-only recovery does not alter
   policy; a config rollback may leave the running resolver on the previously
   loaded candidate. Validate the actual intended config, explicitly reload
   Unbound as an administrator only with adequate measured headroom, and call
   `filter_activation.verify_policy(*filter_activation.read_profile(target))`
   using the configured actual Unbound endpoint. Verify real allowed/blocked
   queries before restarting the WebUI. Never manually delete the journal to
   make startup work.
5. Restart the WebUI through `run.py`/its existing unit and inspect `/filters`.
   If recovery fails, retain all artifacts and the journal; the CLI rolls back
   attempted writes and does not guess which policy to activate.

The recovery command is intentionally offline: stopping the WebUI prevents its
in-process lock/scheduler from racing an administrator CLI. There is no automatic
startup recovery or silent production activation.
