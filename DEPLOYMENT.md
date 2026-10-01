# Local Unbound WebUI deployment

Upstream: https://github.com/mayur-454/WebUI-for-Unbound-DNS
Pinned source commit: 233433be9565eba67d88d78401c44d917a33e5cd

## Operation

- Installed at `/opt/unbound-webui` on `192.168.0.254`.
- Unit: `unbound-webui.service`, enabled on boot; root with systemd filesystem/capability restrictions.
- URL: `https://192.168.0.254` (443); HTTP 80 redirects to HTTPS.
- Certificate is local/self-signed. No public exposure; nftables permits WebUI ports only from `192.168.0.0/24` and blocks IPv6.
- Admin password was chosen on the webpage; only its salted PBKDF2 hash is stored in `users.json`, mode 0600. No default admin/admin listener.
- `/setup` is one-time and restricted to administrator PC 192.168.0.2. A `.configured` marker prevents reopening it.
- Python package versions are captured in `requirements.lock`.

## Safety policy

`run.py` launches upstream through `safety.py`. It fails closed if TLS initialization fails; session cookies require HTTPS. Login requires CSRF and limits attempts. Configuration metadata uses Jinja's tojson serialization. Leading command options are rejected for diagnostic targets.

Upstream form save/apply rebuilds config lossily, so these endpoints are disabled. Config creation/deletion, GUI include/tab rewrites, Unbound certificate deletion/regeneration, TLS regeneration, reboot and network restart are also disabled. The Configuration page explicitly displays this limitation.

Use Configuration -> select an existing file -> Raw Editor. Raw saves preserve the text, stage a copy of the complete Unbound tree, relocate include references in the staged tree, validate both staged main and selected file, require a full-tree backup, atomically replace preserving ownership/mode, validate again, and roll back on failure. Raw save does not activate: use Settings -> Reload after saving. Restore of a single `.conf` backup uses the same validated path and rolls back on activation failure.

The GUI's original backup create/download buttons operate on the selected single file, not the complete config tree. Transaction backups are separate `backups/full_config_*.tgz` files. These full-tree archives are not restored via the single-file GUI uploader.

## Enhancements

- Container RAM now uses root cgroup memory.current minus reclaimable inactive-file/slab working-set caches, not host `/proc/meminfo` or the WebUI service's own 2 GiB limit. Because the LXC hides its parent memory.max, `/etc/systemd/system/unbound-webui.service.d/container-memory.conf` supplies `WEBUI_CONTAINER_MEMORY_BYTES=4294967296`. Update it if Proxmox RAM allocation changes. UI labels are MiB.
- `static/css/responsive.css` removes the main content 1200px cap, shrinks/wraps cards and adds compact Menu navigation under 900px. Static contracts and navigation VM tests passed at 375/768/1280/2560; pixel overflow remains for user confirmation because the user's existing Brave has no usable agent CDP endpoint.
- `/filters` and `filters.py` provide native local-zone filtering in `/etc/unbound/unbound.conf.d/webui-filters.conf`. Always-NXDOMAIN blocks cover apex and children; more-specific transparent exceptions win. Existing module-config remains unchanged.
- Manual blocks/allowlist changes apply after backup, staged/live validation and actual DNS policy verification. Subscriptions are added disabled, refreshed explicitly, then enabled. The global scheduler is off unless `WEBUI_FILTER_REFRESH_INTERVAL_SECONDS` is explicitly configured; imports never download feeds.
- Formats: UTF-8 plain domains, blocking hosts, simple `||domain^`, and strict RPZ QNAME NXDOMAIN input (including split HaGeZi feeds). Multiple sources belong to one logical subscription. Defaults: 96 MiB per source, 192 MiB aggregate per refresh, 3M unique cached domains aggregate including disabled lists, 25 subscriptions, 8 sources per subscription. Public HTTPS/443, DNS pinning and redirect protections remain.
- Schema-v2 `filter-data/state.json` contains metadata/manual rules; immutable SQLite subscription caches live in `filter-data/cache/`. Valid v1 state migrates with a retained exact backup and no DNS activation. The ten retained filter archives require their shared gzip blobs and referenced caches; a `.tgz` alone is not a complete restore. Failed refresh/activation preserves last-known-good rules/cache; uncertain publication retains a recovery journal and fails closed.
- See [SCALABLE_FILTERS.md](SCALABLE_FILTERS.md) for all settings, transaction/resource limits and validated offline backup/journal recovery. [BENCHMARKS.md](BENCHMARKS.md) records the actual Full/Mini measurements. The original 2 GiB/512 MiB service budget could not support safe Full updates. The container is now 4 GiB and the WebUI cap is 2 GiB; an isolated live Full refresh/reload passed with at least 1.72 GiB available. Full remains disabled in production; existing rules were preserved.
- Run suites from a separate development copy using the deployment's venv, not from the live app directory. See `AGENTS.md` for the complete 127-case Python/12-case Node commands. `verify_filter_routes.py` is legacy/live-mutating; current TIF probes are guarded isolated wrappers and must use development paths/high ports.
- Integration testing exposed an unsafe app import order in the old tests. Original main config was restored from backup, all original checksums verified, and DNS/exporters recovered. Unbound and exporters restarted during recovery; cache counters restarted. Tests now load a fresh module and assert temporary paths before any write.

## Backup and maintenance

Original DNS and firewall backup: `/root/unbound-webui-backup-20260930-165344/`.
DNS config is unchanged by installation; original service PIDs/start times remained unchanged.
Firewall addition: `/etc/nftables-unbound-webui.nft`, included from existing `/etc/nftables.conf`; exporter restrictions preserved.

Logs: `journalctl -u unbound-webui`.
Control: `systemctl status|restart unbound-webui`.
Tests: from the separate development copy, run `/opt/unbound-webui/venv/bin/python -m unittest test_safety -v`; never use the live application directory as test cwd.
Tests use a temporary config tree, not the live `/etc/unbound`; authentication is overridden only within the test process.

Tests use an independently loaded app module with asserted temporary paths (not a cached production `app` singleton). The import-isolation regression is `venv/bin/python test_import_isolation.py`. This is required even when different test modules are run together, because setting environment overrides after another module has imported the app does not change its already-resolved paths.

Do not blindly overwrite this tree on upgrade. Re-audit upstream config serialization and merge template fixes plus the launcher/safety layer. This is a small third-party root administration UI, not an internet-facing hardened product. Keep LAN-only exposure. Monitor backups/disk usage on the small LXC.

## Deploying scalable subscriptions

1. Keep production Unbound and client DNS unchanged. Stage this feature revision
   in a separate development directory on the target and run the isolated suites,
   import-isolation guard and probe safety tests there using the existing venv.
2. Stop only `unbound-webui` for the upgrade. Back up the installed application
   code, `filter-data`, `filter-backups`, and Unbound config together, retaining
   permissions. Preserve users/secrets/certificates, `.env`, `.configured`, other
   backups and systemd/firewall drop-ins; do not copy test state or credential files.
3. Copy `filters.py`, `filter_store.py`, `filter_resources.py`,
   `filter_activation.py`, `filter_refresh.py`, `filter_recovery.py`, `run.py`,
   `static/js/filters.js` and `templates/filters.html` from the feature revision.
   `app.py`, `safety.py`, existing authentication/TLS helpers and other Unbound
   config remain unchanged. No additional Python package is required.
4. Set optional filter limits in the WebUI systemd drop-in. Leave automatic
   refresh at `0` initially. For a custom DNS listener, configure
   `WEBUI_FILTER_VERIFY_HOST`/`WEBUI_FILTER_VERIFY_PORT` to **Unbound itself**.
   The UI reads actual limits; do not work around validation by running upstream
   `app.py` directly or disabling resource checks.
5. Start the existing WebUI unit through `run.py`. Valid old state migrates to v2
   while existing DNS stays loaded; inspect `state.v1.backup.json`, metadata,
   subscription counts/enabled flags, and logs. A recovery journal or malformed
   state/cache requires the documented offline recovery, not deletion/reset.
6. Start with a small list/Mini to verify operation even on the current 4 GiB
   container/2 GiB WebUI budget. The previous 2 GiB/512 MiB budget was insufficient
   for routine Full updates.
   Add a subscription disabled, explicitly refresh, inspect metadata, then enable
   only with successful resource/config/DNS checks. Allowlist changes preserve
   parent/child precedence. Turn on a global refresh interval (minimum 300s) only
   after manual operation is verified. HaGeZi advertises eight-hour expiry;
   `28800` seconds is a reasonable explicit global interval if desired.
7. The same container now has 4 GiB RAM and `MemoryMax=2G` for the WebUI;
   `WEBUI_CONTAINER_MEMORY_BYTES` is aligned with that allocation. Isolated live
   Full refresh/reload passed on these budgets (see the completed-deployment
   section and benchmark records). This is not a blanket capacity guarantee:
   confirm service, resolver, cache, validation/reload and disk headroom as feeds
   or workloads grow. The default validator AS cap remains 1280 MiB. Production
   Full still requires explicit operator activation; it was not enabled by rollout.

All development tests/benchmarks used temporary separate config/filter trees and
high loopback ports; production resolver PID/start identity remained unchanged.

## Deployment completed — 2026-10-01

- Deployed feature commit `03e78f7b699e5a6bcdd126342f264cc67b121e19` from the feature
  branch; `main` remains unmerged. WebUI runs the existing `run.py` TLS launcher.
- Container RAM is 4 GiB. The host drop-in reports 4 GiB, caps the WebUI/validator
  cgroup at 2 GiB, and preserves the existing LAN HTTPS443/HTTP80 redirect and
  bootstrap address as environment settings rather than source constants.
- Schema 1 migrated to schema 2 with the original enabled subscription's
  **230,960 cached domains** and metadata preserved. No production config bytes,
  client DNS settings, or Unbound PID/start identity changed. No Full subscription
  was added/enabled and automatic refresh remains off.
- Backup: `/root/unbound-webui-deploy-backup-20261001-050740/`; includes opaque
  app/auth/TLS state (venv excluded), original filter data/code and full Unbound
  config. Keep it private. Resource settings have a separate earlier backup.
- Live verification: HTTPS login200, Secure cookie, login CSRF403, authenticated
  filter API redirect307 without a session, unsafe config save403, normal DNS
  NOERROR and an existing blocked domain NXDOMAIN. Effective service cap2GiB and
  container memory reporting4GiB were checked.
- The two test cgroups belonged to **one container**, emulating the separate
  resolver and WebUI services; they were removed after successful testing. See
  `benchmarks/2026-10-01/` for results. Full activation/reload can delay DNS answers
  briefly; measured readiness after the isolated reload was about8.7 seconds.
