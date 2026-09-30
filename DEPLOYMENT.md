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

- Container RAM now uses root cgroup memory.current minus reclaimable inactive-file/slab working-set caches, not host `/proc/meminfo` or the WebUI service's 512 MiB limit. Because the LXC hides its parent memory.max, `/etc/systemd/system/unbound-webui.service.d/container-memory.conf` supplies `WEBUI_CONTAINER_MEMORY_BYTES=2147483648`. Update it if Proxmox RAM allocation changes. UI labels are MiB.
- `static/css/responsive.css` removes the main content 1200px cap, shrinks/wraps cards and adds compact Menu navigation under 900px. Static contracts and navigation VM tests passed at 375/768/1280/2560; pixel overflow remains for user confirmation because the user's existing Brave has no usable agent CDP endpoint.
- `/filters` and `filters.py` provide native local-zone filtering in `/etc/unbound/unbound.conf.d/webui-filters.conf`. Always-NXDOMAIN blocks cover apex and children; more-specific transparent exceptions win. Existing module-config remains unchanged.
- Manual blocks/allowlist changes apply immediately after backup and staged/live config validation. Subscriptions are added disabled, refreshed explicitly, then enabled. No list is enabled by default and no scheduler is installed.
- Formats: UTF-8 plain domains, blocking hosts, simple `||domain^`; not full Adblock syntax. Unsupported lines are counted/displayed. Limits: 20 MiB per list, 300k unique cached domains aggregate, 25 subscriptions; public HTTPS/443 only with DNS address pinning and redirect checks.
- Filter state/cache is `/opt/unbound-webui/filter-data/state.json`; full config/state backups are in `filter-backups/` with latest ten retained. Failed downloads preserve last good cache, config and DNS; failed activation restores previous config/state.
- Isolated suites: `venv/bin/python -m unittest test_container_memory test_safety -v` and `venv/bin/python -m unittest test_filters -v`. Never execute verification scripts that mutate live DNS when user rules already exist.
- Integration testing exposed an unsafe app import order in the old tests. Original main config was restored from backup, all original checksums verified, and DNS/exporters recovered. Unbound and exporters restarted during recovery; cache counters restarted. Tests now load a fresh module and assert temporary paths before any write.

## Backup and maintenance

Original DNS and firewall backup: `/root/unbound-webui-backup-20260930-165344/`.
DNS config is unchanged by installation; original service PIDs/start times remained unchanged.
Firewall addition: `/etc/nftables-unbound-webui.nft`, included from existing `/etc/nftables.conf`; exporter restrictions preserved.

Logs: `journalctl -u unbound-webui`.
Control: `systemctl status|restart unbound-webui`.
Tests: `cd /opt/unbound-webui && venv/bin/python -m unittest test_safety -v`.
Tests use a temporary config tree, not the live `/etc/unbound`; authentication is overridden only within the test process.

Tests use an independently loaded app module with asserted temporary paths (not a cached production `app` singleton). The import-isolation regression is `venv/bin/python test_import_isolation.py`. This is required even when different test modules are run together, because setting environment overrides after another module has imported the app does not change its already-resolved paths.

Do not blindly overwrite this tree on upgrade. Re-audit upstream config serialization and merge template fixes plus the launcher/safety layer. This is a small third-party root administration UI, not an internet-facing hardened product. Keep LAN-only exposure. Monitor backups/disk usage on the small LXC.
