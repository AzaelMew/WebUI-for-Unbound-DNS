# AGENTS.md

Guidance for AI agents working on this project.

## What this is

WebUI for an Unbound DNS resolver — a FastAPI app that administers a live,
production DNS server as root. Bugs don't just crash the app; they can take
down DNS for an entire LAN. Treat every change as high-stakes.

Upstream is [mayur-454/WebUI-for-Unbound-DNS](https://github.com/mayur-454/WebUI-for-Unbound-DNS);
this fork (AzaelMew) layers a safety module, domain filters, container-aware
memory reporting, and responsive UI fixes on top of the pinned upstream commit.

## Repository layout

| Path | Role |
|---|---|
| `app.py` | Upstream FastAPI application (pinned upstream code; avoid editing) |
| `auth.py`, `ssl_utils.py` | Upstream auth and TLS certificate helpers |
| `run.py` | **The launcher.** Production entrypoint. Wires upstream through `safety.py`, `container_memory.py`, `filters.py`, then serves TLS-only uvicorn. Bind/listen port come from env (`WEBUI_LISTEN_HOST`, `WEBUI_LISTEN_PORT`), defaulting to `127.0.0.1:8443`. |
| `safety.py` | Deployment policy layer. Disables upstream's lossy form saves, re-implements raw save/restore as validated transactions, adds login/setup CSRF, HTTPS-only cookies, rate limiting. |
| `filters.py` | Domain filter manager: manual blocks, allowlist exceptions, HTTPS blocklist subscriptions. Writes only the managed fragment `unbound.conf.d/webui-filters.conf`. |
| `container_memory.py` | Reports container cgroup working-set memory instead of host `/proc/meminfo` (LXC hides the parent limit; override via `WEBUI_CONTAINER_MEMORY_BYTES`). |
| `templates/`, `static/` | Jinja templates and assets. `responsive.css` is ours; the rest is upstream. |
| `unbound-webui.service` | Reference systemd unit for the deployed service. |
| `DEPLOYMENT.md` | Operator-facing install/maintenance notes for the live deployment. |

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
   guards it. Keep that guard green.
4. **Don't commit secrets or host-specific state.** `users.json`, `.secret_key`,
   `ssl_cert.pem`/`ssl_key.pem`, `backups/`, `.env`, and any live resolver
   configuration are gitignored — keep them that way.
5. **Don't hardcode operator addresses** (IPs, LAN subnets, hostnames) into
   source. They belong in env vars, systemd drop-ins, or deployment docs.

## Testing

Tests require the app venv (FastAPI/Pydantic v2/httpx). Run them on the target
host, not a random machine:

```bash
python -m unittest test_container_memory test_safety -v   # isolated suites
python -m unittest test_filters -v
python test_import_isolation.py                            # must print PASS
```

Never execute `verify_filter_routes.py` or the `probe_tif_*.py` scripts
against a deployment that has real user filters — they mutate and restore
live DNS rules and refuse to run over non-empty state.

## Deployment model

The live instance runs from `/opt/unbound-webui` on the resolver LXC as a
systemd service (`unbound-webui.service`), synced from this repo by scp —
it is not a git checkout. Deploy by editing here, testing on the target,
then copying files. Production config is validated (`unbound-checkconf`)
and backed up before every filter or raw-config change, with automatic
rollback on failure.

## Style

- Match the existing dark/orange dashboard aesthetic; layout fixes belong in
  `static/css/responsive.css`, not inline styles in upstream templates.
- Keep upstream files (`app.py`, upstream templates) byte-stable where
  possible — patch them minimally so upstream diffs stay reviewable.
- Test-first for behavior changes: watch the test fail, then implement.
