<h1 align="center">WebUI for Unbound DNS</h1>

**AzaelMew's safety-focused fork** of
[mayur-454/WebUI-for-Unbound-DNS](https://github.com/mayur-454/WebUI-for-Unbound-DNS),
based on upstream commit `233433be9565eba67d88d78401c44d917a33e5cd`.
It adds transactional domain filtering, a protected configuration editor,
container-aware memory reporting and responsive UI improvements.

> [!WARNING]
> This is an AI-assisted root administration application for a live DNS resolver,
> not an internet-hardened service. Keep it private/LAN-only, preserve backups,
> and use **`run.py`**, never the upstream `app.py` entrypoint. Incorrect changes
> can disrupt DNS for the entire LAN.

## What this fork provides

- **TLS-only launcher:** secure cookies, login/setup CSRF, login rate limiting
  and one-time administrator setup. Upstream default credentials are invalidated
  before the listener starts.
- **Protected configuration editing:** unsafe/lossy upstream form-save endpoints
  are disabled. The Config page edits only the lines that define each option
  (comments, includes and unknown directives stay intact), validates a staged
  complete config tree, backs up the original, writes atomically, and on *Save &
  apply* reloads Unbound and verifies the running values and DNS, rolling back on
  any failure. It shows where each value is set and which saved options Unbound has
  not loaded yet. A raw per-file editor uses the same pipeline. See `SERVER_CONFIG.md`.
- **Native Unbound filtering:** manual blocks and allowlist subtrees, with
  allowlist exceptions winning over every managed list. Rules live only in
  `unbound.conf.d/webui-filters.conf`; unrelated resolver configuration is preserved.
- **DNS rewrites editor:** manage exact hostname → IPv4/IPv6 answers and TTL from
  the WebUI, with add/edit/delete, disabled drafts, bulk preview/import and one
  validated apply for a batch. No Raw Editor or unsafe upstream save is needed.
- **Scalable subscriptions:** metadata-only state, immutable SQLite caches,
  streamed downloads/parsing and disk-backed deduplication/unions instead of
  millions of strings embedded in `state.json`.
- **Multiple sources per subscription:** combine split feeds into one logical
  cache and update. Sources are individually validated; one failure preserves
  the complete last-known-good subscription.
- **Feed formats:** plain domains, blocking hosts files, simple `||domain^`
  Adblock rules and strict RPZ QNAME NXDOMAIN input, including HaGeZi's split
  feeds. This is not a full Adblock or arbitrary RPZ-action implementation.
- **Safe activation and recovery:** full-tree validation, container/service/disk
  admission checks, actual DNS policy verification, rollback, durable journals
  and compressed backup artifacts with an explicit offline recovery CLI.
- **Opt-in scheduled refresh:** off by default; configurable global interval for
  enabled subscriptions, bounded operations and no overlapping same-list refresh.
- **Container RAM reporting and responsive dark/orange dashboard.**

DNS filtering does not provide cosmetic filtering, remove same-domain ads or
prevent clients from bypassing DNS through another resolver/custom DoH. It also
isn't a replacement for every AdGuard Home feature such as its client-management
or query-log interface.

## Documentation

| Document | Contents |
|---|---|
| [DEPLOYMENT.md](DEPLOYMENT.md) | Installation/upgrade, live deployment, preserving listeners/auth/state and operator maintenance |
| [SCALABLE_FILTERS.md](SCALABLE_FILTERS.md) | State schema/migration, supported syntax, all settings, transactions, backup set and offline recovery |
| [SERVER_CONFIG.md](SERVER_CONFIG.md) | Config page: line-preserving edits, pending-vs-running view, transaction/verification, lock-out invariants and offline recovery |
| [DNS_REWRITES.md](DNS_REWRITES.md) | Direct A/AAAA editing, drafts, bulk import, conflict handling and offline rewrite recovery |
| [BENCHMARKS.md](BENCHMARKS.md) | Actual Mini/Full and native-RPZ comparisons, importer/resolver memory, latency and 4 GiB live-refresh results |
| [AGENTS.md](AGENTS.md) | Contributor/agent safety rules, module ownership, isolated testing and deployment boundaries |

## Setup

For an **existing production resolver**, follow [DEPLOYMENT.md](DEPLOYMENT.md)
first. Do not run an upstream installer or replace your resolver configuration.
The application needs an installed Unbound resolver, `unbound-checkconf`, and
systemd activation support; diagnostic pages also use tools such as `dig`.

### 1. Python environment

Use Python 3.10+ with a venv. On a Debian-based host, install the Python venv/pip
prerequisites if they are missing, then from this checkout:

```sh
python3 -m venv venv
venv/bin/python -m pip install "fastapi[standard]" itsdangerous "cryptography>=42"
```

TLS is **required**, not an optional plaintext fallback. SQLite is part of
Python's standard library; the file-backed filter implementation adds no separate
cache/database dependency. For an existing installation, retain and use its
verified venv rather than blindly upgrading live packages.

### 2. Launch through the safety layer

```sh
venv/bin/python run.py
```

The default listener is **`https://127.0.0.1:8443`**. For a remote host, an SSH
tunnel is a private way to reach the default listener:

```sh
ssh -L 8443:127.0.0.1:8443 <administrator>@<resolver-host>
```

Open `https://127.0.0.1:8443/setup`, choose the administrator password in the
webpage and then sign in. There is **no supported default `admin/admin` login**.
The `.configured` marker closes setup after onboarding. Never send passwords in
chat or commit authentication/TLS files.

A self-signed certificate requires verification/trust on your own server; do not
ignore certificate warnings on unknown endpoints or disable certificate checking
globally.

### 3. Production service and listeners

`unbound-webui.service` is the reference service for `/opt/unbound-webui`.
Keep the existing filesystem/capability restrictions and LAN firewall policy.
Use environment variables/systemd drop-ins for deployment-specific settings:

- `WEBUI_LISTEN_HOST`, `WEBUI_LISTEN_PORT`: listener; default `127.0.0.1:8443`.
- `WEBUI_BOOTSTRAP_IP`: administrator source address for initial setup; default
  loopback. A LAN listener needs a matching explicitly configured bootstrap source.
- `WEBUI_HTTP_REDIRECT`, `WEBUI_HTTP_PORT`: optional redirect-only HTTP listener.
- `WEBUI_CONTAINER_MEMORY_BYTES`: actual container allocation when LXC hides its
  parent memory limit; it is not the WebUI service's `MemoryMax`.

If replacing an older launcher with hardcoded bind/bootstrap settings, move those
settings into the drop-in **before** the upgrade so existing URLs and firewall
assumptions remain unchanged.

The managed filter fragment must be explicitly initialized and included in the
existing config tree before applying filters. Imports/route installation do not
create DNS policy, rewrite includes or reload Unbound. The UI reports an
uninitialized fragment; do not reset an existing nonempty policy to make it start.

## Using subscriptions

1. Open **Domain filters** and add a name, format and one or more public HTTPS
   raw-feed URLs. A new subscription always starts **disabled**.
2. **Refresh now**, inspect counts/bytes/errors/unsupported lines, then explicitly
   enable it. An empty or failed source does not replace the old cache.
3. Use the managed allowlist for exceptions. For a blocked `example.com` and an
   allowed `good.example.com`, other children stay blocked while that allowed
   subtree, including `www.good.example.com`, is exempt.
4. Changing sources or format disables the subscription and invalidates the old
   cache; refresh successfully before re-enabling. Renaming alone preserves policy.

All sources/redirects require public HTTPS on port 443, no URL userinfo, global-only
DNS answers, address pinning and bounded downloads. Do not weaken these checks to
accept private endpoints or concatenate remote RPZ files into live configuration.

### Default filter limits

| Setting | Default |
|---|---:|
| Bytes per source | 96 MiB |
| Bytes per subscription refresh, combined | 192 MiB |
| Unique cached/manual domains, including disabled lists | 3,000,000 |
| Subscriptions / sources per subscription | 25 / 8 |
| Source download / total refresh deadlines | 120 s / 600 s |
| Automatic refresh | Off (`0`) |

Settings are configurable and finite; the UI shows actual configured values.
`WEBUI_FILTER_REFRESH_INTERVAL_SECONDS` enables the global schedule only when
explicitly set to 300–604800 seconds. See [SCALABLE_FILTERS.md](SCALABLE_FILTERS.md)
for environment names and validator/DNS-verification settings.

## Large feeds and one-container deployment

Filtering runs **inside Unbound**, so it does not require a second DNS/filter
container. Clients must use that resolver directly to remove an existing AdGuard
forwarding hop; this project does not change DHCP/router/client DNS automatically.

Measured HaGeZi Full snapshot: **2,389,473 domains**, 48,926,475 Adblock download
bytes; the two RPZ parts produced the same canonical domain set. The file-backed
backend uses approximately **51 MiB Python peak RSS**, but Unbound and its
validator each require approximately **1 GiB** for this representation.

- The original **2 GiB container / 512 MiB WebUI service cap** could not safely
  support routine Full validation alongside the old Full resolver.
- On the **same container upgraded to 4 GiB**, with a **2 GiB WebUI/validator
  budget**, isolated live Full refresh/reload passed while the resolver remained
  running, retaining at least **1.72 GiB available memory**.
- That test used separate service cgroups **within one container**, not two
  containers. Full reload readiness took about **8.7 seconds** and can delay DNS
  answers during activation. No general WAN-speedup claim is implied.
- Native RPZ output was worse in the measured comparison, so production output
  remains local-zones; RPZ is a validated input format.

The feature is deployed on the documented target, with its existing **230,960-
domain** subscription preserved. **Production Full was not added/enabled and
scheduled refresh is off.** Resource admission checks remain necessary as feeds,
caches and workloads grow. Read [BENCHMARKS.md](BENCHMARKS.md) rather than assuming
another resolver's capacity or that every 4 GiB workload will fit.

## Backups and recovery

Config-page saves keep the ten most recent verified backups of the previous file
bytes in `config-backups/`, with a recovery journal in `config-data/` while a
transaction runs. If one is interrupted the page turns read-only; stop the WebUI and
use `server_config.py` (dry run by default, never reloads DNS) as described in
[SERVER_CONFIG.md](SERVER_CONFIG.md).

Filter state is schema-v2 metadata plus immutable cache generations under
`filter-data/`. Valid v1 state migrates with an exact original backup and no DNS
activation. Metadata-only saves and activated transactions preserve recoverable
state/cache sets across publication/fsync failures.

The ten retained filter archives require their shared compressed rollback blobs
and referenced caches. **A `.tgz` alone is not a complete backup.** Preserve
`filter-data` and `filter-backups` together. Archives are atomically published
only after integrity/state checks; new/reused blobs are verified before live
changes, and rollback namespace deletions are directory-fsynced.

If `filter-data/transaction.json` remains, stop the WebUI and follow the
validation-only/offline `filter_recovery.py` procedure in
[SCALABLE_FILTERS.md](SCALABLE_FILTERS.md). Do not delete the journal, silently
reset state, or automatically restart production DNS to bypass recovery.

## Testing and contributing

Use the deployment's venv from a **separate development copy**, with temporary
config/filter trees and asserted path isolation. Never run tests/probes against
production filter state. The integrated rewrite/filter/config suite contains 199 Python
cases plus 44 Node UI cases; the import-isolation guard passed. Launcher and live
deployment checks must also pass before rollout.
The known Starlette/httpx deprecation warning does not represent a failed test.

See [AGENTS.md](AGENTS.md) for the full test commands and probe boundaries.
`verify_filter_routes.py` is a legacy live-mutating script and must not be run on
the deployment. Current `probe_tif_mini.py`/`probe_tif_full.py` are guarded isolated
benchmark wrappers, not production filter toggles.

<details>
  <summary><b>Upstream screenshots (historical UI)</b></summary>

  These show the upstream design, not proof of current fork behavior. In
  particular, unsafe form saves/default-login/plaintext behavior described by
  older upstream instructions is not supported by this fork.

  **Home Page:**
  <img width="1495" height="1186" alt="Upstream home page" src="https://github.com/user-attachments/assets/1bcaf0d8-02d5-4980-ad23-ef0595acf326" />

  **Config Page:**
  <img width="1495" height="1186" alt="Upstream configuration page" src="https://github.com/user-attachments/assets/987ed7cf-5590-4890-aab7-614415d62dc7" />

  **Debug Page:**
  <img width="1495" height="1186" alt="Upstream diagnostic page" src="https://github.com/user-attachments/assets/8bb9823e-1349-4998-b308-3937e151ebec" />

  **Settings Page:**
  <img width="1495" height="1186" alt="Upstream settings page" src="https://github.com/user-attachments/assets/a7ac70aa-1a5a-4306-bd7a-cb10dbcea26d" />

  **Login Page:**
  <img width="1495" height="1186" alt="Upstream login page" src="https://github.com/user-attachments/assets/d73153fd-3139-4891-be51-4770413cd4a8" />
</details>
