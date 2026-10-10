# Dashboard

`/dashboard` shows query rate, cache hit rate, recursion time and response codes over
1h / 6h / 24h / 7d, plus lists for query types, response codes, cache size and (when
logged) top domains, clients and blocked names. Inspired by
[ar51an/unbound-dashboard](https://github.com/ar51an/unbound-dashboard), but with no
Grafana/Prometheus/Loki: history lives in one small SQLite file.

## How it works

- `dashboard.py` samples `unbound-control stats_noreset` every 60 s in one background
  thread started by the app lifecycle. It runs against a **light** config tree (the same
  one `server_config.py` uses), so a sample never parses the giant generated filter
  fragment.
- Samples go to `dashboard-data/metrics.sqlite` (0600, gitignored), only the dashboard's
  counters, pruned past the retention window. Rates are computed at read time from counter
  deltas; a restart/reset is detected and never produces negative rates. Missing samples
  show as gaps, not interpolated lines. Recursion time is a true windowed average.
- Read-only: it never edits config, filters or rewrites and never enables logging.
- Charts are dependency-free SVG (`static/js/dashboard.js`); remote values only reach the
  DOM through `textContent`.

## Settings (environment / systemd drop-in)

| Variable | Default | Meaning |
|---|---|---|
| `WEBUI_DASHBOARD_SAMPLE_SECONDS` | `60` | Sample interval (10-3600); `0` disables sampling |
| `WEBUI_DASHBOARD_RETENTION_DAYS` | `7` | History kept (1-30) |

About 1 KB per sample: roughly 10 MB for 7 days at 60 s.

## Data requirements

- `extended-statistics: yes` for response-code and query-type panels (the page says so if
  missing; it does not change the setting).
- Top domains/clients/blocked are parsed from Unbound's own log file (`WEBUI_DASHBOARD_QUERY_LOG`, default `/var/log/unbound/unbound.log`, plus the `.1` rotation; journal fallback): `log-replies: yes` (or `log-queries`) for domains/clients, `log-local-actions: yes` for blocked. They follow the selected range as far as the log reaches (newest 24 MiB read).
  Cached 30 s per range. The formats were checked against the live `log-replies` / `log-local-actions` lines.
- NXDOMAIN % includes filter blocks (`always_nxdomain`); Unbound exposes no separate counter.

## Tests

```bash
<deployment-venv>/bin/python -m unittest test_dashboard -v
node --test test_dashboard_ui.js
node --check static/js/dashboard.js
```
