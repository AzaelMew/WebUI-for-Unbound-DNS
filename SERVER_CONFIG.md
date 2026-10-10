# Server configuration editor

Open **Config** in the sidebar (`/config`). It replaces the upstream form, whose
save/apply rebuilt `unbound.conf` from a fixed key list and was therefore disabled.
Implementation: `server_config.py`, `templates/server_config.html`,
`static/js/server_config.js`.

## How it works

- **The files are the state.** There is no shadow state file. Each load parses the
  real include graph (in Unbound's read order) and asks `unbound-checkconf -o` for
  the file-effective value and `unbound-control get_option` for the running value
  of every managed option, both against a *light copy* of the tree (generated
  `webui-*.conf` fragments emptied) so reads take well under a second.
- **Minimal patches.** Changing an option edits only the line that defines it, in
  the file that defines it (value only; comments, indentation and ordering stay).
  A new option is appended inside the `server:` clause of the file that already
  holds most server directives. **Use default** removes the directive. Lists
  (`interface`, `access-control`, `private-address`) keep unchanged lines and their
  comments and add/remove only the difference. Forward zones are edited in place;
  unknown directives in a zone (e.g. `forward-no-cache`) are preserved.
- **Pending detection.** An option whose file value differs from the running value
  is shown with both values; *Reload Unbound to apply* loads saved-but-unloaded
  changes (validated, then reloaded and verified).
- **Never touched:** `webui-filters.conf` / `webui-rewrites.conf` (their pages own
  them), local-zone/local-data, includes, remote-control and any directive the form
  does not list. Use the **Files & raw editor** tab for those.

## Transaction (same contract as filters and rewrites)

1. Optimistic **revision** (hash of all non-generated files) — stale forms get 409;
   edits are kept in the browser and re-compared against the new files.
2. Plan -> validate input against the schema (types, ranges, no quotes/`#`/control
   characters) -> candidate **invariants** (below).
3. Staged copy of the full tree (hard-linked large fragments) validated by the
   memory-capped `unbound-checkconf`; the option reader proves each edit lands as
   requested in the candidate.
4. Verified backup of the previous bytes (`config-backups/config_*.tgz`, last 10)
   and a recovery journal (`config-data/transaction.json`, previous bytes).
5. Atomic replace preserving owner/mode, live `unbound-checkconf`.
6. **Save & apply** only: `systemctl reload-or-restart unbound`, then wire-DNS
   canaries of the filter/rewrite fragments and `get_option`/`list_forwards`
   comparison against the candidate. Any failure restores the files, reloads and
   re-verifies DNS. A rollback that cannot be verified keeps the journal and blocks
   further edits.

*Validate & save (no reload)* stops after step 5; the badge then shows the option(s)
as pending.

## Invariants (reject, never warn)

- Loopback (`WEBUI_FILTER_VERIFY_HOST`, default 127.0.0.1) stays allowed by the most
  specific `access-control` rule and reachable via `interface`; UDP and the family of
  the verify host stay enabled — otherwise the WebUI could not prove DNS works.
- `cache-min-ttl <= cache-max-ttl`; changed caches must total <= half of available
  memory; `module-config` must end with `iterator`.
- Disruptive options (`port`, `interface`, `access-control`, protocol toggles,
  `module-config`, `tls-upstream`, forwarding) require an explicit acknowledgement to
  *apply* (the UI confirms). A port change makes verification follow the new port
  unless `WEBUI_FILTER_VERIFY_PORT` is set.
- Structured editing is disabled (read-only page) when the graph contains a symlink,
  CRLF/binary/oversize (>1 MiB) non-generated file, relative/escaping include or
  duplicate include; the raw editor still works for the other files.

## Raw editor

Per-file editor for anything else. Same pipeline and invariants, whole-tree option
verification, mandatory acknowledgement when applying; generated fragments and
anything outside the include graph are not selectable.

## Offline recovery

If a transaction was interrupted, the page is read-only until you stop the WebUI and run

```bash
<venv>/bin/python server_config.py --base /opt/unbound-webui --main /etc/unbound/unbound.conf          # dry run
<venv>/bin/python server_config.py --base /opt/unbound-webui --main /etc/unbound/unbound.conf --apply  # restore, never reloads DNS
```

It restores the journalled previous bytes, verifies them and removes the journal.
Review, then reload Unbound yourself.

## Tests

`test_server_config.py` (44 cases: parser, patch minimality, validation, fault
injection at every transaction stage, recovery, real FastAPI routes, real
`unbound-checkconf` on a temp tree when installed) and `test_server_config_ui.js`
(17 Node cases against the shipped template/JS).
