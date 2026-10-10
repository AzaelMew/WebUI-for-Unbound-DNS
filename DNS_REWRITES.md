# DNS rewrites in the WebUI

Open **DNS rewrites** in the sidebar (`/rewrites`). This is an A/AAAA record editor,
not the upstream configuration form and not the filter allowlist.

## Editing and applying

- Enter an exact fully qualified hostname, IPv4/IPv6 addresses and TTL (1–86400s).
  International hostnames normalize to IDNA; URLs, wildcards, scoped IPv6 and
  duplicate hostnames are rejected. Private addresses are valid DNS RDATA.
- A disabled record is a saved **draft** and changes no DNS answers. Check
  **Enabled** and use **Save & apply** to activate a record. Editing, disabling or
  deleting enabled records applies through a validated transaction.
- Bulk import accepts `hostname IP` lines, comma-separated addresses, or alternating
  hostname/IP lines. Preview first. Imports merge/upsert instead of deleting
  unrelated saved records, and replacing existing names requires confirmation.
  **Import as disabled drafts** is checked by default.
- **Enable all drafts & apply once** performs one transaction/reload for the whole
  saved set, not a reload for every hostname. Unsaved form/paste contents are not
  included until saved/imported.
- Revisions reject stale browser edits with HTTP409. Refresh saved state and review
  it alongside preserved edits before retrying; there is no automatic overwrite.

Limits: **1000 records**, **16 addresses per hostname**. Each address creates an A
or AAAA answer according to its family. Exact-host transparent zones allow other
names/children to resolve normally; a listed A-only hostname returns NoData for
AAAA rather than leaking a public IPv6 address. DNS changes do not configure
reverse proxies, ports, public DNS or client DNS settings. Client caches can retain
old answers until TTL expiry. Large-policy reloads can delay DNS responses.

## Storage and boundaries

- Managed config: `<Unbound-config-dir>/webui-rewrites.conf` only.
- State: `<WebUI-base>/rewrite-data/state.json`, schema1 with `revision`, canonical
  records and last-save metadata. State/directories are private; do not commit them.
- Backups/journal: `rewrite-backups/` and `rewrite-data/transaction.json`.
- Constructor/import/route installation never initializes the fragment or activates
  DNS. An approved deployment explicitly calls `RewriteManager.initialize_empty()`;
  this validates/creates an empty fragment without DNS reload.
- Enabled changes stage the full included configuration, check resource/disk
  admission, require a verified atomically published backup, atomically replace
  only the rewrite fragment, validate live configuration, activate and verify the
  independent rewrite TXT canary plus representative A/AAAA answers, then commit
  metadata. Failure restores/verifies the old policy or retains a recovery journal.
- Disabled-only changes persist metadata without DNS activation. Publication/fsync
  failures preserve recoverable state and block further writes when uncertain.
- Exact existing local-zone/local-data overrides are not silently adopted or
  rewritten. Migrate an unmanaged override explicitly; for an exact managed
  NXDOMAIN filter conflict, first add the hostname to the filter allowlist. The
  allowlist's transparent zone can coexist with the rewrite. A more-specific
  rewrite also coexists with a blocked parent.
- Included paths must be absolute and confined to the selected config root. No
  source downloads are involved and subscription SSRF restrictions stay unchanged.

## Backups and offline recovery

Ten rewrite archives are retained. They contain the small managed rewrite fragment,
state and other config context, with hashes/CRC validation. The large generated
`webui-filters.conf` is deliberately omitted and its hash recorded as context:
**rewrite recovery does not restore filters or unrelated configuration**. Preserve
filter backups separately as described in `SCALABLE_FILTERS.md`.

Backup publication and recovery also require exact canonical agreement between
the stored records and rendered fragment, including the rewrite canary namespace
and hash. A self-consistent archive hash is not permission to restore different
addresses, unrelated directives or a fragment belonging to another policy.

Stop the WebUI before applying offline recovery. Default is validation-only:

```sh
venv/bin/python rewrites_recovery.py --base /opt/unbound-webui \
  --main /etc/unbound/unbound.conf \
  --target /etc/unbound/unbound.conf.d/webui-rewrites.conf
```

This selects the interrupted journal. To select a retained archive, add
`--backup /opt/unbound-webui/rewrite-backups/rewrites_<retained-name>.tgz`.
After a successful dry-run, repeat with **`--apply --webui-stopped`**. It restores
only rewrite state/fragment, validates against the current complete config and
never activates DNS automatically. Explicitly validate/reload/verify the intended
resolver policy before restarting the WebUI. Do not delete a journal or reset
malformed state to bypass recovery.

## Verification

`test_rewrites.py` covers strict normalization, revision conflicts, auth/CSRF,
drafts, batch application, backups, conflicts, malformed data, path protections,
publication failures and offline recovery. `test_rewrite_semantics.py` queries the
actual generated fragment in an isolated resolver, including 14 synthetic mappings,
maximum IPv6 RRsets, family NoData, parent blocking, independent filter/rewrite
canaries and rollback. `test_rewrites_ui.js` exercises real browser-side logic in
an isolated Node DOM harness; no operator host/IP mappings are hardcoded in source.
