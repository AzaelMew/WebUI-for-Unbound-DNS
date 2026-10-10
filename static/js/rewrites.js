/* DNS rewrites: user and server values only enter textContent / value. */
(() => {
    'use strict';
    const page = document.getElementById('rewrite-page');
    if (!page) return;
    const get = id => document.getElementById(id);
    let state = null, busy = false, stale = false, editing = null;
    const lockedControls = new Map();
    const element = (tag, text, className) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    };
    function notice(message, error = false) {
        get('rewrite-notice').textContent = message;
        get('rewrite-notice').className = 'alert ' + (error ? 'alert-danger' : 'alert-info');
    }
    function lockControls(root = page) {
        if (!busy) return;
        for (const node of root.querySelectorAll('button, input, textarea, select')) {
            if (!lockedControls.has(node)) lockedControls.set(node, node.disabled);
            node.disabled = true;
        }
    }
    function guard(node, disabled) {
        if (busy && lockedControls.has(node)) lockedControls.set(node, disabled);
        node.disabled = busy || disabled;
    }
    function ready() {
        if (busy) return false;
        if (!state || !state.initialized) {
            notice('Managed rewrites are not initialized. Ask the administrator to initialize the managed fragment before saving or applying changes.', true);
            return false;
        }
        if (stale) {
            notice('Saved state changed. Refresh saved state, review it alongside your preserved edits, then save again. Nothing was automatically overwritten.', true);
            return false;
        }
        return true;
    }
    function updateGuards() {
        const blocked = !state || !state.initialized || stale;
        guard(get('rewrite-save'), blocked);
        for (const node of get('rewrite-records').querySelectorAll('.rewrite-mutation')) guard(node, blocked);
        guard(get('rewrite-enable-all'), blocked || !state.records.some(item => !item.enabled));
        guard(get('rewrite-disable-all'), blocked || !state.records.some(item => item.enabled));
    }
    function editorLabel() {
        // Disabling an already-enabled record also changes live DNS.
        const previous = state?.records.find(item => item.hostname === editing);
        const applies = get('rewrite-enabled').checked || Boolean(previous?.enabled);
        get('rewrite-save').textContent = applies ? 'Save & apply' : 'Save draft';
        get('rewrite-editor-hint').textContent = applies
            ? 'This change affects enabled DNS answers and applies in one transaction.'
            : 'Disabled records are saved drafts and do not change DNS.';
    }
    function clearEditor() {
        editing = null;
        get('rewrite-hostname').value = '';
        get('rewrite-addresses').value = '';
        get('rewrite-ttl').value = '300';
        get('rewrite-enabled').checked = false;
        get('rewrite-editor-heading').textContent = 'Add rewrite';
        get('rewrite-cancel').textContent = 'Clear form';
        editorLabel();
    }
    function edit(item) {
        if (busy) return;
        if ((get('rewrite-hostname').value || get('rewrite-addresses').value) && !window.confirm('Replace the editor contents with this saved record? Unsaved editor values will be discarded.')) return;
        editing = item.hostname;
        get('rewrite-hostname').value = item.hostname;
        get('rewrite-addresses').value = item.addresses.join('\n');
        get('rewrite-ttl').value = String(item.ttl);
        get('rewrite-enabled').checked = item.enabled;
        get('rewrite-editor-heading').textContent = `Edit ${item.hostname}`;
        get('rewrite-cancel').textContent = 'Cancel edit';
        editorLabel();
        get('rewrite-hostname').focus();
    }
    function draw(saved) {
        state = saved;
        invalidatePreview();
        get('rewrite-count').textContent = `${state.records.length} saved · ${state.records.filter(item => item.enabled).length} enabled`;
        get('rewrite-state').textContent = `Revision ${state.revision} · Managed file: ${state.managed_file} · Last saved: ${state.last_updated ? new Date(state.last_updated).toLocaleString() : 'Never'}`;
        get('rewrite-limits').textContent = state.limits ? `Limits: ${state.limits.max_records} records, ${state.limits.max_addresses} addresses per hostname. TTL: 1–86400 seconds.` : 'Safety limits unavailable. Ask the administrator to check the server.';
        const list = get('rewrite-records');
        list.replaceChildren();
        if (!state.records.length) list.append(element('p', 'No saved rewrites. Add a record or import disabled drafts.', 'text-dim'));
        for (const item of state.records) {
            const card = element('section', undefined, 'card rewrite-record');
            const head = element('div', undefined, 'card-header');
            head.append(element('h3', item.hostname, 'text-mono'), element('span', item.enabled ? 'Enabled' : 'Disabled draft', 'badge badge-' + (item.enabled ? 'orange' : 'gray')));
            const body = element('div', undefined, 'card-body');
            for (const ip of item.addresses) body.append(element('p', `${ip.includes(':') ? 'AAAA' : 'A'} · ${ip}`, 'text-mono'));
            body.append(element('p', `TTL: ${item.ttl} seconds`, 'text-dim mt-1'));
            const actions = element('div', undefined, 'btn-group rewrite-actions mt-2');
            const action = (label, handler, mutation = true) => {
                const button = element('button', label, 'btn btn-ghost');
                if (mutation) button.className += ' rewrite-mutation';
                button.type = 'button';
                button.disabled = mutation && (!state.initialized || stale);
                button.addEventListener('click', () => { if (!busy) handler(); });
                actions.append(button);
            };
            action('Edit', () => edit(item), false);
            action(item.enabled ? 'Disable & apply' : 'Enable & apply', () => {
                if (!ready()) return;
                mutate(state.records.map(record => record.hostname === item.hostname ? {...record, enabled: !record.enabled} : record), 'Saved and applied in one DNS transaction.');
            });
            action(item.enabled ? 'Delete & apply' : 'Delete draft', () => {
                if (!ready() || !window.confirm(`Delete “${item.hostname}”? ${item.enabled ? 'Its DNS answers will be removed and DNS reloaded.' : 'This removes the saved draft without a DNS reload.'}`)) return;
                mutate(state.records.filter(record => record.hostname !== item.hostname), item.enabled ? 'Deleted and applied.' : 'Draft deleted; no DNS reload.');
            });
            body.append(actions);
            card.append(head, body);
            lockControls(card);
            list.append(card);
        }
        editorLabel();
        updateGuards();
        lockControls();
        if (!state.initialized) notice('Managed rewrites are not initialized. Ask the administrator to initialize the managed fragment before saving or applying changes.', true);
    }
    async function request(payload) {
        const options = {redirect: 'manual', headers: {'X-Requested-With': 'XMLHttpRequest'}};
        if (payload !== undefined) {
            options.method = 'POST';
            options.headers['Content-Type'] = 'application/json';
            options.headers['X-CSRF-Token'] = document.querySelector('meta[name="csrf-token"]')?.content || '';
            options.body = JSON.stringify(payload);
        }
        const response = await fetch('/api/rewrites', options);
        if (response.type === 'opaqueredirect' || [301, 302, 303, 307, 308, 401].includes(response.status)) {
            window.location.assign('/login?next=/rewrites');
            const error = new Error('Your session expired. Sign in again.');
            error.auth = true;
            throw error;
        }
        const data = await response.json();
        if (!response.ok || !data.success) {
            const error = new Error(typeof data.detail === 'string' ? data.detail : (typeof data.error === 'string' ? data.error : 'Request failed. Check your input.'));
            error.status = response.status;
            throw error;
        }
        return data.state;
    }
    function begin() {
        busy = true;
        page.setAttribute('aria-busy', 'true');
        lockControls();
    }
    function finish() {
        busy = false;
        page.removeAttribute('aria-busy');
        for (const [node, disabled] of lockedControls) node.disabled = disabled;
        lockedControls.clear();
        updateGuards();
    }
    async function mutate(records, done, onSuccess) {
        if (!ready()) return;
        const revision = state.revision;
        begin();
        notice('Working… Validating and applying enabled changes may delay DNS queries. Do not repeat the action.');
        try {
            draw(await request({revision, records}));
            if (onSuccess) onSuccess();
            notice(done);
        } catch (error) {
            if (!error.auth) {
                stale = error.status === 409;
                try {
                    const saved = await request();
                    if (saved.revision !== revision) stale = true;
                    draw(saved);
                } catch (_) { /* Keep the original error and all editor values. */ }
            }
            notice(stale ? `${error.message} Saved state changed. Refresh saved state and review before retrying; your edits are preserved. No automatic overwrite.` : error.message, true);
        } finally { finish(); }
    }
    async function refresh() {
        if (busy) return;
        begin();
        try {
            const saved = await request();
            stale = false;
            draw(saved);
            notice(state.initialized ? 'Saved state refreshed. Review the saved records before saving your preserved editor or paste; no edits were applied.' : 'Managed rewrites are not initialized. Ask the administrator to initialize the managed fragment.', !state.initialized);
        } catch (error) { notice(error.message, true); }
        finally { finish(); }
    }
    function hostname(value) {
        const raw = value.trim().replace(/\.$/, '');
        if (!raw || /[\s/*:@?#\\<>"'\[\],%]/.test(raw)) throw new Error('Use an exact hostname, not a URL, wildcard or IP address.');
        let name;
        try { name = new URL('http://' + raw).hostname.toLowerCase(); }
        catch (_) { throw new Error('Invalid hostname.'); }
        if (!name.includes('.') || name.length > 253 || /^\d+(\.\d+)*$/.test(name) || !name.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) throw new Error('Invalid hostname. Use a fully qualified DNS name, not an IP address.');
        return name;
    }
    function address(value) {
        if (/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value) && value.split('.').every(part => Number(part) <= 255)) return value;
        if (value.includes(':') && /^[0-9a-f:.]+$/i.test(value)) {
            try { return new URL('http://[' + value + ']/').hostname.slice(1, -1); }
            catch (_) { /* Fall through to the visible validation error. */ }
        }
        throw new Error(`Invalid IP address: ${value}. Use IPv4 or IPv6 without ports, brackets or zone IDs.`);
    }
    function parseRecord(name, ips, ttl, enabled) {
        if (!/^\d+$/.test(String(ttl)) || Number(ttl) < 1 || Number(ttl) > 86400) throw new Error('TTL must be an integer between 1 and 86400 seconds.');
        const addresses = [...new Set(ips.split(/[\s,]+/).filter(Boolean).map(address))];
        if (!addresses.length) throw new Error('Enter at least one IPv4 or IPv6 address.');
        if (addresses.length > (state?.limits?.max_addresses ?? 16)) throw new Error('Too many addresses for one hostname. Check the displayed limits.');
        return {hostname: hostname(name), addresses, ttl: Number(ttl), enabled};
    }
    get('rewrite-enabled').addEventListener('change', editorLabel);
    get('rewrite-cancel').addEventListener('click', () => { if (!busy) clearEditor(); });
    get('rewrite-refresh').addEventListener('click', refresh);
    get('rewrite-form').addEventListener('submit', event => {
        event.preventDefault();
        if (!ready()) return;
        try {
            const item = parseRecord(get('rewrite-hostname').value, get('rewrite-addresses').value, get('rewrite-ttl').value, get('rewrite-enabled').checked);
            if (editing && !state.records.some(record => record.hostname === editing)) throw new Error('The edited record no longer exists. Review saved state; clear the form to add a new record.');
            if (state.records.some(record => record.hostname === item.hostname && record.hostname !== editing)) throw new Error('This hostname already exists. Edit its saved record or use bulk import to replace it explicitly.');
            const records = editing ? state.records.map(record => record.hostname === editing ? item : record) : [...state.records, item];
            if (records.length > (state.limits?.max_records ?? 1000)) throw new Error('Too many records. Check the displayed limits.');
            const applies = item.enabled || Boolean(state.records.find(record => record.hostname === editing)?.enabled);
            mutate(records, applies ? 'Saved and applied in one DNS transaction.' : 'Saved draft; no DNS reload.', clearEditor);
        } catch (error) { notice(error.message, true); }
    });
    let previewSignature = null;
    function bulkSignature() {
        return JSON.stringify([get('rewrite-bulk-input').value, get('rewrite-bulk-ttl').value, get('rewrite-bulk-disabled').checked, state?.revision]);
    }
    function invalidatePreview() {
        previewSignature = null;
        guard(get('rewrite-import'), true);
        get('rewrite-import').textContent = get('rewrite-bulk-disabled').checked ? 'Import drafts' : 'Import & apply once';
        get('rewrite-preview-result').textContent = 'Preview and validate your paste before importing. Changed inputs or saved state require a new preview.';
    }
    function bulkRecords() {
        const lines = get('rewrite-bulk-input').value.split(/\r?\n/).map((text, index) => ({text: text.trim(), line: index + 1})).filter(line => line.text);
        if (!lines.length) throw new Error('Paste at least one hostname and IP address.');
        const records = [], seen = new Set();
        for (let i = 0; i < lines.length; i++) {
            const current = lines[i], inline = current.text.match(/^(\S+)\s+(.+)$/);
            let name, ips;
            if (inline) { name = inline[1]; ips = inline[2]; }
            else {
                name = current.text;
                if (!lines[i + 1]) throw new Error(`Line ${current.line}: missing IP address after hostname.`);
                ips = lines[++i].text;
            }
            try {
                const item = parseRecord(name, ips, get('rewrite-bulk-ttl').value, !get('rewrite-bulk-disabled').checked);
                if (seen.has(item.hostname)) throw new Error(`Duplicate hostname in paste: ${item.hostname}. Combine its addresses into one entry.`);
                seen.add(item.hostname);
                records.push(item);
            } catch (error) { throw new Error(`Line ${current.line}: ${error.message}`); }
        }
        const merged = new Map(state.records.map(item => [item.hostname, item]));
        for (const item of records) merged.set(item.hostname, item);
        if (merged.size > (state.limits?.max_records ?? 1000)) throw new Error('Import exceeds the record limit. Existing records are not discarded.');
        return {imported: records, merged: [...merged.values()]};
    }
    function previewBulk() {
        if (!ready()) return;
        invalidatePreview();
        const result = get('rewrite-preview-result');
        try {
            const {imported} = bulkRecords();
            result.replaceChildren();
            result.textContent = '';
            result.append(element('p', `${imported.length} records validated. Review every replacement before importing.`, 'text-orange'));
            for (const item of imported) {
                const previous = state.records.find(record => record.hostname === item.hostname);
                const row = element('div', undefined, 'rewrite-preview-row mt-1');
                row.append(element('p', `${item.hostname} · ${previous ? 'Replace ' + (previous.enabled ? 'enabled record' : 'disabled draft') : 'Add new record'} · ${item.enabled ? 'Enabled' : 'Disabled draft'} · TTL ${item.ttl}`, 'text-mono'));
                row.append(element('p', item.addresses.join(', '), 'text-mono text-dim'));
                if (previous) row.append(element('p', `Previously: ${previous.addresses.join(', ')} · TTL ${previous.ttl}`, 'text-dim text-sm'));
                result.append(row);
            }
            const applies = imported.some(item => item.enabled || state.records.find(record => record.hostname === item.hostname)?.enabled);
            result.append(element('p', applies ? 'This import changes enabled answers and applies once. Replacing an enabled record with a draft disables its DNS rewrite.' : 'Only disabled drafts change. No DNS reload.', 'text-orange mt-1'));
            previewSignature = bulkSignature();
            get('rewrite-import').textContent = applies ? 'Import & apply once' : 'Import drafts';
            guard(get('rewrite-import'), false);
        } catch (error) { result.textContent = error.message; }
    }
    get('rewrite-preview').addEventListener('click', previewBulk);
    for (const id of ['rewrite-bulk-input', 'rewrite-bulk-ttl', 'rewrite-bulk-disabled']) {
        get(id).addEventListener('input', () => { if (!busy) invalidatePreview(); });
        get(id).addEventListener('change', () => { if (!busy) invalidatePreview(); });
    }
    get('rewrite-bulk-form').addEventListener('submit', event => {
        event.preventDefault();
        if (!ready()) return;
        if (!previewSignature || previewSignature !== bulkSignature()) {
            invalidatePreview();
            notice('Preview the current paste and options before importing.', true);
            return;
        }
        try {
            const {imported, merged} = bulkRecords();
            const replacements = imported.filter(item => state.records.some(record => record.hostname === item.hostname));
            const applies = imported.some(item => item.enabled || state.records.find(record => record.hostname === item.hostname)?.enabled);
            if (replacements.length && !window.confirm(`Replace ${replacements.length} existing records (enabled records or disabled drafts)? Only matching hostnames are replaced; unrelated records remain. ${applies ? 'This changes enabled DNS answers and applies once; replacing an enabled record with a draft disables it.' : 'These replacements remain disabled drafts; no DNS reload.'}`)) return;
            mutate(merged, applies ? 'Imported and applied in one DNS transaction.' : 'Imported disabled drafts; no DNS reload.', invalidatePreview);
        } catch (error) { notice(error.message, true); }
    });
    for (const [id, enabled] of [['rewrite-enable-all', true], ['rewrite-disable-all', false]]) {
        get(id).addEventListener('click', () => {
            if (!ready()) return;
            const count = state.records.filter(item => item.enabled !== enabled).length;
            if (!count || !window.confirm(`${enabled ? 'Enable' : 'Disable'} ${count} saved ${enabled ? 'drafts' : 'records'} and apply once? Only saved records are included, not unsaved editor values or unimported paste. A full DNS reload may delay queries.`)) return;
            mutate(state.records.map(item => ({...item, enabled})), `${enabled ? 'Enabled' : 'Disabled'} saved records and applied in one DNS transaction.`);
        });
    }
    refresh();
})();
