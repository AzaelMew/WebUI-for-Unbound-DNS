/* Server configuration editor: server and user values only enter textContent / value. */
(() => {
    'use strict';
    const page = document.getElementById('config-page');
    if (!page) return;
    const get = id => document.getElementById(id);
    const PRESETS = [
        {label: 'Cloudflare (DNS-over-TLS)', zone: {name: '.', addrs: ['1.1.1.1@853#cloudflare-dns.com', '1.0.0.1@853#cloudflare-dns.com'], tls: true, first: false}},
        {label: 'Quad9 (DNS-over-TLS)', zone: {name: '.', addrs: ['9.9.9.9@853#dns.quad9.net', '149.112.112.112@853#dns.quad9.net'], tls: true, first: false}},
    ];
    let state = null, draft = blank(), busy = false, activeTab = 'network', raw = null;
    const invalid = new Set(), rows = new Map(), locked = new Map();

    function blank() { return {changes: {}, lists: {}, zones: null}; }
    function element(tag, text, className) {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    }
    function button(label, id, handler, className = 'btn btn-ghost') {
        const node = element('button', label, className);
        node.type = 'button';
        if (id) node.id = id;
        node.addEventListener('click', () => { if (!busy) handler(); });
        return node;
    }
    function notice(message, error = false) {
        get('cfg-notice').textContent = message;
        get('cfg-notice').className = 'alert ' + (error ? 'alert-danger' : 'alert-info');
    }
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    const lines = text => text.split(/\r?\n/).map(line => line.trim()).filter(Boolean);
    const shown = value => typeof value === 'boolean' ? (value ? 'on' : 'off') : String(value);

    // ---- transport ---------------------------------------------------------
    async function request(method, url, payload) {
        const options = {method, redirect: 'manual', headers: {'X-Requested-With': 'XMLHttpRequest'}};
        if (payload !== undefined) {
            options.headers['Content-Type'] = 'application/json';
            options.headers['X-CSRF-Token'] = document.querySelector('meta[name="csrf-token"]')?.content || '';
            options.body = JSON.stringify(payload);
        }
        const response = await fetch(url, options);
        if (response.type === 'opaqueredirect' || [301, 302, 303, 307, 308, 401].includes(response.status)) {
            window.location.assign('/login?next=/config');
            const error = new Error('Your session expired. Sign in again.');
            error.auth = true;
            throw error;
        }
        const data = await response.json();
        if (!response.ok || !data.success) {
            const error = new Error(typeof data.detail === 'string' ? data.detail : 'Request failed. Check your input.');
            error.status = response.status;
            throw error;
        }
        return data;
    }
    function setBusy(value) {
        busy = value;
        if (value) {
            page.setAttribute('aria-busy', 'true');
            for (const node of page.querySelectorAll('button, input, textarea, select')) {
                if (!locked.has(node)) locked.set(node, node.disabled);
                node.disabled = true;
            }
        } else {
            page.removeAttribute('aria-busy');
            for (const [node, disabled] of locked) node.disabled = disabled;
            locked.clear();
            refreshBar();
        }
    }
    function setDisabled(node, disabled) {
        // Controls changed while a request is in flight keep their intended state when it ends.
        if (busy && locked.has(node)) locked.set(node, disabled);
        node.disabled = busy || disabled;
    }
    async function guarded(task) {
        if (busy) return;
        setBusy(true);
        try { await task(); }
        catch (error) { if (!error.auth) notice(error.message, true); }
        finally { setBusy(false); }
    }
    async function load() {
        const data = await request('GET', '/api/server-config');
        state = data.state;
        reconcile();
        draw();
    }
    function reconcile() {
        for (const [key, value] of Object.entries(draft.changes)) {
            const info = state.values[key];
            if (!info || (value === null ? !info.configured : same(value, info.value))) delete draft.changes[key];
        }
        for (const [key, value] of Object.entries(draft.lists)) {
            if (!state.lists[key] || same(value, state.lists[key].items)) delete draft.lists[key];
        }
        if (draft.zones && !zonesChanged()) draft.zones = null;
    }

    // ---- draft model -------------------------------------------------------
    function zonePayload(zones) { return zones.map(zone => ({name: zone.name.trim().toLowerCase().replace(/(.)\.$/, '$1'), addrs: zone.addrs, tls: Boolean(zone.tls), first: Boolean(zone.first)})); }
    function zonesChanged() {
        return Boolean(draft.zones) && !same(zonePayload(draft.zones), zonePayload(state.forward_zones));
    }
    function fieldOf(key) {
        for (const section of state.schema) for (const field of section.fields) if (field.key === key) return field;
        return null;
    }
    function changeList() {
        const list = [];
        const risky = new Set(state.disruptive);
        for (const [key, value] of Object.entries(draft.changes)) {
            const old = state.values[key].value;
            list.push({key, disruptive: risky.has(key), text: value === null
                ? `${key}: remove from config (Unbound default applies; now ${shown(old)})`
                : `${key}: ${shown(old)} → ${shown(value)}`});
        }
        for (const [key, items] of Object.entries(draft.lists)) {
            const old = state.lists[key].items;
            const added = items.filter(item => !old.includes(item)), removed = old.filter(item => !items.includes(item));
            list.push({key, disruptive: risky.has(key), text: `${key}: +${added.length} −${removed.length}` + (added.length ? ` (add ${added.slice(0, 3).join(', ')}${added.length > 3 ? '…' : ''})` : '') + (removed.length ? ` (remove ${removed.slice(0, 3).join(', ')}${removed.length > 3 ? '…' : ''})` : '')});
        }
        if (zonesChanged()) {
            const before = new Set(zonePayload(state.forward_zones).map(zone => zone.name)), after = new Set(zonePayload(draft.zones).map(zone => zone.name));
            list.push({key: 'forward-zones', disruptive: true, text: `forwarding: ${after.size} zone${after.size === 1 ? '' : 's'} (+${[...after].filter(n => !before.has(n)).length} −${[...before].filter(n => !after.has(n)).length})`});
        }
        return list;
    }
    function canSubmit() {
        return !busy && state && state.editable && !state.recovery_required && !invalid.size && changeList().length > 0;
    }
    function refreshBar() {
        if (!state) return;
        const changes = changeList();
        const summary = get('cfg-summary');
        summary.replaceChildren();
        if (!changes.length) summary.textContent = invalid.size ? 'Fix the highlighted values before saving.' : 'No unsaved changes.';
        else {
            summary.append(element('strong', `${changes.length} unsaved change${changes.length === 1 ? '' : 's'}${invalid.size ? ' · fix highlighted values first' : ''}`));
            const list = element('ul', undefined, 'cfg-changes');
            for (const change of changes) list.append(element('li', change.text + (change.disruptive ? '  ⚠ affects connectivity' : ''), 'text-mono'));
            summary.append(list);
        }
        const ok = canSubmit();
        for (const id of ['cfg-save', 'cfg-apply']) get(id).disabled = busy || !ok;
        get('cfg-discard').disabled = busy || (!changes.length && !invalid.size);
        get('cfg-apply-pending').disabled = busy || !state.editable || state.recovery_required;
        for (const [key, entry] of rows) {
            const changed = key in draft.changes;
            entry.row.className = 'form-row cfg-row' + (changed ? ' cfg-modified' : '');
            const info = state.values[key];
            entry.undo.hidden = !changed;
            entry.reset.hidden = changed || !info.configured;
        }
    }

    // ---- fields ------------------------------------------------------------
    function setValue(field, value) {
        const key = field.key, info = state.values[key];
        invalid.delete(key);
        get('cfg-in-' + key)?.removeAttribute('aria-invalid');
        if (same(value, info.value)) delete draft.changes[key];
        else draft.changes[key] = value;
        refreshBar();
    }
    function fail(field, message) {
        invalid.add(field.key);
        const input = get('cfg-in-' + field.key);
        input?.setAttribute('aria-invalid', 'true');
        notice(`${field.label}: ${message}`, true);
        refreshBar();
    }
    function control(field) {
        const info = state.values[field.key], id = 'cfg-in-' + field.key;
        const current = field.key in draft.changes ? draft.changes[field.key] : info.value;
        const removing = current === null;
        let input;
        if (field.kind === 'bool') {
            const wrap = element('div', undefined, 'toggle-wrap'), label = element('label', undefined, 'toggle');
            input = element('input');
            input.type = 'checkbox';
            input.checked = removing ? info.value : Boolean(current);
            label.append(input, element('span', undefined, 'toggle-slider'));
            wrap.append(label, element('span', input.checked ? 'on' : 'off', 'toggle-label'));
            input.id = id;
            input.addEventListener('change', () => { setValue(field, input.checked); wrap.children[1].textContent = input.checked ? 'on' : 'off'; });
            return {node: wrap, input};
        }
        if (field.kind === 'enum') {
            input = element('select', undefined, 'form-control form-control-sm');
            for (const option of field.options) { const item = element('option', option); item.value = option; input.append(item); }
            input.value = removing ? String(info.value) : String(current);
            input.addEventListener('change', () => setValue(field, input.value));
        } else {
            input = element('input', undefined, 'form-control' + (field.kind === 'int' || field.kind === 'size' ? ' form-control-sm' : ''));
            input.type = field.kind === 'int' ? 'number' : 'text';
            if (field.kind === 'int') { input.min = String(field.min); input.max = String(field.max); input.step = '1'; }
            input.value = removing ? '' : String(current);
            input.setAttribute('spellcheck', 'false');
            input.setAttribute('autocomplete', 'off');
            input.addEventListener('input', () => {
                const text = input.value.trim();
                if (field.kind === 'int') {
                    if (!/^-?\d+$/.test(text) || Number(text) < field.min || Number(text) > field.max) return fail(field, `enter a whole number from ${field.min} to ${field.max}.`);
                    return setValue(field, Number(text));
                }
                if (field.kind === 'size') {
                    if (!/^\d+[kKmMgG]?$/.test(text)) return fail(field, 'use a size such as 256m.');
                    return setValue(field, text.toLowerCase());
                }
                if (!text) { // Empty text removes the directive when it is configured.
                    invalid.delete(field.key);
                    if (info.configured) draft.changes[field.key] = null; else delete draft.changes[field.key];
                    return refreshBar();
                }
                setValue(field, text);
            });
        }
        input.id = id;
        return {node: input, input};
    }
    function metaText(field) {
        const info = state.values[field.key], parts = [];
        parts.push(info.configured ? `Set in ${info.source}` : 'Not set · Unbound default');
        if (info.pending) parts.push(`running: ${shown(info.running)} (reload pending)`);
        if (field.key in draft.changes && draft.changes[field.key] === null) parts.push('will be removed on save');
        return parts.join(' · ');
    }
    function fieldRow(field) {
        const info = state.values[field.key];
        const row = element('div', undefined, 'form-row cfg-row');
        row.id = 'cfg-row-' + field.key;
        const label = element('div', undefined, 'form-label');
        label.append(element('span', field.label, 'key'), element('span', field.desc, 'desc'), element('code', field.key, 'cfg-key'));
        const wrap = element('div', undefined, 'cfg-control');
        const {node, input} = control(field);
        const meta = element('p', metaText(field), 'text-dim text-sm cfg-meta' + (info.pending ? ' text-orange' : ''));
        const undo = button('Undo', 'cfg-undo-' + field.key, () => { delete draft.changes[field.key]; invalid.delete(field.key); drawPanels(); refreshBar(); });
        const reset = button('Use default', 'cfg-reset-' + field.key, () => { draft.changes[field.key] = null; drawPanels(); refreshBar(); });
        undo.hidden = true;
        reset.hidden = true;
        const actions = element('div', undefined, 'btn-group cfg-field-actions');
        actions.append(undo, reset);
        wrap.append(node, meta, actions);
        row.append(label, wrap);
        rows.set(field.key, {row, input, meta, undo, reset});
        if (field.key in draft.changes && draft.changes[field.key] === null) input.disabled = true;
        return row;
    }
    function listEditor(key) {
        const spec = state.list_specs[key], info = state.lists[key];
        const current = key in draft.lists ? draft.lists[key] : info.items;
        const card = element('section', undefined, 'card cfg-list');
        const head = element('div', undefined, 'card-header');
        head.append(element('h3', spec.label), element('code', key, 'cfg-key'));
        if (spec.disruptive) head.append(element('span', 'affects connectivity', 'badge badge-orange'));
        if (info.pending) head.append(element('span', 'running config differs', 'badge badge-gray'));
        const body = element('div', undefined, 'card-body');
        body.append(element('p', spec.desc, 'text-dim mb-1'));
        const area = element('textarea', undefined, 'form-control text-mono');
        area.id = 'cfg-list-' + key;
        area.rows = 6;
        area.value = current.join('\n');
        area.setAttribute('spellcheck', 'false');
        area.setAttribute('placeholder', spec.placeholder);
        area.addEventListener('input', () => {
            const items = lines(area.value);
            if (same(items, info.items)) delete draft.lists[key]; else draft.lists[key] = items;
            refreshBar();
        });
        const undo = button('Undo', 'cfg-list-undo-' + key, () => { delete draft.lists[key]; drawPanels(); refreshBar(); });
        body.append(area, element('p', info.sources.length ? `Defined in ${info.sources.join(', ')}` : 'Not set · Unbound default', 'text-dim text-sm mt-1'), undo);
        card.append(head, body);
        return card;
    }

    // ---- forwarding --------------------------------------------------------
    function zones() { return draft.zones || state.forward_zones; }
    function edit(change) {
        if (!draft.zones) draft.zones = state.forward_zones.map(zone => ({...zone, addrs: [...zone.addrs]}));
        change(draft.zones);
        if (!zonesChanged()) draft.zones = null;
        refreshBar();
    }
    function zoneCard(zone, index) {
        const card = element('section', undefined, 'card cfg-zone');
        const head = element('div', undefined, 'card-header');
        head.append(element('h3', zone.name || 'New zone', 'text-mono'));
        if (zone.source) head.append(element('span', zone.source, 'badge badge-gray'));
        const body = element('div', undefined, 'card-body');
        const name = element('input', undefined, 'form-control text-mono');
        name.id = 'cfg-zone-name-' + index;
        name.value = zone.name;
        name.setAttribute('placeholder', 'example.com or . for everything');
        name.addEventListener('input', () => edit(all => { all[index].name = name.value; }));
        const addrs = element('textarea', undefined, 'form-control text-mono');
        addrs.id = 'cfg-zone-addrs-' + index;
        addrs.rows = 3;
        addrs.value = zone.addrs.join('\n');
        addrs.setAttribute('placeholder', '1.1.1.1@853#cloudflare-dns.com');
        addrs.addEventListener('input', () => edit(all => { all[index].addrs = lines(addrs.value); }));
        body.append(element('label', 'Zone name', 'form-label'), name, element('label', 'Upstream servers (IP[@port][#tls-name], one per line)', 'form-label mt-1'), addrs);
        for (const [flag, text] of [['tls', 'Use DNS-over-TLS to these upstreams'], ['first', 'Fall back to normal recursion if they fail']]) {
            const wrap = element('div', undefined, 'cfg-check mt-1'), box = element('input');
            box.type = 'checkbox';
            box.id = `cfg-zone-${flag}-${index}`;
            box.checked = Boolean(zone[flag]);
            box.addEventListener('change', () => edit(all => { all[index][flag] = box.checked; }));
            wrap.append(box, element('label', text));
            body.append(wrap);
        }
        if (zone.others && zone.others.length) body.append(element('p', `Also has ${zone.others.join(', ')} — preserved as written.`, 'text-dim text-sm mt-1'));
        body.append(button('Remove zone', 'cfg-zone-remove-' + index, () => { edit(all => { all.splice(index, 1); }); drawPanels(); }, 'btn btn-danger mt-1'));
        card.append(head, body);
        return card;
    }
    function forwardingPanel(panel) {
        panel.append(element('p', 'Send queries for a domain (or everything, with ".") to specific upstream resolvers instead of recursing from the roots. Forwarding "." changes how every lookup is resolved, so applying it needs confirmation. DNS-over-TLS needs a CA bundle under Advanced → TLS CA bundle to verify upstream certificates.', 'text-dim mb-2'));
        const list = element('div', undefined, 'cfg-zones');
        zones().forEach((zone, index) => list.append(zoneCard(zone, index)));
        if (!zones().length) list.append(element('p', 'No forward zones: Unbound resolves recursively.', 'text-dim'));
        panel.append(list);
        const actions = element('div', undefined, 'btn-group mt-2');
        actions.append(button('Add zone', 'cfg-zone-add', () => { edit(all => all.push({name: '', addrs: [], tls: false, first: false})); drawPanels(); }, 'btn btn-orange'));
        PRESETS.forEach((preset, index) => actions.append(button(preset.label, 'cfg-preset-' + index, () => {
            edit(all => {
                const at = all.findIndex(zone => zone.name === preset.zone.name);
                const value = {...preset.zone, addrs: [...preset.zone.addrs]};
                if (at >= 0) all[at] = value; else all.push(value);
            });
            drawPanels();
        })));
        panel.append(actions);
    }

    // ---- files / raw editor ------------------------------------------------
    function filesPanel(panel) {
        const table = element('table', undefined, 'info-table');
        table.id = 'cfg-files';
        for (const file of state.files) {
            const tr = element('tr');
            const note = file.role === 'managed' ? 'Generated; edit on the Filters / DNS rewrites pages' : (file.reason || (file.role === 'main' ? 'Main file' : 'Editable'));
            tr.append(element('td', file.path, 'text-mono'), element('td', `${file.directives} directives`), element('td', note, file.role === 'readonly' ? 'text-orange' : 'text-dim'));
            table.append(tr);
        }
        panel.append(element('p', 'Files in the include graph, in the order Unbound reads them. Later definitions override earlier ones.', 'text-dim mb-1'), table);
        const editable = state.files.filter(file => file.role === 'main' || file.role === 'editable');
        const card = element('section', undefined, 'card mt-2');
        const head = element('div', undefined, 'card-header');
        head.append(element('h3', 'Raw file editor'));
        card.append(head);
        const body = element('div', undefined, 'card-body');
        body.append(element('p', 'For anything the form does not cover. Saves are validated on a staged copy and backed up; applying requires confirmation and is verified like form changes. Unsaved form changes are discarded when a raw save succeeds.', 'text-dim mb-1'));
        const select = element('select', undefined, 'form-control');
        select.id = 'cfg-raw-file';
        for (const file of editable) { const option = element('option', file.path); option.value = file.path; select.append(option); }
        const area = element('textarea', undefined, 'form-control text-mono code-area');
        area.id = 'cfg-raw-text';
        area.rows = 16;
        area.setAttribute('spellcheck', 'false');
        area.disabled = true;
        const save = button('Validate & save (no reload)', 'cfg-raw-save', () => saveRaw(false));
        const apply = button('Save & apply', 'cfg-raw-apply', () => saveRaw(true), 'btn btn-orange');
        save.disabled = apply.disabled = true;
        const loadButton = button('Load file', 'cfg-raw-load', () => guarded(async () => {
            const data = await request('GET', '/api/server-config/file?path=' + encodeURIComponent(select.value));
            raw = {path: data.state.path, revision: data.state.revision};
            area.value = data.state.content;
            for (const node of [area, save, apply]) setDisabled(node, false);
            notice(`Loaded ${raw.path}.`);
        }));
        const group = element('div', undefined, 'btn-group mt-1');
        group.append(loadButton, save, apply);
        body.append(select, area, group);
        card.append(body);
        panel.append(card);
    }
    async function saveRaw(apply) {
        if (!raw) return;
        if (apply && !window.confirm(`Save ${raw.path} and reload Unbound? A bad edit can interrupt DNS; failures are rolled back automatically.`)) return;
        if (Object.keys(draft.changes).length || Object.keys(draft.lists).length || zonesChanged()) {
            if (!window.confirm('Unsaved form changes will be discarded after this raw save. Continue?')) return;
        }
        await guarded(async () => {
            try {
                const data = await request('POST', '/api/server-config/file', {revision: state.revision, path: raw.path, content: get('cfg-raw-text').value, apply, acknowledge: apply});
                draft = blank(); invalid.clear(); raw = null;
                state = data.state;
                draw();
                notice(outcome(data));
            } catch (error) { await afterFailure(error); }
        });
    }

    // ---- drawing -----------------------------------------------------------
    function sectionPanel(section) {
        const panel = element('div');
        if (section.intro) panel.append(element('p', section.intro, 'text-dim mb-2'));
        for (const key of section.lists) panel.append(listEditor(key));
        if (section.fields.length) {
            const card = element('section', undefined, 'card');
            const head = element('div', undefined, 'card-header');
            head.append(element('h3', section.title));
            const body = element('div', undefined, 'card-body');
            for (const field of section.fields) body.append(fieldRow(field));
            card.append(head, body);
            panel.append(card);
        }
        return panel;
    }
    function drawPanels() {
        rows.clear();
        const holder = get('cfg-panels'), tabs = get('cfg-tabs');
        holder.replaceChildren();
        tabs.replaceChildren();
        const entries = state.schema.map(section => ({id: section.id, title: section.title, build: () => sectionPanel(section)}));
        entries.splice(2, 0, {id: 'forwarding', title: 'Forwarding', build: () => { const panel = element('div'); forwardingPanel(panel); return panel; }});
        entries.push({id: 'files', title: 'Files & raw editor', build: () => { const panel = element('div'); filesPanel(panel); return panel; }});
        if (!entries.some(entry => entry.id === activeTab)) activeTab = entries[0].id;
        const panels = new Map();
        const select = id => {
            activeTab = id;
            for (const [key, node] of panels) node.hidden = key !== id;
            for (const tab of tabs.children) {
                const on = tab.id === 'cfg-tab-' + id;
                tab.className = 'tab-btn' + (on ? ' active' : '');
                tab.setAttribute('aria-selected', on ? 'true' : 'false');
            }
        };
        for (const entry of entries) {
            const tab = element('button', entry.title, 'tab-btn');
            tab.type = 'button';
            tab.id = 'cfg-tab-' + entry.id;
            tab.setAttribute('role', 'tab');
            tab.addEventListener('click', () => select(entry.id));
            tabs.append(tab);
            const panel = element('div', undefined, 'cfg-panel');
            panel.id = 'cfg-panel-' + entry.id;
            panel.setAttribute('role', 'tabpanel');
            panel.append(entry.build());
            holder.append(panel);
            panels.set(entry.id, panel);
        }
        select(activeTab);
    }
    function draw() {
        drawPanels();
        const files = state.files.length, pending = state.pending;
        const badge = get('cfg-badge');
        if (state.recovery_required) { badge.textContent = 'Recovery required'; badge.className = 'badge badge-red'; }
        else if (!state.editable) { badge.textContent = 'Read-only'; badge.className = 'badge badge-red'; }
        else if (pending.length) { badge.textContent = `${pending.length} pending reload`; badge.className = 'badge badge-orange'; }
        else if (!state.running_available) { badge.textContent = 'Running state unavailable'; badge.className = 'badge badge-gray'; }
        else { badge.textContent = 'In sync with running'; badge.className = 'badge badge-green'; }
        get('cfg-meta').textContent = `Main file: ${state.main} · ${files} files in include graph · Revision ${state.revision.slice(0, 10)}` + (state.running_available ? '' : ' · Running values unavailable (unbound-control)');
        const banner = get('cfg-pending');
        banner.hidden = !pending.length;
        get('cfg-pending-text').textContent = pending.length ? `Saved but not loaded by Unbound: ${pending.join(', ')}. ` : '';
        if (state.recovery_required) notice('An interrupted configuration transaction was detected. Stop the WebUI and run server_config.py recovery; editing is disabled until then.', true);
        else if (!state.editable) notice('Structured editing is disabled: ' + state.blockers.join('; '), true);
        refreshBar();
    }

    // ---- actions -----------------------------------------------------------
    function outcome(data) {
        const backup = data.backup ? ` Backup: ${data.backup}.` : '';
        const warn = data.warnings && data.warnings.length ? ' ' + data.warnings.join(' ') : '';
        if (data.unchanged) return 'No effective change: the files already contain these values.';
        if (data.applied) return 'Saved, reloaded Unbound and verified the running configuration.' + backup + warn;
        return 'Validated and saved. Unbound keeps running the previous settings until you reload.' + backup + warn;
    }
    async function afterFailure(error) {
        if (error.auth) return;
        try {
            const data = await request('GET', '/api/server-config');
            state = data.state;
            reconcile();
            draw();
        } catch (_) { /* Keep the original error and the draft. */ }
        notice(error.status === 409 ? `${error.message} Your edits are kept and now compared against the new files; review the summary and save again.` : error.message, true);
    }
    async function submit(apply) {
        if (!canSubmit()) return;
        const changes = changeList(), risky = changes.filter(change => change.disruptive);
        const question = apply
            ? `Save and apply ${changes.length} change${changes.length === 1 ? '' : 's'}?${risky.length ? ' This can interrupt DNS or lock clients out (' + risky.map(change => change.key).join(', ') + '); a failed check is rolled back automatically.' : ''}\n\n${changes.map(change => change.text).join('\n')}`
            : null;
        if (question && (risky.length || changes.length > 3) && !window.confirm(question)) return;
        await guarded(async () => {
            notice(apply ? 'Working… validating, backing up, reloading and verifying. DNS may pause briefly; do not repeat the action.' : 'Working… validating and saving.');
            try {
                const data = await request('POST', '/api/server-config', {
                    revision: state.revision, changes: draft.changes, lists: draft.lists,
                    zones: zonesChanged() ? zonePayload(draft.zones) : null, apply, acknowledge: apply && risky.length > 0,
                });
                draft = blank(); invalid.clear();
                state = data.state;
                draw();
                notice(outcome(data));
            } catch (error) { await afterFailure(error); }
        });
    }
    get('cfg-save').addEventListener('click', () => submit(false));
    get('cfg-apply').addEventListener('click', () => submit(true));
    get('cfg-discard').addEventListener('click', () => {
        if (busy) return;
        draft = blank();
        invalid.clear();
        drawPanels();
        refreshBar();
        notice('Unsaved changes discarded.');
    });
    get('cfg-apply-pending').addEventListener('click', () => {
        if (busy || !state) return;
        if (!window.confirm(`Reload Unbound now to load: ${state.pending.join(', ')}? The files are already saved, so a failed reload cannot be rolled back automatically. DNS may pause briefly.`)) return;
        guarded(async () => {
            notice('Working… reloading and verifying.');
            try {
                const data = await request('POST', '/api/server-config/apply-pending', {revision: state.revision});
                state = data.state;
                reconcile();
                draw();
                notice('Reloaded Unbound and verified the running configuration.');
            } catch (error) { await afterFailure(error); }
        });
    });
    guarded(async () => {
        await load();
        if (state.editable && !state.recovery_required) notice('Configuration loaded. Change values, then validate & save or save & apply.');
    });
})();
