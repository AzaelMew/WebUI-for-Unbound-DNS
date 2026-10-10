'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Execute the shipped JS against controls parsed from the shipped template.
// HTML sinks deliberately throw, so escaping mistakes cannot pass unnoticed.
class Element {
    constructor(tag) {
        this.tagName = tag.toUpperCase(); this.children = []; this.attributes = {};
        this.listeners = {}; this.disabled = false; this.checked = false;
        this.value = ''; this._text = ''; this.hidden = false;
    }
    set textContent(value) { this._text = String(value); this.replaceChildren(); }
    get textContent() { return this._text + this.children.map(node => node.textContent).join(''); }
    set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
    set outerHTML(_) { throw new Error('Unsafe HTML sink'); }
    setAttribute(name, value) {
        assert.ok(!/^on/i.test(name), 'No event attributes');
        this.attributes[name] = String(value);
        const properties = ['id', 'type', 'value', 'content'];
        if (properties.includes(name)) this[name] = value;
        if (name === 'class') this.className = value;
        if (['checked', 'required', 'disabled', 'hidden'].includes(name)) this[name] = true;
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
    removeAttribute(name) { delete this.attributes[name]; }
    append(...nodes) {
        for (const node of nodes) {
            node.parentNode = this; this.children.push(node);
            let root = this; while (root.parentNode) root = root.parentNode;
            if (root.onAppend) root.onAppend(node);
        }
    }
    replaceChildren(...nodes) {
        for (const node of this.children) node.parentNode = null;
        this.children = []; this.append(...nodes);
    }
    addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
    dispatch(type) {
        if (type === 'click' && this.disabled) return;
        for (const listener of this.listeners[type] || []) listener({target: this, preventDefault() {}});
    }
    focus() { this.focused = true; }
    matches(selector) {
        if (selector.startsWith('#')) return this.id === selector.slice(1);
        if (selector.startsWith('.')) return (this.className || '').split(/\s+/).includes(selector.slice(1));
        if (selector === 'meta[name="csrf-token"]') return this.tagName === 'META' && this.getAttribute('name') === 'csrf-token';
        return this.tagName.toLowerCase() === selector;
    }
    querySelectorAll(selector) {
        const selectors = selector.split(',').map(value => value.trim()), result = [];
        const walk = node => { for (const child of node.children) {
            if (selectors.some(part => child.matches(part))) result.push(child); walk(child);
        }};
        walk(this); return result;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function documentFromTemplate() {
    const file = path.join(__dirname, 'templates/rewrites.html');
    assert.ok(fs.existsSync(file), 'DNS rewrites template exists');
    const root = new Element('document'), meta = new Element('meta');
    meta.setAttribute('name', 'csrf-token'); meta.setAttribute('content', 'test-csrf'); root.append(meta);
    const stack = [root];
    const html = fs.readFileSync(file, 'utf8').replace(/{[%{][\s\S]*?[%}]}/g, '');
    for (const match of html.matchAll(/<\/?([a-z][\w-]*)\b([^>]*)>|([^<]+)/gi)) {
        if (match[3]) {
            const text = new Element('text'); text.textContent = match[3].replace(/&amp;/g, '&'); stack.at(-1).append(text);
        } else if (match[0].startsWith('</')) {
            if (stack.at(-1).tagName === match[1].toUpperCase()) stack.pop();
        } else {
            const node = new Element(match[1]);
            for (const attr of match[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) node.setAttribute(attr[1], attr[2] ?? '');
            stack.at(-1).append(node);
            if (!['input', 'meta', 'br', 'hr', 'link'].includes(match[1])) stack.push(node);
        }
    }
    root.createElement = tag => new Element(tag);
    root.getElementById = id => root.querySelector('#' + id); return root;
}
const record = (overrides = {}) => ({hostname: 'one.example', addresses: ['192.0.2.1', '2001:db8::1'], ttl: 300, enabled: false, ...overrides});
const snapshot = (overrides = {}) => ({version: 1, revision: 7, initialized: true, managed_file: '/isolated/webui-rewrites.conf', limits: {max_records: 1000, max_addresses: 16}, records: [], last_updated: null, ...overrides});
const response = (state, options = {}) => ({ok: true, status: 200, json: async () => ({success: true, state}), ...options});
const failure = (status, detail) => response(undefined, {ok: false, status, json: async () => ({success: false, detail})});
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; }
async function settle() { await new Promise(done => setImmediate(done)); }
async function harness(state = snapshot(), responder) {
    const document = documentFromTemplate(), calls = [], confirmations = [], redirects = [];
    const window = {confirm: text => { confirmations.push(text); return true; }, location: {assign: url => redirects.push(url)}};
    let current = state;
    const fetch = async (url, options) => {
        const payload = options.body ? JSON.parse(options.body) : undefined;
        calls.push({url, options, payload});
        if (responder) return responder(url, options, calls.length);
        if (payload) current = {...current, revision: current.revision + 1, records: payload.records};
        return response(current);
    };
    const file = path.join(__dirname, 'static/js/rewrites.js');
    assert.ok(fs.existsSync(file), 'DNS rewrites script exists');
    vm.runInNewContext(fs.readFileSync(file, 'utf8'), {document, window, fetch, URL}, {filename: 'rewrites.js'});
    await settle(); return {document, window, calls, confirmations, redirects, get: id => document.getElementById(id)};
}
function button(root, label) {
    const node = root.querySelectorAll('button').find(item => item.textContent === label);
    assert.ok(node, `Button “${label}” exists`); return node;
}
function fillEditor(ui, values = {}) {
    ui.get('rewrite-hostname').value = values.hostname ?? 'new.example';
    ui.get('rewrite-addresses').value = values.addresses ?? '192.0.2.9, 2001:db8::9';
    ui.get('rewrite-ttl').value = values.ttl ?? '300';
    ui.get('rewrite-enabled').checked = values.enabled ?? false;
    ui.get('rewrite-enabled').dispatch('change');
}

test('form saves drafts then edits IPv4/IPv6 and TTL, toggles and confirms deletion with revisioned CSRF requests', async () => {
    const ui = await harness();
    assert.equal(ui.get('rewrite-ttl').value, '300');
    assert.equal(ui.get('rewrite-enabled').checked, false);
    fillEditor(ui);
    assert.equal(ui.get('rewrite-save').textContent, 'Save draft');
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.deepEqual(ui.calls[1].payload, {revision: 7, records: [record({hostname: 'new.example', addresses: ['192.0.2.9', '2001:db8::9']})]});
    assert.equal(ui.calls[1].options.headers['X-CSRF-Token'], 'test-csrf');
    assert.equal(ui.calls[1].options.redirect, 'manual');
    assert.match(ui.get('rewrite-notice').textContent, /draft.*no DNS reload/i);
    button(ui.get('rewrite-records'), 'Edit').dispatch('click');
    assert.equal(ui.get('rewrite-hostname').value, 'new.example');
    assert.equal(ui.get('rewrite-addresses').value, '192.0.2.9\n2001:db8::9');
    fillEditor(ui, {hostname: 'renamed.example', addresses: '2001:db8::2\n192.0.2.2', ttl: '600', enabled: true});
    assert.equal(ui.get('rewrite-save').textContent, 'Save & apply');
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.equal(ui.calls[2].payload.revision, 8);
    assert.deepEqual(ui.calls[2].payload.records, [record({hostname: 'renamed.example', addresses: ['2001:db8::2', '192.0.2.2'], enabled: true, ttl: 600})]);
    button(ui.get('rewrite-records'), 'Disable & apply').dispatch('click'); await settle();
    assert.equal(ui.calls[3].payload.records[0].enabled, false);
    ui.window.confirm = () => false;
    button(ui.get('rewrite-records'), 'Delete draft').dispatch('click');
    assert.equal(ui.calls.length, 4);
    ui.window.confirm = text => { ui.confirmations.push(text); return true; };
    button(ui.get('rewrite-records'), 'Delete draft').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[4].payload, {revision: 10, records: []});
    assert.match(ui.confirmations.at(-1), /renamed.example/);
});

test('bulk preview accepts alternating pairs and comma addresses, merges drafts and confirms existing-host replacements', async () => {
    const ui = await harness(snapshot({records: [record({hostname: 'keep.example', enabled: true}), record()]}));
    assert.equal(ui.get('rewrite-bulk-disabled').checked, true, 'default is safe draft import');
    ui.get('rewrite-bulk-input').value = 'one.example\n192.0.2.8,2001:db8::8\nnew.example 192.0.2.9';
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 1, 'preview required before import');
    ui.get('rewrite-preview').dispatch('click');
    assert.equal(ui.calls.length, 1, 'preview does not mutate');
    assert.match(ui.get('rewrite-preview-result').textContent, /one.example.*Replace.*new.example.*Add/s);
    assert.equal(ui.get('rewrite-import').disabled, false);
    ui.window.confirm = () => false;
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 1, 'overwrite can be cancelled');
    ui.window.confirm = text => { ui.confirmations.push(text); return true; };
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 2);
    assert.deepEqual(ui.calls[1].payload, {revision: 7, records: [
        record({hostname: 'keep.example', enabled: true}),
        record({addresses: ['192.0.2.8', '2001:db8::8']}),
        record({hostname: 'new.example', addresses: ['192.0.2.9']}),
    ]});
    assert.match(ui.confirmations.at(-1), /replace.*draft/i);
    assert.match(ui.get('rewrite-notice').textContent, /draft.*no DNS reload/i);
});

test('enable and disable all operate on the complete saved set with one POST per batch, not on unimported input', async () => {
    const records = Array.from({length: 14}, (_, i) => record({hostname: `host${i}.example`, enabled: i === 0}));
    const ui = await harness(snapshot({records}));
    fillEditor(ui, {hostname: 'unsaved.example'});
    ui.get('rewrite-bulk-input').value = 'unimported.example 192.0.2.70';
    ui.window.confirm = () => false;
    ui.get('rewrite-enable-all').dispatch('click'); assert.equal(ui.calls.length, 1);
    ui.window.confirm = text => { ui.confirmations.push(text); return true; };
    ui.get('rewrite-enable-all').dispatch('click'); await settle();
    assert.equal(ui.calls.length, 2);
    assert.equal(ui.calls[1].payload.records.length, 14);
    assert.ok(ui.calls[1].payload.records.every(item => item.enabled));
    assert.equal(ui.get('rewrite-enable-all').disabled, true);
    assert.equal(ui.get('rewrite-hostname').value, 'unsaved.example');
    assert.equal(ui.get('rewrite-bulk-input').value, 'unimported.example 192.0.2.70');
    ui.get('rewrite-disable-all').dispatch('click'); await settle();
    assert.equal(ui.calls.length, 3);
    assert.ok(ui.calls[2].payload.records.every(item => !item.enabled));
    assert.equal(ui.get('rewrite-disable-all').disabled, true);
});

test('preview warns and labels apply when importing drafts over an enabled record, then invalidates on state refresh', async () => {
    const ui = await harness(snapshot({records: [record({enabled: true})]}));
    ui.get('rewrite-bulk-input').value = 'one.example 192.0.2.8';
    ui.get('rewrite-preview').dispatch('click');
    assert.match(ui.get('rewrite-preview-result').textContent, /disables its DNS rewrite/);
    assert.equal(ui.get('rewrite-import').textContent, 'Import & apply once');
    ui.get('rewrite-refresh').dispatch('click'); await settle();
    assert.equal(ui.get('rewrite-import').disabled, true, 'refresh requires a fresh preview');
    assert.equal(ui.get('rewrite-bulk-input').value, 'one.example 192.0.2.8');
    ui.get('rewrite-preview').dispatch('click');
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.at(-1).payload.records[0].enabled, false);
    assert.match(ui.confirmations.at(-1), /enabled.*disables/i);
    assert.match(ui.get('rewrite-notice').textContent, /applied/i);
});

test('invalid paste and input are rejected before POST, with duplicate IDNA hostname and safety-limit checks', async () => {
    const ui = await harness(snapshot({records: [record()], limits: {max_records: 2, max_addresses: 2}}));
    for (const paste of [
        '', 'missing.example', 'singlelabel 192.0.2.1', '*.example 192.0.2.1', 'https://one.example 192.0.2.1',
        'bad.example 999.0.2.1', 'bad.example 01.2.3.4', 'bad.example 2001:db8:::1',
        'bad.example [2001:db8::1]', 'bad.example fe80::1%eth0',
        'dup.example 192.0.2.1\nDUP.EXAMPLE.\n2001:db8::1',
        'bücher.example 192.0.2.1\nxn--bcher-kva.example 192.0.2.2',
        'bad.example 192.0.2.1,192.0.2.2,192.0.2.3',
        'new.example 192.0.2.1\nmore.example 192.0.2.2',
        '<img src=x onerror=alert(1)> 192.0.2.1',
    ]) {
        ui.get('rewrite-bulk-input').value = paste;
        ui.get('rewrite-preview').dispatch('click');
        assert.equal(ui.get('rewrite-import').disabled, true, `Rejected ${paste}`);
        ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
        assert.equal(ui.calls.length, 1, `No POST for ${paste}`);
    }
    for (const values of [
        {hostname: '192.0.2.1'}, {hostname: 'singlelabel'}, {hostname: '*.example'}, {hostname: '-bad.example'},
        {hostname: 'one.example'}, {addresses: ''}, {addresses: 'not-an-ip'},
        {ttl: '0'}, {ttl: '86401'}, {ttl: '1.5'}, {ttl: '1e2'},
    ]) {
        fillEditor(ui, values); ui.get('rewrite-form').dispatch('submit'); await settle();
        assert.equal(ui.calls.length, 1, `Invalid ${JSON.stringify(values)}`);
    }
    fillEditor(ui, {hostname: ' BÜCHER.example. ', addresses: '2001:0db8::1,2001:db8::1,192.0.2.2'});
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.deepEqual(ui.calls[1].payload.records[1], record({hostname: 'xn--bcher-kva.example', addresses: ['2001:db8::1', '192.0.2.2']}));
});

test('unchecked draft option explicitly imports enabled data once; changed paste cannot reuse a preview', async () => {
    const ui = await harness();
    ui.get('rewrite-bulk-input').value = 'first.example 192.0.2.1\nsecond.example\n2001:db8::2';
    ui.get('rewrite-bulk-disabled').checked = false;
    ui.get('rewrite-bulk-disabled').dispatch('change');
    ui.get('rewrite-bulk-ttl').value = '900';
    ui.get('rewrite-preview').dispatch('click');
    assert.equal(ui.get('rewrite-import').textContent, 'Import & apply once');
    ui.get('rewrite-bulk-input').value += '\nthird.example 192.0.2.3';
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 1);
    assert.equal(ui.get('rewrite-import').disabled, true);
    ui.get('rewrite-preview').dispatch('click');
    ui.get('rewrite-bulk-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 2);
    assert.equal(ui.calls[1].payload.records.length, 3);
    assert.ok(ui.calls[1].payload.records.every(item => item.enabled && item.ttl === 900));
});

test('malicious server hostname, path and error stay literal text through edit, delete and failure refresh', async () => {
    const name = '<img src=x onerror="alert(1)">', error = '<script>alert(2)</script>';
    const state = snapshot({records: [record({hostname: name})], managed_file: '<svg onload=alert(3)>'});
    const ui = await harness(state, (_url, _options, count) => count === 2 ? failure(422, error) : response(state));
    const card = ui.get('rewrite-records').querySelector('section');
    assert.ok(card.textContent.includes(name));
    assert.ok(ui.get('rewrite-state').textContent.includes(state.managed_file));
    assert.equal(card.querySelectorAll('img, svg, script, a').length, 0);
    button(card, 'Edit').dispatch('click'); assert.equal(ui.get('rewrite-hostname').value, name);
    button(card, 'Delete draft').dispatch('click'); await settle();
    assert.ok(ui.confirmations[0].includes(name));
    assert.equal(ui.get('rewrite-hostname').value, name);
    assert.equal(ui.get('rewrite-notice').textContent, error);
    assert.equal(ui.get('rewrite-notice').querySelector('script'), null);
});

test('failed save preserves every edit and bulk option while showing refreshed saved data', async () => {
    const initial = snapshot({records: [record()]});
    const updated = snapshot({records: [record({addresses: ['192.0.2.20']})]});
    const ui = await harness(initial, (_url, _options, count) => count === 2 ? failure(422, 'Validation failed') : response(count === 1 ? initial : updated));
    button(ui.get('rewrite-records'), 'Edit').dispatch('click');
    fillEditor(ui, {hostname: 'edited.example', addresses: '2001:db8::9', ttl: '500', enabled: true});
    ui.get('rewrite-bulk-input').value = 'paste.example 192.0.2.77';
    ui.get('rewrite-bulk-ttl').value = '800'; ui.get('rewrite-bulk-disabled').checked = false;
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.equal(ui.calls.length, 3, 'one POST plus safe saved-state GET');
    assert.match(ui.get('rewrite-notice').textContent, /Validation failed/);
    assert.match(ui.get('rewrite-records').textContent, /192.0.2.20/);
    assert.equal(ui.get('rewrite-hostname').value, 'edited.example');
    assert.equal(ui.get('rewrite-addresses').value, '2001:db8::9');
    assert.equal(ui.get('rewrite-ttl').value, '500'); assert.equal(ui.get('rewrite-enabled').checked, true);
    assert.equal(ui.get('rewrite-bulk-input').value, 'paste.example 192.0.2.77');
    assert.equal(ui.get('rewrite-bulk-ttl').value, '800'); assert.equal(ui.get('rewrite-bulk-disabled').checked, false);
});

test('409 preserves edits and blocks retries until explicit refresh and review of the new revision', async () => {
    const initial = snapshot({records: [record()]}), changed = snapshot({revision: 8, records: [record({ttl: 700})]});
    const ui = await harness(initial, (_url, options, count) => {
        if (count === 2) return failure(409, 'Revision conflict');
        if (options.method === 'POST') return response(snapshot({revision: 9, records: JSON.parse(options.body).records}));
        return response(count === 1 ? initial : changed);
    });
    button(ui.get('rewrite-records'), 'Edit').dispatch('click');
    fillEditor(ui, {hostname: 'one.example', ttl: '600'});
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.match(ui.get('rewrite-notice').textContent, /Refresh.*review.*preserved.*No automatic overwrite/i);
    assert.equal(ui.get('rewrite-ttl').value, '600');
    assert.equal(ui.get('rewrite-save').disabled, true);
    ui.get('rewrite-form').dispatch('submit'); assert.equal(ui.calls.length, 3);
    ui.get('rewrite-refresh').dispatch('click'); await settle();
    assert.equal(ui.get('rewrite-ttl').value, '600');
    assert.equal(ui.get('rewrite-save').disabled, false);
    assert.match(ui.get('rewrite-records').textContent, /700 seconds/);
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.equal(ui.calls[4].payload.revision, 8);
    assert.equal(ui.calls[4].payload.records[0].ttl, 600);
});

test('pending POST locks all controls including redraw-created buttons and preserves guards after unlock', async () => {
    const gate = deferred(), initial = snapshot({records: [record()]}), saved = snapshot({revision: 8, records: [record({enabled: true})]});
    const ui = await harness(initial, (_url, _options, count) => count === 1 ? response(initial) : gate.promise);
    const controls = [], snapshots = [];
    ui.document.onAppend = node => {
        if (node.tagName === 'SECTION' && ui.get('rewrite-page').getAttribute('aria-busy') === 'true') {
            for (const control of node.querySelectorAll('button, input, textarea, select')) snapshots.push(control.disabled);
        }
    };
    button(ui.get('rewrite-records'), 'Enable & apply').dispatch('click');
    assert.equal(ui.get('rewrite-page').getAttribute('aria-busy'), 'true');
    for (const control of ui.get('rewrite-page').querySelectorAll('button, input, textarea, select')) {
        controls.push(control); assert.equal(control.disabled, true);
    }
    ui.get('rewrite-form').dispatch('submit'); ui.get('rewrite-bulk-form').dispatch('submit');
    ui.get('rewrite-enable-all').dispatch('click'); assert.equal(ui.calls.length, 2);
    gate.resolve(response(saved)); await settle();
    assert.ok(snapshots.length > 0); assert.ok(snapshots.every(Boolean));
    assert.equal(ui.get('rewrite-page').getAttribute('aria-busy'), null);
    assert.equal(ui.get('rewrite-hostname').disabled, false);
    assert.equal(button(ui.get('rewrite-records'), 'Edit').disabled, false);
    assert.equal(ui.get('rewrite-enable-all').disabled, true);
    assert.equal(ui.get('rewrite-disable-all').disabled, false);
    assert.equal(ui.get('rewrite-import').disabled, true);
});

test('session redirects and 401 go to login once; CSRF 403 is an error, not a logout', async () => {
    for (const options of [{status: 401}, {status: 302}, {status: 307}, {status: 200, type: 'opaqueredirect'}]) {
        const ui = await harness(snapshot(), (_url, _options, count) => count === 1 ? response(snapshot()) : response(undefined, options));
        fillEditor(ui); ui.get('rewrite-form').dispatch('submit'); await settle();
        assert.deepEqual(ui.redirects, ['/login?next=/rewrites']);
        assert.equal(ui.calls.length, 2, 'no follow-up GET after session expiry');
        assert.equal(ui.get('rewrite-hostname').value, 'new.example');
    }
    const ui = await harness(snapshot(), (_url, _options, count) => count === 2 ? failure(403, 'CSRF token rejected') : response(snapshot()));
    fillEditor(ui); ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.deepEqual(ui.redirects, []);
    assert.match(ui.get('rewrite-notice').textContent, /CSRF token rejected/);
    assert.equal(ui.get('rewrite-hostname').value, 'new.example');
});

test('uninitialized state has administrator warning and guards without bootstrapping or POSTing', async () => {
    const ui = await harness(snapshot({initialized: false, records: [record()]}));
    assert.match(ui.get('rewrite-notice').textContent, /administrator.*initialize/i);
    assert.equal(ui.get('rewrite-save').disabled, true);
    assert.equal(ui.get('rewrite-enable-all').disabled, true);
    assert.equal(button(ui.get('rewrite-records'), 'Enable & apply').disabled, true);
    fillEditor(ui); ui.get('rewrite-form').dispatch('submit');
    ui.get('rewrite-bulk-input').value = 'new.example 192.0.2.9';
    ui.get('rewrite-preview').dispatch('click'); ui.get('rewrite-bulk-form').dispatch('submit');
    await settle(); assert.equal(ui.calls.length, 1);
});

test('stale guard survives a failed error-refresh and disables existing row actions while preserving editor values', async () => {
    const initial = snapshot({records: [record()]});
    const ui = await harness(initial, (_url, _options, count) => count === 1 ? response(initial) : failure(count === 2 ? 409 : 503, count === 2 ? 'Conflict' : 'Unavailable'));
    button(ui.get('rewrite-records'), 'Edit').dispatch('click');
    fillEditor(ui, {hostname: 'edited.example'});
    ui.get('rewrite-form').dispatch('submit'); await settle();
    assert.equal(button(ui.get('rewrite-records'), 'Enable & apply').disabled, true);
    assert.equal(button(ui.get('rewrite-records'), 'Delete draft').disabled, true);
    assert.equal(ui.get('rewrite-hostname').value, 'edited.example');
    assert.match(ui.get('rewrite-notice').textContent, /Conflict.*Refresh.*review/);
    ui.get('rewrite-form').dispatch('submit'); assert.equal(ui.calls.length, 3);
});

test('navigation links DNS rewrites after Filters and page controls have labels and responsive keyboard styling', () => {
    const base = fs.readFileSync(path.join(__dirname, 'templates/base.html'), 'utf8');
    assert.match(base, /href="\/rewrites"[^>]*active_tab=='rewrites'/);
    assert.ok(base.indexOf('href="/rewrites"') > base.indexOf('href="/filters"'));
    assert.ok(base.indexOf('href="/rewrites"') < base.indexOf('href="/debug"'));
    const document = documentFromTemplate();
    for (const id of ['rewrite-hostname', 'rewrite-addresses', 'rewrite-ttl', 'rewrite-enabled', 'rewrite-bulk-input', 'rewrite-bulk-ttl', 'rewrite-bulk-disabled']) {
        assert.ok(document.querySelectorAll('label').some(label => label.getAttribute('for') === id), `${id} has label`);
    }
    assert.match(document.getElementById('rewrite-page').textContent, /public DNS, routing or port forwarding/);
    const css = fs.readFileSync(path.join(__dirname, 'static/css/responsive.css'), 'utf8');
    assert.match(css, /#rewrite-page[\s\S]*focus-visible/);
    assert.match(css, /#rewrite-page[\s\S]*min-height:\s*44px/);
});

test('saved records render all IPv4/IPv6, TTL, status and actual limits without hardcoded entries', async () => {
    const records = Array.from({length: 14}, (_, i) => record({hostname: `host${i}.example`}));
    const ui = await harness(snapshot({records, limits: {max_records: 25, max_addresses: 3}}));
    assert.equal(ui.get('rewrite-records').querySelectorAll('section').length, 14);
    const card = ui.get('rewrite-records').querySelector('section');
    for (const value of ['host0.example', '192.0.2.1', '2001:db8::1', 'A', 'AAAA', '300', 'Disabled']) assert.ok(card.textContent.includes(value));
    assert.match(ui.get('rewrite-limits').textContent, /25.*3/);
    assert.match(ui.get('rewrite-state').textContent, /7/);
    assert.ok(ui.get('rewrite-state').textContent.includes('/isolated/webui-rewrites.conf'));
    assert.equal(ui.calls[0].url, '/api/rewrites');
    assert.equal(ui.calls[0].options.redirect, 'manual');
});
