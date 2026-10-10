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
    const file = path.join(__dirname, 'templates/server_config.html');
    assert.ok(fs.existsSync(file), 'Server config template exists');
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
const field = (key, kind, label, extra = {}) => ({key, kind, label, desc: `About ${key}`, ...extra});
const SCHEMA = [
    {id: 'network', title: 'Network', lists: ['interface'], fields: [field('port', 'int', 'Port', {min: 1, max: 65535, disruptive: true}), field('do-ip6', 'bool', 'IPv6', {disruptive: true})]},
    {id: 'access', title: 'Access control', lists: ['access-control'], fields: [], intro: 'Most specific wins.'},
    {id: 'security', title: 'Security', lists: [], fields: [field('identity', 'str', 'Identity'), field('hide-identity', 'bool', 'Hide identity')]},
    {id: 'performance', title: 'Performance', lists: [], fields: [field('cache-min-ttl', 'int', 'Minimum TTL', {min: 0, max: 2147483647}), field('rrset-cache-size', 'size', 'RRset cache', {min: 65536, max: 1 << 30}), field('verbosity', 'enum', 'Verbosity', {options: ['0', '1', '2']})]},
];
const value = (v, extra = {}) => ({value: v, configured: true, source: 'unbound.conf.d/unbound.conf:9', running: v, pending: false, ...extra});
const snapshot = (overrides = {}) => ({
    revision: 'a'.repeat(64), main: '/isolated/unbound.conf', schema: SCHEMA,
    list_specs: {interface: {label: 'Listen addresses', desc: 'One per line', placeholder: '0.0.0.0', disruptive: true},
        'access-control': {label: 'Client access rules', desc: 'network action', placeholder: '10.0.0.0/8 allow', disruptive: true}},
    values: {port: value(53), 'do-ip6': value(true), identity: value('', {configured: false, source: null, running: ''}), 'hide-identity': value(true),
        'cache-min-ttl': value(300), 'rrset-cache-size': value('256m'), verbosity: value('0')},
    lists: {interface: {items: ['0.0.0.0', '::'], running: ['0.0.0.0', '::'], pending: false, sources: ['unbound.conf.d/unbound.conf:2']},
        'access-control': {items: ['127.0.0.1/32 allow', '10.0.0.0/8 allow'], running: [], pending: false, sources: []}},
    forward_zones: [], running_available: true, running_error: null, pending: [], editable: true, blockers: [],
    disruptive: ['port', 'do-ip6', 'interface', 'access-control'], recovery_required: false,
    files: [{path: 'unbound.conf', role: 'main', reason: '', size: 80, directives: 0}, {path: 'unbound.conf.d/unbound.conf', role: 'editable', reason: '', size: 900, directives: 30},
        {path: 'unbound.conf.d/webui-filters.conf', role: 'managed', reason: 'Generated', size: 99, directives: 0}],
    limits: {}, ...overrides,
});
const ok = (state, extra = {}) => ({ok: true, status: 200, json: async () => ({success: true, state, ...extra})});
const fail = (status, detail) => ({ok: false, status, json: async () => ({success: false, detail})});
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise(done => setImmediate(done)); };
async function harness(initial = snapshot(), responder) {
    const document = documentFromTemplate(), calls = [], confirmations = [], redirects = [];
    const window = {confirm: text => { confirmations.push(text); return harness.answer; }, location: {assign: url => redirects.push(url)}};
    harness.answer = true;
    let current = initial;
    const fetch = async (url, options) => {
        const payload = options.body ? JSON.parse(options.body) : undefined;
        calls.push({url, options, payload});
        if (responder) { const response = responder(url, options, payload, calls.length, current); if (response) return response; }
        if (options.method === 'POST' && url === '/api/server-config') {
            const next = snapshot({revision: 'b'.repeat(64), values: {...current.values}});
            for (const [key, v] of Object.entries(payload.changes)) next.values[key] = v === null ? {...value(0), configured: false, source: null} : value(v);
            current = next;
            return ok(current, {applied: payload.apply, unchanged: false, backup: 'config_1.tgz'});
        }
        return ok(current);
    };
    const script = fs.readFileSync(path.join(__dirname, 'static/js/server_config.js'), 'utf8');
    vm.runInNewContext(script, {document, window, fetch, URL, encodeURIComponent}, {filename: 'server_config.js'});
    await settle();
    return {document, window, calls, confirmations, redirects, get: id => document.getElementById(id)};
}
const type = (node, text) => { node.value = text; node.dispatch('input'); };

test('renders every section from the server schema with sources and a sync badge', async () => {
    const ui = await harness();
    assert.equal(ui.calls[0].url, '/api/server-config');
    assert.deepEqual(ui.get('cfg-tabs').children.map(tab => tab.textContent),
        ['Network', 'Access control', 'Forwarding', 'Security', 'Performance', 'Files & raw editor']);
    assert.equal(ui.get('cfg-in-port').value, '53');
    assert.equal(ui.get('cfg-in-do-ip6').checked, true);
    assert.equal(ui.get('cfg-in-rrset-cache-size').value, '256m');
    assert.equal(ui.get('cfg-list-interface').value, '0.0.0.0\n::');
    assert.match(ui.get('cfg-row-port').textContent, /Set in unbound\.conf\.d\/unbound\.conf:9/);
    assert.match(ui.get('cfg-row-identity').textContent, /Not set · Unbound default/);
    assert.equal(ui.get('cfg-badge').textContent, 'In sync with running');
    assert.equal(ui.get('cfg-panel-network').hidden, false);
    assert.equal(ui.get('cfg-panel-security').hidden, true);
    ui.get('cfg-tab-security').dispatch('click');
    assert.equal(ui.get('cfg-panel-security').hidden, false);
    assert.equal(ui.get('cfg-save').disabled, true);
    assert.match(ui.get('cfg-files').textContent, /webui-filters\.conf.*Generated; edit on the Filters/s);
});

test('a value Unbound lowered itself is explained, not flagged as pending', async () => {
    const state = snapshot();
    state.values['cache-min-ttl'] = value(300, {running: 120, reduced: true});
    const ui = await harness(state);
    assert.match(ui.get('cfg-row-cache-min-ttl').textContent, /running: 120 \(Unbound lowered it to fit a system limit\)/);
    assert.equal(ui.get('cfg-pending').hidden, true);
    assert.equal(ui.get('cfg-badge').textContent, 'In sync with running');
});

test('single non-disruptive change applies without confirmation using a revisioned CSRF request', async () => {
    const ui = await harness();
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    assert.match(ui.get('cfg-summary').textContent, /1 unsaved change.*cache-min-ttl: 300 → 60/s);
    assert.equal(ui.get('cfg-apply').disabled, false);
    ui.get('cfg-apply').dispatch('click'); await settle();
    const post = ui.calls[1];
    assert.equal(post.options.headers['X-CSRF-Token'], 'test-csrf');
    assert.equal(post.options.redirect, 'manual');
    assert.deepEqual(post.payload, {revision: 'a'.repeat(64), changes: {'cache-min-ttl': 60}, lists: {}, zones: null, apply: true, acknowledge: false});
    assert.deepEqual(ui.confirmations, []);
    assert.match(ui.get('cfg-notice').textContent, /reloaded Unbound and verified/);
    assert.equal(ui.get('cfg-in-cache-min-ttl').value, '60');
    assert.equal(ui.get('cfg-apply').disabled, true);
});

test('save-only reports that the running resolver is unchanged', async () => {
    const ui = await harness();
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    ui.get('cfg-save').dispatch('click'); await settle();
    assert.equal(ui.calls[1].payload.apply, false);
    assert.match(ui.get('cfg-notice').textContent, /keeps running the previous settings/);
});

test('disruptive changes need confirmation, send acknowledge and can be declined', async () => {
    const ui = await harness();
    type(ui.get('cfg-in-port'), '5353');
    assert.match(ui.get('cfg-summary').textContent, /port: 53 → 5353.*affects connectivity/s);
    harness.answer = false;
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(ui.calls.length, 1, 'declined confirmation sends nothing');
    assert.match(ui.confirmations[0], /interrupt DNS.*port/s);
    harness.answer = true;
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(ui.calls[1].payload.acknowledge, true);
    // Saving without applying never claims connectivity risk.
    type(ui.get('cfg-in-port'), '53');
    ui.get('cfg-save').dispatch('click'); await settle();
    assert.equal(ui.calls.at(-1).payload.acknowledge, false);
});

test('invalid values block submission and are marked; fixing them re-enables saving', async () => {
    const ui = await harness();
    const input = ui.get('cfg-in-port');
    type(input, '99999');
    assert.equal(input.getAttribute('aria-invalid'), 'true');
    assert.equal(ui.get('cfg-apply').disabled, true);
    assert.match(ui.get('cfg-notice').textContent, /whole number from 1 to 65535/);
    type(input, '5353');
    assert.equal(input.getAttribute('aria-invalid'), null);
    assert.equal(ui.get('cfg-apply').disabled, false);
    type(ui.get('cfg-in-rrset-cache-size'), '12 mb');
    assert.equal(ui.get('cfg-save').disabled, true);
    type(ui.get('cfg-in-rrset-cache-size'), '512M');
    assert.equal(ui.get('cfg-in-rrset-cache-size').getAttribute('aria-invalid'), null);
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(ui.calls[1].payload.changes['rrset-cache-size'], '512m');
});

test('use default sends null, undo and discard restore baseline, equal values are not changes', async () => {
    const ui = await harness();
    assert.equal(ui.get('cfg-reset-identity').hidden, true, 'unset option has nothing to reset');
    ui.get('cfg-reset-cache-min-ttl').dispatch('click');
    assert.match(ui.get('cfg-summary').textContent, /remove from config/);
    assert.equal(ui.get('cfg-in-cache-min-ttl').disabled, true);
    ui.get('cfg-undo-cache-min-ttl').dispatch('click');
    assert.equal(ui.get('cfg-in-cache-min-ttl').value, '300');
    assert.equal(ui.get('cfg-save').disabled, true);
    type(ui.get('cfg-in-cache-min-ttl'), '60'); type(ui.get('cfg-in-cache-min-ttl'), '300');
    assert.equal(ui.get('cfg-save').disabled, true, 'typing the original value back is no change');
    ui.get('cfg-reset-verbosity').dispatch('click');
    ui.get('cfg-save').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[1].payload.changes, {verbosity: null});
    ui.get('cfg-in-hide-identity').checked = false; ui.get('cfg-in-hide-identity').dispatch('change');
    assert.equal(ui.get('cfg-discard').disabled, false);
    ui.get('cfg-discard').dispatch('click');
    assert.equal(ui.get('cfg-in-hide-identity').checked, true);
    assert.equal(ui.get('cfg-save').disabled, true);
});

test('list edits send only changed lists; clearing text removes a configured directive', async () => {
    const ui = await harness();
    const area = ui.get('cfg-list-access-control');
    area.value = '127.0.0.1/32 allow\n10.0.0.0/8 allow\n  192.168.0.0/16   allow  \n\n';
    area.dispatch('input');
    assert.match(ui.get('cfg-summary').textContent, /access-control: \+1 −0/);
    ui.get('cfg-list-undo-access-control').dispatch('click');
    assert.equal(ui.get('cfg-list-access-control').value, '127.0.0.1/32 allow\n10.0.0.0/8 allow');
    ui.get('cfg-list-access-control').value = '127.0.0.1/32 allow'; ui.get('cfg-list-access-control').dispatch('input');
    type(ui.get('cfg-in-identity'), 'resolver');
    type(ui.get('cfg-in-identity'), '');
    assert.equal(ui.get('cfg-save').disabled, false, 'list change is still pending');
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[1].payload.lists, {'access-control': ['127.0.0.1/32 allow']});
    assert.deepEqual(ui.calls[1].payload.changes, {});
});

test('forward zones: presets, edit, remove and payload without UI-only fields', async () => {
    const ui = await harness(snapshot({forward_zones: [{name: 'corp.example', addrs: ['192.0.2.53'], tls: false, first: false, others: ['forward-no-cache'], source: 'unbound.conf.d/unbound.conf:50'}]}));
    assert.match(ui.get('cfg-panel-forwarding').textContent, /forward-no-cache — preserved as written/);
    ui.get('cfg-preset-0').dispatch('click');
    assert.equal(ui.get('cfg-zone-name-1').value, '.');
    assert.equal(ui.get('cfg-zone-addrs-1').value, '1.1.1.1@853#cloudflare-dns.com\n1.0.0.1@853#cloudflare-dns.com');
    assert.equal(ui.get('cfg-zone-tls-1').checked, true);
    ui.get('cfg-zone-addrs-0').value = '192.0.2.53\n192.0.2.54'; ui.get('cfg-zone-addrs-0').dispatch('input');
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(ui.confirmations.length, 1, 'forwarding changes always confirm');
    assert.deepEqual(ui.calls[1].payload.zones, [
        {name: 'corp.example', addrs: ['192.0.2.53', '192.0.2.54'], tls: false, first: false},
        {name: '.', addrs: ['1.1.1.1@853#cloudflare-dns.com', '1.0.0.1@853#cloudflare-dns.com'], tls: true, first: false}]);
    assert.equal(ui.calls[1].payload.acknowledge, true);
});

test('zone edits that restore the saved zones are not changes; removal is', async () => {
    const zone = {name: 'a.example', addrs: ['192.0.2.1'], tls: false, first: false, others: [], source: 'f:1'};
    const ui = await harness(snapshot({forward_zones: [zone]}));
    ui.get('cfg-zone-first-0').checked = true; ui.get('cfg-zone-first-0').dispatch('change');
    assert.equal(ui.get('cfg-save').disabled, false);
    ui.get('cfg-zone-first-0').checked = false; ui.get('cfg-zone-first-0').dispatch('change');
    assert.equal(ui.get('cfg-save').disabled, true);
    ui.get('cfg-zone-remove-0').dispatch('click');
    assert.match(ui.get('cfg-summary').textContent, /forwarding: 0 zones \(\+0 −1\)/);
    ui.get('cfg-save').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[1].payload.zones, []);
});

test('zone names written with a trailing dot compare equal to their normalised form', async () => {
    const ui = await harness(snapshot({forward_zones: [{name: 'corp.example.', addrs: ['192.0.2.53'], tls: false, first: false, others: [], source: 'f:1'}]}));
    ui.get('cfg-preset-1').dispatch('click');
    assert.match(ui.get('cfg-summary').textContent, /forwarding: 2 zones \(\+1 −0\)/);
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(ui.calls[1].payload.zones[0].name, 'corp.example');
});

test('revision conflict reloads state, keeps the draft against the new files and never overwrites', async () => {
    let posts = 0;
    const ui = await harness(snapshot(), (url, options) => {
        if (options.method === 'POST') { posts++; return fail(409, 'Configuration files changed since this page loaded; reload before saving'); }
    });
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.equal(posts, 1);
    assert.equal(ui.calls.at(-1).options.method, 'GET', 'fresh state fetched after the conflict');
    assert.match(ui.get('cfg-notice').textContent, /files changed.*edits are kept/s);
    assert.equal(ui.get('cfg-in-cache-min-ttl').value, '60');
    assert.match(ui.get('cfg-summary').textContent, /cache-min-ttl: 300 → 60/);
});

test('validation or rollback failures show the server message and keep the draft', async () => {
    const ui = await harness(snapshot(), (url, options) => options.method === 'POST' ? fail(500, 'Unbound is running a different configuration than the candidate: port is 53') : null);
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    ui.get('cfg-apply').dispatch('click'); await settle();
    assert.match(ui.get('cfg-notice').textContent, /different configuration/);
    assert.equal(ui.get('cfg-notice').className, 'alert alert-danger');
    assert.equal(ui.get('cfg-in-cache-min-ttl').value, '60');
    assert.equal(ui.get('cfg-apply').disabled, false);
});

test('expired session redirects to login without leaking a message as success', async () => {
    const ui = await harness(snapshot(), (url, options) => options.method === 'POST' ? {ok: false, status: 401, type: 'default', json: async () => ({})} : null);
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    ui.get('cfg-save').dispatch('click'); await settle();
    assert.deepEqual(ui.redirects, ['/login?next=/config']);
});

test('pending reload banner lists differing options and reloads after confirmation', async () => {
    const pending = snapshot({pending: ['cache-min-ttl'], values: {...snapshot().values, 'cache-min-ttl': value(60, {running: 300, pending: true})}});
    const ui = await harness(pending, (url, options, payload) => url.endsWith('apply-pending') ? ok(snapshot(), {applied: true}) : null);
    assert.equal(ui.get('cfg-pending').hidden, false);
    assert.match(ui.get('cfg-pending-text').textContent, /cache-min-ttl/);
    assert.equal(ui.get('cfg-badge').textContent, '1 pending reload');
    assert.match(ui.get('cfg-row-cache-min-ttl').textContent, /running: 300 \(reload pending\)/);
    ui.get('cfg-apply-pending').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[1].payload, {revision: 'a'.repeat(64)});
    assert.equal(ui.get('cfg-pending').hidden, true);
    assert.equal(ui.get('cfg-badge').textContent, 'In sync with running');
});

test('read-only and recovery states disable every mutation', async () => {
    for (const [extra, pattern] of [[{editable: false, blockers: ['unbound.conf: symbolic link']}, /Structured editing is disabled/], [{recovery_required: true}, /interrupted configuration transaction/i]]) {
        const ui = await harness(snapshot(extra));
        type(ui.get('cfg-in-cache-min-ttl'), '60');
        assert.equal(ui.get('cfg-apply').disabled, true);
        assert.equal(ui.get('cfg-save').disabled, true);
        assert.equal(ui.get('cfg-apply-pending').disabled, true);
        assert.match(ui.get('cfg-notice').textContent, pattern);
    }
});

test('hostile server strings are only ever rendered as text', async () => {
    const hostile = '<img src=x onerror=alert(1)>';
    const state = snapshot({blockers: [hostile], forward_zones: [{name: hostile, addrs: [hostile], tls: false, first: false, others: [hostile], source: hostile}],
        files: [{path: hostile, role: 'readonly', reason: hostile, size: 1, directives: 0}]});
    state.values.identity = value(hostile);
    state.lists.interface.items = [hostile];
    const ui = await harness(state);
    assert.equal(ui.get('cfg-in-identity').value, hostile);
    assert.match(ui.get('cfg-panel-forwarding').textContent, /img src=x/);
});

test('raw editor loads an editable file, confirms applies and discards form drafts only after consent', async () => {
    const ui = await harness(snapshot(), (url, options, payload) => {
        if (url.startsWith('/api/server-config/file') && options.method === 'GET') return ok({path: 'unbound.conf.d/unbound.conf', content: 'server:\n  port: 53\n', revision: 'a'.repeat(64)});
        if (url === '/api/server-config/file' && options.method === 'POST') return ok(snapshot({revision: 'c'.repeat(64)}), {applied: payload.apply, backup: 'config_2.tgz'});
    });
    const options = ui.get('cfg-raw-file').children.map(option => option.value);
    assert.deepEqual(options, ['unbound.conf', 'unbound.conf.d/unbound.conf']);
    ui.get('cfg-raw-file').value = 'unbound.conf.d/unbound.conf';
    ui.get('cfg-raw-load').dispatch('click'); await settle();
    assert.equal(ui.calls[1].url, '/api/server-config/file?path=unbound.conf.d%2Funbound.conf');
    assert.equal(ui.get('cfg-raw-text').value, 'server:\n  port: 53\n');
    ui.get('cfg-raw-text').value = 'server:\n  port: 53\n  num-threads: 2\n';
    type(ui.get('cfg-in-cache-min-ttl'), '60');
    harness.answer = false;
    ui.get('cfg-raw-apply').dispatch('click'); await settle();
    assert.equal(ui.calls.length, 2, 'declining either confirmation sends nothing');
    harness.answer = true;
    ui.get('cfg-raw-apply').dispatch('click'); await settle();
    assert.deepEqual(ui.calls[2].payload, {revision: 'a'.repeat(64), path: 'unbound.conf.d/unbound.conf', content: 'server:\n  port: 53\n  num-threads: 2\n', apply: true, acknowledge: true});
    assert.equal(ui.get('cfg-in-cache-min-ttl').value, '300', 'form draft discarded after the raw save');
    assert.match(ui.get('cfg-notice').textContent, /reloaded Unbound and verified/);
});
