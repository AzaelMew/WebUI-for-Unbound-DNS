'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// A deliberately small DOM boundary: execute the real script and submit real
// registered handlers. Unsafe HTML sinks throw instead of silently accepting it.
class Element {
    constructor(tag) {
        this.tagName = tag.toUpperCase();
        this.children = [];
        this.attributes = {};
        this.listeners = {};
        this.disabled = false;
        this.value = '';
        this._text = '';
    }
    set textContent(value) { this._text = String(value); this.replaceChildren(); }
    get textContent() { return this._text + this.children.map(node => node.textContent).join(''); }
    set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
    set outerHTML(_) { throw new Error('Unsafe HTML sink'); }
    setAttribute(name, value) {
        assert.ok(!/^on/i.test(name), 'No inline event handlers');
        this.attributes[name] = String(value);
        if (name === 'class') this.className = value;
        if (name === 'id') this.id = value;
        if (name === 'value') this.value = value;
        if (name === 'type') this.type = value;
        if (name === 'disabled') this.disabled = true;
        if (name === 'required') this.required = true;
        if (name === 'content') this.content = value;
    }
    getAttribute(name) { return this.attributes[name] ?? null; }
    removeAttribute(name) { delete this.attributes[name]; }
    append(...nodes) {
        for (const node of nodes) {
            node.parentNode = this;
            this.children.push(node);
            if (this.tagName === 'SELECT' && this.children.length === 1) this.value = node.value;
            let root = this;
            while (root.parentNode) root = root.parentNode;
            if (root.onAppend) root.onAppend(node);
        }
    }
    replaceChildren(...nodes) {
        for (const node of this.children) node.parentNode = null;
        this.children = [];
        this.append(...nodes);
    }
    addEventListener(type, listener) { (this.listeners[type] ??= []).push(listener); }
    dispatch(type) {
        if (type === 'click' && this.disabled) return;
        const event = {target: this, preventDefault() {}};
        for (const listener of this.listeners[type] || []) listener(event);
    }
    matches(selector) {
        if (selector.startsWith('#')) return this.id === selector.slice(1);
        if (selector.startsWith('.')) return (this.className || '').split(/\s+/).includes(selector.slice(1));
        if (selector === 'meta[name="csrf-token"]') return this.tagName === 'META' && this.getAttribute('name') === 'csrf-token';
        return this.tagName.toLowerCase() === selector;
    }
    querySelectorAll(selector) {
        const selectors = selector.split(',').map(value => value.trim());
        const result = [];
        const walk = node => {
            for (const child of node.children) {
                if (selectors.some(part => child.matches(part))) result.push(child);
                walk(child);
            }
        };
        walk(this);
        return result;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}
function documentFromTemplate() {
    const root = new Element('document');
    const meta = new Element('meta');
    meta.setAttribute('name', 'csrf-token');
    meta.setAttribute('content', 'test-csrf');
    root.append(meta);
    const stack = [root];
    const html = fs.readFileSync(path.join(__dirname, 'templates/filters.html'), 'utf8').replace(/{[%{][\s\S]*?[%}]}/g, '');
    for (const match of html.matchAll(/<\/?([a-z][\w-]*)\b([^>]*)>|([^<]+)/gi)) {
        if (match[3]) {
            const text = new Element('text');
            text.textContent = match[3].replace(/&amp;/g, '&');
            stack.at(-1).append(text);
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
    root.getElementById = id => root.querySelector('#' + id);
    return root;
}
function snapshot(overrides = {}) {
    return {
        blocked: ['manual.example'], allowed: [], effective_count: 1234,
        initialized: true, managed_file: '/isolated/webui-filters.conf',
        limits: {max_bytes: 7 * 1048576, max_total_bytes: 14 * 1048576, max_entries: 4321, max_subscriptions: 11, max_sources: 4},
        refresh_interval_seconds: 0, lists: [], ...overrides,
    };
}
function subscription(overrides = {}) {
    return {
        id: 'list-1', name: 'My list', url: 'https://feeds.example/first',
        sources: ['https://feeds.example/first', 'https://feeds.example/second'],
        format: 'hosts', enabled: false, count: 15, downloaded_bytes: 2621440,
        last_updated: '2026-09-29T10:00:00Z', last_attempt: '2026-09-30T10:00:00Z',
        last_error: '', unsupported: 2, samples: ['@@||exception.example^'], ...overrides,
    };
}
function response(state, options = {}) {
    return {ok: true, status: 200, json: async () => ({success: true, state}), ...options};
}
function deferred() {
    let resolve;
    const promise = new Promise(done => { resolve = done; });
    return {promise, resolve};
}
async function settle() { await new Promise(done => setImmediate(done)); }
async function harness(state = snapshot(), responder) {
    const document = documentFromTemplate();
    const calls = [], confirmations = [], redirects = [];
    const window = {confirm: text => { confirmations.push(text); return true; }, location: {assign: url => redirects.push(url)}};
    const fetch = async (url, options) => {
        calls.push({url, options, payload: options.body ? JSON.parse(options.body) : undefined});
        return responder ? responder(url, options, calls.length) : response(state);
    };
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'static/js/filters.js'), 'utf8'), {document, window, fetch}, {filename: 'filters.js'});
    await settle();
    return {document, window, calls, confirmations, redirects, get: id => document.getElementById(id)};
}
function button(root, label) {
    const node = root.querySelectorAll('button').find(item => item.textContent === label);
    assert.ok(node, `Button “${label}” exists`);
    return node;
}

test('snapshot renders actual safety limits, subscription metadata and opt-in global refresh', async () => {
    const state = snapshot({lists: [subscription()]});
    const ui = await harness(state);
    const limits = ui.get('filter-limits');
    assert.ok(limits, 'dynamic limits placeholder exists');
    assert.match(limits.textContent, /7 MiB per source/);
    assert.match(limits.textContent, /14 MiB per subscription refresh/);
    assert.match(limits.textContent, /4,321/);
    assert.match(limits.textContent, /11 subscriptions/);
    assert.match(limits.textContent, /4 sources/);
    assert.match(ui.get('filter-refresh-policy').textContent, /off/i);
    const card = ui.get('filter-lists').querySelector('section');
    assert.match(card.textContent, /Format: hosts/);
    assert.match(card.textContent, /2 sources/);
    for (const url of state.lists[0].sources) assert.ok(card.textContent.includes(url));
    assert.match(card.textContent, /2\.5 MiB downloaded/);
    assert.match(card.textContent, /15 cached domains/);
    assert.match(card.textContent, /Last success:/);
    assert.match(card.textContent, /Last attempt:/);
    assert.match(card.textContent, /2 unsupported lines/);
    assert.ok(card.textContent.includes(state.lists[0].samples[0]));
    const configured = await harness(snapshot({refresh_interval_seconds: 7200}));
    assert.match(configured.get('filter-refresh-policy').textContent, /7,200 seconds/);
    assert.match(configured.get('filter-refresh-policy').textContent, /enabled subscriptions/i);
    assert.equal(configured.get('filter-lists').querySelector('input'), null, 'no fake per-list schedule');
});

test('inline editing confirms source/format invalidation and submits all subscription fields', async () => {
    const initial = snapshot({lists: [subscription({enabled: true})]});
    const updated = snapshot({lists: [subscription({name: 'Edited', sources: ['https://feeds.example/new'], format: 'rpz', enabled: false, count: 0, last_updated: null})]});
    const ui = await harness(initial, (_url, _options, count) => response(count === 1 ? initial : updated));
    const card = ui.get('filter-lists').querySelector('section');
    button(card, 'Edit').dispatch('click');
    const form = card.querySelector('form');
    assert.ok(form && !form.hidden, 'inline edit form is visible');
    const name = form.querySelector('input');
    const sources = form.querySelector('textarea');
    const format = form.querySelector('select');
    assert.equal(name.value, 'My list');
    assert.equal(sources.value, initial.lists[0].sources.join('\n'));
    assert.equal(format.value, 'hosts');
    name.value = ' Edited ';
    sources.value = ' https://feeds.example/new \n\n';
    format.value = 'rpz';
    ui.window.confirm = text => { ui.confirmations.push(text); return false; };
    form.dispatch('submit');
    await settle();
    assert.equal(ui.calls.length, 1, 'cancelled confirmation does not mutate');
    assert.match(ui.confirmations[0], /disable/i);
    assert.match(ui.confirmations[0], /cache/i);
    assert.match(ui.confirmations[0], /refresh/i);
    ui.window.confirm = text => { ui.confirmations.push(text); return true; };
    form.dispatch('submit');
    await settle();
    assert.equal(ui.calls[1].url, '/api/filters/lists/list-1/edit');
    assert.deepEqual(ui.calls[1].payload, {name: 'Edited', sources: ['https://feeds.example/new'], format: 'rpz'});
    assert.match(ui.get('filter-notice').textContent, /disabled.*refresh.*enable/i);
    assert.equal(button(ui.get('filter-lists'), 'Enable & apply').disabled, true, 'invalidated cache cannot be enabled');
    assert.equal(ui.get('filter-blocked').value, 'manual.example');
});

test('pending mutations lock selects and redraw-created controls while restoring cache guards', async () => {
    const gate = deferred();
    const initial = snapshot({lists: [subscription()]});
    const updated = snapshot({lists: [subscription({count: 0})]});
    const ui = await harness(initial, (_url, _options, count) => count === 1 ? response(initial) : gate.promise);
    let redraws = 0;
    const redrawControls = [];
    ui.document.onAppend = node => {
        if (node.tagName !== 'SECTION' || !ui.get('filter-page').getAttribute('aria-busy')) return;
        redraws++;
        for (const control of node.querySelectorAll('button, input, textarea, select')) redrawControls.push({tag: control.tagName, disabled: control.disabled});
    };
    button(ui.get('filter-lists'), 'Refresh now').dispatch('click');
    assert.equal(ui.get('filter-page').getAttribute('aria-busy'), 'true');
    for (const control of ui.get('filter-page').querySelectorAll('button, input, textarea, select')) assert.equal(control.disabled, true, `${control.tagName} is locked`);
    ui.get('filter-subscription-form').dispatch('submit');
    assert.equal(ui.calls.length, 2, 'busy guard rejects duplicate submits');
    gate.resolve(response(updated));
    await settle();
    assert.equal(redraws, 1, 'observed redraw while mutation remained busy');
    assert.ok(redrawControls.length > 0);
    for (const control of redrawControls) assert.equal(control.disabled, true, `new ${control.tag} remains locked during redraw`);
    assert.equal(ui.get('filter-page').getAttribute('aria-busy'), null);
    assert.equal(ui.get('filter-list-format').disabled, false);
    assert.equal(button(ui.get('filter-lists'), 'Refresh now').disabled, false);
    assert.equal(ui.get('filter-lists').querySelector('select').disabled, false);
    assert.equal(button(ui.get('filter-lists'), 'Enable & apply').disabled, true, 'empty-cache guard survives unlocking');
});

test('hostile remote names, sources, errors and unsupported samples remain literal text', async () => {
    const name = '<img src=x onerror="alert(1)">';
    const url = 'javascript:alert(2)\"><svg onload=alert(3)>';
    const error = '<script>alert(4)</script>';
    const sample = '\"><a href="javascript:alert(5)">unsupported</a>';
    const state = snapshot({lists: [subscription({name, url, sources: [url], last_error: error, samples: [sample]})]});
    const ui = await harness(state);
    const card = ui.get('filter-lists').querySelector('section');
    for (const value of [name, url, error, sample]) assert.ok(card.textContent.includes(value), `literal ${value}`);
    assert.equal(card.querySelectorAll('img, svg, script, a').length, 0, 'no injected elements or links');
    for (const node of card.querySelectorAll('button, input, textarea, select, p')) {
        assert.equal(node.getAttribute('href'), null);
        assert.equal(node.getAttribute('onclick'), null);
    }
    button(card, 'Edit').dispatch('click');
    assert.equal(card.querySelector('input').value, name);
    assert.equal(card.querySelector('textarea').value, url);
    button(card, 'Delete').dispatch('click');
    await settle();
    assert.ok(ui.confirmations[0].includes(name), 'confirmation is text, not an HTML attribute');
});

test('renaming alone preserves enabled state and cache without an invalidation confirmation', async () => {
    const initial = snapshot({lists: [subscription({enabled: true})]});
    const renamed = snapshot({lists: [subscription({enabled: true, name: 'Renamed'})]});
    const ui = await harness(initial, (_url, _options, count) => response(count === 1 ? initial : renamed));
    const card = ui.get('filter-lists').querySelector('section');
    button(card, 'Edit').dispatch('click');
    const form = card.querySelector('form');
    form.querySelector('input').value = 'Renamed';
    form.dispatch('submit');
    await settle();
    assert.equal(ui.confirmations.length, 0);
    assert.deepEqual(ui.calls[1].payload, {name: 'Renamed', sources: initial.lists[0].sources, format: 'hosts'});
    assert.match(ui.get('filter-lists').textContent, /Renamed.*Enabled.*15 cached domains/s);
    assert.match(ui.get('filter-notice').textContent, /Cache and enabled state preserved/);
});

test('format-only editing requires confirmation and cancel edit does not mutate', async () => {
    const ui = await harness(snapshot({lists: [subscription()]}));
    const card = ui.get('filter-lists').querySelector('section');
    button(card, 'Edit').dispatch('click');
    const form = card.querySelector('form');
    button(form, 'Cancel edit').dispatch('click');
    assert.equal(form.hidden, true);
    assert.equal(ui.calls.length, 1);
    button(card, 'Edit').dispatch('click');
    form.querySelector('select').value = 'domains';
    form.dispatch('submit');
    await settle();
    assert.equal(ui.confirmations.length, 1);
    assert.equal(ui.calls[1].payload.format, 'domains');
});

test('refresh failure redraw preserves last good metadata and unsaved domain editors', async () => {
    const original = subscription({enabled: true});
    const initial = snapshot({lists: [original]});
    const failure = subscription({...original, last_attempt: '2026-09-30T11:00:00Z', last_error: 'Second source unavailable'});
    const ui = await harness(initial, (_url, _options, count) => {
        if (count === 2) return response(undefined, {ok: false, status: 422, json: async () => ({success: false, detail: 'Download failed'})});
        return response(count === 1 ? initial : snapshot({lists: [failure]}));
    });
    ui.get('filter-blocked').value = 'unsaved.example';
    ui.get('filter-allowed').value = 'allow.unsaved.example';
    button(ui.get('filter-lists'), 'Refresh now').dispatch('click');
    await settle();
    assert.equal(ui.calls[2].url, '/api/filters');
    const card = ui.get('filter-lists').querySelector('section');
    assert.match(card.textContent, /Enabled.*2\.5 MiB downloaded.*15 cached domains/s);
    assert.ok(card.textContent.includes(new Date(original.last_updated).toLocaleString()));
    assert.ok(card.textContent.includes(new Date(failure.last_attempt).toLocaleString()));
    assert.match(card.textContent, /Second source unavailable.*Last good cache was preserved/);
    assert.match(ui.get('filter-notice').textContent, /Download failed/);
    assert.equal(ui.get('filter-blocked').value, 'unsaved.example');
    assert.equal(ui.get('filter-allowed').value, 'allow.unsaved.example');
    assert.equal(button(card, 'Disable & apply').disabled, false);
    assert.equal(ui.get('filter-list-format').disabled, false);
});

test('a failed first refresh does not claim to have preserved a nonexistent cache', async () => {
    const ui = await harness(snapshot({lists: [subscription({count: 0, downloaded_bytes: 0, last_updated: null, last_error: 'Unavailable'})]}));
    const card = ui.get('filter-lists').querySelector('section');
    assert.match(card.textContent, /No cached domains.*Refresh successfully before enabling/);
    assert.doesNotMatch(card.textContent, /Last good cache was preserved/);
    assert.equal(button(card, 'Enable & apply').disabled, true);
});

test('refresh, enable, disable and confirmed delete retain their API behavior', async () => {
    const states = [
        snapshot({lists: [subscription({count: 0, last_updated: null})]}),
        snapshot({lists: [subscription()]}),
        snapshot({lists: [subscription({enabled: true})]}),
        snapshot({lists: [subscription()]}), snapshot(),
    ];
    const ui = await harness(states[0], (_url, _options, count) => response(states[count - 1]));
    assert.equal(button(ui.get('filter-lists'), 'Enable & apply').disabled, true);
    button(ui.get('filter-lists'), 'Enable & apply').dispatch('click');
    assert.equal(ui.calls.length, 1);
    button(ui.get('filter-lists'), 'Refresh now').dispatch('click');
    await settle();
    assert.equal(button(ui.get('filter-lists'), 'Enable & apply').disabled, false);
    button(ui.get('filter-lists'), 'Enable & apply').dispatch('click');
    await settle();
    button(ui.get('filter-lists'), 'Disable & apply').dispatch('click');
    await settle();
    ui.window.confirm = () => false;
    button(ui.get('filter-lists'), 'Delete').dispatch('click');
    assert.equal(ui.calls.length, 4, 'cancelled deletion does not mutate');
    ui.window.confirm = text => { ui.confirmations.push(text); return true; };
    button(ui.get('filter-lists'), 'Delete').dispatch('click');
    await settle();
    assert.deepEqual(ui.calls.slice(1).map(call => [call.url, call.payload]), [
        ['/api/filters/lists/list-1/refresh', {}],
        ['/api/filters/lists/list-1/enabled', {enabled: true}],
        ['/api/filters/lists/list-1/enabled', {enabled: false}],
        ['/api/filters/lists/list-1/delete', {}],
    ]);
    assert.match(ui.get('filter-lists').textContent, /No subscriptions added/);
});

test('manual blocked and allowlist forms keep their trimmed domain payloads', async () => {
    const ui = await harness();
    for (const kind of ['blocked', 'allowed']) {
        ui.get(`filter-${kind}`).value = ' first.example \r\n\nsecond.example ';
        ui.get(`filter-${kind}-form`).dispatch('submit');
        await settle();
        assert.equal(ui.calls.at(-1).url, '/api/filters/domains');
        assert.deepEqual(ui.calls.at(-1).payload, {kind, domains: ['first.example', 'second.example']});
    }
});

test('legacy URL snapshots render a safe single source with auto format', async () => {
    const legacy = subscription({url: '<img src=x onerror=alert(1)>', sources: undefined, format: undefined, downloaded_bytes: undefined});
    const ui = await harness(snapshot({lists: [legacy], limits: undefined}));
    const card = ui.get('filter-lists').querySelector('section');
    assert.match(card.textContent, /Format: auto.*1 source.*0 MiB downloaded/);
    assert.ok(card.textContent.includes(legacy.url));
    assert.equal(card.querySelector('textarea').value, legacy.url);
    assert.match(ui.get('filter-limits').textContent, /unavailable/);
});

test('creation submits trimmed newline sources and the selected format, never auto-enables', async () => {
    const ui = await harness();
    const sources = ui.get('filter-list-sources');
    assert.ok(sources, 'multi-source textarea exists');
    const format = ui.get('filter-list-format');
    assert.ok(format?.required, 'feed format is required');
    assert.deepEqual(format.children.filter(node => node.tagName === 'OPTION').map(node => node.value), ['auto', 'domains', 'hosts', 'adblock', 'rpz']);
    ui.get('filter-list-name').value = '  Example subscription  ';
    sources.value = ' https://feeds.example/first \r\n\nhttps://feeds.example/second ';
    format.value = 'rpz';
    ui.get('filter-subscription-form').dispatch('submit');
    await settle();
    assert.deepEqual(ui.calls[1].payload, {name: 'Example subscription', sources: ['https://feeds.example/first', 'https://feeds.example/second'], format: 'rpz'});
    assert.equal(ui.calls[1].url, '/api/filters/lists');
    assert.equal(ui.calls[1].options.headers['X-CSRF-Token'], 'test-csrf');
    assert.equal(ui.calls.length, 2);
    assert.match(ui.get('filter-notice').textContent, /disabled.*refresh.*enable/i);
});
