'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

// Minimal DOM: HTML sinks throw so unsafe rendering cannot pass.
class Node {
    constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.style = {}; this._text = ''; }
    set innerHTML(_) { throw new Error('Unsafe HTML sink'); }
    set textContent(v) { this._text = String(v); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    append(...n) { this.children.push(...n); }
    replaceChildren(...n) { this.children = n; }
    get clientWidth() { return 400; } get clientHeight() { return 190; }
    getBoundingClientRect() { return { left: 0, width: 400 }; }
    all() { return [this, ...this.children.flatMap(c => c.all ? c.all() : [])]; }
}
global.document = { createElement: t => new Node(t), createElementNS: (_, t) => new Node(t), createTextNode: t => Object.assign(new Node('#text'), { _text: t }), getElementById: () => null };
const dash = require(path.join(__dirname, 'static/js/dashboard.js'));

test('niceMax rounds up to readable axis maxima', () => {
    assert.equal(dash.niceMax(0), 1);
    assert.equal(dash.niceMax(7.3), 10);
    assert.equal(dash.niceMax(180), 200);
    assert.equal(dash.niceMax(0.021), 0.025);
});

test('formatNumber and formatDuration', () => {
    assert.equal(dash.formatNumber(null), '—');
    assert.equal(dash.formatNumber(1234567), '1.2M');
    assert.equal(dash.formatNumber(12), '12');
    assert.equal(dash.formatNumber(0.5), '0.50');
    assert.equal(dash.formatDuration(90061), '1d 1h');
    assert.equal(dash.formatDuration(null), '—');
});

test('line path breaks at null instead of bridging gaps', () => {
    assert.equal(dash.linePath([0, 10, 20, 30], [1, 2, null, 4]), 'M0.0 1.0L10.0 2.0M30.0 4.0');
});

test('stacked layers accumulate and propagate gaps', () => {
    assert.deepEqual(dash.stack([[1, 2, null], [3, null, 5]]), [[1, 2, null], [4, null, null]]);
});

test('area path closes each continuous run separately', () => {
    const d = dash.areaPath([0, 1, 2, 3], [5, 5, null, 5], [9, 9, 9, 9]);
    assert.equal((d.match(/Z/g) || []).length, 2);
});

test('drawChart shows an empty state and a plot, never HTML', () => {
    const host = new Node('div');
    dash.drawChart(host, { ts: [], layers: [{ name: 'a', color: '#fff', values: [] }] });
    assert.match(host.textContent, /No data/);
    dash.drawChart(host, { ts: [100, 160, 220], range: '1h', stacked: true, unit: '/s',
        layers: [{ name: 'a', color: '#fff', values: [1, 2, 3] }, { name: 'b', color: '#000', values: [1, null, 2] }] });
    const paths = host.all().filter(n => n.tag === 'path');
    assert.equal(paths.length, 4);
    assert.ok(paths.every(p => !/NaN|undefined/.test(p.attrs.d)));
});

test('drawList renders hostile names as text only', () => {
    const host = new Node('div');
    dash.drawList(host, [{ name: '<img src=x onerror=alert(1)>', count: 5 }, { name: 'b', count: 1 }], 'none');
    assert.match(host.textContent, /<img src=x/);
    assert.ok(!host.all().some(n => n.tag === 'img'));
    dash.drawList(host, [], 'Needs query logging');
    assert.equal(host.textContent, 'Needs query logging');
});

test('bridge skips quiet-bucket nulls but keeps real gaps', () => {
    // reference (qps) null at index 3 = outage; value null at index 1 = nothing recursed
    assert.deepEqual(dash.bridgeIndexes([5, null, 6, null, 7], [1, 1, 1, null, 1]), [0, 2, 3, 4]);
    const host = new Node('div');
    dash.drawChart(host, { ts: [0, 60, 120, 180, 240], range: '1h', area: true, bridge: [1, 1, 1, null, 1],
        layers: [{ name: 'r', color: '#fff', values: [5, null, 6, null, 7] }] });
    const line = host.all().filter(n => n.tag === 'path' && n.attrs.fill === 'none')[0];
    assert.equal((line.attrs.d.match(/M/g) || []).length, 2); // one segment bridged across the quiet bucket, one break at the outage
});
