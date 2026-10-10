/* Dashboard: dependency-free SVG charts. Server values only enter textContent / attributes. */
(() => {
    'use strict';
    const SVGNS = 'http://www.w3.org/2000/svg';
    const COLORS = { blue: '#4fc3f7', green: '#4caf50', orange: '#ff9800', red: '#f44336', yellow: '#fdd835', grey: '#9e9e9e' };

    function niceMax(value) {
        if (!(value > 0)) return 1;
        const power = Math.pow(10, Math.floor(Math.log10(value)));
        for (const step of [1, 2, 2.5, 5, 10]) if (step * power >= value) return step * power;
        return 10 * power;
    }
    function formatNumber(value, digits = 1) {
        if (value === null || value === undefined || Number.isNaN(value)) return '—';
        const abs = Math.abs(value);
        if (abs >= 1e9) return (value / 1e9).toFixed(digits) + 'G';
        if (abs >= 1e6) return (value / 1e6).toFixed(digits) + 'M';
        if (abs >= 1e4) return (value / 1e3).toFixed(digits) + 'k';
        if (Number.isInteger(value)) return value.toLocaleString('en-US');
        return value.toFixed(abs < 10 ? 2 : digits);
    }
    function formatDuration(seconds) {
        if (typeof seconds !== 'number' || !(seconds >= 0)) return '—';
        const d = Math.floor(seconds / 86400), h = Math.floor(seconds % 86400 / 3600), m = Math.floor(seconds % 3600 / 60);
        return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
    }
    // Break the line wherever a value is missing so gaps are never drawn as data.
    function linePath(xs, ys) {
        let out = '', pen = false;
        xs.forEach((x, i) => {
            if (ys[i] === null || ys[i] === undefined) { pen = false; return; }
            out += (pen ? 'L' : 'M') + x.toFixed(1) + ' ' + ys[i].toFixed(1);
            pen = true;
        });
        return out;
    }
    function areaPath(xs, tops, bottoms) {
        let out = '', run = [];
        const flush = () => {
            if (run.length) {
                out += 'M' + run.map(i => xs[i].toFixed(1) + ' ' + tops[i].toFixed(1)).join('L')
                    + 'L' + run.slice().reverse().map(i => xs[i].toFixed(1) + ' ' + bottoms[i].toFixed(1)).join('L') + 'Z';
            }
            run = [];
        };
        xs.forEach((_, i) => { if (tops[i] === null || tops[i] === undefined) flush(); else run.push(i); });
        flush();
        return out;
    }
    // Stacked layers: cumulative sums per index (null when any layer is missing).
    function stack(layers) {
        const sums = [];
        return layers.map(values => values.map((v, i) => {
            if (v === null || v === undefined) { sums[i] = null; return null; }
            sums[i] = sums[i] === null ? null : (sums[i] || 0) + v;
            return sums[i];
        }));
    }
    // Indexes to draw for a metric that is undefined in quiet buckets: skip a null when the
    // reference series has data there (nothing happened), keep it when it is null too (real gap).
    function bridgeIndexes(values, reference) {
        const keep = [];
        values.forEach((v, i) => { if (v !== null && v !== undefined || reference[i] === null || reference[i] === undefined) keep.push(i); });
        return keep;
    }
    function clock(ts, range) {
        const d = new Date(ts * 1000);
        const hm = d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
        return range === '7d' || range === '24h' ? d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' }) + ' ' + hm : hm;
    }

    const el = (tag, attrs = {}, text) => {
        const node = document.createElementNS ? document.createElementNS(SVGNS, tag) : document.createElement(tag);
        for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
        if (text !== undefined) node.textContent = text;
        return node;
    };
    const html = (tag, text, className) => {
        const node = document.createElement(tag);
        if (text !== undefined) node.textContent = text;
        if (className) node.className = className;
        return node;
    };

    /* spec: {ts, layers:[{name,color,values}], stacked, fixedMax, unit, range} */
    function drawChart(host, spec) {
        host.replaceChildren();
        const width = Math.max(host.clientWidth || 600, 200), height = Math.max(host.clientHeight || 190, 120);
        const svg = el('svg', { viewBox: `0 0 ${width} ${height}`, preserveAspectRatio: 'none' });
        host.append(svg);
        const pad = { l: 44, r: 8, t: 8, b: 20 };
        const plotW = width - pad.l - pad.r, plotH = height - pad.t - pad.b;
        const any = spec.layers.some(l => l.values.some(v => v !== null && v !== undefined));
        if (!spec.ts.length || !any) {
            svg.append(el('text', { x: width / 2, y: height / 2, 'text-anchor': 'middle', class: 'empty' }, 'No data in this range yet'));
            return;
        }
        const drawn = spec.stacked ? stack(spec.layers.map(l => l.values)) : spec.layers.map(l => l.values);
        let peak = 0;
        drawn.forEach(vals => vals.forEach(v => { if (v !== null && v !== undefined && v > peak) peak = v; }));
        const max = spec.fixedMax || niceMax(peak);
        const t0 = spec.ts[0], t1 = spec.ts[spec.ts.length - 1];
        const x = t => pad.l + (t1 === t0 ? plotW / 2 : (t - t0) / (t1 - t0) * plotW);
        const y = v => pad.t + plotH - Math.min(v / max, 1) * plotH;
        const xs = spec.ts.map(x);
        for (let i = 0; i <= 4; i++) {
            const value = max * i / 4, py = y(value);
            svg.append(el('line', { x1: pad.l, x2: width - pad.r, y1: py, y2: py, class: 'axis' }));
            svg.append(el('text', { x: pad.l - 5, y: py + 3, 'text-anchor': 'end', class: 'tick' }, formatNumber(value) + (spec.unit || '')));
        }
        for (const frac of [0, 0.5, 1]) {
            const t = t0 + (t1 - t0) * frac;
            svg.append(el('text', { x: pad.l + plotW * frac, y: height - 5, 'text-anchor': frac === 0 ? 'start' : frac === 1 ? 'end' : 'middle', class: 'tick' }, clock(t, spec.range)));
        }
        const base = spec.ts.map(() => y(0));
        drawn.forEach((vals, index) => {
            const ys = vals.map(v => v === null || v === undefined ? null : y(v));
            const color = spec.layers[index].color;
            const pick = spec.bridge && !spec.stacked ? bridgeIndexes(vals, spec.bridge) : xs.map((_, i) => i);
            const lx = pick.map(i => xs[i]), ly = pick.map(i => ys[i]);
            if (spec.stacked || spec.area) {
                const lower = spec.stacked && index ? drawn[index - 1].map(v => v === null || v === undefined ? y(0) : y(v)) : base;
                svg.append(el('path', { d: areaPath(lx, ly, pick.map(i => lower[i])), fill: color, 'fill-opacity': spec.stacked ? 0.55 : 0.18, stroke: 'none' }));
            }
            svg.append(el('path', { d: linePath(lx, ly), fill: 'none', stroke: color, 'stroke-width': 1.6, 'stroke-linejoin': 'round' }));
        });
        const cursor = el('line', { y1: pad.t, y2: pad.t + plotH, class: 'cursor', visibility: 'hidden' });
        svg.append(cursor);
        const tip = html('div', undefined, 'dash-tip');
        tip.hidden = true;
        host.append(tip);
        host.onmousemove = event => {
            const rect = host.getBoundingClientRect();
            const px = (event.clientX - rect.left) / rect.width * width;
            let best = 0;
            xs.forEach((value, i) => { if (Math.abs(value - px) < Math.abs(xs[best] - px)) best = i; });
            cursor.setAttribute('x1', xs[best]); cursor.setAttribute('x2', xs[best]); cursor.setAttribute('visibility', 'visible');
            tip.replaceChildren(html('div', clock(spec.ts[best], spec.range)));
            spec.layers.forEach(layer => {
                const row = html('div');
                const dot = html('i'); dot.style.background = layer.color;
                row.append(dot, document.createTextNode(`${layer.name}: ${formatNumber(layer.values[best])}${spec.unit || ''}`));
                tip.append(row);
            });
            tip.hidden = false;
            tip.style.left = Math.min(xs[best] / width * rect.width + 12, rect.width - 150) + 'px';
        };
        host.onmouseleave = () => { tip.hidden = true; cursor.setAttribute('visibility', 'hidden'); };
    }

    function drawList(host, rows, empty) {
        host.replaceChildren();
        if (!rows.length) { host.append(html('p', empty, 'dash-empty')); return; }
        const top = Math.max(...rows.map(r => r.count), 1);
        const list = html('ul', undefined, 'dash-list');
        for (const row of rows) {
            const item = html('li');
            const name = html('span', row.name, 'name'); name.title = row.name;
            const bar = html('div', undefined, 'bar'), fill = html('b');
            fill.style.width = (row.count / top * 100).toFixed(1) + '%';
            bar.append(fill);
            item.append(name, html('span', formatNumber(row.count), 'count'), bar);
            list.append(item);
        }
        host.append(list);
    }
    function legend(host, layers) {
        host.replaceChildren();
        for (const layer of layers) {
            const item = html('span'), dot = html('i');
            dot.style.background = layer.color;
            item.append(dot, document.createTextNode(layer.name));
            host.append(item);
        }
    }

    const api = { bridgeIndexes, niceMax, formatNumber, formatDuration, linePath, areaPath, stack, drawChart, drawList };
    if (typeof module !== 'undefined' && module.exports) module.exports = api;
    const page = typeof document !== 'undefined' && document.getElementById('dash-page');
    if (!page) return;

    const get = id => document.getElementById(id);
    let range = localStorage.getItem('dash-range') || '1h', timer = null, last = null, inflight = false;
    const setText = (id, text) => { get(id).textContent = text; };

    function render(data) {
        last = data;
        const s = data.summary, g = data.series, ts = g.ts, r = data.range;
        const notice = get('dash-notice');
        if (data.last_error) {
            notice.className = 'alert alert-danger';
            notice.textContent = 'Last sample failed: ' + data.last_error;
        } else if (!data.samples) {
            notice.className = 'alert alert-info';
            notice.textContent = data.sampling ? 'Collecting the first samples; charts fill in after a couple of minutes.'
                : 'Sampling is disabled (WEBUI_DASHBOARD_SAMPLE_SECONDS=0), so there is no history.';
        } else if (!s.extended) {
            notice.className = 'alert alert-warning';
            notice.textContent = 'Response-code and query-type panels need “extended-statistics: yes” in the Unbound config (Config → Logging). Nothing was changed.';
        } else {
            notice.className = 'alert alert-info';
            notice.textContent = `${data.samples.toLocaleString()} samples kept · every ${data.interval}s · charts use ${data.bucket_seconds}s buckets`;
        }
        const badge = get('dash-sampling');
        badge.className = 'badge ' + (data.last_error ? 'badge-red' : data.sampling ? 'badge-green' : 'badge-gray');
        badge.textContent = data.last_error ? 'sample error' : data.sampling ? 'sampling' : 'sampling off';

        setText('t-queries', formatNumber(s.queries));
        setText('t-qps', s.avg_qps === null ? 'No data yet' : `${formatNumber(s.avg_qps)} /s avg · covers ${formatDuration(s.covered_seconds)}`);
        setText('t-hit', s.hit_pct === null ? '—' : s.hit_pct + '%');
        setText('t-hits', `Hits ${formatNumber(s.cache_hits)} / Misses ${formatNumber(s.cache_misses)}`);
        setText('t-rec', s.recursion_ms === null ? '—' : s.recursion_ms + ' ms');
        setText('t-prefetch', `Prefetch ${formatNumber(s.prefetch)} · Expired served ${formatNumber(s.expired)}`);
        setText('t-nx', s.nxdomain_pct === null ? '—' : s.nxdomain_pct + '%');
        setText('t-servfail', `SERVFAIL ${formatNumber(s.servfail)}${s.uptime_seconds !== null ? ' · up ' + formatDuration(s.uptime_seconds) : ''}`);

        const qps = [{ name: 'Hits', color: COLORS.green, values: g.hits }, { name: 'Misses', color: COLORS.orange, values: g.misses }];
        drawChart(get('ch-qps'), { ts, layers: qps, stacked: true, unit: '/s', range: r });
        legend(get('l-qps'), qps);
        drawChart(get('ch-hit'), { ts, layers: [{ name: 'Hit rate', color: COLORS.green, values: g.hit_pct }], fixedMax: 100, area: true, bridge: g.qps, unit: '%', range: r });
        drawChart(get('ch-rec'), { ts, layers: [{ name: 'Recursion', color: COLORS.orange, values: g.recursion_ms }], area: true, bridge: g.qps, unit: 'ms', range: r });
        const rc = [{ name: 'NOERROR', color: COLORS.green, values: g.noerror }, { name: 'NXDOMAIN', color: COLORS.yellow, values: g.nxdomain },
            { name: 'REFUSED', color: COLORS.grey, values: g.refused }, { name: 'SERVFAIL', color: COLORS.red, values: g.servfail }];
        drawChart(get('ch-rc'), { ts, layers: rc, stacked: true, unit: '/s', range: r });
        legend(get('l-rc'), rc);

        const pairs = obj => Object.entries(obj).map(([name, count]) => ({ name: name === 'nodata' ? 'nodata (within NOERROR)' : name, count }));
        drawList(get('list-qtypes'), pairs(data.qtypes), s.extended ? 'No queries in this range' : 'Needs extended-statistics');
        drawList(get('list-rcodes'), pairs(data.rcodes), s.extended ? 'No answers in this range' : 'Needs extended-statistics');
        const gauges = data.gauges, cache = [];
        if ('rrset.cache.count' in gauges) cache.push({ name: 'RRset entries', count: gauges['rrset.cache.count'] });
        if ('msg.cache.count' in gauges) cache.push({ name: 'Message entries', count: gauges['msg.cache.count'] });
        if ('infra.cache.count' in gauges) cache.push({ name: 'Infra entries', count: gauges['infra.cache.count'] });
        if ('key.cache.count' in gauges) cache.push({ name: 'Key entries', count: gauges['key.cache.count'] });
        drawList(get('list-cache'), cache, 'No cache data yet');

        const top = data.top;
        drawList(get('list-domains'), top.domains, 'No logged queries in this range');
        drawList(get('list-clients'), top.clients, 'No logged queries in this range');
        drawList(get('list-blocked'), top.blocked, 'No blocked queries logged in this range');
        const note = get('dash-top-note');
        if (!top.available) {
            note.textContent = top.error ? 'Could not read the query log: ' + top.error
                : 'No query log lines found. Unbound must log replies (log-replies: yes; log-local-actions: yes for blocked); this page never changes that setting.';
        } else {
            const when = ts => new Date(ts * 1000).toLocaleString('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
            const partial = top.first && top.first > data.start + 600;
            note.textContent = `Top lists use ${top.queries.toLocaleString()} logged queries and ${top.blocked_total.toLocaleString()} blocked`
                + (top.first ? ` from ${when(top.first)} to ${when(top.last)}` : '')
                + (partial ? ' — the available log is shorter than the selected range.' : '.');
        }
    }

    async function load() {
        if (inflight) return;
        inflight = true;
        try {
            const response = await fetch('/api/dashboard?range=' + encodeURIComponent(range), { headers: { 'X-Requested-With': 'XMLHttpRequest' }, redirect: 'manual' });
            if (response.type === 'opaqueredirect' || response.status === 401 || response.status === 403 || response.status === 307) { location.href = '/login'; return; }
            if (!response.ok) throw new Error('HTTP ' + response.status);
            render(await response.json());
        } catch (error) {
            get('dash-notice').className = 'alert alert-danger';
            get('dash-notice').textContent = 'Could not load metrics: ' + error.message;
        } finally { inflight = false; }
    }
    function selectRange(next) {
        range = next;
        localStorage.setItem('dash-range', range);
        page.querySelectorAll('[data-range]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.range === range)));
        load();
    }
    page.querySelectorAll('[data-range]').forEach(b => b.addEventListener('click', () => selectRange(b.dataset.range)));
    window.addEventListener('resize', () => { clearTimeout(timer); timer = setTimeout(() => last && render(last), 150); });
    setInterval(() => { if (!document.hidden) load(); }, 30000);
    selectRange(['1h', '6h', '24h', '7d'].includes(range) ? range : '1h');
})();
