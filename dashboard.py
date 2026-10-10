"""Read-only metrics dashboard: a bounded sampler, a small SQLite history and JSON views.

Nothing here edits Unbound configuration, filters or rewrites. The sampler only runs
``unbound-control stats_noreset`` against a *light* config tree (generated filter
fragments emptied) so a sample never parses the giant managed fragment. Top domain /
client lists are parsed from Unbound's own log file (log-replies / log-local-actions /
log-queries) and stay empty unless the operator already logs; this module never enables
logging.
"""
import contextlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from collections import Counter
from pathlib import Path

log = logging.getLogger('webui.dashboard')

KEEP_PREFIXES = ('total.', 'num.query.', 'num.answer.', 'unwanted.', 'rrset.cache.count',
                 'msg.cache.count', 'infra.cache.count', 'key.cache.count', 'mem.cache.',
                 'mem.total.sbrk', 'time.up', 'num.rrset.bogus')
RANGES = {'1h': 3600, '6h': 6 * 3600, '24h': 24 * 3600, '7d': 7 * 24 * 3600}
RCODES = ('NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED')
GAUGES = ('rrset.cache.count', 'msg.cache.count', 'infra.cache.count', 'key.cache.count',
          'mem.cache.rrset', 'mem.cache.message', 'mem.total.sbrk', 'time.up',
          'total.requestlist.current.all')
LOCAL_ACTIONS = {'always_nxdomain', 'always_refuse', 'always_null', 'always_transparent',
                 'always_deny', 'static', 'redirect', 'refuse', 'deny', 'transparent',
                 'typetransparent', 'inform', 'inform_deny', 'inform_redirect',
                 'block_a', 'nodefault'}
BLOCK_ACTIONS = {'always_nxdomain', 'always_refuse', 'always_null', 'always_deny', 'refuse', 'deny'}
MAX_POINTS = 240
RATIO_WINDOW = 300


def _bounded_int(name, default, low, high):
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(low, min(high, value))


def parse_stats(text):
    """Parse ``key=value`` output; keep only dashboard keys, never per-thread rows."""
    out = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        key = key.strip()
        if not sep or key.startswith('thread') or not key.startswith(KEEP_PREFIXES):
            continue
        try:
            out[key] = float(value)
        except ValueError:
            continue
    if 'total.num.recursivereplies' in out and 'total.recursion.time.avg' in out:
        # avg is cumulative since reset, so avg*count is an exact running sum that
        # can be differenced into a true windowed average.
        out['recursion.sum_ms'] = out['total.recursion.time.avg'] * 1000 * out['total.num.recursivereplies']
    return out


def _delta(new, old):
    return new - old if new >= old else new  # counter reset (restart / stats reset)


class History:
    def __init__(self, path, retention_seconds):
        self.path = Path(path)
        self.retention = retention_seconds
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS samples (ts INTEGER PRIMARY KEY, data TEXT NOT NULL)')

    @contextlib.contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute('PRAGMA journal_mode=WAL')
            with db:  # commit / rollback
                yield db
        finally:
            db.close()

    def add(self, ts, sample):
        with self._db() as db:
            db.execute('INSERT OR REPLACE INTO samples VALUES (?, ?)', (int(ts), json.dumps(sample, separators=(',', ':'))))
            db.execute('DELETE FROM samples WHERE ts < ?', (int(ts) - self.retention,))
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def rows(self, start, end):
        """Samples in [start, end] plus the newest one before ``start`` as a delta baseline."""
        with self._db() as db:
            before = db.execute('SELECT ts, data FROM samples WHERE ts < ? ORDER BY ts DESC LIMIT 1', (int(start),)).fetchall()
            inside = db.execute('SELECT ts, data FROM samples WHERE ts BETWEEN ? AND ? ORDER BY ts', (int(start), int(end))).fetchall()
        return [(ts, json.loads(data)) for ts, data in before + inside]

    def count(self):
        with self._db() as db:
            return db.execute('SELECT COUNT(*) FROM samples').fetchone()[0]


def _bucketize(rows, start, end, step):
    """Newest sample per time bucket, ordered; baseline row (before start) kept first."""
    out = []
    for ts, sample in rows:
        if ts < start:
            out = [(ts, sample)]
            continue
        bucket = int((ts - start) // step)
        if out and out[-1][0] >= start and int((out[-1][0] - start) // step) == bucket:
            out[-1] = (ts, sample)
        else:
            out.append((ts, sample))
    return out


def build_view(rows, start, end, interval):
    """Pure transform of raw rows into summary + chart series (rates per second)."""
    span = max(end - start, 1)
    step = max(interval, -(-span // MAX_POINTS))
    points = _bucketize(rows, start, end, step)
    all_keys = {k for _, s in rows for k in s}
    qtypes = sorted(k for k in all_keys if k.startswith('num.query.type.'))
    rcodes = sorted(k for k in all_keys if k.startswith('num.answer.rcode.'))

    def counter_keys():
        return (('total.num.queries', 'total.num.cachehits', 'total.num.cachemiss', 'total.num.prefetch',
                 'total.num.expired', 'total.num.recursivereplies', 'recursion.sum_ms', 'unwanted.replies',
                 'unwanted.queries') + tuple(qtypes) + tuple(rcodes))

    keys = counter_keys()
    totals = Counter()
    # Window totals use every raw sample (not just buckets) so bucket choice never changes them.
    for (_, old), (_, new) in zip(rows, rows[1:]):
        if new.get('time.up', 0) and old.get('time.up', 0) > new['time.up']:
            old = {}
        for key in keys:
            if key in new:
                totals[key] += _delta(new[key], old.get(key, 0.0))
    ts_axis, series = [], {name: [] for name in (
        'qps', 'hits', 'misses', 'hit_pct', 'recursion_ms', 'nxdomain_pct', 'servfail', 'cache_entries',
        'cache_mb', 'noerror', 'nxdomain', 'refused')}
    gap_limit = step * 2.5 + interval
    # Ratio series (hit %, recursion ms, NXDOMAIN %) are undefined in a bucket with no
    # traffic of that kind, so they use a trailing window of at least RATIO_WINDOW seconds.
    # The window restarts after a real sampling gap so it never averages across an outage.
    window, win = [], max(1, -(-RATIO_WINDOW // step))
    for (t0, old), (t1, new) in zip(points, points[1:]):
        dt = t1 - t0
        ts_axis.append(t1)
        if dt <= 0 or dt > gap_limit or ('total.num.queries' not in new):
            window.clear()
            for name in series:
                series[name].append(None)
            continue
        reset = old.get('time.up', 0) > new.get('time.up', 0) > 0
        d = {k: _delta(new.get(k, 0.0), 0.0 if reset else old.get(k, 0.0)) for k in keys}
        q = d['total.num.queries']
        series['qps'].append(q / dt)
        series['hits'].append(d['total.num.cachehits'] / dt)
        series['misses'].append(d['total.num.cachemiss'] / dt)
        d['answers'] = sum(d[k] for k in rcodes if not k.endswith('.nodata')) or q  # nodata is a subset of NOERROR
        window.append(d)
        del window[:-win]
        w = Counter()
        for item in window:
            w.update(item)
        series['hit_pct'].append(w['total.num.cachehits'] / w['total.num.queries'] * 100 if w['total.num.queries'] else None)
        series['recursion_ms'].append(w['recursion.sum_ms'] / w['total.num.recursivereplies']
                                      if w['total.num.recursivereplies'] else None)
        nx = d.get('num.answer.rcode.NXDOMAIN', 0.0)
        series['nxdomain_pct'].append(w['num.answer.rcode.NXDOMAIN'] / w['answers'] * 100
                                      if w['answers'] and rcodes else None)
        series['servfail'].append(d.get('num.answer.rcode.SERVFAIL', 0.0) / dt if rcodes else None)
        series['noerror'].append(d.get('num.answer.rcode.NOERROR', 0.0) / dt if rcodes else None)
        series['nxdomain'].append(nx / dt if rcodes else None)
        series['refused'].append(d.get('num.answer.rcode.REFUSED', 0.0) / dt if rcodes else None)
        series['cache_entries'].append(new.get('rrset.cache.count', 0) + new.get('msg.cache.count', 0))
        series['cache_mb'].append((new.get('mem.cache.rrset', 0) + new.get('mem.cache.message', 0)) / 1048576)
    queries = totals['total.num.queries']
    hits = totals['total.num.cachehits']
    rr = totals['total.num.recursivereplies']
    latest = rows[-1][1] if rows else {}
    covered = (rows[-1][0] - max(rows[0][0], start)) if len(rows) > 1 else 0
    summary = {
        'queries': int(queries), 'cache_hits': int(hits), 'cache_misses': int(totals['total.num.cachemiss']),
        'prefetch': int(totals['total.num.prefetch']), 'expired': int(totals['total.num.expired']),
        'hit_pct': round(hits / queries * 100, 1) if queries else None,
        'recursion_ms': round(totals['recursion.sum_ms'] / rr, 2) if rr else None,
        'avg_qps': round(queries / covered, 3) if covered > 0 else None,
        'covered_seconds': int(max(covered, 0)),
        'unwanted_replies': int(totals['unwanted.replies']),
        'uptime_seconds': int(latest['time.up']) if 'time.up' in latest else None,
        'extended': bool(rcodes or qtypes),
    }
    rc_total = {k.rsplit('.', 1)[1]: int(totals[k]) for k in rcodes if totals[k]}
    qt_total = {k.rsplit('.', 1)[1]: int(totals[k]) for k in qtypes if totals[k]}
    nx = rc_total.get('NXDOMAIN', 0)
    answered = sum(v for k, v in rc_total.items() if k != 'nodata')
    summary['nxdomain_pct'] = round(nx / answered * 100, 1) if answered else None
    summary['servfail'] = rc_total.get('SERVFAIL', 0)
    gauges = {name: latest[name] for name in GAUGES if name in latest}
    return {
        'summary': summary,
        'series': {'ts': ts_axis, **series},
        'bucket_seconds': step,
        'rcodes': dict(sorted(rc_total.items(), key=lambda kv: -kv[1])),
        'qtypes': dict(sorted(qt_total.items(), key=lambda kv: -kv[1])[:12]),
        'gauges': gauges,
    }


_PREFIX = r'^(?:\[(\d+)\] )?(?:unbound\[\d+:\d+\] )?'  # "[epoch] unbound[pid:thread] " is absent in journal output
_REPLY = re.compile(_PREFIX + r'reply: (\S+) (\S+) (\w+) IN (\w+)')
_ACTION = re.compile(_PREFIX + r'info: (?:\S+ )?(\w+) ([0-9a-fA-F:.]+)@\d+ (\S+) (\w+) IN\s*$')
_QUERY = re.compile(r'^(?:\[(\d+)\] )?(?:unbound\[\d+:\d+\] )?info: ([0-9a-fA-F:.]+) (\S+) (\w+) IN\s*$')
MAX_LOG_BYTES = 24 * 1024 * 1024


def _name(value):
    value = value.rstrip('.').lower()
    return value if value and len(value) <= 253 else None


def parse_query_log(lines, since=0, top=15):
    """Top lists from Unbound's own log. Understands ``log-replies`` reply lines,
    ``log-local-actions`` lines and plain ``log-queries`` lines; unknown lines are ignored.
    Blocked names are removed from the allowed-domain list so they are not counted twice."""
    domains, clients, blocked, blocked_clients = Counter(), Counter(), Counter(), Counter()
    queries = blocked_total = 0
    first = last = None
    for line in lines:
        ts = None
        match = _REPLY.match(line)
        kind = 'reply'
        if match:
            ts, client, name = int(match[1]) if match[1] else None, match[2], match[3]
        else:
            match = _ACTION.match(line)
            if match and match[2] in LOCAL_ACTIONS:
                kind, ts, client, name = 'action', int(match[1]) if match[1] else None, match[3], match[4]
            else:
                match = _QUERY.match(line)
                if not match:
                    continue
                kind, ts, client, name = 'query', int(match[1]) if match[1] else None, match[2], match[3]
        if ts is not None and ts < since:
            continue
        try:
            ipaddress.ip_address(client)
        except ValueError:
            continue
        name = _name(name)
        if name is None:
            continue
        if ts is not None:
            first = ts if first is None else min(first, ts)
            last = ts if last is None else max(last, ts)
        if kind == 'action':
            if match[2] in BLOCK_ACTIONS:
                blocked[name] += 1
                blocked_clients[client] += 1
                blocked_total += 1
            continue
        queries += 1
        domains[name] += 1
        clients[client] += 1
    for name in blocked:
        domains.pop(name, None)  # reply lines for blocked names are not "allowed" traffic
    return {
        'available': queries + blocked_total > 0, 'parsed': queries, 'queries': queries, 'blocked_total': blocked_total,
        'first': first, 'last': last,
        'domains': [{'name': n, 'count': c} for n, c in domains.most_common(top)],
        'clients': [{'name': n, 'count': c} for n, c in clients.most_common(top)],
        'blocked': [{'name': n, 'count': c} for n, c in blocked.most_common(top)],
    }


def log_lines(path=None, max_bytes=MAX_LOG_BYTES):
    """Newest lines of Unbound's log file (plus the previous rotation), bounded in bytes.
    Falls back to the journal when no log file exists."""
    base = Path(path or os.environ.get('WEBUI_DASHBOARD_QUERY_LOG', '/var/log/unbound/unbound.log'))
    chunks, remaining = [], max_bytes
    for candidate in (base, base.with_name(base.name + '.1')):
        if remaining <= 0 or not candidate.is_file():
            continue
        with open(candidate, 'rb') as handle:
            size = handle.seek(0, os.SEEK_END)
            take = min(size, remaining)
            handle.seek(size - take)
            data = handle.read(take)
        remaining -= take
        text = data.decode('utf-8', 'replace').splitlines()
        chunks.append(text[1:] if take < size else text)  # drop a cut-off first line
    if chunks:
        return [line for chunk in reversed(chunks) for line in chunk]
    result = subprocess.run(['journalctl', '-u', 'unbound', '--no-pager', '-n', '20000', '--output=cat'],
                            capture_output=True, text=True, timeout=15)
    return result.stdout.splitlines() if result.returncode == 0 else []


class Dashboard:
    def __init__(self, data_dir, stats_reader, log_reader=log_lines, interval=None, retention_days=None,
                 clock=time.time, top_ttl=30):
        if interval is None:
            interval = _bounded_int('WEBUI_DASHBOARD_SAMPLE_SECONDS', 60, 0, 3600)
            interval = max(10, interval) if interval else 0  # 0 disables; never hammer unbound-control
        self.interval = interval
        days = _bounded_int('WEBUI_DASHBOARD_RETENTION_DAYS', 7, 1, 30) if retention_days is None else retention_days
        self.history = History(Path(data_dir) / 'metrics.sqlite', days * 86400)
        self.stats_reader, self.log_reader, self.clock, self.top_ttl = stats_reader, log_reader, clock, top_ttl
        self.last_error = None
        self.last_sample = None
        self._stop = threading.Event()
        self._thread = None
        self._top = {}
        self._top_lock = threading.Lock()
        self._sample_lock = threading.Lock()

    def sample(self):
        """Take one sample; failures are recorded, never raised into the app."""
        with self._sample_lock:
            try:
                data = parse_stats(self.stats_reader())
                if 'total.num.queries' not in data:
                    raise RuntimeError('unbound-control returned no statistics')
                now = int(self.clock())
                self.history.add(now, data)
                self.last_sample, self.last_error = now, None
            except Exception as exc:  # noqa: BLE001 - sampler must survive any reader failure
                self.last_error = str(exc)[:300]
                log.warning('dashboard sample failed: %s', self.last_error)

    def _loop(self):
        self.sample()
        while not self._stop.wait(self.interval):
            self.sample()

    def start(self):
        if self.interval <= 0 or self._thread:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='dashboard-sampler', daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread:
            thread.join(5)

    def top(self, start=0):
        key = int(start) // 60  # one cache slot per minute-aligned window start
        with self._top_lock:
            stamp, cached = self._top.get(key, (0, None))
            if cached is not None and self.clock() - stamp < self.top_ttl:
                return cached
            try:
                value = parse_query_log(self.log_reader(), since=start)
            except Exception as exc:  # noqa: BLE001
                value = {'available': False, 'parsed': 0, 'queries': 0, 'blocked_total': 0, 'first': None, 'last': None,
                         'domains': [], 'clients': [], 'blocked': [], 'error': str(exc)[:200]}
            self._top = {k: v for k, v in self._top.items() if self.clock() - v[0] < self.top_ttl}
            self._top[key] = (self.clock(), value)
            return value

    def view(self, range_key='1h'):
        if range_key not in RANGES:
            raise ValueError('Unknown range; use one of ' + ', '.join(RANGES))
        end = int(self.clock())
        start = end - RANGES[range_key]
        result = build_view(self.history.rows(start, end), start, end, max(self.interval, 1))
        result.update({
            'range': range_key, 'start': start, 'end': end, 'interval': self.interval,
            'samples': self.history.count(), 'last_sample': self.last_sample, 'last_error': self.last_error,
            'sampling': self._thread is not None,
            'top': self.top(start),
        })
        return result


def default_stats_reader(config_manager):
    """stats_noreset through a light tree: never parses the production filter fragment."""
    def read():
        with config_manager._light() as config:
            result = subprocess.run(['unbound-control', '-c', str(config), 'stats_noreset'],
                                    capture_output=True, text=True, timeout=10)
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout or 'unbound-control failed').strip())
        return result.stdout
    return read


def install(upstream, dashboard=None):
    from fastapi import Depends, HTTPException, Request

    if dashboard is None:
        dashboard = Dashboard(Path(upstream.BASE_DIR) / 'dashboard-data',
                              default_stats_reader(upstream.config_manager))
    upstream.dashboard = dashboard
    read = [Depends(upstream._login_required)]

    @upstream.app.get('/dashboard', dependencies=read)
    def dashboard_page(request: Request):
        return upstream._template(request, 'dashboard.html', {'active_tab': 'dashboard'})

    @upstream.app.get('/api/dashboard', dependencies=read)
    def dashboard_data(range: str = '1h'):
        try:
            return dashboard.view(range)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    upstream.app.router.add_event_handler('startup', dashboard.start)
    upstream.app.router.add_event_handler('shutdown', dashboard.stop)
    return dashboard
