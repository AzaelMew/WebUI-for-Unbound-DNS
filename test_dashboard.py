"""Dashboard backend: pure transforms, history, sampler and a real TestClient route check.
Never imports ``app``; the route test loads a throwaway upstream-shaped FastAPI app."""
import importlib.util
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('isolated_dashboard', ROOT / 'dashboard.py')
dash = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dash)


def stats(q, hit, up, nx=0, avg=0.1, rr=None):
    miss = q - hit
    rr = miss if rr is None else rr
    return (f'thread0.num.queries={q}\ntotal.num.queries={q}\ntotal.num.cachehits={hit}\n'
            f'total.num.cachemiss={miss}\ntotal.num.prefetch=0\ntotal.num.expired=0\n'
            f'total.num.recursivereplies={rr}\ntotal.recursion.time.avg={avg}\ntime.up={up}\n'
            f'num.answer.rcode.NOERROR={q - nx}\nnum.answer.rcode.NXDOMAIN={nx}\nnum.answer.rcode.SERVFAIL=0\n'
            f'num.query.type.A={q}\nrrset.cache.count=5\nmsg.cache.count=7\nmem.cache.rrset=1048576\nmem.cache.message=1048576\n')


class ParseTests(unittest.TestCase):
    def test_drops_thread_rows_and_adds_recursion_sum(self):
        data = dash.parse_stats(stats(10, 4, 100, avg=0.5))
        self.assertNotIn('thread0.num.queries', data)
        self.assertAlmostEqual(data['recursion.sum_ms'], 0.5 * 1000 * 6)

    def test_ignores_garbage(self):
        self.assertEqual(dash.parse_stats('nonsense\ntotal.num.queries=abc\n'), {})


class ViewTests(unittest.TestCase):
    def rows(self, spec):
        return [(ts, dash.parse_stats(stats(*args, **kw))) for ts, args, kw in spec]

    def test_rates_hit_pct_and_totals(self):
        rows = self.rows([(0, (0, 0, 10), {}), (60, (600, 300, 70), {'nx': 60}), (120, (1800, 900, 130), {'nx': 120})])
        view = dash.build_view(rows, 0, 120, 60)
        self.assertEqual(view['summary']['queries'], 1800)
        self.assertEqual(view['summary']['hit_pct'], 50.0)
        self.assertEqual(view['series']['qps'], [10.0, 20.0])
        self.assertEqual(view['summary']['nxdomain_pct'], 6.7)
        self.assertEqual(view['qtypes'], {'A': 1800})

    def test_nodata_is_not_double_counted_in_percentages(self):
        rows = self.rows([(0, (0, 0, 1), {}), (60, (100, 50, 61), {'nx': 10})])
        for _, sample in rows:
            sample['num.answer.rcode.nodata'] = 40.0 if sample['total.num.queries'] else 0.0
        view = dash.build_view(rows, 0, 60, 60)
        self.assertEqual(view['summary']['nxdomain_pct'], 10.0)
        self.assertEqual(view['series']['nxdomain_pct'], [10.0])
        self.assertEqual(view['rcodes']['nodata'], 40)

    def test_counter_reset_does_not_go_negative(self):
        rows = self.rows([(0, (1000, 500, 500), {}), (60, (30, 10, 20), {})])
        view = dash.build_view(rows, 0, 60, 60)
        self.assertEqual(view['summary']['queries'], 30)
        self.assertEqual(view['series']['qps'], [0.5])

    def test_gap_is_null_not_interpolated(self):
        rows = self.rows([(0, (0, 0, 1), {}), (60, (60, 30, 61), {}), (3000, (120, 60, 3001), {})])
        view = dash.build_view(rows, 0, 3000, 60)
        self.assertIsNone(view['series']['qps'][-1])

    def test_windowed_recursion_average(self):
        rows = self.rows([(0, (100, 0, 1), {'avg': 0.010}), (60, (200, 0, 61), {'avg': 0.020})])
        view = dash.build_view(rows, 0, 60, 60)
        # sum went 1000ms -> 4000ms over 100 replies = 30ms in the window
        self.assertEqual(view['series']['recursion_ms'], [30.0])

    def test_quiet_minutes_do_not_leave_holes_in_ratio_series(self):
        # recursion only happens in every 3rd minute; a 5-minute window must still define every point
        spec, q, rr, hit = [(0, (0, 0, 1), {})], 0, 0, 0
        for i in range(1, 11):
            q += 60
            busy = i % 3 == 0
            hit += 0 if busy else 60
            rr += 30 if busy else 0
            spec.append((i * 60, (q, hit, i * 60 + 1), {'rr': rr, 'avg': 0.02}))
        view = dash.build_view(self.rows(spec), 0, 600, 60)
        self.assertTrue(all(v is not None for v in view['series']['qps']))
        self.assertTrue(all(v is not None for v in view['series']['hit_pct'][2:]))
        self.assertTrue(all(v is not None for v in view['series']['recursion_ms'][2:]))

    def test_ratio_window_does_not_average_across_an_outage(self):
        rows = self.rows([(0, (0, 0, 1), {}), (60, (60, 60, 61), {}), (3000, (6000, 0, 3001), {'rr': 5000}),
                          (3060, (6060, 60, 3061), {})])
        view = dash.build_view(rows, 0, 3060, 60)
        self.assertIsNone(view['series']['hit_pct'][-2])  # the gap itself
        self.assertEqual(view['series']['hit_pct'][-1], 100.0)  # not blended with pre-outage data

    def test_empty_history(self):
        view = dash.build_view([], 0, 100, 60)
        self.assertEqual(view['series']['ts'], [])
        self.assertIsNone(view['summary']['hit_pct'])

    def test_baseline_sample_before_range_is_used(self):
        rows = self.rows([(0, (100, 50, 1), {}), (70, (400, 200, 71), {})])
        view = dash.build_view(rows, 60, 120, 60)
        self.assertEqual(view['summary']['queries'], 300)


class TopTests(unittest.TestCase):
    REPLY = '[{ts}] unbound[5338:0] reply: {c} {n} {t} IN {rc} 0.000000 1 85'
    ACTION = '[{ts}] unbound[5338:0] info: {n} always_nxdomain {c}@48260 {n} A IN'

    def test_real_log_format_replies_and_local_actions(self):
        lines = [self.REPLY.format(ts=1000, c='192.168.0.5', n='Example.COM.', t='A', rc='NOERROR'),
                 self.REPLY.format(ts=1001, c='192.168.0.5', n='example.com.', t='AAAA', rc='NOERROR'),
                 self.REPLY.format(ts=1002, c='192.168.0.9', n='other.org.', t='A', rc='NOERROR'),
                 self.REPLY.format(ts=1003, c='192.168.0.9', n='ads.net.', t='A', rc='NXDOMAIN'),
                 self.ACTION.format(ts=1003, c='192.168.0.9', n='ads.net.'),
                 self.REPLY.format(ts=1004, c='2001:db8::1', n='v6.test.', t='A', rc='NOERROR'),
                 '[1005] unbound[5338:0] info: generate keytag query _ta-4f66. NULL IN', 'garbage']
        top = dash.parse_query_log(lines)
        self.assertEqual(top['domains'][0], {'name': 'example.com', 'count': 2})
        self.assertNotIn('ads.net', [d['name'] for d in top['domains']])  # blocked is not "allowed"
        self.assertEqual(top['blocked'], [{'name': 'ads.net', 'count': 1}])
        self.assertEqual(top['blocked_total'], 1)
        self.assertEqual(top['clients'][0], {'name': '192.168.0.5', 'count': 2})
        self.assertEqual((top['queries'], top['first'], top['last']), (5, 1000, 1004))

    def test_since_filters_by_epoch(self):
        lines = [self.REPLY.format(ts=ts, c='10.0.0.1', n='a.test.', t='A', rc='NOERROR') for ts in (100, 200, 300)]
        self.assertEqual(dash.parse_query_log(lines, since=200)['queries'], 2)

    def test_plain_log_queries_and_journal_formats(self):
        top = dash.parse_query_log(['[7] unbound[1:0] info: 192.168.0.5 a.test. A IN', 'info: 192.168.0.5 b.test. A IN',
                                    'reply: 192.168.0.6 c.test. A IN NOERROR 0.0 1 50'])
        self.assertEqual(top['queries'], 3)

    def test_no_logging_is_unavailable_not_error(self):
        self.assertFalse(dash.parse_query_log(['x info: server stats for thread 0'])['available'])

    def test_hostile_values_are_ignored_or_kept_as_data(self):
        top = dash.parse_query_log([self.REPLY.format(ts=1, c='not-an-ip', n='a.test.', t='A', rc='NOERROR'),
                                    self.REPLY.format(ts=1, c='10.0.0.1', n='x' * 300 + '.', t='A', rc='NOERROR')])
        self.assertEqual(top['queries'], 0)

    def test_log_file_tail_is_bounded_and_uses_previous_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp) / 'unbound.log'
            row = lambda i: self.REPLY.format(ts=i, c='10.0.0.1', n=f'h{i}.test.', t='A', rc='NOERROR') + '\n'
            (pathlib.Path(tmp) / 'unbound.log.1').write_text(''.join(row(i) for i in range(0, 50)))
            base.write_text(''.join(row(i) for i in range(50, 100)))
            lines = dash.log_lines(base, max_bytes=10_000_000)
            self.assertEqual(len(lines), 100)
            self.assertTrue(lines[0].startswith('[0]') and lines[-1].startswith('[99]'))  # chronological
            small = dash.log_lines(base, max_bytes=len(row(99)) * 5 + 3)
            self.assertLessEqual(len(small), 5)
            self.assertTrue(all(l.startswith('[') for l in small))  # cut-off first line dropped


class SamplerTests(unittest.TestCase):
    def make(self, reader, now):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return dash.Dashboard(tmp.name, reader, log_reader=lambda: [], interval=60, retention_days=1, clock=lambda: now[0])

    def test_sample_persists_prunes_and_survives_failures(self):
        now, calls = [1_000_000], []

        def reader():
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('control socket down')
            return stats(100 * len(calls), 50 * len(calls), len(calls) * 60)
        board = self.make(reader, now)
        board.sample()
        now[0] += 60
        board.sample()
        self.assertEqual(board.last_error, 'control socket down')
        self.assertEqual(board.history.count(), 1)
        now[0] += 60
        board.sample()
        self.assertIsNone(board.last_error)
        now[0] += 2 * 86400
        board.sample()
        self.assertEqual(board.history.count(), 1)  # older rows pruned past retention

    def test_empty_output_is_an_error_not_a_zero_sample(self):
        board = self.make(lambda: 'error: no control', [5])
        board.sample()
        self.assertEqual(board.history.count(), 0)
        self.assertIn('no statistics', board.last_error)

    def test_disabled_interval_never_starts_thread(self):
        board = self.make(lambda: '', [5])
        board.interval = 0
        board.start()
        self.assertFalse(board.view('1h')['sampling'])

    def test_unknown_range_rejected(self):
        with self.assertRaises(ValueError):
            self.make(lambda: '', [5]).view('90d')

    def test_history_file_private(self):
        board = self.make(lambda: stats(1, 1, 1), [10])
        board.sample()
        self.assertEqual(board.history.path.stat().st_mode & 0o777, 0o600)


class RouteTests(unittest.TestCase):
    def test_routes_require_login_and_lifecycle_runs_sampler(self):
        try:
            from fastapi import FastAPI, Depends, HTTPException, Request
            from fastapi.testclient import TestClient
        except ImportError:
            self.skipTest('FastAPI not installed')
        state = {'ok': False}

        def login():
            if not state['ok']:
                raise HTTPException(401, 'login')

        class Upstream:
            pass
        up = Upstream()
        up.app, up.BASE_DIR, up._login_required = FastAPI(), '.', login
        up._template = lambda request, name, ctx: {'template': name, **ctx}
        with tempfile.TemporaryDirectory() as tmp:
            board = dash.Dashboard(tmp, lambda: stats(10, 5, 5), log_reader=lambda: [], interval=60)
            dash.install(up, board)
            with TestClient(up.app) as client:
                self.assertEqual(client.get('/api/dashboard').status_code, 401)
                self.assertEqual(client.get('/dashboard').status_code, 401)
                state['ok'] = True
                data = client.get('/api/dashboard?range=6h').json()
                self.assertEqual(data['range'], '6h')
                self.assertTrue(data['sampling'])
                self.assertEqual(client.get('/api/dashboard?range=bad').status_code, 422)
                self.assertEqual(client.get('/dashboard').json()['template'], 'dashboard.html')
                self.assertEqual(board.history.count(), 1)
            self.assertFalse(board._thread)


if __name__ == '__main__':
    unittest.main()
