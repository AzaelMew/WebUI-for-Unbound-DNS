"""Backend-free safeguards for isolated benchmark tooling."""
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent


class SafetyTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('isolated_filter_benchmark', ROOT / 'filter_benchmark.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_rejects_production_workspace(self):
        self.assertTrue((ROOT / 'filter_benchmark.py').exists(), 'safe benchmark implementation is missing')
        bench = self.load()
        for path in ('/etc/unbound', '/opt/unbound-webui', '/opt/unbound-webui/probes'):
            with self.assertRaises(ValueError):
                bench.safe_workspace(path)

    def test_process_is_reaped_on_exception(self):
        bench = self.load()
        with self.assertRaisesRegex(RuntimeError, 'deliberate'):
            with bench.managed_process([sys.executable, '-c', 'import time; time.sleep(60)']) as proc:
                raise RuntimeError('deliberate')
        self.assertIsNotNone(proc.poll())

    def test_process_kill_fallback(self):
        bench = self.load()
        with bench.managed_process([sys.executable, '-c', 'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print("ready",flush=True); time.sleep(60)'], stdout=subprocess.PIPE, stop_timeout=.05) as proc:
            self.assertEqual(proc.stdout.readline(), b'ready\n')
        self.assertIsNotNone(proc.poll())
        proc.stdout.close()

    def test_file_backed_parser_and_allow_precedence(self):
        bench = self.load()
        with tempfile.TemporaryDirectory(dir=bench.safe_workspace(__import__('os').environ.get('FILTER_BENCHMARK_WORKSPACE', str(pathlib.Path.home() / '.hermes/cache/scratch')))) as td:
            root = pathlib.Path(td)
            source = root / 'feed.txt'
            source.write_text('! comment\n||Example.com^\n||example.com^\n||bad.good.example.com^\n||other.invalid^\n@@||allow.com^\n')
            result = bench.parse_source(source, root / 'domains.sqlite')
            self.assertEqual(result['unique_domains'], 3)
            self.assertEqual(result['unsupported'], 1)
            for kind in ('localzone', 'rpz'):
                output = root / kind
                count = bench.render_domains(root / 'domains.sqlite', output, kind, ['good.example.com'])
                self.assertEqual(count, 2)
                text = output.read_text()
                self.assertNotIn('bad.good.example.com', text)
                self.assertIn('example.com', text)
                if kind == 'rpz':
                    self.assertIn('*.example.com CNAME .', text)
                    self.assertIn('*.good.example.com CNAME rpz-passthru.', text)
                else:
                    self.assertIn('good.example.com.\" transparent', text)

    def test_summary_reports_errors_and_nan_not_fabricated_success(self):
        bench = self.load()
        result = bench.latency_summary([1, 2, 3, 4, 5], 2)
        self.assertEqual(result['count'], 5)
        self.assertEqual(result['errors'], 2)
        self.assertEqual(result['median_ms'], 3)
        self.assertEqual(result['p95_ms'], 5)

    def test_workspace_rejects_environment_redirect_to_production(self):
        bench = self.load()
        from unittest.mock import patch
        with patch.dict(__import__('os').environ, {'TMPDIR': '/etc/unbound'}), patch.object(pathlib.Path, 'mkdir') as mkdir:
            with self.assertRaises(ValueError):
                bench.safe_workspace('/etc/unbound')
            mkdir.assert_not_called()

    def test_pipe_resources_closed_when_process_killed(self):
        bench = self.load()
        with bench.managed_process([sys.executable, '-c', 'import time; time.sleep(60)'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            pass
        self.assertTrue(proc.stdout.closed)
        self.assertTrue(proc.stderr.closed)

    def test_sigint_reaps_child(self):
        bench = self.load()
        with self.assertRaises(KeyboardInterrupt):
            with bench.managed_process([sys.executable, '-c', 'import time; time.sleep(60)']) as proc:
                __import__('os').kill(__import__('os').getpid(), __import__('signal').SIGINT)
        self.assertIsNotNone(proc.poll())

    def test_dns_readiness_timeout_reaps_child(self):
        bench = self.load()
        with self.assertRaises(TimeoutError):
            with bench.managed_process([sys.executable, '-c', 'import time; time.sleep(60)']) as proc:
                bench.wait_dns(proc, bench.free_port(), timeout=.04)
        self.assertIsNotNone(proc.poll())

    def test_cached_source_hash_mismatch_is_rejected(self):
        bench = self.load()
        workspace = bench.safe_workspace(__import__('os').environ.get('FILTER_BENCHMARK_WORKSPACE', str(pathlib.Path.home() / '.hermes/cache/scratch')))
        with tempfile.TemporaryDirectory(dir=workspace) as td:
            source = pathlib.Path(td) / 'feed'
            source.write_text('example.com\n')
            pathlib.Path(str(source) + '.metadata.json').write_text('{"sha256":"wrong","url":"https://example.com/feed"}')
            with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                bench.cached_source_info(source)

    def test_wire_query_rejects_port_53(self):
        bench = self.load()
        with self.assertRaises(ValueError):
            bench.query(53, 'example.com')

    def test_end_to_end_fixture_records_real_dns_and_workers(self):
        bench = self.load()
        if not __import__('shutil').which('unbound'):
            self.skipTest('Unbound required')
        workspace = bench.safe_workspace(__import__('os').environ.get('FILTER_BENCHMARK_WORKSPACE', __import__('os').environ.get('TMPDIR', str(pathlib.Path.home() / '.hermes/cache/scratch'))))
        with tempfile.TemporaryDirectory(dir=workspace) as td:
            root = pathlib.Path(td)
            source = root / 'source'
            source.write_text('||example.com^\n||blocked.other.net^\n')
            result = bench.benchmark(root, source, original_source=None, cached_count=100, uncached_count=30)
            self.assertTrue(result['production_unchanged'])
            self.assertEqual(result['parser']['unique_domains'], 2)
            self.assertEqual(len(result['resolvers']), 3)
            for resolver in result['resolvers']:
                self.assertNotIn('error', resolver)
                for case in ('cached', 'uncached', 'blocked'):
                    self.assertEqual(resolver[case]['errors'], 0)
                self.assertEqual(resolver['uncached']['upstream_queries'], 30)
                self.assertEqual(resolver['cached']['upstream_queries'], 0)

    def test_import_has_no_process_or_backend_side_effect(self):
        result = subprocess.run([sys.executable, '-c', 'import probe_tif_mini, probe_tif_full, filter_benchmark; assert "filters" not in __import__("sys").modules'], cwd=ROOT / 'tools', capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
