"""Actual wire-DNS semantics; needs Unbound, never the app or live config."""
import os
import pathlib
import shutil
import tempfile
import unittest
import filter_benchmark as bench


@unittest.skipUnless(shutil.which('unbound') and shutil.which('unbound-checkconf'), 'isolated Unbound binaries required')
class ResolverSemantics(unittest.TestCase):
    def test_apex_descendants_allow_wins_for_both_representations(self):
        root = bench.safe_workspace(os.environ.get('FILTER_BENCHMARK_WORKSPACE', os.environ.get('TMPDIR', str(pathlib.Path.home() / '.hermes/cache/scratch'))))
        with tempfile.TemporaryDirectory(dir=root) as td, bench.mock_upstream() as upstream:
            path = pathlib.Path(td)
            source = path / 'feed'
            source.write_text('example.com\nbad.good.example.com\nexplicit.allowed.example.net\n')
            database = path / 'domains.sqlite'
            bench.parse_source(source, database)
            for kind in ('localzone', 'rpz'):
                with self.subTest(kind=kind):
                    fragment = path / kind
                    bench.render_domains(database, fragment, kind, ['good.example.com', 'allowed.example.net'])
                    with bench.isolated_resolver(path, kind, fragment, upstream.port) as resolver:
                        for name in ('example.com', 'a.example.com', 'a.b.example.com', 'bad.example.com'):
                            answer = bench.query(resolver['port'], name)
                            self.assertEqual(answer['rcode'], 3, (kind, name, answer))
                        for name in ('good.example.com', 'www.good.example.com', 'bad.good.example.com', 'allowed.example.net', 'explicit.allowed.example.net', 'example.com.unrelated.net'):
                            answer = bench.query(resolver['port'], name)
                            self.assertEqual(answer['rcode'], 0, (kind, name, answer))
                            self.assertEqual(answer['answers'], ['192.0.2.123'], (kind, name, answer))

    def test_isolated_resolver_cleanup_after_query_exception(self):
        root = bench.safe_workspace(os.environ.get('FILTER_BENCHMARK_WORKSPACE', os.environ.get('TMPDIR', str(pathlib.Path.home() / '.hermes/cache/scratch'))))
        with tempfile.TemporaryDirectory(dir=root) as td, bench.mock_upstream() as upstream:
            with self.assertRaisesRegex(RuntimeError, 'deliberate'):
                with bench.isolated_resolver(pathlib.Path(td), 'baseline', None, upstream.port) as resolver:
                    pid = resolver['pid']
                    raise RuntimeError('deliberate')
            self.assertFalse(pathlib.Path(f'/proc/{pid}').exists())


if __name__ == '__main__':
    unittest.main()
