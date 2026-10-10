"""Safety and real isolated backend tests; no production imports or DNS."""
import sys as _sys
from pathlib import Path as _Path
_sys.path[:0] = [str(_Path(__file__).resolve().parent.parent), str(_Path(__file__).resolve().parent)]  # repo root + tools/
import importlib
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest


class ProbeTests(unittest.TestCase):
    def probe(self):
        try:
            return importlib.import_module('probe_filter_backend')
        except ModuleNotFoundError:
            self.fail('Reusable backend probe has not been implemented')

    def test_workspace_refuses_production_even_with_tmpdir_override(self):
        probe = self.probe()
        old = os.environ.get('TMPDIR')
        os.environ['TMPDIR'] = '/etc/unbound'
        try:
            for path in ['/etc/unbound', '/opt/unbound-webui', '/tmp/backend-probe']:
                with self.subTest(path=path), self.assertRaises(ValueError):
                    probe.safe_workspace(path)
            scratch = Path.home() / '.hermes/cache/scratch'
            scratch.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(dir=scratch) as td:
                self.assertEqual(probe.safe_workspace(td), Path(td).resolve())
                link = Path(td) / 'escape'
                link.symlink_to('/etc')
                with self.assertRaises(ValueError):
                    probe.safe_workspace(link / 'unbound')
        finally:
            if old is None:
                os.environ.pop('TMPDIR', None)
            else:
                os.environ['TMPDIR'] = old

    def test_owned_process_reaps_on_interrupt_and_timeout(self):
        probe = self.probe()
        self.assertTrue(hasattr(probe, 'owned_process'), 'Owned child cleanup missing')
        for error in [KeyboardInterrupt(), subprocess.TimeoutExpired('test', .01), RuntimeError('test')]:
            with self.subTest(error=type(error).__name__):
                with self.assertRaises(type(error)):
                    with probe.owned_process([sys.executable, '-c', 'import time; time.sleep(60)']) as proc:
                        raise error
                self.assertIsNotNone(proc.poll())
                with self.assertRaises(ProcessLookupError):
                    os.kill(proc.pid, 0)

    def test_compact_prunes_only_blocked_ancestors(self):
        probe = self.probe()
        self.assertTrue(hasattr(probe, 'compact'), 'Disk-backed compaction missing')
        import sqlite3
        scratch = Path.home() / '.hermes/cache/scratch'
        with tempfile.TemporaryDirectory(dir=scratch) as td:
            root = Path(td)
            database = root / 'cache.sqlite'
            domains = ['a.example', 'b.a.example', 'c.b.a.example', 'aa.example', 'z.example', 'child.z.example']
            with sqlite3.connect(database) as db:
                db.execute('CREATE TABLE domains(domain TEXT PRIMARY KEY) WITHOUT ROWID')
                db.executemany('INSERT INTO domains VALUES (?)', [(d,) for d in domains])
            output = root / 'compact.conf'
            result = probe.compact(database, output, root)
            self.assertEqual(result['domains'], 3)
            self.assertEqual(result['redundant_domains'], 3)
            text = output.read_text()
            for name in ['a.example', 'aa.example', 'z.example']:
                self.assertIn('"' + name + '." always_nxdomain', text)
            self.assertNotIn('"b.a.example.', text)

    @unittest.skipUnless(shutil.which('unbound-checkconf') and shutil.which('unbound'), 'Requires target resolver tools')
    def test_real_backend_refresh_enable_dns_snapshot_backup_and_cleanup(self):
        probe = self.probe()
        self.assertTrue(hasattr(probe, 'run_backend'), 'Final backend benchmark missing')
        scratch = Path.home() / '.hermes/cache/scratch'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as td:
            root = Path(td)
            feed = root / 'feed.txt'
            feed.write_text('||ads.example^\n||child.ads.example^\n||other.example^\n')
            before = set(root.iterdir())
            result = probe.run_backend(root, feed, 'https://lists.example/feed', compact_probe=True)
            self.assertEqual(result['cache']['count'], 3)
            self.assertEqual(result['rendered']['domains'], 3)
            self.assertTrue(result['canonical_match'])
            self.assertTrue(result['production_unchanged'])
            self.assertEqual(result['snapshot']['subscription_domain_arrays'], 0)
            self.assertEqual(result['compact']['domains'], 2)
            self.assertEqual(result['snapshot']['effective_count'], 3)
            checks = [event for event in result['events'] if event['operation'] == 'checkconf' and event['phase'] == 'enable']
            self.assertEqual(len(checks), 3)
            self.assertTrue(all(event['returncode'] == 0 for event in checks))
            self.assertTrue(all(not answer['errors'] for answer in result['resolver']['queries'].values()))
            self.assertEqual(result['backup']['compression'], 'gzip')
            self.assertGreater(result['backup']['additional_data_bytes'], 0)
            self.assertFalse(result['backup']['same_inode_as_managed'])
            self.assertTrue(result['backup']['same_blob_reused'])
            self.assertEqual(result['backup']['repeated_blob_allocated_delta_bytes'], 0)
            self.assertTrue(result['activation_verifications'])
            self.assertTrue(all(event['verified_before_state_commit'] for event in result['activation_verifications']))
            self.assertTrue(result['rollback']['policy_bytes_restored'])
            self.assertTrue(result['rollback']['state_bytes_restored'])
            self.assertTrue(result['rollback']['canary_verified'])
            self.assertEqual(before, set(root.iterdir()))
            for pid in result['owned_pids']:
                with self.assertRaises(ProcessLookupError):
                    os.kill(pid, 0)


if __name__ == '__main__':
    unittest.main()
