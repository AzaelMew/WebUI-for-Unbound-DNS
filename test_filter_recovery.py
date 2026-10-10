"""Recovery operates only on temporary config trees; never imports app."""
import io
import json
import subprocess
import sys
import tarfile
from pathlib import Path
from unittest.mock import patch
import test_filters_scaling as scaling
import filters


class RecoveryTests(scaling.ScalingTests):
    # Reuse fixtures, not the inherited scaling suite.
    def setUp(self):
        super().setUp()
        self.manager_instance = self.manager(downloader=lambda url: b'old.example\n')
        self.manager_instance.initialize_empty()
        self.identifier = self.manager_instance.add_list('Recovery', 'https://lists.example/a')['lists'][0]['id']
        self.manager_instance.refresh_list(self.identifier)
        self.manager_instance.enable_list(self.identifier, True)
        self.backup, self.blob = self.manager_instance._backup()
        self.good = self.manager_instance.state_path.read_bytes()
        self.policy = self.target.read_bytes()
        self.manager_instance.downloader = lambda url: b'new.example\n'
        self.manager_instance.refresh_list(self.identifier)

    def recover(self, **kwargs):
        import filter_recovery
        return filter_recovery.recover(self.base, self.main, self.target, self.backup.name, **kwargs)

    def test_validated_restore_clears_interrupted_journal_without_activation(self):
        self.manager_instance.journal_path.write_text(json.dumps({'backup': self.backup.name}))
        unrelated = self.target.parent / 'unrelated.conf'
        unrelated.write_text('server:\n    verbosity: 1\n')
        with patch.object(filters.subprocess, 'run', wraps=subprocess.run) as run:
            result = self.recover(restore=True)
        self.assertTrue(result['restored'])
        self.assertEqual(self.target.read_bytes(), self.policy)
        self.assertEqual(self.manager_instance.state_path.read_bytes(), self.good)
        self.assertFalse(self.manager_instance.journal_path.exists())
        self.assertEqual(unrelated.read_text(), 'server:\n    verbosity: 1\n')
        self.assertFalse(any(call.args[0][0] == 'systemctl' for call in run.call_args_list))
        self.manager()

    def test_dry_run_validates_without_live_writes(self):
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        self.assertFalse(self.recover()['restored'])
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)

    def test_corrupt_or_missing_external_cache_rejected_before_live_writes(self):
        state = json.loads(self.good)
        cache = self.manager_instance.data / state['lists'][0]['cache']
        cache.chmod(0o600)
        cache.write_bytes(b'corrupt SQLite')
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        with self.assertRaises(ValueError):
            self.recover(restore=True)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)
        cache.unlink()
        with self.assertRaises(ValueError):
            self.recover(restore=True)

    def test_canonical_cache_content_must_match_restored_fragment(self):
        import sqlite3
        previous = json.loads(self.good)
        cache = self.manager_instance.data / previous['lists'][0]['cache']
        cache.chmod(0o600)
        with sqlite3.connect(cache) as db:
            db.execute('UPDATE domains SET domain=?', ('different.example',))
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'policy|fragment'):
            self.recover(restore=True)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)

    def test_corrupt_gzip_rejected_before_live_writes(self):
        self.blob.chmod(0o600)
        with self.blob.open('r+b') as output:
            output.seek(-1, 2)
            output.write(b'X')
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        with self.assertRaises(ValueError):
            self.recover(restore=True)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)

    def test_malicious_archive_members_rejected_before_live_writes(self):
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        original = self.backup.read_bytes()
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('unbound/link', tarfile.SYMTYPE), ('unbound/hard', tarfile.LNKTYPE),
                           ('unbound/device', tarfile.CHRTYPE)]:
            with tarfile.open(self.backup, 'w:gz') as archive:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '/etc/unbound'
                archive.addfile(info, io.BytesIO(b''))
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.recover(restore=True)
            self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)
        self.backup.write_bytes(original)

    def test_external_blob_symlink_and_manifest_traversal_rejected(self):
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        raw = self.blob.read_bytes()
        self.blob.unlink()
        outside = self.root / 'outside.gz'
        outside.write_bytes(raw)
        self.blob.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.recover(restore=True)
        self.blob.unlink()
        self.blob.write_bytes(raw)
        with tarfile.open(self.backup) as source:
            members = [(info, source.extractfile(info).read() if info.isfile() else None)
                       for info in source.getmembers()]
        with tarfile.open(self.backup, 'w:gz') as archive:
            for info, body in members:
                if info.name == 'filter-manifest.json':
                    manifest = json.loads(body)
                    manifest['managed_blob'] = '../outside.gz'
                    body = json.dumps(manifest).encode()
                    info.size = len(body)
                archive.addfile(info, io.BytesIO(body) if body is not None else None)
        with self.assertRaises(ValueError):
            self.recover(restore=True)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)

    def test_live_validation_failure_restores_current_files_and_retains_journal(self):
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        def check(path):
            if Path(path) == self.main:
                raise ValueError('Injected live validation failure')
        with self.assertRaisesRegex(ValueError, 'live validation'):
            self.recover(restore=True, checker=check)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)
        self.assertTrue(self.manager_instance.journal_path.exists())

    def test_metadata_journal_recovery_restores_last_good_without_changing_policy(self):
        import filter_recovery
        manager = self.manager_instance
        previous = json.loads(manager.state_path.read_text())
        previous['lists'][0]['last_error'] = 'last good metadata'
        journal = {'kind': 'metadata', 'previous_state': previous,
                   'candidate_caches': [manager.state['lists'][0]['cache']]}
        manager.journal_path.write_text(json.dumps(journal))
        before = self.target.read_bytes()
        result = filter_recovery.recover(self.base, self.main, self.target, journal=True, restore=True)
        self.assertTrue(result['restored'])
        self.assertEqual(json.loads(manager.state_path.read_text()), previous)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertFalse(manager.journal_path.exists())
        self.manager()

    def test_old_uncompressed_blob_backup_remains_recoverable(self):
        import gzip
        with gzip.open(self.blob, 'rb') as source:
            raw = source.read()
        old_blob = self.blob.with_suffix('')
        old_blob.write_bytes(raw)
        with tarfile.open(self.backup) as source:
            members = [(info, source.extractfile(info).read() if info.isfile() else None)
                       for info in source.getmembers()]
        with tarfile.open(self.backup, 'w:gz') as archive:
            for info, body in members:
                if info.name == 'filter-manifest.json':
                    manifest = json.loads(body)
                    manifest['managed_blob'] = 'blobs/' + old_blob.name
                    body = json.dumps(manifest).encode()
                    info.size = len(body)
                archive.addfile(info, io.BytesIO(body) if body is not None else None)
        self.recover(restore=True)
        self.assertEqual(self.target.read_bytes(), self.policy)

    def test_migration_metadata_journal_restores_exact_v1_backup_and_can_restart(self):
        import filter_recovery
        manager = self.manager_instance
        legacy = {'version': 1, 'blocked': [], 'allowed': [], 'lists': [
            {'id': self.identifier, 'name': 'Recovery', 'url': 'https://lists.example/a', 'enabled': True,
             'domains': ['new.example'], 'last_updated': None, 'last_attempt': None,
             'last_error': None, 'unsupported': 0, 'samples': []}]}
        raw = json.dumps(legacy, separators=(',', ':')).encode()
        (manager.data / 'state.v1.backup.json').write_bytes(raw)
        manager.journal_path.write_text(json.dumps({'kind': 'metadata', 'previous_state': legacy,
            'previous_state_text': raw.decode(), 'candidate_caches': [manager.state['lists'][0]['cache']]}))
        filter_recovery.recover(self.base, self.main, self.target, journal=True, restore=True)
        self.assertEqual(manager.state_path.read_bytes(), raw)
        self.manager()

    def test_stamped_backup_restore_preserves_exact_canary_without_network(self):
        manager = self.manager_instance
        manager.verifier = lambda token, blocked: None
        manager.set_domains('blocked', ['manual.example'])
        self.backup, self.blob = manager._backup()
        self.policy = self.target.read_bytes()
        token, blocked = filters.filter_activation.read_profile(self.target)
        manager.set_domains('blocked', ['changed.example'])
        self.recover(restore=True)
        self.assertEqual(self.target.read_bytes(), self.policy)
        self.assertEqual(filters.filter_activation.read_profile(self.target), (token, blocked))

    def test_blob_decompression_bound_refuses_expansion_before_replace(self):
        import gzip
        import hashlib
        body = filters.HEADER.encode() + b'    local-zone: "ads.example." always_nxdomain\n' * 1024
        blob = self.manager_instance.backups / 'blobs' / (hashlib.sha256(body).hexdigest() + '.conf.gz')
        with gzip.open(blob, 'wb') as output:
            output.write(body)
        before = self.target.read_bytes()
        with self.assertRaisesRegex(ValueError, 'size bound'):
            filters._restore_blob(blob, self.target, max_bytes=100)
        self.assertEqual(self.target.read_bytes(), before)

    def test_metadata_journal_with_no_previous_state_restores_uninitialized_files(self):
        import filter_recovery
        manager = self.manager_instance
        self.target.unlink()
        empty = {'version': 2, 'blocked': [], 'allowed': [], 'lists': [], 'effective_count': 0}
        manager.state_path.write_text(json.dumps(empty))
        manager.journal_path.write_text(json.dumps({'kind': 'metadata', 'previous_state': None,
                                                   'previous_state_text': None, 'candidate_caches': []}))
        filter_recovery.recover(self.base, self.main, self.target, journal=True, restore=True)
        self.assertFalse(manager.state_path.exists())
        self.assertFalse(self.target.exists())
        self.assertFalse(manager.journal_path.exists())
        self.manager()

    def test_corrupt_archive_gzip_crc_rejected_before_live_writes(self):
        before = self.target.read_bytes(), self.manager_instance.state_path.read_bytes()
        with self.backup.open('r+b') as output:
            output.seek(-8, 2)
            old = output.read(1)
            output.seek(-8, 2)
            output.write(bytes([old[0] ^ 0xff]))
        with self.assertRaisesRegex(ValueError, 'archive'):
            self.recover(restore=True)
        self.assertEqual((self.target.read_bytes(), self.manager_instance.state_path.read_bytes()), before)

    def test_cli_restore_is_explicit_and_offline(self):
        result = subprocess.run([sys.executable, 'filter_recovery.py', '--base', str(self.base),
            '--main', str(self.main), '--target', str(self.target), '--backup', self.backup.name, '--restore'],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), self.policy)
        self.assertIn('not activated', result.stdout)


# unittest discovers methods on inherited test classes. Hide inherited tests.
for _name in list(vars(scaling.ScalingTests)):
    if _name.startswith('test_') and _name not in RecoveryTests.__dict__:
        setattr(RecoveryTests, _name, None)

if __name__ == '__main__':
    import unittest
    unittest.main(verbosity=2)
