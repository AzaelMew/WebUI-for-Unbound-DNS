"""Parent regression gates for configured limits and pre-mutation resources."""
import unittest
from unittest.mock import patch
import filters
import test_filters_scaling


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_filters_scaling.ScalingTests('test_v1_migration_preserves_metadata_enabled_cache_and_backup')
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def test_configured_limits_are_integer_not_boolean_or_truncated_float(self):
        for value in [True, 3.5, '3.5']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.fixture.manager(max_entries=value)

    def test_compatibility_parser_reports_actual_domain_limit(self):
        with self.assertRaisesRegex(ValueError, '1'):
            filters.parse_list(b'a.example\nb.example\n', max_domains=1)

    def test_memory_refusal_leaves_existing_rules_and_state_unchanged(self):
        manager = self.fixture.manager()
        manager.initialize_empty()
        before = self.fixture.target.read_bytes()
        state = manager.state_path.read_bytes()
        with patch('filter_resources.available_memory', return_value=384 * 1024 * 1024):
            with self.assertRaisesRegex(ValueError, 'headroom'):
                manager.set_domains('blocked', ['new.example'])
        self.assertEqual(self.fixture.target.read_bytes(), before)
        self.assertEqual(manager.state_path.read_bytes(), state)
        self.assertEqual(self.fixture.activations, 0)
        self.assertFalse(manager.journal_path.exists())

    def test_manual_api_payload_does_not_override_configured_limit_with_a_constant(self):
        self.assertNotIn('maxItems', filters.DomainsPayload.model_json_schema()['properties']['domains'])

    def test_existing_corrupt_rollback_blob_rejects_change_before_activation(self):
        manager = self.fixture.manager()
        manager.initialize_empty()
        manager.set_domains('blocked', ['old.example'])
        _, blob = manager._backup()
        assert blob is not None
        blob.chmod(0o600)
        blob.write_bytes(b'broken gzip')
        original = self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations
        with self.assertRaisesRegex(ValueError, 'blob'):
            manager.set_domains('blocked', ['new.example'])
        self.assertEqual((self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations), original)

    def test_interrupted_tar_does_not_publish_a_retained_archive(self):
        manager = self.fixture.manager()
        manager.initialize_empty()
        before_archives = sorted(p.name for p in manager.backups.glob('filters_*.tgz'))
        before = self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations
        with patch.object(filters.tarfile.TarFile, 'add', side_effect=OSError('interrupted archive')):
            with self.assertRaisesRegex(OSError, 'interrupted archive'):
                manager.set_domains('blocked', ['new.example'])
        self.assertEqual(sorted(p.name for p in manager.backups.glob('filters_*.tgz')), before_archives)
        self.assertEqual((self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations), before)

    def test_config_tree_symlink_is_refused_before_live_changes(self):
        manager = self.fixture.manager()
        manager.initialize_empty()
        file = self.fixture.config / 'real.conf'
        file.write_text('server:\n    verbosity: 0\n')
        (self.fixture.target.parent / 'linked.conf').symlink_to(file)
        before = self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations
        with self.assertRaisesRegex(ValueError, 'symlink'):
            manager.set_domains('blocked', ['new.example'])
        self.assertEqual((self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations), before)

    def test_config_tree_hardlinks_are_archived_as_recoverable_regular_files(self):
        import os
        manager = self.fixture.manager()
        manager.initialize_empty()
        file = self.fixture.target.parent / 'other.conf'
        file.write_text('server:\n    verbosity: 0\n')
        os.link(file, self.fixture.target.parent / 'linked.conf')
        manager.set_domains('blocked', ['new.example'])
        archive, _ = manager._backup()
        with filters.tarfile.open(archive) as backup:
            self.assertTrue(all(item.isfile() or item.isdir() for item in backup.getmembers()))

    def test_new_compressed_blob_is_verified_before_live_change(self):
        manager = self.fixture.manager()
        manager.initialize_empty()
        before = self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations
        original = filters._compress_blob
        def corrupt(source, blob, deadline=None):
            original(source, blob, deadline)
            blob.chmod(0o600)
            with blob.open('r+b') as handle:
                handle.seek(-8, 2)
                value = handle.read(1)
                handle.seek(-8, 2)
                handle.write(bytes([value[0] ^ 0xff]))
        with patch.object(filters, '_compress_blob', corrupt):
            with self.assertRaisesRegex(ValueError, 'blob'):
                manager.set_domains('blocked', ['new.example'])
        self.assertEqual((self.fixture.target.read_bytes(), manager.state_path.read_bytes(), self.fixture.activations), before)

    def test_missing_original_fragment_rollback_fsyncs_directory_before_journal_clear(self):
        import os
        manager = self.fixture.manager()
        checked = manager._check
        sync = filters.os.fsync
        deletion_synced = []
        def check(path, deadline=None):
            if path == self.fixture.main:
                raise ValueError('Injected live check failure')
            return checked(path, deadline)
        def fsync(fd):
            destination = os.readlink('/proc/self/fd/' + str(fd))
            if destination == str(self.fixture.target.parent) and not self.fixture.target.exists():
                deletion_synced.append(True)
            return sync(fd)
        with patch.object(manager, '_check', check), patch.object(filters.os, 'fsync', fsync):
            with self.assertRaisesRegex(ValueError, 'Injected live'):
                manager.initialize_empty()
        self.assertTrue(deletion_synced, 'rollback unlink must be durably synced before clearing the journal')
        self.assertFalse(self.fixture.target.exists())
        self.assertFalse(manager.journal_path.exists())


if __name__ == '__main__':
    unittest.main()
