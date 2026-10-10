"""Owned isolated rewrite tests. Never import app or activate a real service."""
import importlib
import json
import os
import tempfile
import unittest
import tarfile
from unittest.mock import patch
from pathlib import Path


def backend():
    try:
        return importlib.import_module('rewrites')
    except ModuleNotFoundError as exc:
        if exc.name != 'rewrites':
            raise
        raise AssertionError('Dedicated rewrites backend is not implemented') from exc


def record(hostname='one.example', addresses=None, enabled=True, ttl=300):
    return {'hostname': hostname, 'addresses': addresses or ['192.0.2.1'],
            'enabled': enabled, 'ttl': ttl}


class NormalizationTests(unittest.TestCase):
    def test_launcher_installs_rewrites_before_tls_listener(self):
        import ast
        source = Path(__file__).with_name('run.py').read_text()
        tree = ast.parse(source)
        imports = [node for node in tree.body if isinstance(node, ast.ImportFrom) and node.module == 'rewrites']
        self.assertTrue(imports, 'TLS launcher does not import the rewrite installer')
        alias = next((name.asname or name.name for name in imports[0].names if name.name == 'install'), None)
        self.assertIsNotNone(alias)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == alias]
        self.assertEqual(len(calls), 1, 'Install rewrites exactly once in the protected launcher')
        listener = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'run' and isinstance(node.func.value, ast.Name) and node.func.value.id == 'uvicorn')
        self.assertLess(calls[0].lineno, listener.lineno)

    def test_normalize_dual_stack_idna_ttl_and_reject_unsafe_records(self):
        rw = backend()
        actual = rw.normalize_records([record('BÜCHER.Example.', ['192.168.1.1', '2001:0DB8::1'], ttl=60)])
        self.assertEqual(actual, [record('xn--bcher-kva.example', ['192.168.1.1', '2001:db8::1'], ttl=60)])
        bad = [record('*.' + 'one.example'), record('https://one.example'),
               record('one.example\nserver:'), record(addresses=['fe80::1%eth0']),
               record(addresses=['not-an-ip']), record(ttl=True), record(ttl=0),
               record(ttl=86401), record(enabled=1), record(addresses=['192.0.2.1', '192.0.2.1'])]
        for item in bad:
            with self.subTest(item=item), self.assertRaises(ValueError):
                rw.normalize_records([item])
        with self.assertRaises(ValueError):
            rw.normalize_records([record(), record('ONE.example.')])
        with self.assertRaises(ValueError):
            rw.normalize_records([record(addresses=[f'192.0.2.{n}' for n in range(1, 18)])])
        with self.assertRaises(ValueError):
            rw.normalize_records([record(f'n{n}.example') for n in range(1001)])


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.rw = backend()
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.root = Path(self.tmp.name)
        self.base = self.root / 'app'
        self.base.mkdir()
        self.config = self.root / 'unbound'
        self.fragments = self.config / 'unbound.conf.d'
        self.fragments.mkdir(parents=True)
        self.main = self.config / 'unbound.conf'
        self.main.write_text('server:\n    chroot: ""\n    username: ""\n    module-config: "validator iterator"\ninclude: "' + str(self.fragments / '*.conf') + '"\n')
        self.target = self.fragments / 'webui-rewrites.conf'
        self.calls = []

    def tearDown(self):
        self.tmp.cleanup()

    def manager(self, **kwargs):
        self.assertTrue(hasattr(self.rw, 'RewriteManager'), 'RewriteManager is not implemented')
        return self.rw.RewriteManager(self.base, self.main, self.target,
                                      activate=lambda: self.calls.append('activate'), **kwargs)

    def test_draft_persistence_revision_and_constructor_are_dns_inert(self):
        manager = self.manager()
        self.assertFalse(self.target.exists())
        snapshot = manager.snapshot()
        self.assertEqual(snapshot['revision'], 0)
        self.assertFalse(snapshot['initialized'])
        saved = manager.save_records([record(enabled=False)], 0)
        self.assertEqual(saved['revision'], 1)
        self.assertEqual(saved['records'], [record(enabled=False)])
        self.assertEqual(self.calls, [])
        self.assertFalse(self.target.exists())
        self.assertEqual(self.manager().snapshot(), saved)
        with self.assertRaises(self.rw.RevisionConflict):
            manager.save_records([], 0)
        self.assertEqual(manager.snapshot(), saved)
        self.assertEqual(manager.data.stat().st_mode & 0o777, 0o700)
        self.assertEqual(manager.state_path.stat().st_mode & 0o777, 0o600)

    def test_explicit_initialization_and_enabled_batch_only_rewrites_own_fragment(self):
        manager = self.manager()
        self.assertTrue(hasattr(manager, 'initialize_empty'), 'Explicit initializer missing')
        manager.initialize_empty()
        self.assertEqual(self.target.read_text(), self.rw.HEADER)
        self.assertEqual(self.calls, [])
        filters = self.fragments / 'webui-filters.conf'
        filters.write_text('# another managed policy\nserver:\n    local-zone: "blocked.example." always_nxdomain\n')
        other = self.fragments / 'other.conf'
        other.write_text('server:\n    local-data: "untouched.example. 77 IN A 192.0.2.99"\n')
        before = {p: p.read_bytes() for p in (self.main, filters, other)}
        rows = [record(), record('two.example', ['2001:db8::2'], ttl=61), record('draft.example', enabled=False)]
        saved = manager.save_records(rows, 0)
        self.assertEqual(self.calls, ['activate'])
        self.assertIn('local-zone: "one.example." transparent', self.target.read_text())
        self.assertIn('one.example. 300 IN A 192.0.2.1', self.target.read_text())
        self.assertIn('two.example. 61 IN AAAA 2001:db8::2', self.target.read_text())
        self.assertNotIn('draft.example', self.target.read_text())
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertEqual(self.target.stat().st_mode & 0o777, 0o644)
        with tarfile.open(sorted(manager.backups.glob('rewrites_*.tgz'))[-1]) as archive:
            names = archive.getnames()
            self.assertIn('rewrite-manifest.json', names)
            self.assertIn('rewrite-state.json', names)
            self.assertIn('unbound/unbound.conf.d/webui-rewrites.conf', names)
            self.assertNotIn('unbound/unbound.conf.d/webui-filters.conf', names)
        rows[-1]['hostname'] = 'renamed-draft.example'
        manager.save_records(rows, saved['revision'])
        self.assertEqual(self.calls, ['activate'])
        manager.save_records([], manager.snapshot()['revision'])
        self.assertEqual(self.calls, ['activate', 'activate'])
        self.assertNotIn('one.example', self.target.read_text())

    def test_failed_candidate_verification_restores_verified_old_records(self):
        profiles = []
        def verify(token, records):
            profiles.append((token, records))
            if records and records[0]['hostname'] == 'two.example':
                raise RuntimeError('candidate DNS is stale')
        manager = self.manager(verifier=verify)
        manager.initialize_empty()
        manager.save_records([record()], 0)
        self.assertEqual(len(profiles), 1, 'Candidate must be DNS verified')
        self.assertEqual(len(profiles[0][0]), 64)
        self.assertIn(self.rw.PROBE_NAME, self.target.read_text())
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, 'stale'):
            manager.save_records([record('two.example')], 1)
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
        self.assertEqual(profiles[-1][1], [record()])
        self.assertEqual(self.calls, ['activate'] * 3)
        self.assertFalse(manager.journal_path.exists())
        manager.verifier = lambda token, rows: (_ for _ in ()).throw(RuntimeError('DNS offline'))
        with self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.save_records([record('three.example')], 1)
        self.assertTrue(manager.journal_path.exists())
        with self.assertRaisesRegex(ValueError, 'recover'):
            self.manager()

    def test_exact_unmanaged_data_and_filter_zones_require_explicit_migration(self):
        manager = self.manager()
        manager.initialize_empty()
        other = self.fragments / 'operator.conf'
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        for text in ('server:\n    local-data: "one.example. 60 IN A 192.0.2.88"\n',
                     'server:\n    local-zone: "one.example." transparent\n',
                     'server:\n    local-zone: "one.example." always_nxdomain\n'):
            other.write_text(text)
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'conflict.*one.example.*(allowlist|migrate)'):
                manager.save_records([record()], 0)
            self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
        other.write_text('server:\n    local-zone: "example." always_nxdomain\n')
        manager.save_records([record()], 0)
        self.assertEqual(self.calls, ['activate'])

    def test_exact_managed_filter_allowlist_is_a_working_conflict_remediation(self):
        manager = self.manager()
        manager.initialize_empty()
        filter_file = self.fragments / 'webui-filters.conf'
        filter_file.write_text('server:\n    local-zone: "one.example." always_nxdomain\n')
        with self.assertRaisesRegex(ValueError, 'allowlist'):
            manager.save_records([record()], 0)
        filter_file.write_text('server:\n    local-zone: "one.example." transparent\n')
        saved = manager.save_records([record()], 0)
        self.assertEqual(saved['revision'], 1)
        self.assertEqual(self.calls, ['activate'])

    def test_fail_closed_header_symlink_state_and_journal(self):
        self.target.write_text('# unrelated\nserver:\n')
        with self.assertRaisesRegex(ValueError, 'header'):
            self.manager()
        self.target.unlink()
        outside = self.root / 'outside.conf'
        outside.write_text('server:\n')
        self.target.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.manager()
        self.target.unlink()
        manager = self.manager()
        manager.state_path.write_text('{"version":1,"revision":true,"records":[],"last_updated":null}')
        with self.assertRaisesRegex(ValueError, 'Malformed'):
            self.manager()
        manager.state_path.unlink()
        manager.journal_path.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'recover'):
            self.manager()
        manager.journal_path.unlink()
        manager.data.rename(self.base / 'moved-data')
        manager.data.symlink_to(self.base / 'moved-data')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            manager.save_records([record(enabled=False)], 0)

    def test_external_includes_are_refused_before_live_write(self):
        manager = self.manager()
        manager.initialize_empty()
        outside = self.root / 'external.conf'
        outside.write_text('server:\n    local-data: "not-managed.example. IN A 192.0.2.77"\n')
        self.main.write_text(self.main.read_text() + f'include: "{outside}"\n')
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'include.*config root'):
            manager.save_records([record()], 0)
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)

    def test_generated_filter_includes_cannot_escape_staging_and_large_reads_are_forbidden(self):
        manager = self.manager()
        manager.initialize_empty()
        filter_file = self.fragments / 'webui-filters.conf'
        external = self.root / 'external.conf'
        external.write_text('server:\n')
        filter_file.write_text(f'server:\ninclude: "{external}"\n')
        with self.assertRaisesRegex(ValueError, 'include'):
            manager.save_records([record()], 0)
        filter_file.write_text('server:\n' + ''.join(f'    local-zone: "n{n}.blocked.example." always_nxdomain\n' for n in range(20000)))
        original_bytes, original_text = Path.read_bytes, Path.read_text
        def read_bytes(path, *args, **kwargs):
            self.assertNotEqual(path.name, 'webui-filters.conf', 'Never materialize giant filter policy')
            return original_bytes(path, *args, **kwargs)
        def read_text(path, *args, **kwargs):
            self.assertNotEqual(path.name, 'webui-filters.conf', 'Never materialize giant filter policy')
            return original_text(path, *args, **kwargs)
        from filters import _file_digest
        before = _file_digest(filter_file)
        with patch.object(Path, 'read_bytes', read_bytes), patch.object(Path, 'read_text', read_text):
            manager.save_records([record()], 0)
            manager.snapshot()
        self.assertEqual(_file_digest(filter_file), before)

    def test_nonempty_policy_without_matching_state_is_not_silently_adopted(self):
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        manager.state_path.unlink()
        with self.assertRaisesRegex(ValueError, 'state.*(missing|match)'):
            self.manager()

    def test_glob_must_really_include_target_and_staged_context_preserves_line_endings(self):
        manager = self.manager()
        self.main.write_text('server:\n    chroot: ""\n    username: ""\ninclude: "' + str(self.config / '*.conf') + '"\n')
        # '*' must not match slash: the target is one directory deeper.
        with self.assertRaisesRegex(ValueError, 'not included'):
            manager.initialize_empty()
        self.assertFalse(self.target.exists())
        self.main.write_bytes(('server:\r\n    chroot: ""\r\n    username: ""\r\n    module-config: "validator iterator"\r\ninclude: "' + str(self.fragments / '*.conf') + '"\r\n').encode())
        other = self.fragments / 'context.conf'
        context = b'# preserve CRLF bytes\r\nserver:\r\n    verbosity: 0\r\n'
        other.write_bytes(context)
        real_check = manager._check
        def check(path):
            path = Path(path)
            if path != self.main:
                self.assertEqual((path.parent / other.relative_to(self.config)).read_bytes(), context)
            return real_check(path)
        with patch.object(manager, '_check', check):
            manager.initialize_empty()
        self.assertEqual(other.read_bytes(), context)

    def test_preflight_counts_non_conf_includes_and_honors_real_resource_failures(self):
        manager = self.manager()
        manager.initialize_empty()
        context = self.fragments / 'large-policy.inc'
        context.write_text('server:\n' + '# policy context\n' * 20000)
        self.main.write_text(self.main.read_text() + f'include: "{context}"\n')
        sizes = []
        original = self.rw.filter_resources.validation_budget
        def budget(policy_bytes, **kwargs):
            sizes.append(policy_bytes)
            self.assertGreaterEqual(policy_bytes, context.stat().st_size, 'All included policy must count towards memory preflight')
            return original(policy_bytes, **kwargs)
        with patch.object(self.rw.filter_resources, 'validation_budget', budget):
            manager.save_records([record()], 0)
        self.assertGreaterEqual(len(sizes), 2)
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        for helper in ('validation_budget', 'check_disk_headroom'):
            with patch.object(self.rw.filter_resources, helper, side_effect=ValueError('insufficient resource headroom')):
                with self.assertRaisesRegex(ValueError, 'headroom'):
                    manager.save_records([record('two.example')], 1)
            self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)

    def test_archive_crc_symlink_partial_publication_and_header_validation(self):
        import io
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        backup = manager._backup()
        bad = manager.backups / 'bad.tgz'
        contents = bytearray(backup.read_bytes())
        contents[-8] ^= 1
        bad.write_bytes(contents)
        with self.assertRaisesRegex(ValueError, 'backup'):
            manager._verify_backup(bad)
        bad.unlink()
        bad.symlink_to(backup)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            manager._verify_backup(bad)
        bad.unlink()
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        archives = set(manager.backups.glob('rewrites_*.tgz'))
        with patch.object(manager, '_verify_backup', side_effect=ValueError('incomplete backup')):
            with self.assertRaisesRegex(ValueError, 'incomplete'):
                manager.save_records([record('two.example')], 1)
        self.assertEqual(set(manager.backups.glob('rewrites_*.tgz')), archives)
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
        self.assertFalse(list(manager.backups.glob('.backup-*')))
        # A self-consistent hash manifest is not permission to restore unrelated config.
        with tarfile.open(backup) as archive:
            manifest = json.load(archive.extractfile('rewrite-manifest.json'))
        own = 'unbound/' + str(self.target.relative_to(self.config))
        body = b'# unrelated configuration\nserver:\n'
        import hashlib
        manifest['files'][own] = {'size': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
        with tarfile.open(backup) as source, tarfile.open(bad, 'w:gz') as dest:
            for member in source:
                content = (body if member.name == own else json.dumps(manifest).encode() if member.name == 'rewrite-manifest.json'
                           else source.extractfile(member).read())
                member.size = len(content)
                dest.addfile(member, io.BytesIO(content))
        with self.assertRaisesRegex(ValueError, 'header'):
            manager._verify_backup(bad)


    def test_hash_consistent_archive_requires_canonical_state_fragment_agreement(self):
        import io
        import hashlib
        import copy
        import uuid
        import rewrites_recovery
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        backup = manager._backup()
        own = 'unbound/' + str(self.target.relative_to(self.config))
        with tarfile.open(backup) as archive:
            entries = []
            for member in archive:
                source = archive.extractfile(member)
                assert source is not None
                with source:
                    entries.append((member, source.read()))
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        plain = manager._render(manager.state['records'])
        correct_token = hashlib.sha256(plain).hexdigest()
        wrong_namespace = plain + (self.rw.filter_activation.TOKEN_PREFIX + correct_token + '\n' +
            f'    local-zone: "{self.rw.filter_activation.PROBE_NAME}." static\n' +
            f'    local-data: \'{self.rw.filter_activation.PROBE_NAME}. IN TXT "{correct_token}"\'\n').encode()
        for changed in [plain.replace(b'192.0.2.1', b'192.0.2.2'),
                        plain + b'    local-zone: "unrelated.example." always_nxdomain\n',
                        wrong_namespace, None]:
            with self.subTest(fragment=changed):
                bad = manager.backups / ('rewrites_9999999999999999999_' + uuid.uuid4().hex + '.tgz')
                manifest = json.loads(next(body for member, body in entries if member.name == 'rewrite-manifest.json'))
                if changed is None:
                    del manifest['files'][own]
                else:
                    manifest['files'][own] = {'size':len(changed),'sha256':hashlib.sha256(changed).hexdigest()}
                with tarfile.open(bad, 'w:gz') as archive:
                    for member, body in entries:
                        if member.name == own and changed is None:
                            continue
                        value = changed if member.name == own else json.dumps(manifest).encode() if member.name == 'rewrite-manifest.json' else body
                        assert value is not None
                        info = copy.copy(member)
                        info.size = len(value)
                        archive.addfile(info, io.BytesIO(value))
                with self.assertRaisesRegex(ValueError, 'state.*(match|missing)'):
                    manager._verify_backup(bad)
                with self.assertRaisesRegex(ValueError, 'state.*(match|missing)'):
                    rewrites_recovery.recover(self.base,self.main,self.target,backup=bad,apply=True,webui_stopped=True)
                self.assertEqual((self.target.read_bytes(),manager.state_path.read_bytes()),before)

    def test_metadata_recovery_rejects_state_fragment_disagreement_before_staging(self):
        import rewrites_recovery
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        original_state = manager.state_path.read_text()
        self.target.write_bytes(self.target.read_bytes().replace(b'192.0.2.1', b'192.0.2.2'))
        journal = {'version':1,'kind':'metadata','config_root':str(manager.root),
                   'managed_file':str(manager.target.relative_to(manager.root)),
                   'previous_state_text':original_state}
        manager.journal_path.write_text(json.dumps(journal))
        before = self.target.read_bytes(),manager.state_path.read_bytes(),manager.journal_path.read_bytes()
        with self.assertRaisesRegex(ValueError, 'state.*match'):
            rewrites_recovery.recover(self.base,self.main,self.target,apply=True,webui_stopped=True)
        self.assertEqual((self.target.read_bytes(),manager.state_path.read_bytes(),manager.journal_path.read_bytes()),before)

    def test_write_faults_before_after_rename_and_real_directory_fsync_restore(self):
        import stat
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        for destination in (self.target, manager.state_path):
            for after in (False, True):
                original = os.replace
                failed = False
                def replace(source, target):
                    nonlocal failed
                    if Path(target) == destination and not failed:
                        failed = True
                        if after:
                            original(source, target)
                        raise OSError('injected rename fault')
                    return original(source, target)
                with self.subTest(destination=destination, after=after), patch.object(os, 'replace', replace):
                    with self.assertRaisesRegex(OSError, 'fault'):
                        manager.save_records([record('two.example')], 1)
                self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
                self.assertFalse(manager.journal_path.exists())
        for destination in (self.target, manager.state_path, manager.journal_path):
            renamed = failed = False
            original_replace, original_fsync = os.replace, os.fsync
            def replace(source, target):
                nonlocal renamed
                result = original_replace(source, target)
                if Path(target) == destination:
                    renamed = True
                return result
            def fsync(fd):
                nonlocal failed
                if renamed and not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
                    failed = True
                    raise OSError('actual directory fsync fault')
                return original_fsync(fd)
            with self.subTest(destination=destination), patch.object(os, 'replace', replace), patch.object(os, 'fsync', fsync):
                with self.assertRaisesRegex(OSError, 'fsync'):
                    manager.save_records([record('two.example')], 1)
            self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
            if manager.journal_path.exists():
                with self.assertRaisesRegex(ValueError, 'recover'):
                    self.manager()
                # Here no live write occurred; explicit test-only removal of owned journal.
                manager.journal_path.unlink()
            self.assertTrue(failed)

    def test_metadata_restore_and_journal_clear_uncertainty_preserve_recovery_guard(self):
        manager = self.manager()
        manager.save_records([record(enabled=False)], 0)
        original = self.rw._atomic
        def publish(path, body, *args, **kwargs):
            original(path, body, *args, **kwargs)
            if path == manager.state_path:
                raise OSError('persistent metadata fsync failure')
        with patch.object(self.rw, '_atomic', publish), self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.save_records([record('two.example', enabled=False)], 1)
        self.assertTrue(manager.journal_path.exists())
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))
        with self.assertRaisesRegex(ValueError, 'recover'):
            manager.save_records([], 1)

    def test_retention_cleanup_failure_is_not_reported_as_failed_apply(self):
        manager = self.manager()
        manager.initialize_empty()
        for n in range(11):
            manager.save_records([record(f'n{n}.example')], n)
        self.assertEqual(len(list(manager.backups.glob('rewrites_*.tgz'))), 10)
        original = self.rw._durable_unlink
        def unlink(path):
            if path.parent == manager.backups:
                raise OSError('retention directory fsync unavailable')
            return original(path)
        with patch.object(self.rw, '_durable_unlink', unlink):
            with self.assertLogs(level='WARNING') as logs:
                saved = manager.save_records([record('final.example')], 11)
        self.assertIn('retention deferred', logs.output[0])
        self.assertEqual(saved['revision'], 12)
        self.assertEqual(self.manager().snapshot(), saved)

    def test_stale_parallel_edit_is_serialized_under_shared_lock(self):
        import threading
        manager, second = self.manager(), self.manager()
        barrier = threading.Barrier(2)
        outcomes = []
        def edit(instance, hostname):
            barrier.wait(timeout=5)
            try:
                outcomes.append(instance.save_records([record(hostname, enabled=False)], 0)['revision'])
            except self.rw.RevisionConflict:
                outcomes.append('stale')
        threads = [threading.Thread(target=edit, args=(manager, 'one.example')),
                   threading.Thread(target=edit, args=(second, 'two.example'))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)
            self.assertFalse(thread.is_alive())
        self.assertCountEqual(outcomes, [1, 'stale'])
        self.assertEqual(self.manager().snapshot()['revision'], 1)
        self.assertEqual(self.calls, [])

    def test_journal_unlink_then_directory_fsync_failure_republishes_recovery_source(self):
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        def clear():
            manager.journal_path.unlink(missing_ok=True)
            raise OSError('journal clear directory fsync failure')
        with patch.object(manager, '_clear_journal', clear), self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.save_records([record('two.example')], 1)
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
        self.assertTrue(manager.journal_path.exists())
        import rewrites_recovery
        recovered = rewrites_recovery.recover(self.base, self.main, self.target)
        self.assertEqual(recovered['revision'], 1)
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))

    def test_default_activation_commands_are_bounded_without_running_a_service(self):
        from types import SimpleNamespace
        calls = []
        def run(command, **kwargs):
            calls.append((command, kwargs))
            return SimpleNamespace(returncode=0, stderr='', stdout='')
        with patch.object(self.rw.subprocess, 'run', run):
            self.rw.RewriteManager._activate()
        self.assertEqual([call[0] for call in calls], [['systemctl', 'reload-or-restart', 'unbound'], ['systemctl', 'is-active', '--quiet', 'unbound']])
        self.assertEqual([call[1]['timeout'] for call in calls], [20, 10])

    def test_explicit_offline_recovery_dryrun_journal_backup_and_malformed_source(self):
        manager = self.manager()
        manager.initialize_empty()
        manager.save_records([record()], 0)
        old_fragment, old_state = self.target.read_bytes(), manager.state_path.read_bytes()
        backup = manager._backup()
        manager.verifier = lambda token, rows: (_ for _ in ()).throw(RuntimeError('DNS uncertain'))
        with self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.save_records([record('two.example')], 1)
        try:
            recovery = importlib.import_module('rewrites_recovery')
        except ModuleNotFoundError:
            self.fail('Explicit offline recovery is not implemented')
        journal = manager.journal_path.read_bytes()
        result = recovery.recover(self.base, self.main, self.target)
        self.assertFalse(result['applied'])
        self.assertEqual(manager.journal_path.read_bytes(), journal)
        with self.assertRaisesRegex(ValueError, 'stopped'):
            recovery.recover(self.base, self.main, self.target, apply=True)
        calls = len(self.calls)
        result = recovery.recover(self.base, self.main, self.target, apply=True, webui_stopped=True)
        self.assertTrue(result['applied'])
        self.assertEqual(len(self.calls), calls)
        self.assertFalse(manager.journal_path.exists())
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), (old_fragment, old_state))
        manager = self.manager()
        manager.save_records([record('three.example')], 1)
        result = recovery.recover(self.base, self.main, self.target, backup=backup, apply=True, webui_stopped=True)
        self.assertTrue(result['activation_required'])
        self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), (old_fragment, old_state))
        for malformed in ({}, {'version': 1, 'kind': 'policy', 'backup': '../unsafe.tgz'}):
            manager.journal_path.write_text(json.dumps(malformed))
            with self.assertRaisesRegex(ValueError, 'journal'):
                recovery.recover(self.base, self.main, self.target)
        manager.journal_path.unlink()


class RouteTests(unittest.TestCase):
    setUp = ManagerTests.setUp
    tearDown = ManagerTests.tearDown
    manager = ManagerTests.manager

    def test_real_fastapi_sync_routes_auth_csrf_strict_payload_and_stale_edit(self):
        from fastapi import FastAPI, HTTPException, Request
        import warnings
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message='Using `httpx` with `starlette.testclient` is deprecated.*')
            from fastapi.testclient import TestClient
        from types import SimpleNamespace
        import inspect
        def login(request: Request):
            if request.headers.get('x-test-user') != 'yes':
                raise HTTPException(401, 'Login required')
        def csrf(request: Request):
            if request.headers.get('x-csrf-token') != 'test-token':
                raise HTTPException(403, 'CSRF required')
        upstream = SimpleNamespace(app=FastAPI(), _login_required=login, _verify_csrf=csrf,
            _template=lambda request, template, context: {'template': template, **context})
        manager = self.manager()
        self.assertTrue(hasattr(self.rw, 'install'), 'Rewrite routes not implemented')
        self.rw.install(upstream, manager)
        headers = {'x-test-user': 'yes', 'x-csrf-token': 'test-token'}
        with TestClient(upstream.app) as client:
            for path in ('/rewrites', '/api/rewrites'):
                self.assertEqual(client.get(path).status_code, 401)
            self.assertEqual(client.post('/api/rewrites', json={'records': [], 'revision': 0}).status_code, 401)
            self.assertEqual(client.post('/api/rewrites', headers={'x-test-user': 'yes'}, json={'records': [], 'revision': 0}).status_code, 403)
            self.assertEqual(client.get('/rewrites', headers=headers).json(), {'template': 'rewrites.html', 'active_tab': 'rewrites'})
            payload = {'records': [record(enabled=False)], 'revision': 0}
            saved = client.post('/api/rewrites', headers=headers, json=payload)
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()['state']['revision'], 1)
            self.assertEqual(client.post('/api/rewrites', headers=headers, json=payload).status_code, 409)
            payload['revision'] = 1
            for key, value in (('enabled', 1), ('ttl', True)):
                invalid = {'revision': 1, 'records': [record(enabled=False)]}
                invalid['records'][0][key] = value
                self.assertEqual(client.post('/api/rewrites', headers=headers, json=invalid).status_code, 422)
            self.assertEqual(client.get('/api/rewrites', headers=headers).json()['state']['revision'], 1)
        for route in upstream.app.routes:
            if getattr(route, 'path', '') in {'/rewrites', '/api/rewrites'}:
                self.assertFalse(inspect.iscoroutinefunction(route.endpoint))
        self.assertFalse(self.target.exists())
        self.assertEqual(self.calls, [])


if __name__ == '__main__':
    unittest.main()
