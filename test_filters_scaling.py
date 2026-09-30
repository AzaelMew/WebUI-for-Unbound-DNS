"""Isolated scalable filter tests: never import app or activate production."""
import json
import tempfile
import unittest
import threading
import time
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch
import filters


class ScalingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.base = self.root / 'app'
        self.base.mkdir()
        self.config = self.root / 'unbound'
        self.config.mkdir()
        fragments = self.config / 'unbound.conf.d'
        fragments.mkdir()
        self.main = self.config / 'unbound.conf'
        self.main.write_text('server:\n    chroot: ""\n    username: ""\n    module-config: "subnetcache validator iterator"\ninclude: "' + str(fragments / '*.conf') + '"\n')
        self.target = fragments / 'webui-filters.conf'
        self.activations = 0
        self.fail_activation = False

    def tearDown(self):
        self.tmp.cleanup()

    def activate(self):
        self.activations += 1
        if self.fail_activation:
            self.fail_activation = False
            raise RuntimeError('test activation failure')

    def manager(self, **kwargs):
        return filters.FilterManager(self.base, self.main, self.target, activate=self.activate, **kwargs)

    def test_disabled_refresh_state_publish_failure_preserves_last_good(self):
        for after_rename in (False, True):
            with self.subTest(after_rename=after_rename):
                manager = self.manager(downloader=lambda url: b'old.example\n')
                identifier = (manager.snapshot()['lists'][0]['id'] if manager.state['lists'] else
                              manager.add_list('Test', 'https://lists.example/a')['lists'][0]['id'])
                manager.refresh_list(identifier)
                previous = manager.snapshot()['lists'][0]
                manager.downloader = lambda url: b'new.example\n'
                original = filters._atomic
                failed = False
                def publish(path, body, *args, **kwargs):
                    nonlocal failed
                    if path == manager.state_path and not failed:
                        failed = True
                        if after_rename:
                            original(path, body, *args, **kwargs)
                        raise OSError('injected state fsync failure')
                    return original(path, body, *args, **kwargs)
                with patch.object(filters, '_atomic', publish), self.assertRaises(OSError):
                    manager.refresh_list(identifier)
                persisted = json.loads(manager.state_path.read_text())
                self.assertEqual(persisted, manager.state)
                self.assertEqual(persisted['lists'][0]['cache'], previous['cache'])
                self.assertEqual(persisted['lists'][0]['last_updated'], previous['last_updated'])
                self.manager()

    def test_migration_publish_failure_restores_original_before_discarding_caches(self):
        data = self.base / 'filter-data'
        data.mkdir()
        legacy = {'version': 1, 'blocked': [], 'allowed': [], 'lists': [
            {'id': 'legacy', 'name': 'Legacy', 'url': 'https://lists.example/a', 'enabled': True,
             'domains': ['old.example'], 'last_updated': None, 'last_attempt': None,
             'last_error': None, 'unsupported': 0, 'samples': []}]}
        raw = json.dumps(legacy).encode()
        path = data / 'state.json'
        original = filters._atomic
        for after_rename in (False, True):
            path.write_bytes(raw)
            failed = False
            def publish(destination, body, *args, **kwargs):
                nonlocal failed
                if destination == path and not failed:
                    failed = True
                    if after_rename:
                        original(destination, body, *args, **kwargs)
                    raise OSError('injected migration fsync failure')
                return original(destination, body, *args, **kwargs)
            with self.subTest(after_rename=after_rename), patch.object(filters, '_atomic', publish), self.assertRaises(OSError):
                self.manager()
            self.assertEqual(path.read_bytes(), raw)
        self.manager()

    def test_failed_metadata_restore_retains_published_candidate_and_recovery_journal(self):
        manager = self.manager(downloader=lambda url: b'old.example\n')
        identifier = manager.add_list('Test', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.downloader = lambda url: b'new.example\n'
        original = filters._atomic
        def publish(path, body, *args, **kwargs):
            if path == manager.state_path:
                original(path, body, *args, **kwargs)
                raise OSError('persistent state fsync failure')
            return original(path, body, *args, **kwargs)
        with patch.object(filters, '_atomic', publish), self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.refresh_list(identifier)
        self.assertTrue(manager.journal_path.exists())
        persisted = json.loads(manager.state_path.read_text())
        self.assertEqual(manager.state, persisted)
        journal = json.loads(manager.journal_path.read_text())
        for reference in journal['candidate_caches']:
            self.assertTrue((manager.data / reference).is_file())
        with self.assertRaisesRegex(ValueError, 'recover'):
            self.manager()

    def test_enabled_refresh_failed_restore_protects_journal_candidates(self):
        manager = self.manager(downloader=lambda url: b'old.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Enabled', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.enable_list(identifier, True)
        manager.downloader = lambda url: b'new.example\n'
        original = filters._atomic
        def publish(path, body, *args, **kwargs):
            if path == manager.state_path:
                original(path, body, *args, **kwargs)
                raise OSError('persistent state fsync failure')
            return original(path, body, *args, **kwargs)
        with patch.object(filters, '_atomic', publish), self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.refresh_list(identifier)
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))
        journal = json.loads(manager.journal_path.read_text())
        for reference in journal['candidate_caches']:
            self.assertTrue((manager.data / reference).is_file())

    def test_independent_source_and_total_bytes_bounds(self):
        body = b'a.example\nb.example\nc.example\n'
        self.assertEqual(len(body), 30)
        manager = self.manager(max_bytes=50, max_total_bytes=100, downloader=lambda url: body)
        identifier = manager.add_list('Two', sources=['https://lists.example/a', 'https://lists.example/b'])['lists'][0]['id']
        result = manager.refresh_list(identifier)['lists'][0]
        self.assertEqual(result['downloaded_bytes'], 60)
        self.assertEqual(self.manager(max_bytes=50, max_total_bytes=100).state, manager.state)
        manager.downloader = lambda url: b'x' * 51
        with self.assertRaisesRegex(ValueError, '50.*source'):
            manager.refresh_list(identifier)
        manager.limits['max_total_bytes'] = 55
        manager.downloader = lambda url: body
        with self.assertRaisesRegex(ValueError, '60.*55.*aggregate'):
            manager.refresh_list(identifier)
        self.assertEqual(manager.state['lists'][0]['cache'], result['cache'])

    def test_network_download_gets_source_and_separate_remaining_total_cap(self):
        manager = self.manager(max_bytes=50, max_total_bytes=100)
        identifier = manager.add_list('Network', sources=['https://lists.example/a', 'https://lists.example/b'])['lists'][0]['id']
        bounds = []
        def download(url, destination, max_bytes, timeout):
            bounds.append(max_bytes)
            destination.write_bytes(b'a.example\nb.example\nc.example\n')
            return 30
        with patch.object(filters, 'download_file', download):
            manager.refresh_list(identifier)
        self.assertEqual(bounds, [50, 50])
        manager.limits['max_total_bytes'] = 55
        def limited(url, destination, max_bytes, timeout):
            if max_bytes < 30:
                raise ValueError(f'Download exceeds {max_bytes} bytes')
            return download(url, destination, max_bytes, timeout)
        with patch.object(filters, 'download_file', limited), self.assertRaisesRegex(ValueError, '50.*source.*55.*aggregate'):
            manager.refresh_list(identifier)

    def test_candidate_verification_failure_restores_verified_old_policy(self):
        for failure in ('stale candidate', 'no DNS answer'):
            with self.subTest(failure=failure):
                profiles = []
                def verify(token, blocked):
                    profiles.append((token, blocked))
                    if blocked == 'new.example':
                        raise RuntimeError(failure)
                manager = self.manager(verifier=verify, downloader=lambda url: b'old.example\n')
                if not self.target.exists():
                    manager.initialize_empty()
                identifier = (manager.state['lists'][0]['id'] if manager.state['lists'] else
                              manager.add_list('Verified', 'https://lists.example/a')['lists'][0]['id'])
                manager.refresh_list(identifier)
                manager.enable_list(identifier, True)
                old = manager.state['lists'][0].copy()
                before = self.target.read_bytes()
                manager.downloader = lambda url: b'new.example\n'
                with self.assertRaisesRegex(RuntimeError, failure):
                    manager.refresh_list(identifier)
                self.assertEqual(self.target.read_bytes(), before)
                self.assertEqual(manager.state['lists'][0]['cache'], old['cache'])
                self.assertEqual(manager.state['lists'][0]['last_updated'], old['last_updated'])
                self.assertEqual(profiles[-1][1], 'old.example')
                self.assertFalse(manager.journal_path.exists())

    def test_rollback_verification_failure_retains_journal_and_generations(self):
        manager = self.manager(verifier=lambda token, blocked: None, downloader=lambda url: b'old.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Verified', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.enable_list(identifier, True)
        before = self.target.read_bytes()
        manager.downloader = lambda url: b'new.example\n'
        def verify(token, blocked):
            raise RuntimeError('DNS not answering')
        manager.verifier = verify
        with self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.refresh_list(identifier)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertTrue(manager.journal_path.exists())
        for reference in json.loads(manager.journal_path.read_text())['candidate_caches']:
            self.assertTrue((manager.data / reference).is_file())

    def test_insufficient_disk_preflight_preserves_policy_state_and_cache(self):
        manager = self.manager(downloader=lambda url: b'old.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Disk', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.enable_list(identifier, True)
        before = self.target.read_bytes(), manager.state_path.read_bytes()
        caches = set(manager.store.directory.glob('*.sqlite'))
        with patch.object(filters.filter_resources, 'check_disk_headroom', side_effect=ValueError('Insufficient disk headroom')):
            with self.assertRaisesRegex(ValueError, 'disk'):
                manager.set_domains('blocked', ['new.example'])
            self.assertEqual((self.target.read_bytes(), manager.state_path.read_bytes()), before)
            activation_count = self.activations
            with self.assertRaisesRegex(ValueError, 'disk'):
                manager.refresh_list(identifier)
        self.assertEqual(self.activations, activation_count)
        self.assertEqual(set(manager.store.directory.glob('*.sqlite')), caches)
        self.assertEqual(manager.state['lists'][0]['count'], 1)
        self.assertEqual(self.target.read_bytes(), before[0])
        self.assertIn('disk', manager.state['lists'][0]['last_error'])

    def test_journal_clear_failure_and_failed_state_restore_keep_recovery_guard(self):
        manager = self.manager()
        manager.initialize_empty()
        original = filters._atomic
        calls = 0
        def publish(path, body, *args, **kwargs):
            nonlocal calls
            if path == manager.state_path:
                calls += 1
                if calls == 2:
                    raise OSError('restore cannot publish')
            return original(path, body, *args, **kwargs)
        def clear():
            manager.journal_path.unlink()
            raise OSError('journal directory fsync failure')
        with patch.object(filters, '_atomic', publish), patch.object(manager, '_clear_journal', clear), self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.set_domains('blocked', ['new.example'])
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))
        self.assertTrue(manager.journal_path.exists())
        with self.assertRaisesRegex(ValueError, 'recover'):
            manager.set_domains('blocked', ['other.example'])

    def test_real_directory_fsync_failure_after_state_rename_restores_cache(self):
        import os
        import stat
        manager = self.manager(downloader=lambda url: b'old.example\n')
        identifier = manager.add_list('Fsync', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        previous = manager.state['lists'][0].copy()
        manager.downloader = lambda url: b'new.example\n'
        original_replace, original_fsync = os.replace, os.fsync
        renamed, failed = False, False
        def replace(source, destination):
            nonlocal renamed
            result = original_replace(source, destination)
            if Path(destination) == manager.state_path:
                renamed = True
            return result
        def fsync(fd):
            nonlocal failed
            if renamed and not failed and stat.S_ISDIR(os.fstat(fd).st_mode):
                failed = True
                raise OSError('actual post-rename directory fsync failure')
            return original_fsync(fd)
        with patch.object(filters.os, 'replace', replace), patch.object(filters.os, 'fsync', fsync), self.assertRaises(OSError):
            manager.refresh_list(identifier)
        self.assertTrue(failed)
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))
        self.assertEqual(manager.state['lists'][0]['cache'], previous['cache'])
        self.manager()

    def test_network_total_limit_reports_observed_aggregate_and_configured_limits(self):
        manager = self.manager(max_bytes=50, max_total_bytes=55)
        identifier = manager.add_list('Limits', sources=['https://lists.example/a', 'https://lists.example/b'])['lists'][0]['id']
        actual_download = filters.download_file
        def download(url, destination, max_bytes, timeout):
            return actual_download(url, destination, max_bytes, timeout,
                resolver=lambda host: ['93.184.216.34'],
                transport=lambda *args: (200, {'content-length': '30'}, b'a.example\nb.example\nc.example\n'))
        with patch.object(filters, 'download_file', download), self.assertRaisesRegex(ValueError, 'aggregate 60.*50.*source.*55.*aggregate'):
            manager.refresh_list(identifier)

    def test_atomic_files_fsync_after_preserved_or_immutable_permissions(self):
        import os
        import stat
        manager = self.manager()
        path = self.root / 'metadata'
        path.write_bytes(b'old')
        path.chmod(0o640)
        source = self.root / 'source'
        source.write_bytes(b'new')
        original = os.fsync
        expected = 0o640
        observed = []
        def fsync(fd):
            info = os.fstat(fd)
            if stat.S_ISREG(info.st_mode):
                mode = stat.S_IMODE(info.st_mode)
                observed.append(mode)
                self.assertEqual(mode, expected)
            return original(fd)
        with patch.object(filters.os, 'fsync', fsync):
            filters._atomic(path, b'new')
            filters._atomic_copy(source, path)
            expected = 0o400
            manager.store.build(iter(['ads.example']), 10)
        self.assertEqual(observed, [0o640, 0o640, 0o400])

    def test_v1_migration_preserves_metadata_enabled_cache_and_backup(self):
        data = self.base / 'filter-data'
        data.mkdir()
        legacy = {'version': 1, 'blocked': ['manual.example'], 'allowed': ['good.example'], 'lists': [
            {'id': 'legacy123', 'name': 'Legacy', 'url': 'https://lists.example/a', 'enabled': True,
             'domains': ['ads.example', 'ads.example', 'other.example'], 'last_updated': 'old',
             'last_attempt': 'attempt', 'last_error': 'historic error', 'unsupported': 2, 'samples': ['old sample']}]}
        raw = json.dumps(legacy).encode()
        (data / 'state.json').write_bytes(raw)
        self.target.write_text(filters.HEADER + '    local-zone: "ads.example." always_nxdomain\n')
        before = self.target.read_bytes()
        manager = self.manager()
        state = manager.snapshot()
        self.assertEqual(state['version'], 2)
        item = state['lists'][0]
        self.assertNotIn('domains', item)
        self.assertEqual(item['count'], 2)
        self.assertEqual(item['sources'], [legacy['lists'][0]['url']])
        self.assertTrue(item['enabled'])
        self.assertEqual(item['last_error'], 'historic error')
        self.assertEqual(item['samples'], ['old sample'])
        self.assertEqual(state['blocked'], legacy['blocked'])
        self.assertEqual(state['allowed'], legacy['allowed'])
        self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(self.activations, 0)
        self.assertEqual((data / 'state.v1.backup.json').read_bytes(), raw)
        self.assertTrue((data / item['cache']).is_file())
        self.assertNotIn('domains', json.loads((data / 'state.json').read_text())['lists'][0])
        self.assertEqual(self.manager().snapshot(), state)

    def test_multisource_union_edit_invalidates_cache_and_enabled_refresh_rolls_back(self):
        first = b'ads.example\nshared.example\n'
        second = b'other.example\nshared.example\n'
        manager = self.manager(downloader=lambda url: first if url.endswith('/a') else second)
        manager.initialize_empty()
        item = manager.add_list('Both', sources=['https://lists.example/a', 'https://lists.example/b'], format='domains')['lists'][0]
        result = manager.refresh_list(item['id'])['lists'][0]
        self.assertEqual(result['count'], 3)
        self.assertEqual(result['downloaded_bytes'], len(first) + len(second))
        manager.enable_list(item['id'], True)
        before = self.target.read_bytes()
        old = manager.snapshot()['lists'][0]
        manager.downloader = lambda url: b'new.example\n'
        self.fail_activation = True
        with self.assertRaises(RuntimeError):
            manager.refresh_list(item['id'])
        current = manager.snapshot()['lists'][0]
        self.assertEqual(current['cache'], old['cache'])
        self.assertEqual(current['last_updated'], old['last_updated'])
        self.assertTrue(current['last_error'])
        self.assertEqual(self.target.read_bytes(), before)
        edited = manager.edit_list(item['id'], 'New', ['https://lists.example/new'], 'auto')['lists'][0]
        self.assertFalse(edited['enabled'])
        self.assertIsNone(edited['cache'])
        self.assertEqual(edited['count'], 0)
        self.assertEqual(self.target.read_text(), filters.HEADER)
        with self.assertRaises(ValueError):
            manager.enable_list(item['id'], True)

    def test_rpz_standard_omitted_owner_ns_and_multiline_soa(self):
        feed = (b'$TTL 3600\n@ SOA localhost. root.localhost. 1790778660 28800 3600 259200 3600\n'
                b'  NS  localhost.\nads.example CNAME .\n*.ads.example CNAME .\n')
        path = self.root / 'standard-rpz'
        path.write_bytes(feed)
        self.assertEqual(list(filters._parse_rpz(path)), ['ads.example', 'ads.example'])
        path.write_bytes(b'  NS localhost.\nads.example CNAME .\n')
        with self.assertRaisesRegex(ValueError, 'owner'):
            list(filters._parse_rpz(path))
        path.write_bytes(b'@ SOA localhost. root.localhost. (\n 1 1h 15m 30d 1h )\n  NS localhost.\nads.example CNAME .\n  CNAME rpz-passthru.\n')
        with self.assertRaisesRegex(ValueError, 'Unsupported RPZ action'):
            list(filters._parse_rpz(path))
        path.write_bytes(b'@ SOA localhost. root.localhost. (\n 1 1h 15m 30d 1h )\n  NS localhost.\nads.example CNAME .\n')
        self.assertEqual(list(filters._parse_rpz(path)), ['ads.example'])

    def test_rpz_qname_nxdomain_metadata_wildcards_and_fail_closed_actions(self):
        feed = (b'; comment\n$ORIGIN rpz.example.\n$TTL 1h\n'
                b'@ IN SOA ns.example. hostmaster.example. (\n 1 1h 15m 30d 1h )\n'
                b'@ IN NS ns.example.\n'
                b'ads.example 60 IN CNAME .\n*.ads.example CNAME .\n'
                b'other.example.rpz.example. CNAME .\n')
        manager = self.manager(downloader=lambda url: feed)
        manager.initialize_empty()
        item = manager.add_list('RPZ', 'https://lists.example/rpz', format='rpz')['lists'][0]
        manager.refresh_list(item['id'])
        manager.enable_list(item['id'], True)
        before = self.target.read_bytes()
        self.assertIn(b'"ads.example." always_nxdomain', before)
        self.assertIn(b'"other.example." always_nxdomain', before)
        self.assertNotIn(b'rpz.example', before)
        self.assertEqual(manager.snapshot()['lists'][0]['count'], 2)
        for bad in [b'bad.example CNAME rpz-passthru.\n', b'bad.example A 0.0.0.0\n',
                    b'24.0.2.0.192.rpz-ip CNAME .\n', b'$INCLUDE /etc/passwd\n',
                    b'bad.example CNAME *\n', b'bad.example.rpz-nsdname CNAME .\n',
                    b'broken IN SOA ns.example.\n']:
            manager.downloader = lambda url: feed + bad
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                manager.refresh_list(item['id'])
            self.assertEqual(self.target.read_bytes(), before)
            self.assertEqual(manager.snapshot()['lists'][0]['count'], 2)
        manager.edit_list(item['id'], 'Auto RPZ', ['https://lists.example/rpz'], 'auto')
        manager.downloader = lambda url: feed
        self.assertEqual(manager.refresh_list(item['id'])['lists'][0]['count'], 2)

    def test_streaming_download_file_enforces_bytes_and_redirect_public_pinning(self):
        destination = self.root / 'download'
        calls = []
        def resolve(host):
            return ['127.0.0.1'] if host == 'private.example' else ['93.184.216.34']
        def transport(url, host, address, timeout):
            calls.append((host, address))
            return 200, {'content-type': 'text/plain'}, b'ads.example\n'
        self.assertEqual(filters.download_file('https://lists.example/a', destination, max_bytes=20,
                                              resolver=resolve, transport=transport), 12)
        self.assertEqual(destination.read_bytes(), b'ads.example\n')
        self.assertEqual(calls, [('lists.example', '93.184.216.34')])
        with self.assertRaisesRegex(ValueError, '11'):
            filters.download_file('https://lists.example/a', destination, max_bytes=11,
                                  resolver=resolve, transport=transport)
        with self.assertRaises(ValueError):
            filters.download_file('https://lists.example/a', destination, resolver=resolve,
                transport=lambda *args: (302, {'location': 'https://private.example/a'}, b''))

    def test_api_multisource_add_and_edit(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from types import SimpleNamespace
        manager = self.manager()
        manager.initialize_empty()
        upstream = SimpleNamespace(app=FastAPI(), _login_required=lambda: None, _verify_csrf=lambda: None)
        filters.install(upstream, manager=manager)
        client = TestClient(upstream.app)
        response = client.post('/api/filters/lists', json={'name': 'Sources', 'sources': ['https://lists.example/a', 'https://lists.example/b'], 'format': 'hosts'})
        self.assertEqual(response.status_code, 200, response.text)
        item = response.json()['state']['lists'][0]
        response = client.post('/api/filters/lists/' + item['id'] + '/edit', json={'name': 'Changed', 'sources': ['https://lists.example/c'], 'format': 'rpz'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['state']['lists'][0]['format'], 'rpz')

    def test_refresh_candidate_survives_concurrent_manual_transaction(self):
        manager = self.manager(downloader=lambda url: b'ads.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Concurrent', 'https://lists.example/a')['lists'][0]['id']
        built, proceed = threading.Event(), threading.Event()
        original = manager.store.build
        def build(*args, **kwargs):
            result = original(*args, **kwargs)
            built.set()
            if not proceed.wait(10):
                raise RuntimeError('test thread timeout')
            return result
        manager.store.build = build
        errors = []
        def refresh():
            try:
                manager.refresh_list(identifier)
            except Exception as exc:
                errors.append(exc)
        worker = threading.Thread(target=refresh)
        worker.start()
        try:
            self.assertTrue(built.wait(10))
            for operation in [lambda: manager.refresh_list(identifier),
                              lambda: manager.edit_list(identifier, 'Edit', ['https://lists.example/b']),
                              lambda: manager.delete_list(identifier)]:
                with self.assertRaisesRegex(ValueError, 'progress'):
                    operation()
            manager.set_domains('blocked', ['manual.example'])
        finally:
            proceed.set()
            worker.join(15)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(manager.snapshot()['lists'][0]['count'], 1)

    def test_pending_crash_journal_fails_closed_without_touching_files(self):
        manager = self.manager()
        manager.initialize_empty()
        before = self.target.read_bytes()
        journal = manager.data / 'transaction.json'
        journal.write_text('{"backup": "filters_recover.tgz"}')
        with self.assertRaisesRegex(ValueError, 'recover'):
            self.manager()
        self.assertEqual(self.target.read_bytes(), before)
        self.assertTrue(journal.exists())

    def test_malformed_state_and_cache_fail_closed_preserving_originals(self):
        manager = self.manager(downloader=lambda url: b'ads.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Cache', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        good = manager.state_path.read_bytes()
        before = self.target.read_bytes()
        state = json.loads(good)
        variants = [b'not-json', json.dumps({'version': 9}).encode()]
        for field, value in [('cache', '../outside.sqlite'), ('enabled', 'yes'), ('count', 3), ('format', 'invalid')]:
            bad = json.loads(good)
            bad['lists'][0][field] = value
            variants.append(json.dumps(bad).encode())
        bad = json.loads(good)
        bad['effective_count'] = 1
        variants.append(json.dumps(bad).encode())
        for raw in variants:
            manager.state_path.write_bytes(raw)
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                self.manager()
            self.assertEqual(manager.state_path.read_bytes(), raw)
            self.assertEqual(self.target.read_bytes(), before)
        manager.state_path.write_bytes(good)
        cache = manager.data / state['lists'][0]['cache']
        content = cache.read_bytes()
        cache.unlink()
        outside = self.root / 'external.sqlite'
        outside.write_bytes(content)
        cache.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.manager()
        self.assertEqual(outside.read_bytes(), content)

    def test_limits_include_disabled_union_source_bytes_and_subscription_validation(self):
        manager = self.manager(max_entries=3, max_bytes=50, max_total_bytes=50, max_subscriptions=2, max_sources=2,
                               downloader=lambda url: b'a.example\nb.example\n')
        manager.initialize_empty()
        self.assertEqual(manager.snapshot()['limits'], {'max_entries': 3, 'max_bytes': 50, 'max_total_bytes': 50, 'max_subscriptions': 2, 'max_sources': 2})
        for sources in [[], ['https://lists.example/a', 'http://lists.example/b'],
                        ['https://LISTS.example:443/a', 'https://lists.example/a'],
                        ['https://lists.example/a'] * 3]:
            with self.subTest(sources=sources), self.assertRaises(ValueError):
                manager.add_list('Bad', sources=sources)
        one = manager.add_list('One', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(one)
        with self.assertRaises(ValueError):
            manager.add_list('Dup', 'https://LISTS.example:443/a')
        two = manager.add_list('Two', sources=['https://lists.example/b', 'https://lists.example/c'])['lists'][1]['id']
        with self.assertRaisesRegex(ValueError, '2'):
            manager.add_list('Three', 'https://lists.example/d')
        manager.downloader = lambda url: b'c.example\nd.example\n'
        with self.assertRaisesRegex(ValueError, '3'):
            manager.refresh_list(two)
        self.assertEqual(manager.snapshot()['lists'][0]['count'], 2)
        self.assertEqual(manager.snapshot()['lists'][1]['count'], 0)
        manager.downloader = lambda url: b'a.example\nb.example\nc.example\n'
        with self.assertRaisesRegex(ValueError, '50'):
            manager.refresh_list(two)
        self.assertEqual(self.target.read_text(), filters.HEADER)

    def test_multisource_second_failure_preserves_entire_last_good_generation(self):
        manager = self.manager(downloader=lambda url: b'a.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Sources', sources=['https://lists.example/a', 'https://lists.example/b'])['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.enable_list(identifier, True)
        original = manager.snapshot()['lists'][0]
        config = self.target.read_bytes()
        def download(url):
            if url.endswith('/b'):
                raise ValueError('Second source failed')
            return b'new.example\n'
        manager.downloader = download
        with self.assertRaisesRegex(ValueError, 'Second'):
            manager.refresh_list(identifier)
        current = manager.snapshot()['lists'][0]
        self.assertEqual(current['cache'], original['cache'])
        self.assertEqual(current['count'], original['count'])
        self.assertEqual(current['last_updated'], original['last_updated'])
        self.assertEqual(self.target.read_bytes(), config)

    def test_large_feed_over_300k_streams_cache_render_and_constant_snapshot(self):
        feed = self.root / 'synthetic.txt'
        with feed.open('w') as output:
            for number in range(300_017):
                output.write(f'd{number:06d}.example\n')
        manager = self.manager(downloader=lambda url: feed)
        manager.initialize_empty()
        identifier = manager.add_list('Large', 'https://lists.example/a', format='domains')['lists'][0]['id']
        # Giant caches/configs must never go through whole-file convenience APIs.
        old_text, old_bytes = Path.read_text, Path.read_bytes
        def read_text(path, *args, **kwargs):
            if path.name == 'webui-filters.conf' or path.suffix == '.sqlite':
                raise AssertionError('Whole-file filter read')
            return old_text(path, *args, **kwargs)
        def read_bytes(path, *args, **kwargs):
            if path.name == 'webui-filters.conf' or path.suffix == '.sqlite':
                raise AssertionError('Whole-file filter read')
            return old_bytes(path, *args, **kwargs)
        with patch.object(Path, 'read_text', read_text), patch.object(Path, 'read_bytes', read_bytes):
            manager.refresh_list(identifier)
            manager.enable_list(identifier, True)
            manager.set_domains('allowed', ['d000001.example'])
            with patch.object(manager.store, 'union', side_effect=AssertionError('Snapshot recomputes union')), patch.object(manager.store, 'domains', side_effect=AssertionError('Snapshot reads cache')):
                snapshot = manager.snapshot()
        self.assertEqual(snapshot['lists'][0]['count'], 300_017)
        self.assertEqual(snapshot['effective_count'], 300_016)
        self.assertLess(manager.state_path.stat().st_size, 4000)
        with self.target.open() as source:
            self.assertEqual(sum(1 for line in source if 'always_nxdomain' in line), 300_016)

    def test_refresh_deadline_discards_candidate_and_records_attempt(self):
        manager = self.manager(downloader=lambda url: b'ads.example\n', refresh_timeout=.02)
        manager.initialize_empty()
        identifier = manager.add_list('Timeout', 'https://lists.example/a')['lists'][0]['id']
        def slow(url):
            time.sleep(.03)
            return b'ads.example\n'
        manager.downloader = slow
        with self.assertRaisesRegex(ValueError, 'timeout'):
            manager.refresh_list(identifier)
        item = manager.snapshot()['lists'][0]
        self.assertIsNone(item['cache'])
        self.assertTrue(item['last_attempt'])
        self.assertIn('timeout', item['last_error'])
        self.assertFalse(list(manager.store.directory.glob('*.sqlite')))

    def test_distinct_backup_blobs_compressed_immutable_and_restore_streaming(self):
        import gzip
        import stat
        manager = self.manager()
        manager.initialize_empty()
        for number in range(12):
            manager.set_domains('blocked', [f'd{number:02d}.example'])
        blobs = list((manager.backups / 'blobs').iterdir())
        self.assertEqual(len(blobs), 10)
        self.assertTrue(all(blob.name.endswith('.conf.gz') for blob in blobs))
        self.assertTrue(all(stat.S_IMODE(blob.stat().st_mode) == 0o400 for blob in blobs))
        backup, blob = manager._backup()
        before = self.target.read_bytes()
        self.target.chmod(0o640)
        original_read = Path.read_bytes
        def bounded(path, *args, **kwargs):
            if path == self.target or path == blob:
                raise AssertionError('Whole file read during restore')
            return original_read(path, *args, **kwargs)
        with patch.object(Path, 'read_bytes', bounded):
            filters._restore_blob(blob, self.target)
        self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        with gzip.open(blob, 'rb') as source:
            self.assertEqual(source.read(), before)
        self.fail_activation = True
        with self.assertRaises(RuntimeError):
            manager.set_domains('blocked', ['wrong.example'])
        self.assertEqual(self.target.read_bytes(), before)

    def test_corrupt_rollback_blob_requires_recovery_without_publishing_corruption(self):
        manager = self.manager()
        manager.initialize_empty()
        manager.set_domains('blocked', ['old.example'])
        original_backup = manager._backup
        def corrupt(*args):
            backup, blob = original_backup(*args)
            blob.chmod(0o600)
            with blob.open('r+b') as output:
                output.seek(-1, 2)
                output.write(b'X')
            return backup, blob
        manager._backup = corrupt
        self.fail_activation = True
        with self.assertRaisesRegex(RuntimeError, 'recover'):
            manager.set_domains('blocked', ['new.example'])
        self.assertTrue(manager.journal_path.exists())
        self.assertIn('new.example', self.target.read_text())
        self.assertEqual(manager.state, json.loads(manager.state_path.read_text()))

    def test_backup_generation_references_and_fragment_blobs_survive_until_expiration(self):
        manager = self.manager(downloader=lambda url: b'ads.example\n')
        manager.initialize_empty()
        identifier = manager.add_list('Retained', 'https://lists.example/a')['lists'][0]['id']
        manager.refresh_list(identifier)
        first = manager.snapshot()['lists'][0]['cache']
        manager.enable_list(identifier, True)
        manager.downloader = lambda url: b'new.example\n'
        manager.refresh_list(identifier)
        self.assertTrue((manager.data / first).is_file())
        manager.delete_list(identifier)
        self.assertTrue((manager.data / first).is_file())
        for _ in range(11):
            manager.set_domains('blocked', ['manual.example'])
        self.assertFalse((manager.data / first).exists())
        self.assertEqual(len(list(manager.backups.glob('*.tgz'))), 10)
        # Ten identical old fragments share one blob instead of ten copies.
        self.assertEqual(len(list((manager.backups / 'blobs').glob('*.conf.gz'))), 1)

    def test_https_transport_reads_bounded_chunks_into_file_not_body(self):
        from unittest.mock import MagicMock
        body = b'a.example\n' * 20_000
        class Response:
            status = 200
            def __init__(self):
                self.position = 0
                self.requests = []
            def getheaders(self):
                return [('Content-Type', 'text/plain'), ('Content-Length', str(len(body)))]
            def read1(self, size):
                self.requests.append(size)
                result = body[self.position:self.position + size]
                self.position += len(result)
                return result
        response = Response()
        sock = MagicMock()
        connection = MagicMock()
        connection._context.wrap_socket.return_value = sock
        connection.getresponse.return_value = response
        destination = self.root / 'stream'
        with patch.object(filters.http.client, 'HTTPSConnection', return_value=connection), patch.object(filters.socket, 'create_connection', return_value=sock):
            status, headers, size = filters._https_get('https://lists.example/a', 'lists.example', '93.184.216.34', 10, destination, len(body))
        self.assertEqual(status, 200)
        self.assertEqual(size, len(body))
        self.assertEqual(destination.read_bytes(), body)
        self.assertLessEqual(max(response.requests), 65536)

    def test_invalid_v1_migration_does_not_replace_state_or_config(self):
        data = self.base / 'filter-data'
        data.mkdir()
        bad = {'version': 1, 'blocked': [], 'allowed': [], 'lists': [
            {'id': 'legacy', 'name': 'Legacy', 'url': 'https://lists.example/a', 'enabled': True,
             'domains': ['valid.example', 'invalid".example'], 'last_updated': None,
             'last_attempt': None, 'last_error': None, 'unsupported': 0, 'samples': []}]}
        raw = json.dumps(bad).encode()
        (data / 'state.json').write_bytes(raw)
        self.target.write_text(filters.HEADER)
        with self.assertRaises(ValueError):
            self.manager()
        self.assertEqual((data / 'state.json').read_bytes(), raw)
        self.assertFalse((data / 'state.v1.backup.json').exists())
        self.assertFalse(list((data / 'cache').glob('*.sqlite')))
        self.assertEqual(self.target.read_text(), filters.HEADER)

    def test_malformed_rpz_ttl_cannot_exhaust_parser_runtime(self):
        source = self.root / 'bad-rpz'
        source.write_text('$ORIGIN rpz.example.\n@ IN SOA ns.example. host.example. 1 ' + '9' * 40 + 'x 1h 1d 1h\nads.example CNAME .\n')
        script = ('import filters,sys\ntry:\n list(filters._parse_rpz(sys.argv[1]))\n'
                  'except ValueError:\n sys.exit(0)\nelse:\n sys.exit(1)\n')
        result = subprocess.run([sys.executable, '-c', script, str(source)], timeout=2,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_migration_refuses_conflicting_existing_backup(self):
        data = self.base / 'filter-data'
        data.mkdir()
        raw = b'{"version":1,"blocked":[],"allowed":[],"lists":[]}'
        (data / 'state.json').write_bytes(raw)
        backup = data / 'state.v1.backup.json'
        backup.write_text('unrelated earlier backup')
        with self.assertRaisesRegex(ValueError, 'backup'):
            self.manager()
        self.assertEqual((data / 'state.json').read_bytes(), raw)
        self.assertEqual(backup.read_text(), 'unrelated earlier backup')


if __name__ == '__main__':
    unittest.main(verbosity=2)
