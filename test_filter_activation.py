"""Actual DNS activation and shipped RPZ importer contracts; isolated only."""
import pathlib
import tempfile
import unittest
import filters
import filter_benchmark as bench
import filter_activation


class ActivationTests(unittest.TestCase):
    def setUp(self):
        workspace = bench.safe_workspace(__import__('os').environ.get('TMPDIR', str(pathlib.Path.home() / '.hermes/cache/scratch')))
        self.tmp = tempfile.TemporaryDirectory(dir=workspace)
        self.addCleanup(self.tmp.cleanup)
        self.root = pathlib.Path(self.tmp.name)

    def fragment(self):
        path = self.root / 'policy.conf'
        path.write_text(filters.render_config(['example.com'], ['good.example.com'])[0])
        return path

    def test_marker_roundtrip_and_real_candidate_dns(self):
        path = self.fragment()
        token, blocked = filter_activation.stamp_policy(path)
        self.assertEqual(len(token), 64)
        self.assertEqual(blocked, 'example.com')
        self.assertEqual(filter_activation.read_profile(path), (token, blocked))
        with bench.mock_upstream() as upstream, bench.isolated_resolver(self.root, 'localzone', path, upstream.port) as resolver:
            filter_activation.verify_policy(token, blocked, port=resolver['port'], timeout=2)
            self.assertEqual(bench.query(resolver['port'], 'www.good.example.com')['answers'], ['192.0.2.123'])

    def test_live_resolver_with_wrong_policy_is_not_a_successful_activation(self):
        path = self.fragment()
        filter_activation.stamp_policy(path)
        with bench.mock_upstream() as upstream, bench.isolated_resolver(self.root, 'localzone', path, upstream.port) as resolver:
            with self.assertRaisesRegex(RuntimeError, 'different managed policy'):
                filter_activation.verify_policy('0' * 64, 'example.com', port=resolver['port'], timeout=.2)

    def test_dns_timeout_is_bounded_and_not_supervisor_success(self):
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                filter_activation.verify_policy('0' * 64, port=sock.getsockname()[1], timeout=.05)

    def test_legacy_profile_and_endpoint_validation(self):
        path = self.fragment()
        self.assertEqual(filter_activation.read_profile(path), (None, 'example.com'))
        for kwargs in [{'port': 0}, {'timeout': float('inf')}, {'timeout': 61}, {'host': 'lists.example'}]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                filter_activation.verify_policy(None, **kwargs)

    def test_shipped_multisource_rpz_importer_allowlist_wire_dns(self):
        base = self.root / 'app'
        base.mkdir()
        conf = self.root / 'config'
        conf.mkdir()
        zones = conf / 'unbound.conf.d'
        zones.mkdir()
        target = zones / 'webui-filters.conf'
        main = conf / 'unbound.conf'
        main.write_text('server:\n    username: ""\n    chroot: ""\ninclude: "' + str(zones / '*.conf') + '"\n')
        feeds = {'https://lists.example/a': b'$ORIGIN rpz.example.\n$TTL 60\n@ SOA ns.example. host.example. 1 60 60 60 60\n@ NS ns.example.\nexample.com CNAME .\n*.example.com CNAME .\n',
                 'https://lists.example/b': b'explicit.good.example.com CNAME .\nexplicit.allowed.example.net CNAME .\n'}
        manager = filters.FilterManager(base, main, target, activate=lambda: None, downloader=lambda url: feeds[url])
        manager.initialize_empty()
        identifier = manager.add_list('RPZ', sources=list(feeds), format='rpz')['lists'][0]['id']
        manager.refresh_list(identifier)
        manager.set_domains('allowed', ['good.example.com', 'allowed.example.net'])
        manager.enable_list(identifier, True)
        with bench.mock_upstream() as upstream, bench.isolated_resolver(self.root, 'localzone', target, upstream.port) as resolver:
            for name in ['example.com', 'bad.example.com', 'a.b.example.com']:
                self.assertEqual(bench.query(resolver['port'], name)['rcode'], 3, name)
            for name in ['good.example.com', 'www.good.example.com', 'explicit.good.example.com', 'explicit.allowed.example.net', 'www.allowed.example.net']:
                answer = bench.query(resolver['port'], name)
                self.assertEqual(answer['rcode'], 0, name)
                self.assertEqual(answer['answers'], ['192.0.2.123'], name)


if __name__ == '__main__':
    unittest.main()
