"""Run with the deployed venv. Never touches live DNS configuration."""
import unittest
import tempfile
from pathlib import Path
try:
    import filters
except ImportError:
    from types import SimpleNamespace
    filters = SimpleNamespace(normalize_domain=lambda value: value)



class DomainTests(unittest.TestCase):
    def test_domain_normalizes_idna_and_rejects_config_injection(self):
        self.assertEqual(filters.normalize_domain('  BÜCHER.Example. '), 'xn--bcher-kva.example')
        for value in ['foo', '127.0.0.1', 'bad.example\"\nserver:', '*.foo.example', '-bad.example', 'foo..example', 'foo.example/path', 'foo_example.com']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                filters.normalize_domain(value)

    def test_parse_hosts_plain_and_simple_abp_reports_unsupported(self):
        result = filters.parse_list(b'# title\n0.0.0.0 Ads.Example tracker.example # comment\n127.0.0.1 localhost\nads.example\n||other.example^\n@@||allowed.example^\n||ads.example^$third-party\nexample.com##.ad\n')
        self.assertEqual(result['domains'], ['ads.example', 'other.example', 'tracker.example'])
        self.assertEqual(result['unsupported'], 3)
        for body in [b'', b'# comments only\n', b'<html>error</html>', b'\x00bad.example', b'@@||foo.example^']:
            with self.subTest(body=body), self.assertRaises(ValueError):
                filters.parse_list(body)
        with self.assertRaises(ValueError):
            filters.parse_list(b'one.example\ntwo.example', max_domains=1)
    def test_allowlist_wins_for_children_and_parent_block_survives(self):
        config, count = filters.render_config(['example.com', 'ads.good.example.com', 'other.example'], ['good.example.com'])
        self.assertIn('"example.com." always_nxdomain', config)
        self.assertIn('"good.example.com." transparent', config)
        self.assertNotIn('ads.good.example.com.', config)
        self.assertEqual(count, 2)
        config, count = filters.render_config(['example.com'], ['example.com'])
        self.assertNotIn('always_nxdomain', config)
        self.assertEqual(count, 0)
        with self.assertRaises(ValueError):
            filters.render_config(['x.example', 'y.example'], [], max_domains=1)


class DownloadTests(unittest.TestCase):
    def test_download_pins_public_dns_and_revalidates_each_redirect(self):
        calls = []
        def resolver(host):
            return ['93.184.216.34'] if host == 'lists.example' else ['127.0.0.1']
        def transport(url, host, address, timeout):
            calls.append((url, host, address))
            return 200, {'content-type': 'text/plain'}, b'ads.example\n'
        self.assertEqual(filters.download_list('https://lists.example/a', resolver, transport), b'ads.example\n')
        self.assertEqual(calls, [('https://lists.example/a', 'lists.example', '93.184.216.34')])
        for url in ['http://lists.example/a', 'https://u:p@lists.example/a', 'https://127.0.0.1/a', 'https://[::1]/a', 'https://lists.example:8443/a', 'https://lists.example\\@127.0.0.1/a']:
            with self.subTest(url=url), self.assertRaises(ValueError):
                filters.download_list(url, resolver, transport)
        with self.assertRaises(ValueError):
            filters.download_list('https://lists.example/a', lambda host: ['93.184.216.34', '192.168.0.1'], transport)
        calls.clear()
        def redirect(url, host, address, timeout):
            calls.append(url)
            return 302, {'location': 'https://internal.example/file'}, b''
        with self.assertRaises(ValueError):
            filters.download_list('https://lists.example/a', resolver, redirect)
        self.assertEqual(calls, ['https://lists.example/a'])

    def test_download_rejects_unexpected_and_oversized_responses(self):
        resolver = lambda host: ['93.184.216.34']
        for response in [(500, {}, b'error'), (200, {'content-type': 'text/html'}, b'<html>'), (200, {'content-encoding': 'gzip'}, b'compressed'), (200, {}, b'a' * (filters.MAX_BYTES + 1)), (302, {'location': '/again'}, b'')]:
            with self.subTest(status=response[0]), self.assertRaises(ValueError):
                filters.download_list('https://lists.example/a', resolver, lambda *args: response)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.config = self.root / 'unbound'
        self.config.mkdir()
        (self.config / 'unbound.conf.d').mkdir()
        self.main = self.config / 'unbound.conf'
        self.main.write_text('server:\n    chroot: ""\n    username: ""\n    module-config: "subnetcache validator iterator"\ninclude: "' + str(self.config / 'unbound.conf.d' / '*.conf') + '"\n')
        self.other = self.config / 'unbound.conf.d' / 'other.conf'
        self.other.write_text('server:\n    local-zone: "lan.example." static\n    local-data: "host.lan.example. IN A 192.0.2.10"\n')
        self.target = self.config / 'unbound.conf.d' / 'webui-filters.conf'
        self.base = self.root / 'app'
        self.base.mkdir()
        self.activations = []
        self.fail_activation = False
        def activate():
            self.activations.append(self.target.read_text())
            if self.fail_activation:
                self.fail_activation = False
                raise RuntimeError('Activation deliberately failed')
        self.manager = filters.FilterManager(self.base, self.main, self.target, activate=activate)
    def tearDown(self):
        self.tmp.cleanup()

    def test_initialize_is_explicit_preserves_config_and_caps_backups(self):
        self.assertFalse(self.target.exists())
        self.manager.initialize_empty()
        self.assertEqual(self.target.read_text(), filters.HEADER)
        self.assertEqual(self.activations, [])
        original = self.other.read_bytes()
        for i in range(12):
            self.manager.set_domains('blocked', ['block' + str(i) + '.example'])
        self.assertEqual(self.other.read_bytes(), original)
        self.assertEqual(len(list((self.base / 'filter-backups').glob('*.tgz'))), 10)
        self.assertEqual(filters.FilterManager(self.base, self.main, self.target, activate=lambda: None).snapshot()['blocked'], ['block11.example'])

    def test_activation_failure_rolls_back_config_and_state(self):
        self.manager.initialize_empty()
        self.manager.set_domains('blocked', ['ads.example'])
        before = self.manager.snapshot()
        content = self.target.read_bytes()
        self.fail_activation = True
        with self.assertRaises(RuntimeError):
            self.manager.set_domains('blocked', ['new.example'])
        self.assertEqual(self.target.read_bytes(), content)
        self.assertEqual(self.manager.snapshot(), before)
        self.assertEqual(self.activations[-1], content.decode())

    def test_full_config_failure_prevents_activation_and_symlinks(self):
        self.manager.initialize_empty()
        before = self.target.read_bytes()
        self.other.write_text('server:\n    invalid-option: yes\n')
        with self.assertRaises(ValueError):
            self.manager.set_domains('blocked', ['ads.example'])
        self.assertEqual(self.target.read_bytes(), before)
        self.assertEqual(self.activations, [])
        self.other.write_text('server:\n')
        self.target.unlink()
        self.target.symlink_to(self.other)
        with self.assertRaises(ValueError):
            self.manager.set_domains('blocked', ['ads.example'])


    def test_subscriptions_start_disabled_refresh_explicit_enable_disable_and_allow_wins(self):
        self.manager.initialize_empty()
        self.manager.downloader = lambda url: b'ads.example\nother.example\n'
        snapshot = self.manager.add_list('My list', 'https://lists.example/raw')
        item = snapshot['lists'][0]
        self.assertFalse(item['enabled'])
        self.assertEqual(item['count'], 0)
        with self.assertRaises(ValueError):
            self.manager.enable_list(item['id'], True)
        self.manager.refresh_list(item['id'])
        self.assertNotIn('ads.example', self.target.read_text())
        self.manager.enable_list(item['id'], True)
        self.assertIn('ads.example.', self.target.read_text())
        self.manager.set_domains('blocked', ['manual.ads.example', 'manual.example'])
        result = self.manager.set_domains('allowed', ['ads.example'])
        self.assertEqual(result['blocked'], ['manual.example'])
        self.assertNotIn('ads.example." always_nxdomain', self.target.read_text())
        self.manager.enable_list(item['id'], False)
        self.assertNotIn('other.example', self.target.read_text())
        self.assertIn('manual.example', self.target.read_text())
        self.manager.delete_list(item['id'])
        self.assertEqual(self.manager.snapshot()['lists'], [])

    def test_failed_refresh_retains_last_cache_and_running_config_but_records_error(self):
        self.manager.initialize_empty()
        self.manager.downloader = lambda url: b'ads.example\n'
        item = self.manager.add_list('list', 'https://lists.example/raw')['lists'][0]
        self.manager.refresh_list(item['id'])
        self.manager.enable_list(item['id'], True)
        content = self.target.read_bytes()
        updated = self.manager.snapshot()['lists'][0]['last_updated']
        for body in [b'', b'<html>upstream error</html>']:
            self.manager.downloader = lambda url: body
            with self.assertRaises(ValueError):
                self.manager.refresh_list(item['id'])
            self.assertEqual(self.target.read_bytes(), content)
            status = self.manager.snapshot()['lists'][0]
            self.assertEqual(status['count'], 1)
            self.assertEqual(status['last_updated'], updated)
            self.assertTrue(status['last_error'])
        self.manager.downloader = lambda url: b'new.example\n'
        self.fail_activation = True
        with self.assertRaises(RuntimeError):
            self.manager.refresh_list(item['id'])
        self.assertEqual(self.target.read_bytes(), content)
        self.assertEqual(self.manager.snapshot()['lists'][0]['count'], 1)


class ApiTests(TransactionTests):
    def test_install_routes_require_login_csrf_and_render_integrated_page(self):
        from fastapi import FastAPI, Request, HTTPException
        from fastapi.testclient import TestClient
        from fastapi.templating import Jinja2Templates
        from starlette.middleware.sessions import SessionMiddleware
        from starlette.staticfiles import StaticFiles
        from types import SimpleNamespace
        app = FastAPI()
        app.add_middleware(SessionMiddleware, secret_key='filter-test-only-key')
        def login(request: Request):
            if request.headers.get('X-Test-Login') != 'yes':
                raise HTTPException(401)
        def csrf(request: Request):
            if request.headers.get('X-CSRF-Token') != 'test':
                raise HTTPException(403)
        templates = Jinja2Templates(directory='templates')
        templates.env.globals['url_for'] = lambda endpoint, **kw: '/static/' + kw.get('filename', '')
        app.mount('/static', StaticFiles(directory='static'), name='static')
        upstream = SimpleNamespace(app=app, BASE_DIR=self.base, DEFAULT_CONFIG_FILE=str(self.main), DEFAULT_CONFIG_DIR=str(self.target.parent), _login_required=login, _verify_csrf=csrf,
            _template=lambda request, name, context: templates.TemplateResponse(request=request, name=name, context=dict(context, session={}, csrf_token='test')))
        result = filters.install(upstream, manager=self.manager)
        self.assertIs(result, self.manager)
        self.assertFalse(self.target.exists())
        self.manager.initialize_empty()
        client = TestClient(app)
        self.assertEqual(client.get('/api/filters').status_code, 401)
        routes = [r for r in app.routes if getattr(r, 'path', '').startswith('/api/filters') and 'POST' in getattr(r, 'methods', set())]
        for route in routes:
            path = route.path.replace('{identifier}', 'missing')
            with self.subTest(path=path):
                self.assertEqual(client.post(path, json={}, headers={'X-Test-Login': 'yes'}).status_code, 403)
                self.assertEqual(client.post(path, json={}, headers={'X-CSRF-Token': 'test'}).status_code, 401)
        headers = {'X-Test-Login': 'yes', 'X-CSRF-Token': 'test'}
        response = client.post('/api/filters/domains', json={'kind': 'blocked', 'domains': ['ads.example']}, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['state']['blocked'], ['ads.example'])
        self.assertEqual(client.post('/api/filters/domains', json={'kind':'blocked', 'domains':['bad\".example']}, headers=headers).status_code, 422)
        page = client.get('/filters', headers=headers)
        self.assertEqual(page.status_code, 200, page.text)
        for text in ['Manual blocked domains', 'Allowlist exceptions', 'HTTPS subscriptions', 'filters.js', 'filter-notice', 'filter-blocked']:
            self.assertIn(text, page.text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
