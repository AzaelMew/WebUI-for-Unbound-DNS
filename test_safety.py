"""Regression tests use a temporary config tree, never live DNS files."""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONF = ROOT / 'testdata/unbound'
CONF_DIR = CONF / 'unbound.conf.d'
BACKUP_DIR = ROOT / 'testdata/backups'
CONF_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
MAIN = CONF / 'unbound.conf'
MAIN.write_text('include-toplevel: "' + str(CONF_DIR / '*.conf') + '"\n')
FRAGMENT = CONF_DIR / 'server.conf'
if not FRAGMENT.exists():
    FRAGMENT.write_text('server:\n  interface: 127.0.0.1\n  port: 53535\n')
os.environ['DEFAULT_CONFIG_FILE'] = str(MAIN)
os.environ['DEFAULT_CONFIG_DIR'] = str(CONF_DIR) + '/'
os.environ['BACKUP_DIR'] = str(BACKUP_DIR)

# Import a fresh module with paths asserted to remain beneath this repository.
spec = importlib.util.spec_from_file_location('isolated_safety_app', ROOT / 'app.py')
if spec is None or spec.loader is None:
    raise RuntimeError('Cannot load isolated application module')
upstream = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upstream
spec.loader.exec_module(upstream)
assert Path(upstream.DEFAULT_CONFIG_FILE).is_relative_to(ROOT), 'Refusing production config in tests'
assert Path(upstream.DEFAULT_CONFIG_DIR).resolve().is_relative_to(ROOT), 'Refusing production directory in tests'
upstream.BASE_DIR = ROOT
import safety
safety.install(upstream)
from fastapi.testclient import TestClient
upstream.app.dependency_overrides[upstream._login_required] = lambda: 'test'
upstream.app.dependency_overrides[upstream._verify_csrf] = lambda: None


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(upstream.app, base_url='https://example.test')

    def test_form_save_is_blocked_without_changing_config(self):
        before = MAIN.read_bytes()
        r = self.client.post('/api/config/save', json={'interface': '127.0.0.1'})
        self.assertEqual(r.status_code, 403)
        self.assertEqual(MAIN.read_bytes(), before)
    def test_invalid_raw_save_leaves_included_config_valid(self):
        before = FRAGMENT.read_bytes()
        self.client.post('/api/config/set_file', json={'file': str(FRAGMENT)})
        r = self.client.post('/api/config/raw/save', json={'content': 'server:\n  definitely-not-a-setting: yes\n'})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(FRAGMENT.read_bytes(), before)

    def test_valid_raw_save_keeps_main_includes_and_makes_backup(self):
        before = MAIN.read_bytes()
        self.client.post('/api/config/set_file', json={'file': str(FRAGMENT)})
        desired = FRAGMENT.read_text() + '  hide-identity: yes\n'
        r = self.client.post('/api/config/raw/save', json={'content': desired})
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(FRAGMENT.read_text(), desired)
        self.assertEqual(MAIN.read_bytes(), before)
        self.assertTrue(list(BACKUP_DIR.glob('*.tgz')))
    def test_session_cookie_requires_https(self):
        r = self.client.get('/login')
        self.assertIn('secure', r.headers['set-cookie'].lower())

    def test_config_boundary_rejects_sibling_directory(self):
        sibling = ROOT / 'unbound_other/test.conf'
        with self.assertRaises(ValueError):
            upstream._safe_config_path(str(sibling))

    def test_debug_cannot_pass_command_options(self):
        r = self.client.post('/api/debug/run', json={'tool': 'dig', 'target': '-ftest.conf', 'record': 'A'})
        self.assertEqual(r.status_code, 422)
    def test_metadata_cannot_escape_script_element(self):
        from jinja2 import Environment, FileSystemLoader, select_autoescape
        env = Environment(loader=FileSystemLoader(Path(__file__).with_name('templates')), autoescape=select_autoescape())
        source = Path(__file__).with_name('templates').joinpath('config.html').read_text()
        prelude = source[source.index('<script>'):source.index('</script>') + len('</script>')]
        payload = {'description': '</script><script>alert(1)</script>', 'allowed_tabs': []}
        import json
        rendered = env.from_string(prelude).render(file_meta=payload, file_meta_json=json.dumps(payload), is_main_config=False, all_tabs_json='[]', tab_labels_json='{}')
        self.assertNotIn('</script><script>alert(1)', rendered)
    def test_invalid_backup_restore_never_activates(self):
        before = FRAGMENT.read_bytes()
        Path(upstream.BACKUP_DIR, 'invalid.conf').write_text('server:\n  invalid-option: yes\n')
        self.client.post('/api/config/set_file', json={'file': str(FRAGMENT)})
        r = self.client.post('/api/backup/restore', json={'filename': 'invalid.conf'})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(FRAGMENT.read_bytes(), before)
    def test_login_requires_form_csrf(self):
        r = self.client.post('/login', data={'username': 'nobody', 'password': 'not-a-credential'})
        self.assertEqual(r.status_code, 403)
    def test_bootstrap_requires_session_csrf(self):
        r = self.client.post('/setup', data={'username': 'admin', 'password': 'not-a-credential'})
        self.assertEqual(r.status_code, 403)


if __name__ == '__main__':
    unittest.main()
