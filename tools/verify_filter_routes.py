"""Exercise production filter routes in a separate process, restore empty state."""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))  # repo root: filters, filter_benchmark, run
import subprocess
from pathlib import Path
import run
from fastapi.testclient import TestClient

app = run.upstream
manager = run.filter_manager
before = manager.snapshot()
assert not before['blocked'] and not before['allowed'] and not before['lists'], 'Refusing to replace existing user filters'
original = manager.target.read_bytes()
assert app.DEFAULT_CONFIG_FILE == '/etc/unbound/unbound.conf'
assert 'include-toplevel:' in Path(app.DEFAULT_CONFIG_FILE).read_text(), 'Production config sanity guard failed'
app.app.dependency_overrides[app._login_required] = lambda: 'verification-only'
app.app.dependency_overrides[app._verify_csrf] = lambda: None
client = TestClient(app.app, base_url='https://192.168.0.254')
def live_zones(expected=None, absent=None):
    import time
    for _ in range(30):
        result = subprocess.run(['unbound-control','-c',app.DEFAULT_CONFIG_FILE,'list_local_zones'],capture_output=True,text=True)
        if result.returncode == 0 and (not expected or expected in result.stdout) and (not absent or absent not in result.stdout):
            return result.stdout
        time.sleep(.1)
    raise AssertionError('Reload did not converge: ' + result.stderr)
name = 'webui-filter-check.invalid'
try:
    for kind, domains in [('blocked', [name]), ('allowed', [name])]:
        response = client.post('/api/filters/domains', json={'kind': kind, 'domains': domains})
        assert response.status_code == 200, response.text
        print('REAL FILTER APPLY', kind, response.json()['state']['effective_count'])
        expected = name + '. ' + ('always_nxdomain' if kind == 'blocked' else 'transparent')
        zones = live_zones(expected=expected)
        assert expected in zones, expected
        if kind == 'blocked':
            result = subprocess.check_output(['dig','+time=2','+tries=1','@127.0.0.1',name,'A','+comments','+noquestion','+nostats'], text=True)
            assert 'status: NXDOMAIN' in result
            print('LIVE DNS BLOCK: NXDOMAIN')
finally:
    for kind in ['blocked', 'allowed']:
        response = client.post('/api/filters/domains', json={'kind': kind, 'domains': []})
        assert response.status_code == 200, response.text
    assert manager.target.read_bytes() == original
    assert not manager.snapshot()['blocked'] and not manager.snapshot()['allowed']
    zones = live_zones(absent=name)
    assert name not in zones
    print('RESTORED EMPTY FILTERS; original fragment bytes unchanged')
for url in ['/', '/config', '/settings', '/debug', '/filters', '/api/filters', '/api/sysinfo', '/api/stats']:
    response = client.get(url)
    assert response.status_code == 200, (url, response.text)
    print('PAGE/API', url, response.status_code)
    if url == '/api/sysinfo':
        info = response.json()
        assert info['mem_total'] == 2147483648
        print('CONTAINER MEMORY', info['mem_total'], info['mem_used'], info['mem_pct'])
    if url == '/filters':
        assert '/filters' in response.text and 'responsive.css' in response.text and 'js/filters.js' in response.text
print('PRODUCTION-ROUTE PROBE PASS (auth override only in this separate process)')
