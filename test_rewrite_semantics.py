"""Real isolated Unbound rewrite semantics; only owned high loopback ports."""
import contextlib
import os
import signal
import shutil
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
import filter_activation
import filter_benchmark as bench
import rewrites
from test_rewrites import record

WORKSPACE = Path('/opt/unbound-filter-development/rewrites-backend')


def safe_workspace():
    root = Path(os.environ['TMPDIR']).resolve()
    scratch = (Path.home() / '.hermes/cache/scratch').resolve()
    if not any(root == allowed or root.is_relative_to(allowed) for allowed in (WORKSPACE, scratch)):
        raise ValueError('Rewrite semantic tests require their isolated workspace')
    return root


@unittest.skipUnless(shutil.which('unbound') and shutil.which('unbound-checkconf'), 'Unbound binaries required')
class RewriteSemantics(unittest.TestCase):
    def test_fourteen_mappings_nodata_unlisted_recursion_parent_block_and_independent_canaries(self):
        with tempfile.TemporaryDirectory(dir=safe_workspace()) as td, bench.mock_upstream() as upstream:
            root = Path(td)
            config = root / 'unbound'
            fragments = config / 'unbound.conf.d'
            fragments.mkdir(parents=True)
            base = root / 'app'
            base.mkdir()
            port = bench.free_port()
            self.assertGreaterEqual(port, 1024)
            self.assertGreaterEqual(upstream.port, 1024)
            main = config / 'unbound.conf'
            main.write_text(f'''server:
    interface: 127.0.0.1
    port: {port}
    access-control: 127.0.0.0/8 allow
    username: ""
    directory: "{config}"
    chroot: ""
    pidfile: "{root}/isolated.pid"
    use-syslog: no
    logfile: ""
    verbosity: 0
    num-threads: 1
    module-config: "validator iterator"
    do-ip6: no
    do-not-query-localhost: no
    auto-trust-anchor-file: ""
    harden-dnssec-stripped: no
    qname-minimisation: no
    msg-cache-size: 4m
    rrset-cache-size: 4m
remote-control:
    control-enable: no
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@{upstream.port}
include: "{fragments}/*.conf"
''')
            filter_file = fragments / 'webui-filters.conf'
            filter_file.write_text('# Independent isolated filter\nserver:\n    local-zone: "blocked.example." always_nxdomain\n    local-zone: "two.example." transparent\n')
            filter_token, _ = filter_activation.stamp_policy(filter_file)
            before = filter_file.read_bytes()
            target = fragments / 'webui-rewrites.conf'
            process = None
            log = (root / 'resolver.log').open('w+')
            def stop():
                nonlocal process
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    process = None
            def activate():
                nonlocal process
                stop()
                bench.check_headroom(disk_path=root)
                process = subprocess.Popen(bench.limited(['unbound', '-d', '-c', str(main)], limit_mib=256),
                    stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        log.seek(0)
                        raise RuntimeError('Isolated Unbound exited: ' + log.read())
                    try:
                        if filter_activation.query('127.0.0.1', port, 'ready.unlisted.example', 1, .1) == (0, ['192.0.2.123']):
                            return
                    except OSError:
                        pass
                    time.sleep(.025)
                raise RuntimeError('Isolated resolver did not answer readiness query')
            rows = []
            words = 'one two three four five six seven eight nine ten eleven twelve thirteen fourteen'.split()
            for n, word in enumerate(words, 1):
                addresses = [f'192.0.2.{n}']
                if n % 2 == 0:
                    addresses.append(f'2001:db8::{n:x}')
                rows.append(record(f'{word}.example', addresses, ttl=60 + n))
            # Long hostname + maximum IPv6 RRset exercises EDNS, not truncated UDP.
            rows[-1] = record('.'.join(['a' * 63] * 3 + ['b' * 51]) + '.example',
                               [f'2001:db8::{n:x}' for n in range(1, 17)], ttl=74)
            rows[0]['hostname'] = 'one.blocked.example'
            try:
                with patch.dict(os.environ, {'WEBUI_FILTER_VERIFY_HOST': '127.0.0.1',
                                              'WEBUI_FILTER_VERIFY_PORT': str(port), 'WEBUI_FILTER_VERIFY_TIMEOUT': '5'}):
                    manager = rewrites.RewriteManager(base, main, target, activate=activate, verifier=rewrites.RewriteManager._verify_dns)
                    manager.initialize_empty()
                    saved = manager.save_records(rows, 0)
                    self.assertEqual(len(saved['records']), 14)
                    for item in saved['records']:
                        for kind, version in ((1, 4), (28, 6)):
                            expected = sorted(addr for addr in item['addresses'] if (':' in addr) == (version == 6))
                            rcode, answers = filter_activation.query('127.0.0.1', port, item['hostname'], kind, .5)
                            self.assertEqual(rcode, 0, item)
                            self.assertEqual(sorted(answers), expected, item)
                    filter_activation.verify_policy(filter_token, 'blocked.example', host='127.0.0.1', port=port, timeout=2)
                    self.assertEqual(filter_file.read_bytes(), before)
                    self.assertEqual(filter_activation.query('127.0.0.1', port, 'unlisted.example', 1, .5), (0, ['192.0.2.123']))
                    self.assertEqual(filter_activation.query('127.0.0.1', port, 'child.two.example', 1, .5), (0, ['192.0.2.123']))
                    names = set(upstream.names)
                    self.assertFalse(names.intersection(item['hostname'] for item in saved['records']), 'Listed names must not recurse, even for missing AAAA')
                    # Real callback rollback after a candidate verifier failure.
                    old_fragment, old_state = target.read_bytes(), manager.state_path.read_bytes()
                    original_verify = manager.verifier
                    def fail_candidate(token, records):
                        if records and records[0]['hostname'] == 'candidate.example':
                            raise RuntimeError('injected candidate verification failure')
                        original_verify(token, records)
                    manager.verifier = fail_candidate
                    with self.assertRaisesRegex(RuntimeError, 'candidate verification'):
                        manager.save_records([record('candidate.example')], 1)
                    self.assertEqual((target.read_bytes(), manager.state_path.read_bytes()), (old_fragment, old_state))
                    self.assertEqual(filter_activation.query('127.0.0.1', port, 'two.example', 28, .5), (0, ['2001:db8::2']))
                    self.assertFalse(manager.journal_path.exists())
                    owned_pid = process.pid
            finally:
                stop()
                log.close()
            self.assertFalse(Path(f'/proc/{owned_pid}').exists())


if __name__ == '__main__':
    unittest.main()
