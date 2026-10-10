"""Isolated tests for the structured server-config editor.

No production file, service or resolver is touched: every test builds a
temporary config tree and a fake Unbound that reads it the way checkconf and
unbound-control would.  Never import ``app`` here.
"""
import difflib
import glob
import importlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

sc = importlib.import_module('server_config')

SERVER = """\
server:
  interface: 0.0.0.0
  interface: ::0
  port: 53
  do-ip6: yes

  hide-identity: yes   # keep the box anonymous
  qname-minimisation: yes
  edns-buffer-size: 1232
  cache-min-ttl: 300
  cache-max-ttl: 14400
  target-fetch-policy: "3 2 1 1 1"
  rrset-cache-size: 256m
  msg-cache-size: 128m
  so-rcvbuf: 1m

  private-address: 192.168.0.0/16
  private-address: 10.0.0.0/8

  access-control: 127.0.0.1/32 allow
  access-control: ::1/128 allow
  access-control: 192.168.0.0/16 allow  # LAN
  access-control: 10.0.0.0/8 allow

  # Optional: replace with your actual ULA
"""
DASHBOARD = """\
server:
  extended-statistics: yes
  verbosity: 0
  logfile: "/var/log/unbound/unbound.log"
"""
REMOTE = "remote-control:\n  control-enable: yes\n  control-interface: /run/unbound.ctl\n"
FILTERS = '# Managed by Unbound WebUI filters; do not edit.\nserver:\n    local-zone: "ads.example." always_nxdomain\n'
REWRITES = '# Managed by Unbound WebUI DNS rewrites; do not edit.\nserver:\n    local-data: "nas.example. 300 IN A 192.0.2.7"\n'

DEFAULTS = {'port': '53', 'do-udp': 'yes', 'do-ip4': 'yes', 'do-ip6': 'yes', 'do-tcp': 'yes', 'cache-min-ttl': '0',
            'cache-max-ttl': '86400', 'msg-cache-size': '4m', 'rrset-cache-size': '4m', 'neg-cache-size': '1m',
            'num-threads': '1', 'verbosity': '1', 'hide-identity': 'no', 'tls-cert-bundle': '', 'logfile': ''}
SIZES = {'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}


class FakeUnbound:
    """Independent mini-implementation of checkconf -o / unbound-control reads."""

    def __init__(self, main):
        self.main = main
        self.loaded = self.effective(main)
        self.activations = 0
        self.fail_activate = False
        self.ignore_reload = False
        self.control_down = False

    @staticmethod
    def _files(main):
        main = Path(main)
        yield main
        for line in main.read_text().splitlines():
            match = re.match(r'\s*include(?:-toplevel)?:\s*"?([^"#]+)"?', line)
            if match:
                for name in sorted(glob.glob(match[1].strip())):
                    yield Path(name)

    def effective(self, main):
        scalars, lists, zones, clause, zone = {}, {}, {}, None, None
        for path in self._files(main):
            for raw in path.read_text().splitlines():
                text = raw.split(' #')[0].strip()
                if not text or text.startswith('#'):
                    continue
                key, _, value = text.partition(':')
                value = value.strip().strip('"')
                if not value and key in {'server', 'forward-zone', 'remote-control'}:
                    clause = key
                    zone = {'addrs': []} if key == 'forward-zone' else None
                    continue
                if clause == 'forward-zone':
                    if key == 'name':
                        zones[value.rstrip('.') or '.'] = zone
                    elif key == 'forward-addr':
                        zone['addrs'].append(value)
                elif clause == 'server':
                    if key in ('interface', 'access-control', 'private-address'):
                        lists.setdefault(key, []).append(value)
                    else:
                        scalars[key] = value
        return {'scalars': scalars, 'lists': lists, 'zones': zones}

    def option(self, config, key):
        eff = self.effective(config)
        return self._read(eff, key)

    def running(self, config, key):
        if self.control_down:
            raise RuntimeError('connection refused')
        return self._read(self.loaded, key)

    @staticmethod
    def _read(eff, key):
        if key in ('interface', 'access-control', 'private-address'):
            return list(reversed(eff['lists'].get(key, []))) or ['']
        value = eff['scalars'].get(key, DEFAULTS.get(key, ''))
        if key.endswith('-size') or key == 'so-rcvbuf':
            match = re.fullmatch(r'(\d+)([kmg]?)', value)
            if match:
                value = str(int(match[1]) * SIZES.get(match[2], 1))
        return [value]

    def forwards(self, config):
        if self.control_down:
            raise RuntimeError('connection refused')
        return [f'{name}. IN forward ' + ' '.join(z['addrs']) for name, z in self.loaded['zones'].items()]

    def activate(self):
        if self.fail_activate:
            raise RuntimeError('reload failed')
        self.activations += 1
        if not self.ignore_reload:
            self.loaded = self.effective(self.main)


class Env:
    def __init__(self, case, server=SERVER, extra=None):
        self.dir = tempfile.TemporaryDirectory()
        case.addCleanup(self.dir.cleanup)
        tmp = Path(self.dir.name)
        self.root, self.base = tmp / 'etc-unbound', tmp / 'app'
        (self.root / 'unbound.conf.d').mkdir(parents=True)
        self.base.mkdir()
        self.main = self.root / 'unbound.conf'
        self.main.write_text(f'include-toplevel: "{self.root}/unbound.conf.d/*.conf"\n')
        self.srv = self.root / 'unbound.conf.d/unbound.conf'
        self.srv.write_text(server)
        for name, text in {'dashboard.conf': DASHBOARD, 'remote-control.conf': REMOTE,
                           'webui-filters.conf': FILTERS, 'webui-rewrites.conf': REWRITES,
                           'unbound.conf.bak-old': 'garbage: not included\n'}.items():
            (self.root / 'unbound.conf.d' / name).write_text(text)
        for name, text in (extra or {}).items():
            (self.root / name).parent.mkdir(parents=True, exist_ok=True)
            (self.root / name).write_text(text)
        self.fake = FakeUnbound(self.main)
        self.checked = []
        self.mgr = sc.ConfigManager(self.base, self.main, option_reader=self.fake.option,
                                    running_reader=self.fake.running, forwards_reader=self.fake.forwards,
                                    checker=self.check, activate=self.fake.activate, verifier=self.verify,
                                    memory=lambda: 4 << 30)

    def check(self, config):
        config = Path(config)
        self.checked.append(config)
        for path in FakeUnbound._files(config):
            text = path.read_text()
            if 'bogus-option' in text or 'SYNTAX ERROR' in text:
                raise sc.ConfigError('Unbound config validation failed: unknown option')
        if self.fail_live and config == self.main and 'cache-min-ttl: 60' in self.srv.read_text():
            raise sc.ConfigError('live validation failed')

    fail_live = False
    verify_error = None

    def verify(self, context):
        if self.verify_error:
            raise RuntimeError(self.verify_error)
        reason = self.mgr._mismatch(context)
        if reason:
            raise RuntimeError(reason)

    def revision(self):
        return self.mgr.snapshot()['revision']

    def save(self, **kwargs):
        kwargs.setdefault('revision', self.revision())
        return self.mgr.save(**kwargs)

    def diff(self, before, path=None):
        path = path or self.srv
        return [l for l in difflib.unified_diff(before.splitlines(), path.read_text().splitlines(), lineterm='', n=0)
                if l[:1] in '+-' and l[:3] not in {'+++', '---'}]


class ParserTests(unittest.TestCase):
    def test_include_order_managed_files_and_ignored_backup(self):
        env = Env(self)
        model = sc.Model(env.root, env.main)
        names = [info.rel for info in model.files.values()]
        self.assertEqual(names, ['unbound.conf', 'unbound.conf.d/dashboard.conf', 'unbound.conf.d/remote-control.conf',
                                 'unbound.conf.d/unbound.conf', 'unbound.conf.d/webui-filters.conf',
                                 'unbound.conf.d/webui-rewrites.conf'])
        roles = {info.rel: info.role for info in model.files.values()}
        self.assertEqual(roles['unbound.conf.d/webui-filters.conf'], 'managed')
        self.assertEqual(roles['unbound.conf.d/unbound.conf'], 'editable')
        self.assertEqual(model.blockers, [])

    def test_values_quotes_trailing_comments_and_hash_inside_token(self):
        lines = sc.parse_lines(Path('x'), 'server:\n  a: "3 2 1" # c\n  b: 1.1.1.1@853#cloudflare-dns.com\n  access-control: 10.0.0.0/8 allow # lan\n')
        self.assertEqual([(l.key, l.value, l.tokens) for l in lines[1:]],
                         [('a', '3 2 1', 1), ('b', '1.1.1.1@853#cloudflare-dns.com', 1), ('access-control', '10.0.0.0/8 allow', 2)])
        self.assertEqual(lines[1].text[lines[1].start:lines[1].end], '"3 2 1"')
        self.assertTrue(all(l.clause == 'server' for l in lines[1:]))

    def test_blockers_for_relative_include_symlink_and_oversize(self):
        env = Env(self)
        env.main.write_text(env.main.read_text() + 'include: "relative.conf"\n')
        self.assertTrue(sc.Model(env.root, env.main).blockers)
        env2 = Env(self)
        (env2.root / 'real.conf').write_text('server:\n  port: 53\n')
        os.symlink(env2.root / 'real.conf', env2.root / 'unbound.conf.d/link.conf')
        self.assertTrue(any('symbolic' in b for b in sc.Model(env2.root, env2.main).blockers))
        env3 = Env(self)
        env3.srv.write_text('server:\n' + '# pad\n' * 300000)
        self.assertTrue(any('1 MiB' in b for b in sc.Model(env3.root, env3.main).blockers))

    def test_snapshot_reports_sources_running_pending_and_roles(self):
        env = Env(self)
        state = env.mgr.snapshot()
        self.assertEqual(state['values']['port']['value'], 53)
        self.assertEqual(state['values']['port']['source'], 'unbound.conf.d/unbound.conf:4')
        self.assertEqual(state['values']['rrset-cache-size']['value'], '256m')
        self.assertIs(state['values']['hide-identity']['value'], True)
        self.assertFalse(state['values']['cache-min-ttl']['source'] is None)
        self.assertEqual(state['lists']['interface']['items'], ['0.0.0.0', '::'])
        self.assertEqual(state['pending'], [])
        self.assertTrue(state['editable'])
        env.srv.write_text(env.srv.read_text().replace('cache-min-ttl: 300', 'cache-min-ttl: 60'))
        state = env.mgr.snapshot()
        self.assertEqual(state['pending'], ['cache-min-ttl'])
        self.assertEqual(state['values']['cache-min-ttl']['running'], 300)
        self.assertEqual(state['values']['cache-min-ttl']['value'], 60)
        env.fake.control_down = True
        state = env.mgr.snapshot()
        self.assertFalse(state['running_available'])
        self.assertEqual(state['pending'], [])


class PlanningTests(unittest.TestCase):
    def test_scalar_change_touches_exactly_one_line_and_keeps_comment(self):
        env = Env(self)
        before = env.srv.read_text()
        env.save(changes={'cache-min-ttl': 60}, apply=False)
        self.assertEqual(env.diff(before), ['-  cache-min-ttl: 300', '+  cache-min-ttl: 60'])
        env.save(changes={'hide-identity': False}, apply=False)
        self.assertIn('  hide-identity: no   # keep the box anonymous', env.srv.read_text())
        env.save(changes={'target-fetch-policy': '4 3 2 1 1'}, apply=False)
        self.assertIn('  target-fetch-policy: "4 3 2 1 1"', env.srv.read_text())
        env.save(changes={'rrset-cache-size': '512m'}, apply=False)
        self.assertIn('  rrset-cache-size: 512m', env.srv.read_text())

    def test_directive_defined_in_another_file_is_edited_there(self):
        env = Env(self)
        before_srv, before_dash = env.srv.read_text(), (env.root / 'unbound.conf.d/dashboard.conf').read_text()
        env.save(changes={'verbosity': '2', 'logfile': '/var/log/u.log'}, apply=False)
        self.assertEqual(env.srv.read_text(), before_srv)
        self.assertEqual(sorted(env.diff(before_dash, env.root / 'unbound.conf.d/dashboard.conf')),
                         sorted(['-  verbosity: 0', '+  verbosity: 2', '-  logfile: "/var/log/unbound/unbound.log"', '+  logfile: "/var/log/u.log"']))

    def test_new_directive_is_appended_inside_the_server_clause_of_the_main_server_file(self):
        env = Env(self)
        before = env.srv.read_text()
        env.save(changes={'prefetch': True, 'num-threads': 2}, apply=False)
        text = env.srv.read_text()
        self.assertEqual(env.diff(before), ['+  num-threads: 2', '+  prefetch: yes'])
        lines = text.splitlines()
        self.assertLess(lines.index('  access-control: 10.0.0.0/8 allow'), lines.index('  num-threads: 2'))
        self.assertLess(lines.index('  num-threads: 2'), lines.index('  # Optional: replace with your actual ULA'))
        self.assertEqual(env.fake.effective(env.main)['scalars']['prefetch'], 'yes')

    def test_directive_with_no_server_clause_anywhere_creates_one(self):
        env = Env(self, server='# only comments\n')
        for name in ('dashboard.conf',):
            (env.root / 'unbound.conf.d' / name).write_text('# nothing\n')
        env.save(changes={'num-threads': 2}, apply=False)
        self.assertEqual(env.main.read_text().splitlines()[-2:], ['server:', '    num-threads: 2'])

    def test_reset_removes_every_occurrence_and_noop_changes_nothing(self):
        env = Env(self)
        env.srv.write_text(env.srv.read_text() + '  cache-min-ttl: 100\n')
        env.save(changes={'cache-min-ttl': None}, apply=False)
        self.assertNotIn('cache-min-ttl', env.srv.read_text())
        before = env.srv.read_text()
        result = env.save(changes={'cache-min-ttl': None, 'port': 53}, apply=False)
        self.assertTrue(result['unchanged'])
        self.assertEqual(env.srv.read_text(), before)
        self.assertEqual(env.fake.activations, 0)

    def test_list_edit_preserves_kept_lines_and_comments(self):
        env = Env(self)
        before = env.srv.read_text()
        env.save(lists={'access-control': ['127.0.0.1/32 allow', '::1/128 allow', '192.168.0.0/16 allow', '172.16.0.0/12 allow']},
                 apply=False)
        self.assertEqual(env.diff(before), ['-  access-control: 10.0.0.0/8 allow', '+  access-control: 172.16.0.0/12 allow'])
        self.assertIn('  access-control: 192.168.0.0/16 allow  # LAN', env.srv.read_text())

    def test_list_canonicalises_and_dedupes(self):
        env = Env(self)
        env.save(lists={'private-address': ['10.1.2.3/8', '10.0.0.0/8', ' ', '192.168.0.0/16']}, apply=False)
        self.assertEqual(env.fake.effective(env.main)['lists']['private-address'], ['192.168.0.0/16', '10.0.0.0/8'])

    def test_forward_zone_add_edit_delete_keeps_unknown_directives(self):
        zone_file = '\nforward-zone:\n  name: "corp.example."\n  forward-addr: 192.0.2.53\n  forward-no-cache: yes\n\nforward-zone:\n  name: "old.example"\n  forward-addr: 192.0.2.99\n'
        env = Env(self, server=SERVER + zone_file)
        state = env.mgr.snapshot()
        self.assertEqual({z['name']: z['others'] for z in state['forward_zones']}, {'corp.example.': ['forward-no-cache'], 'old.example': []})
        env.save(zones=[{'name': 'corp.example', 'addrs': ['192.0.2.53', '192.0.2.54@5353'], 'tls': True, 'first': True},
                        {'name': '.', 'addrs': ['1.1.1.1@853#cloudflare-dns.com'], 'tls': True, 'first': False}], apply=False)
        text = env.srv.read_text()
        self.assertIn('  forward-no-cache: yes', text)
        self.assertNotIn('old.example', text)
        self.assertNotIn('192.0.2.99', text)
        self.assertIn('forward-addr: 192.0.2.54@5353', text)
        self.assertIn('forward-tls-upstream: yes', text)
        zones = env.fake.effective(env.main)['zones']
        self.assertEqual(set(zones), {'corp.example', '.'})
        self.assertEqual(zones['.']['addrs'], ['1.1.1.1@853#cloudflare-dns.com'])
        env.save(zones=[], apply=False)
        self.assertNotIn('forward-zone', env.srv.read_text())

    def test_forward_zone_alias_tls_key_is_switched_off(self):
        env = Env(self, server=SERVER + '\nforward-zone:\n  name: "x.example"\n  forward-addr: 192.0.2.1\n  forward-ssl-upstream: yes\n')
        self.assertTrue(env.mgr.snapshot()['forward_zones'][0]['tls'])
        env.save(zones=[{'name': 'x.example', 'addrs': ['192.0.2.1'], 'tls': False, 'first': False}], apply=False)
        self.assertNotIn('ssl-upstream', env.srv.read_text())


class ValidationTests(unittest.TestCase):
    def rejected(self, **kwargs):
        env = Env(self)
        before = {p: p.read_text() for p in (env.main, env.srv)}
        with self.assertRaises(sc.ConfigError):
            env.save(apply=False, **kwargs)
        self.assertEqual({p: p.read_text() for p in before}, before)
        self.assertEqual(env.fake.activations, 0)
        self.assertFalse(list(env.mgr.data.glob('transaction.json')))

    def test_rejects_malformed_values(self):
        for changes in ({'bogus': 1}, {'port': '53'}, {'port': True}, {'port': 0}, {'port': 70000},
                        {'hide-identity': 'yes'}, {'hide-identity': 1}, {'verbosity': '9'},
                        {'identity': 'x\nserver:'}, {'identity': 'a"b'}, {'identity': 'a#b'}, {'logfile': 'relative.log'},
                        {'logfile': '/var/../etc/x'}, {'rrset-cache-size': '12 mb'}, {'rrset-cache-size': '1k'},
                        {'target-fetch-policy': '3 x'}, {'module-config': 'validator'}, {'module-config': 'evil iterator'},
                        {'do-udp': False}, {'edns-buffer-size': 1}):
            with self.subTest(changes=changes):
                self.rejected(changes=changes)

    def test_rejects_malformed_lists_and_zones(self):
        for lists in ({'interface': ['not-an-ip']}, {'interface': ['0.0.0.0@99999']}, {'access-control': ['10.0.0.0/8']},
                      {'access-control': ['10.0.0.0/8 maybe']}, {'private-address': ['junk']}, {'nope': []},
                      {'access-control': ['x' * 5] * 300}):
            with self.subTest(lists=lists):
                self.rejected(lists=lists)
        for zones in ([{'name': 'a b', 'addrs': ['1.1.1.1']}], [{'name': '', 'addrs': ['1.1.1.1']}], [{'name': '..', 'addrs': ['1.1.1.1']}], [{'name': 'ok.example', 'addrs': []}],
                      [{'name': 'ok.example', 'addrs': ['host.example']}], [{'name': 'ok.example', 'addrs': ['1.1.1.1'], 'tls': 'yes'}],
                      [{'name': 'a.example', 'addrs': ['1.1.1.1']}, {'name': 'A.example.', 'addrs': ['1.1.1.2']}],
                      [{'name': 'a.example', 'addrs': ['1.1.1.1'], 'extra': 1}]):
            with self.subTest(zones=zones):
                self.rejected(zones=zones)

    def test_invariants_protect_webui_and_resolver(self):
        self.rejected(changes={'cache-min-ttl': 99999})
        self.rejected(lists={'access-control': ['192.168.0.0/16 allow']})            # loopback lock-out
        self.rejected(lists={'access-control': ['127.0.0.1/32 refuse', '10.0.0.0/8 allow']})
        self.rejected(lists={'interface': ['192.168.0.254']})                       # WebUI cannot verify DNS
        self.rejected(changes={'do-ip4': False})
        self.rejected(changes={'msg-cache-size': '3g'})                             # memory guard (4g available)

    def test_loopback_via_wildcard_or_explicit_address_is_accepted(self):
        env = Env(self)
        env.save(lists={'interface': ['127.0.0.1', '192.168.0.254@53']}, acknowledge=True, apply=False)
        env.save(lists={'access-control': ['127.0.0.0/8 allow_snoop']}, acknowledge=True, apply=False)

    def test_disruptive_changes_need_acknowledgement_only_when_applying(self):
        env = Env(self)
        with self.assertRaisesRegex(sc.ConfigError, 'Acknowledge'):
            env.save(changes={'port': 5353})
        self.assertEqual(env.fake.activations, 0)
        env.save(changes={'port': 5353}, apply=False)
        env.save(changes={'port': 53}, acknowledge=True)
        env.save(changes={'num-threads': 2})  # non-disruptive applies without acknowledgement

    def test_stale_revision_is_a_conflict_and_nothing_changes(self):
        env = Env(self)
        revision = env.revision()
        env.srv.write_text(env.srv.read_text() + '# edited elsewhere\n')
        before = env.srv.read_text()
        with self.assertRaises(sc.RevisionConflict):
            env.mgr.save(revision, changes={'cache-min-ttl': 1}, apply=False)
        self.assertEqual(env.srv.read_text(), before)

    def test_blockers_refuse_structured_edits(self):
        env = Env(self)
        env.main.write_text(env.main.read_text() + 'include: "relative.conf"\n')
        with self.assertRaisesRegex(sc.ConfigError, 'Structured editing'):
            env.save(changes={'num-threads': 2}, apply=False)


class TransactionTests(unittest.TestCase):
    def test_apply_runs_staged_and_live_validation_reloads_and_verifies(self):
        env = Env(self)
        result = env.save(changes={'cache-min-ttl': 60}, apply=True)
        self.assertTrue(result['applied'])
        stage_checks = [p for p in env.checked if p != env.main]
        self.assertTrue(stage_checks and env.checked[-1] == env.main)
        self.assertTrue(all(env.base in p.parents for p in stage_checks), 'validation ran on a staged copy')
        self.assertEqual(env.fake.activations, 1)
        self.assertEqual(result['state']['pending'], [])
        self.assertEqual(result['state']['values']['cache-min-ttl']['running'], 60)
        self.assertFalse(env.mgr.journal_path.exists())

    def test_save_only_does_not_reload_and_reports_pending_then_apply_pending_loads_it(self):
        env = Env(self)
        result = env.save(changes={'cache-min-ttl': 60}, apply=False)
        self.assertFalse(result['applied'])
        self.assertEqual(env.fake.activations, 0)
        self.assertEqual(result['state']['pending'], ['cache-min-ttl'])
        applied = env.mgr.apply_pending(env.revision())
        self.assertEqual(env.fake.activations, 1)
        self.assertEqual(applied['state']['pending'], [])

    def test_backup_contains_previous_files_and_verifies(self):
        env = Env(self)
        before = env.srv.read_text()
        result = env.save(changes={'cache-min-ttl': 60}, apply=False)
        with tarfile.open(env.mgr.backups / result['backup']) as archive:
            manifest = json.load(archive.extractfile('manifest.json'))
            self.assertEqual(list(manifest['files']), ['unbound/unbound.conf.d/unbound.conf'])
            self.assertEqual(archive.extractfile('unbound/unbound.conf.d/unbound.conf').read().decode(), before)
        for n in range(12):
            env.save(changes={'cache-min-ttl': 100 + n}, apply=False)
        self.assertEqual(len(list(env.mgr.backups.glob('config_*.tgz'))), sc.BACKUP_KEEP)

    def test_staged_validation_failure_leaves_everything_untouched(self):
        env = Env(self)
        before = env.srv.read_text()
        with self.assertRaises(sc.ConfigError):
            env.mgr.save_file(env.revision(), 'unbound.conf.d/unbound.conf', before + 'bogus-option: 1\n', apply=False)
        self.assertEqual(env.srv.read_text(), before)
        self.assertFalse(env.mgr.journal_path.exists())
        self.assertEqual(list(env.mgr.backups.glob('config_*.tgz')), [])

    def test_live_validation_failure_restores_files(self):
        env = Env(self)
        before = env.srv.read_text()
        env.fail_live = True
        with self.assertRaisesRegex(sc.ConfigError, 'live validation'):
            env.save(changes={'cache-min-ttl': 60}, apply=True)
        env.fail_live = False
        self.assertEqual(env.srv.read_text(), before)
        self.assertEqual(env.fake.activations, 0)
        self.assertFalse(env.mgr.journal_path.exists())
        env.save(changes={'cache-min-ttl': 61}, apply=False)  # manager is usable again

    def test_activation_failure_restores_files_and_reloads_previous_config(self):
        env = Env(self)
        before = env.srv.read_text()
        calls = []
        real = env.fake.activate
        def activate():
            calls.append(env.srv.read_text())
            if len(calls) == 1:
                raise RuntimeError('reload failed')
            real()
        env.mgr.activate = activate
        with self.assertRaisesRegex(RuntimeError, 'reload failed'):
            env.save(changes={'cache-min-ttl': 60})
        self.assertEqual(env.srv.read_text(), before)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[1], before)
        self.assertEqual(env.fake.loaded['scalars']['cache-min-ttl'], '300')
        self.assertFalse(env.mgr.journal_path.exists())

    def test_reload_that_does_not_apply_the_option_is_rolled_back(self):
        env = Env(self)
        before = env.srv.read_text()
        env.fake.ignore_reload = True
        env.mgr.verifier = lambda ctx: env.verify(ctx) if ctx['phase'] == 'apply' else None
        env.mgr._mismatch = env.mgr._mismatch  # real comparison against the (stale) running config
        with self.assertRaisesRegex(RuntimeError, 'cache-min-ttl'):
            env.save(changes={'cache-min-ttl': 60})
        self.assertEqual(env.srv.read_text(), before)

    def test_dns_verification_failure_rolls_back_and_reverifies_previous_policy(self):
        env = Env(self)
        before = env.srv.read_text()
        phases = []
        def verifier(ctx):
            phases.append(ctx['phase'])
            if ctx['phase'] == 'apply':
                raise RuntimeError('DNS does not answer')
        env.mgr.verifier = verifier
        with self.assertRaisesRegex(RuntimeError, 'DNS does not answer'):
            env.save(changes={'cache-min-ttl': 60})
        self.assertEqual(phases, ['apply', 'rollback'])
        self.assertEqual(env.srv.read_text(), before)
        self.assertFalse(env.mgr.journal_path.exists())

    def test_rollback_failure_keeps_journal_blocks_writes_and_recovery_restores(self):
        env = Env(self)
        before = env.srv.read_text()
        def verifier(ctx):
            raise RuntimeError('DNS does not answer')
        env.mgr.verifier = verifier
        with self.assertRaisesRegex(RuntimeError, 'rollback failed'):
            env.save(changes={'cache-min-ttl': 60})
        self.assertTrue(env.mgr.journal_path.exists())
        with self.assertRaisesRegex(ValueError, 'Interrupted'):
            env.mgr.save('x', changes={'cache-min-ttl': 1}, apply=False)
        # The failed attempt restored files before re-verification; simulate a crash window instead.
        env.srv.write_text(before.replace('cache-min-ttl: 300', 'cache-min-ttl: 60'))
        activations = env.fake.activations
        dry = sc.recover(env.base, env.main)
        self.assertEqual(dry['actions'][0]['action'], 'restore previous')
        self.assertIn('cache-min-ttl: 60', env.srv.read_text())
        done = sc.recover(env.base, env.main, apply=True)
        self.assertTrue(done['applied'])
        self.assertEqual(env.srv.read_text(), before)
        self.assertFalse(env.mgr.journal_path.exists())
        self.assertEqual(env.fake.activations, activations, 'recovery must not reload DNS')

    def test_crash_before_journal_clear_is_visible_to_a_new_manager(self):
        env = Env(self)
        env.mgr.verifier = lambda ctx: (_ for _ in ()).throw(RuntimeError('boom')) if ctx['phase'] == 'apply' else (_ for _ in ()).throw(RuntimeError('rollback boom'))
        with self.assertRaises(RuntimeError):
            env.save(changes={'cache-min-ttl': 60})
        fresh = sc.ConfigManager(env.base, env.main, option_reader=env.fake.option, running_reader=env.fake.running,
                                 checker=env.check, activate=env.fake.activate)
        with self.assertRaisesRegex(ValueError, 'Interrupted'):
            fresh.save('r', changes={}, apply=False)
        self.assertTrue(fresh.snapshot()['recovery_required'])

    def test_managed_fragments_and_other_bytes_are_never_modified(self):
        env = Env(self)
        before = {p: p.read_bytes() for p in env.root.rglob('*') if p.is_file()}
        env.save(changes={'cache-min-ttl': 60}, apply=True)
        after = {p: p.read_bytes() for p in env.root.rglob('*') if p.is_file()}
        self.assertEqual({p for p in before if before[p] != after[p]}, {env.srv})

    def test_hard_linked_staging_never_modifies_large_generated_file(self):
        env = Env(self)
        big = env.root / 'unbound.conf.d/webui-filters.conf'
        big.write_text(FILTERS + '# pad\n' * 250000)
        digest = big.read_bytes()
        env.save(changes={'cache-min-ttl': 60}, apply=True)
        self.assertEqual(big.read_bytes(), digest)
        self.assertGreater(big.stat().st_size, sc.MAX_FILE)
        self.assertEqual(os.stat(big).st_nlink, 1, 'staging links removed after validation')

    def test_file_mode_is_preserved(self):
        env = Env(self)
        env.srv.chmod(0o640)
        env.save(changes={'cache-min-ttl': 60}, apply=False)
        self.assertEqual(env.srv.stat().st_mode & 0o777, 0o640)


class RawFileTests(unittest.TestCase):
    def test_raw_edit_is_validated_acknowledged_and_checked_against_invariants(self):
        env = Env(self)
        rel = 'unbound.conf.d/unbound.conf'
        content = env.srv.read_text().replace('port: 53', 'port: 5353')
        with self.assertRaisesRegex(sc.ConfigError, 'Acknowledge'):
            env.mgr.save_file(env.revision(), rel, content, apply=True)
        # Port moved: reload happens and the verifier is told the new port.
        seen = []
        env.mgr.verifier = lambda ctx: (seen.append(ctx['port']), env.verify(ctx))[1]
        env.mgr.save_file(env.revision(), rel, content, apply=True, acknowledge=True)
        self.assertEqual(seen, [5353])
        with self.assertRaisesRegex(sc.ConfigError, 'allow 127.0.0.1'):
            env.mgr.save_file(env.revision(), rel, content.replace('access-control: 127.0.0.1/32 allow', ''), apply=False)

    def test_raw_edit_rejects_non_editable_paths(self):
        env = Env(self)
        for rel in ('unbound.conf.d/webui-filters.conf', '../x.conf', 'unbound.conf.d/unbound.conf.bak-old', '/etc/passwd'):
            with self.subTest(rel=rel), self.assertRaises(sc.ConfigError):
                env.mgr.save_file(env.revision(), rel, 'server:\n', apply=False)
            with self.subTest(read=rel), self.assertRaises(sc.ConfigError):
                env.mgr.read_file(rel)
        self.assertEqual(env.mgr.read_file('unbound.conf.d/dashboard.conf')['content'], DASHBOARD)

    def test_raw_edit_rejects_crlf_and_oversize(self):
        env = Env(self)
        for content in ('server:\r\n', 'x' * (sc.MAX_FILE + 1), 'a\0b'):
            with self.subTest(content=content[:10]), self.assertRaises(sc.ConfigError):
                env.mgr.save_file(env.revision(), 'unbound.conf.d/dashboard.conf', content, apply=False)


class ConstructionTests(unittest.TestCase):
    def test_data_directory_must_be_outside_config_root_and_not_symlinked(self):
        env = Env(self)
        with self.assertRaises(ValueError):
            sc.ConfigManager(env.root / 'data', env.main)
        link = Path(env.dir.name) / 'link'
        os.symlink(env.base, link)
        with self.assertRaises(ValueError):
            sc.ConfigManager(link, env.main)

    def test_schema_is_consistent(self):
        keys = [f['key'] for s in sc.SECTIONS for f in s['fields']]
        self.assertEqual(len(keys), len(set(keys)))
        self.assertTrue(set(sc.INVARIANT_KEYS) <= set(keys))
        for section in sc.SECTIONS:
            for key in section['lists']:
                self.assertIn(key, sc.LISTS)
            for field in section['fields']:
                self.assertIn(field['kind'], {'bool', 'int', 'size', 'str', 'path', 'enum', 'policy', 'modules'})
                if field['kind'] in {'int', 'size'}:
                    self.assertLessEqual(field['min'], field['max'])
        json.dumps(sc.SECTIONS)  # API-serialisable

    def test_roundtrip_every_schema_field_through_its_own_validator(self):
        samples = {'bool': True, 'int': None, 'size': '16m', 'str': 'abc', 'path': '/tmp/x', 'enum': '1',
                   'policy': '3 2 1', 'modules': 'validator iterator'}
        for field in (f for s in sc.SECTIONS for f in s['fields']):
            value = samples[field['kind']]
            if field['kind'] == 'int':
                value = field['min']
            if field.get('lock_on'):
                continue
            with self.subTest(key=field['key']):
                wire = sc.wire_value(field, value)
                line = sc.parse_lines(Path('x'), f'server:\n  {field["key"]}: {sc.render_directive(field, wire)}\n')[1]
                self.assertEqual(line.value, wire)
                self.assertEqual(sc.comparable(field, line.value), sc.comparable(field, wire))


@unittest.skipUnless(shutil.which('unbound-checkconf'), 'requires the Unbound tools on the deployment host')
class RealToolTests(unittest.TestCase):
    """Run the shipped option reader and full-tree validator on a temporary tree."""

    def env(self):
        env = Env(self)
        # A temporary tree must not need production-only files.
        env.srv.write_text(env.srv.read_text().replace('hide-identity: yes   # keep the box anonymous', 'hide-identity: yes'))
        (env.root / 'unbound.conf.d/dashboard.conf').write_text('server:\n  extended-statistics: yes\n  verbosity: 0\n')
        env.mgr.option_reader = sc.checkconf_option
        env.mgr.checker = env.mgr._check
        # "Running" = the real option reader over a snapshot of the tree taken at the last reload.
        loaded = Path(env.dir.name) / 'loaded'
        state = {}

        def activate():
            shutil.rmtree(loaded, ignore_errors=True)
            state['main'] = env.mgr._build_tree(loaded, {}, 'empty')
        activate()
        env.mgr.activate = activate
        env.mgr.running_reader = lambda config, key: sc.checkconf_option(state['main'], key)
        return env

    def test_checkconf_reads_match_the_parser_and_edits_land_as_requested(self):
        env = self.env()
        with env.mgr._light() as light:
            self.assertEqual(sc.checkconf_option(light, 'rrset-cache-size'), ['268435456'])
            self.assertEqual(sorted(sc.checkconf_option(light, 'interface')), ['0.0.0.0', '::0'])
        result = env.save(changes={'cache-min-ttl': 60, 'rrset-cache-size': '512m', 'prefetch': True,
                                   'target-fetch-policy': '4 3 2 1 1'},
                          lists={'private-address': ['10.0.0.0/8', '172.16.0.0/12']}, apply=True)
        self.assertEqual(result['state']['pending'], [])
        with env.mgr._light() as light:
            self.assertEqual(sc.checkconf_option(light, 'rrset-cache-size'), ['536870912'])
            self.assertEqual(sc.checkconf_option(light, 'prefetch'), ['yes'])
            self.assertEqual(sorted(sc.checkconf_option(light, 'private-address')), ['10.0.0.0/8', '172.16.0.0/12'])

    def test_real_validator_rejects_unknown_option_before_touching_files(self):
        env = self.env()
        before = env.srv.read_text()
        with self.assertRaises(sc.ConfigError):
            env.mgr.save_file(env.revision(), 'unbound.conf.d/unbound.conf', before + 'definitely-not-an-option: 1\n', apply=False)
        self.assertEqual(env.srv.read_text(), before)

    def test_every_schema_key_is_known_to_the_installed_unbound(self):
        env = self.env()
        with env.mgr._light() as light:
            for key in sc.SCHEMA_KEYS + sc.LIST_KEYS:
                with self.subTest(key=key):
                    sc.checkconf_option(light, key)


class LauncherTests(unittest.TestCase):
    def test_launcher_installs_server_config_once_before_the_tls_listener(self):
        import ast
        tree = ast.parse(Path(__file__).with_name('run.py').read_text())
        imports = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == 'server_config']
        self.assertTrue(imports, 'launcher does not import the server-config installer')
        alias = next(a.asname or a.name for a in imports[0].names if a.name == 'install')
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == alias]
        self.assertEqual(len(calls), 1)
        listener = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                        and n.func.attr == 'run' and getattr(n.func.value, 'id', '') == 'uvicorn')
        self.assertLess(calls[0].lineno, listener.lineno)


class RouteTests(unittest.TestCase):
    def test_real_fastapi_routes_auth_csrf_strict_payload_conflict_and_threadpool(self):
        try:
            from fastapi import FastAPI, HTTPException, Request
        except ImportError:
            self.skipTest('requires the deployment venv')
        import inspect
        import warnings
        from types import SimpleNamespace
        with warnings.catch_warnings():
            warnings.filterwarnings('ignore', message='Using `httpx` with `starlette.testclient` is deprecated.*')
            from fastapi.testclient import TestClient

        def login(request: Request):
            if request.headers.get('x-test-user') != 'yes':
                raise HTTPException(401, 'Login required')

        def csrf(request: Request):
            if request.headers.get('x-csrf-token') != 'test-token':
                raise HTTPException(403, 'CSRF required')
        upstream = SimpleNamespace(app=FastAPI(), _login_required=login, _verify_csrf=csrf,
                                   _template=lambda request, template, context: {'template': template, **context})
        upstream.app.get('/config')(lambda: {'upstream': 'form'})
        env = Env(self)
        sc.install(upstream, env.mgr)
        headers = {'x-test-user': 'yes', 'x-csrf-token': 'test-token'}
        with TestClient(upstream.app) as client:
            for path in ('/config', '/api/server-config', '/api/server-config/file?path=unbound.conf'):
                self.assertEqual(client.get(path).status_code, 401)
            self.assertEqual(client.post('/api/server-config', json={'revision': 'x'}).status_code, 401)
            self.assertEqual(client.post('/api/server-config', headers={'x-test-user': 'yes'}, json={'revision': 'x'}).status_code, 403)
            self.assertEqual(client.get('/config', headers=headers).json(), {'template': 'server_config.html', 'active_tab': 'config'})
            state = client.get('/api/server-config', headers=headers).json()
            self.assertTrue(state['success'])
            revision = state['state']['revision']
            saved = client.post('/api/server-config', headers=headers, json={'revision': revision, 'changes': {'cache-min-ttl': 60}, 'apply': False})
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()['changed'], ['cache-min-ttl'])
            self.assertEqual(saved.json()['state']['pending'], ['cache-min-ttl'])
            self.assertEqual(client.post('/api/server-config', headers=headers, json={'revision': revision, 'changes': {'cache-min-ttl': 5}}).status_code, 409)
            current = saved.json()['state']['revision']
            for bad in ({'changes': {'port': '53'}}, {'changes': {'nope': 1}}, {'apply': 'yes'}, {'extra': 1},
                        {'changes': {'port': 5353}}):
                response = client.post('/api/server-config', headers=headers, json={'revision': current, **bad})
                self.assertEqual(response.status_code, 422, bad)
            raw = client.get('/api/server-config/file?path=unbound.conf.d/dashboard.conf', headers=headers).json()
            self.assertEqual(raw['state']['content'], DASHBOARD)
            self.assertEqual(client.get('/api/server-config/file?path=unbound.conf.d/webui-filters.conf', headers=headers).status_code, 422)
            applied = client.post('/api/server-config/apply-pending', headers=headers, json={'revision': current})
            self.assertEqual(applied.status_code, 200, applied.text)
            self.assertEqual(applied.json()['state']['pending'], [])
        routes = {(getattr(r, 'path', ''), tuple(sorted(getattr(r, 'methods', ())))): r for r in upstream.app.routes}
        self.assertNotIn(('/config', ('GET',)), [(p, m) for (p, m) in routes if p == '/config' and False])
        self.assertEqual(sum(1 for r in upstream.app.routes if getattr(r, 'path', '') == '/config'), 1)
        for route in upstream.app.routes:
            if getattr(route, 'path', '').startswith('/api/server-config'):
                self.assertFalse(inspect.iscoroutinefunction(route.endpoint))


if __name__ == '__main__':
    unittest.main()
