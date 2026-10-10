"""Dedicated small A/AAAA rewrite policy; never imported through production app."""
import ipaddress
import copy
import json
import logging
import os
import stat
import gzip
import glob
import fnmatch
import hashlib
import io
import re
import shutil
import shlex
import subprocess
import tarfile
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, ValidationError
from fastapi import Depends, HTTPException, Request
from filters import normalize_domain, _atomic, _atomic_copy, _durable_unlink, _check_config_tree, _file_digest
from safety import _LOCK
import filter_resources
import filter_activation

MAX_RECORDS = 1000
MAX_ADDRESSES = 16
HEADER = '# Managed by Unbound WebUI DNS rewrites; do not edit.\nserver:\n'
PROBE_NAME = 'rewrite-policy-check._webui.invalid'
MAX_FRAGMENT = 6 * 1024 * 1024  # 1000 longest DNS names, 16 IPv6 RDATA each.


class RecordPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    hostname: str
    addresses: list[str]
    enabled: StrictBool
    ttl: StrictInt = 300


def normalize_records(records):
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError(f'Records must be an array of at most {MAX_RECORDS} records')
    output, names = [], set()
    for raw in records:
        try:
            item = RecordPayload.model_validate(raw).model_dump()
        except ValidationError as exc:
            raise ValueError(str(exc)) from exc
        if any(ord(char) < 32 for char in item['hostname']):
            raise ValueError('Hostname contains control characters')
        item['hostname'] = normalize_domain(item['hostname'])
        if item['hostname'] in names:
            raise ValueError('Duplicate hostname: ' + item['hostname'])
        names.add(item['hostname'])
        if not 1 <= item['ttl'] <= 86400:
            raise ValueError('TTL must be an integer from 1 to 86400')
        if not 1 <= len(item['addresses']) <= MAX_ADDRESSES:
            raise ValueError(f'Each record requires 1..{MAX_ADDRESSES} addresses')
        addresses = []
        for address in item['addresses']:
            if '%' in address:
                raise ValueError('Scoped IPv6 addresses cannot be DNS RDATA')
            canonical = str(ipaddress.ip_address(address))
            if canonical in addresses:
                raise ValueError('Duplicate IP address for ' + item['hostname'])
            addresses.append(canonical)
        item['addresses'] = sorted(addresses, key=lambda addr: (ipaddress.ip_address(addr).version, int(ipaddress.ip_address(addr))))
        output.append(item)
    return sorted(output, key=lambda item: item['hostname'])


class RevisionConflict(ValueError):
    """The complete form was based on an obsolete state revision."""


def _regular(path, maximum=None):
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Refusing symlink or special file: ' + str(path))
    if path.exists() and maximum is not None and path.stat().st_size > maximum:
        raise ValueError('Managed file exceeds size limit: ' + str(path))


def _validate_state(state):
    if (not isinstance(state, dict) or set(state) != {'version', 'revision', 'records', 'last_updated'} or
            type(state['version']) is not int or state['version'] != 1 or
            type(state['revision']) is not int or state['revision'] < 0 or
            not (state['last_updated'] is None or isinstance(state['last_updated'], str))):
        raise ValueError('Malformed rewrite state; preserve files and recover explicitly')
    if normalize_records(state['records']) != state['records']:
        raise ValueError('Rewrite state records are not canonical')
    return state


class RewriteManager:
    def __init__(self, base, main, target, activate=None, verifier=None, *, _offline=False):
        self.base, self.main, self.target = map(lambda p: Path(p).absolute(), (base, main, target))
        self.root = self.main.parent
        for path in (self.base, self.main, self.target, self.target.parent):
            if '..' in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
                raise ValueError('Refusing symlink path: ' + str(path))
        if (self.target.name != 'webui-rewrites.conf' or
                not self.target.parent.is_relative_to(self.root) or self.base.is_relative_to(self.root)):
            raise ValueError('Managed rewrite file must be webui-rewrites.conf inside config root; data outside it')
        _regular(self.main)
        self.data, self.backups = self.base / 'rewrite-data', self.base / 'rewrite-backups'
        self.state_path, self.journal_path = self.data / 'state.json', self.data / 'transaction.json'
        for directory in (self.data, self.backups):
            if directory.is_symlink():
                raise ValueError('Refusing symlink rewrite directory')
            if _offline:
                if not directory.is_dir():
                    raise ValueError('Offline recovery requires existing rewrite data/backups directories')
            else:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                directory.chmod(0o700)
        self.activate = activate or self._activate
        # Tests injecting activation never silently query a production resolver.
        # An explicitly injected verifier accepts (token, enabled_records).
        self.verifier = verifier if verifier is not None else (self._verify_dns if activate is None else None)
        self._recovery_required = False
        with _LOCK:
            self._paths()
            if not _offline:
                self._ready()
                self.state = self._load_state()
                self._consistent()
            else:
                self._managed_bytes()

    def _paths(self):
        for path in (self.base, self.main, self.target, self.data, self.backups, self.state_path, self.journal_path):
            if any(parent.is_symlink() for parent in (path, *path.parents)):
                raise ValueError('Refusing symlink rewrite path: ' + str(path))

    def _ready(self):
        self._paths()
        if self._recovery_required or self.journal_path.exists() or self.journal_path.is_symlink():
            raise ValueError('Interrupted rewrite transaction; preserve files and recover explicitly')

    def _load_state(self):
        _regular(self.state_path, 2 * 1024 * 1024)
        if not self.state_path.exists():
            return {'version': 1, 'revision': 0, 'records': [], 'last_updated': None}
        try:
            return _validate_state(json.loads(self.state_path.read_text()))
        except (ValueError, UnicodeError) as exc:
            raise ValueError('Malformed rewrite state; preserve files and recover explicitly: ' + str(exc)) from exc

    def snapshot(self):
        with _LOCK:
            result = copy.deepcopy(self.state)
            result.update(initialized=self.target.is_file() and not self.target.is_symlink(),
                          managed_file=str(self.target), limits={'max_records': MAX_RECORDS, 'max_addresses': MAX_ADDRESSES})
            return result

    def _restore_state(self, previous):
        if previous is None:
            _durable_unlink(self.state_path)
        else:
            _atomic(self.state_path, previous, mode=0o600)
        self.state = self._load_state()

    def _clear_journal(self):
        _durable_unlink(self.journal_path)

    def _retain_journal(self, journal):
        self._recovery_required = True
        if not self.journal_path.exists():
            try:
                _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
            except OSError:
                pass  # In-memory guard persists; never pretend recovery succeeded.
        self.state = self._load_state()

    def _metadata(self, state):
        previous = self.state_path.read_bytes() if self.state_path.exists() else None
        journal = {'version': 1, 'kind': 'metadata', 'previous_state_text': previous.decode() if previous else None,
                   'config_root': str(self.root), 'managed_file': str(self.target.relative_to(self.root))}
        try:
            _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
            _atomic(self.state_path, (json.dumps(state) + '\n').encode())
            self._clear_journal()
        except Exception as error:
            try:
                self._restore_state(previous)
                self._clear_journal()
            except Exception as rollback:
                self._retain_journal(journal)
                raise RuntimeError('Rewrite metadata rollback failed; recover explicitly: ' + str(rollback)) from error
            raise
        self.state = state
        return self.snapshot()

    def save_records(self, records, revision):
        normalized = normalize_records(records)
        with _LOCK:
            self._ready()
            self.state = self._load_state()  # Shared lock also protects multiple manager instances.
            self._consistent()
            if type(revision) is not int or revision != self.state['revision']:
                raise RevisionConflict('Stale rewrite revision; reload the form before applying')
            if normalized == self.state['records']:
                return self.snapshot()
            state = {'version': 1, 'revision': revision + 1, 'records': normalized,
                     'last_updated': datetime.now(timezone.utc).isoformat()}
            if self._enabled(normalized) != self._enabled(self.state['records']):
                return self._transaction(state)
            return self._metadata(state)

    @staticmethod
    def _enabled(records):
        return [item for item in records if item['enabled']]

    def _managed_bytes(self):
        _regular(self.target, MAX_FRAGMENT)
        if not self.target.exists():
            return None
        body = self.target.read_bytes()
        if not body.startswith(HEADER.encode()):
            raise ValueError('Managed rewrite header missing; refusing unrelated config')
        return body

    def _consistent(self):
        self._validate_policy(self.state, self._managed_bytes())

    @classmethod
    def _validate_policy(cls, state, body):
        """Certify records and exact rendered bytes/canary as one recovery set."""
        _validate_state(state)
        if body is None:
            if cls._enabled(state['records']):
                raise ValueError('Rewrite state enabled records do not match missing managed policy; recover explicitly')
            return
        plain = cls._render(state['records'])
        token = hashlib.sha256(plain).hexdigest()
        stamped = (filter_activation.TOKEN_PREFIX + token + '\n' +
                   f'    local-zone: "{PROBE_NAME}." static\n' +
                   f'    local-data: \'{PROBE_NAME}. IN TXT "{token}"\'\n').encode('ascii')
        if body not in (plain, plain + stamped):
            raise ValueError('Rewrite state is missing or does not match managed policy; recover explicitly')

    @staticmethod
    def _render(records):
        lines = [HEADER]
        for item in records:
            if not item['enabled']:
                continue
            name = item['hostname']
            lines.append(f'    local-zone: "{name}." transparent\n')
            for address in item['addresses']:
                kind = 'A' if ipaddress.ip_address(address).version == 4 else 'AAAA'
                lines.append(f'    local-data: "{name}. {item["ttl"]} IN {kind} {address}"\n')
        body = ''.join(lines).encode('ascii')
        if len(body) > MAX_FRAGMENT:
            raise ValueError('Rewrite fragment exceeds bounded size')
        return body

    @staticmethod
    def _activate():
        result = subprocess.run(['systemctl', 'reload-or-restart', 'unbound'], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Unbound activation failed: ' + (result.stderr or result.stdout)[:600])
        if subprocess.run(['systemctl', 'is-active', '--quiet', 'unbound'], timeout=10).returncode:
            raise RuntimeError('Unbound is not active after activation')

    def _check(self, path):
        # Account for the OTHER managed policy, not just this small fragment.
        policy_bytes = sum(conf.stat().st_size for conf in Path(path).parent.rglob('*') if conf.is_file())
        budget = filter_resources.validation_budget(policy_bytes,
            available=filter_resources.available_memory(), service_available=filter_resources.process_headroom(),
            maximum=int(os.environ.get('WEBUI_FILTER_CHECKCONF_MAX_BYTES', filter_resources.DEFAULT_CHECKCONF_MAX_BYTES)))
        executable = shutil.which('unbound-checkconf')
        if executable is None:
            raise ValueError('unbound-checkconf is not installed')
        result = subprocess.run(filter_resources.validator_command(executable, path, budget),
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise ValueError('Unbound config validation failed: ' + (result.stderr or result.stdout)[:1000])

    def _stage(self, stage, body):
        _check_config_tree(self.root)
        configs = self._config_files()
        tree_bytes = sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())
        filter_resources.check_disk_headroom(self.base, tree_bytes + 3 * MAX_FRAGMENT + 16 * 1024 * 1024)
        filter_resources.check_disk_headroom(self.root, MAX_FRAGMENT * 2)
        shutil.copytree(self.root, stage, ignore=lambda directory, names:
                        [self.target.name] if Path(directory) == self.target.parent else [])
        for original in configs:
            conf = stage / original.relative_to(self.root)
            if original == self.target:
                continue
            # Filters are generated data, have no includes; retain giant bytes as-is.
            if conf.name == 'webui-filters.conf':
                continue
            temporary = conf.with_name(conf.name + '.relocate')
            with conf.open('rb') as source, temporary.open('wb') as output:
                for line in source:
                    output.write(re.sub(rb'^(\s*include(?:-toplevel)?:\s*)(.*)$',
                        lambda match: match.group(1) + match.group(2).replace(
                            (str(self.root) + '/').encode(), (str(stage) + '/').encode()), line))
            os.replace(temporary, conf)
        staged = stage / self.target.relative_to(self.root)
        _atomic(staged, body, mode=0o644)
        return staged

    def _config_files(self):
        """Resolve the actual include graph; never validate an external/live include."""
        visited, queue = set(), [self.main]
        target_included = False
        while queue:
            config = queue.pop()
            if config in visited:
                continue
            visited.add(config)
            if config == self.target:
                continue
            with config.open() as source:
                for line in source:
                    match = re.match(r'^\s*include(?:-toplevel)?:\s*(.*)', line)
                    if not match:
                        continue
                    if config.name == 'webui-filters.conf':
                        raise ValueError('Refusing include directive inside generated filter fragment')
                    fields = shlex.split(match[1], comments=True)
                    if len(fields) != 1:
                        raise ValueError('Cannot safely inspect include in config root: ' + str(config))
                    pattern = Path(fields[0])
                    if not pattern.is_absolute() or '..' in pattern.parts or not pattern.is_relative_to(self.root):
                        raise ValueError('Refusing include outside config root (use absolute confined includes): ' + str(pattern))
                    if (len(self.target.parts) == len(pattern.parts) and
                            all(fnmatch.fnmatchcase(part, glob_part) for part, glob_part in zip(self.target.parts, pattern.parts))):
                        target_included = True
                        queue.append(self.target)
                    for filename in glob.glob(str(pattern)):
                        file = Path(filename)
                        _regular(file)
                        queue.append(file)
        if not target_included:
            raise ValueError('Managed rewrite fragment is not included by the main config; administrator must add a confined include')
        return visited

    def _backup(self):
        _check_config_tree(self.root)
        manifest = {'version': 1, 'config_root': str(self.root), 'managed_file': str(self.target.relative_to(self.root)),
                    'state_present': self.state_path.exists(), 'files': {}, 'omitted': {}}
        descriptor, name = tempfile.mkstemp(prefix='.backup-', suffix='.tgz', dir=self.backups)
        os.close(descriptor)
        temporary = Path(name)
        try:
            with tarfile.open(temporary, 'w:gz', dereference=True) as archive:
                for path in sorted(self.root.rglob('*')):
                    if not path.is_file():
                        continue
                    relative = 'unbound/' + str(path.relative_to(self.root))
                    metadata = {'sha256': _file_digest(path), 'size': path.stat().st_size}
                    if path.name == 'webui-filters.conf':
                        manifest['omitted'][relative] = metadata
                    else:
                        manifest['files'][relative] = metadata
                        archive.add(path, arcname=relative, recursive=False)
                if self.state_path.exists():
                    manifest['files']['rewrite-state.json'] = {'sha256': _file_digest(self.state_path), 'size': self.state_path.stat().st_size}
                    archive.add(self.state_path, arcname='rewrite-state.json')
                body = json.dumps(manifest).encode()
                info = tarfile.TarInfo('rewrite-manifest.json')
                info.size, info.mode = len(body), 0o600
                archive.addfile(info, io.BytesIO(body))
            temporary.chmod(0o600)
            with temporary.open('rb') as stream:
                os.fsync(stream.fileno())
            self._verify_backup(temporary)
            backup = self.backups / ('rewrites_' + str(time.time_ns()) + '_' + uuid.uuid4().hex + '.tgz')
            os.replace(temporary, backup)
            fd = os.open(self.backups, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return backup
        finally:
            temporary.unlink(missing_ok=True)

    def _verify_backup(self, path):
        _regular(path)
        try:
            with gzip.open(path, 'rb') as source:
                for chunk in iter(lambda: source.read(65536), b''):
                    pass  # Read through gzip CRC, not merely tar end markers.
            with tarfile.open(path, 'r:gz') as archive:
                members = {}
                for member in archive:
                    name = PurePosixPath(member.name)
                    if (name.is_absolute() or '..' in name.parts or '\\' in member.name or
                            member.name in members or not member.isfile() or
                            not (member.name in {'rewrite-state.json', 'rewrite-manifest.json'} or member.name.startswith('unbound/'))):
                        raise ValueError('Unsafe backup archive member')
                    members[member.name] = member
                manifest_member = members.get('rewrite-manifest.json')
                if manifest_member is None or manifest_member.size > 2 * 1024 * 1024:
                    raise ValueError('Missing or oversized rewrite backup manifest')
                manifest = json.load(archive.extractfile(manifest_member))
                if (manifest.get('version') != 1 or manifest.get('config_root') != str(self.root) or
                        manifest.get('managed_file') != str(self.target.relative_to(self.root)) or
                        set(members) != set(manifest['files']) | {'rewrite-manifest.json'}):
                    raise ValueError('Rewrite backup manifest mismatch')
                for name, metadata in manifest['files'].items():
                    member = members[name]
                    if member.size != metadata['size']:
                        raise ValueError('Rewrite backup member size mismatch')
                    digest = hashlib.sha256()
                    with archive.extractfile(member) as source:
                        for chunk in iter(lambda: source.read(65536), b''):
                            digest.update(chunk)
                    if digest.hexdigest() != metadata['sha256']:
                        raise ValueError('Rewrite backup member hash mismatch')
                saved_state = {'version': 1, 'revision': 0, 'records': [], 'last_updated': None}
                if 'rewrite-state.json' in members:
                    if members['rewrite-state.json'].size > 2 * 1024 * 1024:
                        raise ValueError('Oversized rewrite backup state')
                    state_stream = archive.extractfile('rewrite-state.json')
                    if state_stream is None:
                        raise ValueError('Rewrite backup state missing')
                    with state_stream:
                        saved_state = _validate_state(json.load(state_stream))
                own = 'unbound/' + str(self.target.relative_to(self.root))
                fragment = None
                if own in members:
                    if members[own].size > MAX_FRAGMENT:
                        raise ValueError('Oversized rewrite backup fragment')
                    with archive.extractfile(own) as source:
                        fragment = source.read()
                        if not fragment.startswith(HEADER.encode()):
                            raise ValueError('Rewrite backup managed header missing')
                if manifest['state_present'] != ('rewrite-state.json' in members):
                    raise ValueError('Rewrite backup state presence mismatch')
                self._validate_policy(saved_state, fragment)
                return manifest
        except (OSError, EOFError, tarfile.TarError, ValueError, KeyError, TypeError) as exc:
            raise ValueError('Invalid completed rewrite backup: ' + str(exc)) from exc

    def _transaction(self, state, create=False):
        self._ready()
        previous = self._managed_bytes()
        if previous is None and not create:
            raise ValueError('Managed rewrite file missing; administrator must initialize it explicitly')
        old_state = self.state_path.read_bytes() if self.state_path.exists() else None
        self._conflicts(state['records'])
        with tempfile.TemporaryDirectory(prefix='.rewrite-validate-', dir=self.base) as directory:
            stage = Path(directory) / 'unbound'
            staged = self._stage(stage, self._render(state['records']))
            token = (filter_activation.stamp_policy(staged, probe_name=PROBE_NAME)[0]
                     if not create and self.verifier is not None else None)
            old_token = filter_activation.read_profile(self.target)[0] if previous is not None and self.verifier is not None else None
            self._check(stage / self.main.relative_to(self.root))
            backup = self._backup()
            journal = {'version': 1, 'kind': 'policy', 'backup': backup.name,
                       'config_root': str(self.root), 'managed_file': str(self.target.relative_to(self.root)),
                       'previous_state_text': old_state.decode() if old_state else None,
                       'previous_fragment_text': previous.decode('ascii') if previous is not None else None}
            _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
            attempted = False
            try:
                _atomic_copy(staged, self.target, mode=0o644)
                self._check(self.main)
                if not create:
                    attempted = True
                    self.activate()
                    if self.verifier is not None:
                        self.verifier(token, self._enabled(state['records']))
                _atomic(self.state_path, (json.dumps(state) + '\n').encode())
                self._clear_journal()
            except Exception as error:
                try:
                    if previous is None:
                        _durable_unlink(self.target)
                    else:
                        _atomic(self.target, previous, mode=0o644)
                    self._restore_state(old_state)
                    self._check(self.main)
                    if attempted:
                        self.activate()
                        if self.verifier is not None:
                            self.verifier(old_token, self._enabled(self.state['records']))
                    self._clear_journal()
                except Exception as rollback:
                    self._retain_journal(journal)
                    raise RuntimeError('Rewrite rollback failed; recover explicitly: ' + str(rollback)) from error
                raise
        self.state = copy.deepcopy(state)
        try:
            for stale in sorted(self.backups.glob('rewrites_*.tgz'))[:-10]:
                _regular(stale)
                _durable_unlink(stale)
        except OSError:
            logging.warning('Rewrite backup retention deferred; committed policy is intact')
        return self.snapshot()

    def initialize_empty(self):
        """Explicit deployment operation: validate/create empty policy; NEVER reload."""
        with _LOCK:
            self._ready()
            if self.target.exists() or self.target.is_symlink():
                if self._managed_bytes() != HEADER.encode():
                    raise ValueError('Refusing to reinitialize nonempty rewrite policy')
                self._check(self.main)
                return self.snapshot()
            if self._enabled(self.state['records']):
                raise ValueError('Cannot initialize empty fragment with enabled records in state')
            return self._transaction(self.state, create=True)

    def _conflicts(self, records):
        names = {item['hostname'] for item in records if item['enabled']}
        if not names:
            return
        _check_config_tree(self.root)
        for conf in self._config_files():
            if conf == self.target:
                continue
            with conf.open() as source:
                for line in source:
                    match = re.match(r'^\s*(local-zone|local-data):\s*(.*)', line)
                    if not match:
                        continue
                    try:
                        fields = shlex.split(match[2], comments=True)
                        name = fields[0].split()[0].lower().rstrip('.')
                    except (ValueError, IndexError) as exc:
                        raise ValueError('Cannot safely inspect existing local policy: ' + str(conf)) from exc
                    if name in names:
                        if (conf.name == 'webui-filters.conf' and match[1] == 'local-zone' and
                                len(fields) == 2 and fields[1] == 'transparent'):
                            # Identical transparent zones are accepted by Unbound;
                            # this is the filter allowlist's explicit safe exception.
                            continue
                        raise ValueError(f'Rewrite conflict for {name} in {conf}: allowlist the exact filter zone '
                                         'or migrate the existing local-zone/local-data override explicitly')

    @staticmethod
    def _verify_dns(token, records):
        host = os.environ.get('WEBUI_FILTER_VERIFY_HOST', '127.0.0.1')
        port = int(os.environ.get('WEBUI_FILTER_VERIFY_PORT', '53'))
        timeout = float(os.environ.get('WEBUI_FILTER_VERIFY_TIMEOUT', '10'))
        # verify_policy enforces numeric endpoint, valid port and finite <=60s.
        started = time.monotonic()
        filter_activation.verify_policy(token, host=host, port=port, timeout=timeout, probe_name=PROBE_NAME)
        # One representative of each address-family combination, <=3 names.
        representatives = {}
        for item in records:
            families = tuple(sorted({ipaddress.ip_address(addr).version for addr in item['addresses']}))
            representatives.setdefault(families, item)
        deadline = started + timeout
        reason = 'No representative DNS response'
        while representatives and time.monotonic() < deadline:
            try:
                for item in representatives.values():
                    for kind, version in ((1, 4), (28, 6)):
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise ValueError('Representative DNS verification timed out')
                        rcode, answers = filter_activation.query(host, port, item['hostname'], kind, min(.5, remaining))
                        expected = {addr for addr in item['addresses'] if ipaddress.ip_address(addr).version == version}
                        if rcode != 0 or set(answers) != expected:
                            raise ValueError('DNS does not serve expected rewrite for ' + item['hostname'])
                return
            except (OSError, ValueError) as exc:
                reason = str(exc)
            time.sleep(min(.05, max(0, deadline - time.monotonic())))
        if representatives:
            raise RuntimeError('Unbound rewrite verification failed: ' + reason)


class RecordsPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    revision: StrictInt
    records: list[RecordPayload]


def install(upstream, manager=None):
    """Authenticated threadpool routes. No automatic creation or DNS activation."""
    manager = manager or RewriteManager(upstream.BASE_DIR, upstream.DEFAULT_CONFIG_FILE,
                                       Path(upstream.DEFAULT_CONFIG_DIR) / 'webui-rewrites.conf')
    upstream.rewrite_manager = manager
    read = [Depends(upstream._login_required)]
    write = read + [Depends(upstream._verify_csrf)]

    def respond(fn, *args):
        try:
            return {'success': True, 'state': fn(*args)}
        except RevisionConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(500, str(exc)[:1000]) from exc

    @upstream.app.get('/rewrites', dependencies=read)
    def rewrites_page(request: Request):
        return upstream._template(request, 'rewrites.html', {'active_tab': 'rewrites'})

    @upstream.app.get('/api/rewrites', dependencies=read)
    def rewrites_status():
        return respond(manager.snapshot)

    @upstream.app.post('/api/rewrites', dependencies=write)
    def rewrites_save(payload: RecordsPayload):
        return respond(manager.save_records, [item.model_dump() for item in payload.records], payload.revision)

    return manager
