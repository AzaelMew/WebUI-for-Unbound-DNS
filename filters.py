"""Opt-in Unbound domain filtering. No import/install-time DNS changes."""
import ipaddress
import re
import http.client
import json
import socket
import ssl
import subprocess
import sys
import time
import os
import copy
import shutil
import stat
import tarfile
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from safety import _LOCK
from urllib.parse import urlsplit, urljoin


def validate_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(ord(c) <= 32 for c in url) or '\\' in url:
        raise ValueError('Invalid subscription URL')
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.username is not None or parts.password is not None or not parts.hostname or parts.port not in (None, 443) or parts.fragment:
        raise ValueError('Use a public HTTPS URL on port 443 without credentials or fragment')
    host = normalize_domain(parts.hostname)
    if host != parts.hostname.lower():
        raise ValueError('URL host must use ASCII/IDNA form')
    return host


def _resolve_public(host):
    # Run libc resolution in a bounded subprocess, not an indefinitely stuck thread.
    script = 'import socket,json,sys; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))'
    try:
        result = subprocess.run([sys.executable, '-c', script, host], capture_output=True, text=True, timeout=5, check=True)
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise ValueError('Subscription hostname resolution failed') from exc


def _https_get(url, host, address, timeout):
    deadline = time.monotonic() + timeout
    parts = urlsplit(url)
    connection = http.client.HTTPSConnection(host, timeout=min(10, timeout), context=ssl.create_default_context())
    sock = None
    try:
        sock = socket.create_connection((address, 443), timeout=min(10, timeout))
        connection.sock = connection._context.wrap_socket(sock, server_hostname=host)
        sock = connection.sock
        connection.request('GET', (parts.path or '/') + ('?' + parts.query if parts.query else ''), headers={
            'Host': host, 'User-Agent': 'Unbound-WebUI-DomainFilters/1', 'Accept': 'text/plain, application/octet-stream', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        headers = dict((k.lower(), v) for k, v in response.getheaders())
        if int(headers.get('content-length', '0')) > MAX_BYTES:
            raise ValueError('Download exceeds 20 MiB')
        if response.status in {301, 302, 303, 307, 308}:
            return response.status, headers, b''
        body = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError('Download timeout')
            sock.settimeout(min(5, remaining))
            chunk = response.read1(min(65536, MAX_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
            if len(body) > MAX_BYTES:
                raise ValueError('Download exceeds 20 MiB')
        return response.status, headers, bytes(body)
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError('HTTPS download failed: ' + str(exc)) from exc
    finally:
        connection.close()
        if sock:
            sock.close()


def download_list(url, resolver=None, transport=None):
    resolver, transport = resolver or _resolve_public, transport or _https_get
    deadline, seen = time.monotonic() + 40, set()
    for _hop in range(6):
        host = validate_url(url)
        if url in seen:
            raise ValueError('Redirect loop')
        seen.add(url)
        addresses = resolver(host)
        if not addresses:
            raise ValueError('Subscription hostname has no addresses')
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if not ip.is_global or ip.is_multicast or ip.is_unspecified or ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped is not None):
                raise ValueError('Subscription target must have only public global addresses')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Download timeout')
        # Connect to the validated numeric address; never resolve again in transport.
        status, headers, body = transport(url, host, addresses[0], remaining)
        if status in {301, 302, 303, 307, 308}:
            if not headers.get('location'):
                raise ValueError('Redirect without Location')
            url = urljoin(url, headers['location'])
            continue
        if status != 200:
            raise ValueError(f'Subscription returned HTTP {status}')
        kind = headers.get('content-type', '').split(';')[0].strip().lower()
        if kind not in {'', 'text/plain', 'application/octet-stream', 'text/x-hosts'} or headers.get('content-encoding', 'identity').lower() not in {'', 'identity'}:
            raise ValueError('Unexpected content type/encoding; use a raw text list URL')
        if len(body) > MAX_BYTES:
            raise ValueError('Download exceeds 20 MiB')
        return body
    raise ValueError('Too many redirects')

MAX_BYTES = 20 * 1024 * 1024
MAX_DOMAINS = 300_000
HEADER = '# Managed by Unbound WebUI domain filters; do not edit.\nserver:\n'


def parse_list(body, max_domains=MAX_DOMAINS):
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        raise ValueError('List exceeds 20 MiB')
    try:
        text = body.decode('utf-8-sig')
    except UnicodeError as exc:
        raise ValueError('List is not UTF-8 text') from exc
    if any(ord(c) < 32 and c not in '\n\r\t' for c in text) or re.search(r'<(?:html|!doctype|body|script)\b', text, re.I):
        raise ValueError('Unexpected binary or HTML list content')
    domains, unsupported, samples = set(), 0, []
    ignored = {'localhost', 'localhost.localdomain', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters'}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(('#', '!', '[')):
            continue
        try:
            if re.fullmatch(r'\|\|[^\^]+\^', line):
                values = [line[2:-1]]
            else:
                # Do not strip cosmetic ## rules into plausible domains.
                if '##' in line or '#@#' in line:
                    raise ValueError('Cosmetic syntax')
                values = line.split('#', 1)[0].split()
                if len(values) > 1:
                    address = ipaddress.ip_address(values[0])
                    if str(address) not in {'0.0.0.0', '127.0.0.1', '::', '::1'}:
                        raise ValueError('Non-blocking hosts address')
                    values = values[1:]
                normalized = []
                for value in values:
                    if value.lower() not in ignored:
                        normalized.append(normalize_domain(value))
                values = normalized
            domains.update(normalize_domain(value) for value in values)
        except ValueError:
            unsupported += 1
            if len(samples) < 5:
                samples.append(f'Line {lineno}: {line[:160]}')
        if len(domains) > max_domains:
            raise ValueError('Domain count limit exceeded')
    if not domains:
        raise ValueError('No supported domains found; existing cache was not replaced')
    return {'domains': sorted(domains), 'unsupported': unsupported, 'samples': samples}


def _covered(domain, suffixes):
    labels = domain.split('.')
    return any('.'.join(labels[i:]) in suffixes for i in range(len(labels) - 1))


def render_config(blocked, allowed, max_domains=MAX_DOMAINS):
    blocked = {normalize_domain(d) for d in blocked}
    allowed = {normalize_domain(d) for d in allowed}
    if len(blocked | allowed) > max_domains:
        raise ValueError('Total cached domain limit exceeded (300,000)')
    effective = sorted(d for d in blocked if not _covered(d, allowed))
    rules = [f'    local-zone: "{d}." always_nxdomain\n' for d in effective]
    rules += [f'    local-zone: "{d}." transparent\n' for d in sorted(allowed)]
    return HEADER + ''.join(rules), len(effective)


def normalize_domain(value):
    if not isinstance(value, str):
        raise ValueError('Domain must be text')
    domain = value.strip().rstrip('.').lower()
    try:
        domain = domain.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ValueError('Invalid IDNA domain') from exc
    if len(domain) > 253 or '.' not in domain or not all(
            re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
            for label in domain.split('.')):
        raise ValueError('Use a valid fully qualified domain, not a URL or wildcard')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('IP addresses are not domains')


def _atomic(path, body, mode=0o600):
    if path.is_symlink():
        raise ValueError('Refusing symlink')
    info = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix='.filters-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode) if info else mode)
            if info:
                os.fchown(handle.fileno(), info.st_uid, info.st_gid)
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class FilterManager:
    def __init__(self, base, main, target, activate=None, downloader=None):
        self.base, self.main, self.target = Path(base), Path(main), Path(target)
        self.root = self.main.resolve().parent
        if self.target.name != 'webui-filters.conf' or not self.target.parent.resolve().is_relative_to(self.root):
            raise ValueError('Managed filter file must be webui-filters.conf inside Unbound config directory')
        self.data = self.base / 'filter-data'
        self.backups = self.base / 'filter-backups'
        self.state_path = self.data / 'state.json'
        self.activate = activate or self._activate
        self.downloader = downloader or download_list
        for directory in (self.data, self.backups):
            if directory.is_symlink():
                raise ValueError('Refusing symlink directory')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.state = json.loads(self.state_path.read_text()) if self.state_path.exists() else {
            'version': 1, 'blocked': [], 'allowed': [], 'lists': []}
        self._compile(self.state)

    def _activate(self):
        result = subprocess.run(['systemctl', 'reload-or-restart', 'unbound'], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Unbound activation failed: ' + (result.stderr or result.stdout)[:600])

    def _check(self, path):
        result = subprocess.run(['unbound-checkconf', str(path)], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise ValueError('Unbound config validation failed: ' + (result.stderr or result.stdout)[:1000])

    def _compile(self, state):
        # Include disabled cached domains in the aggregate bound, not just active rules.
        all_domains = set(state['blocked']) | set(state['allowed'])
        active = set(state['blocked'])
        for item in state['lists']:
            all_domains.update(item['domains'])
            if item['enabled']:
                active.update(item['domains'])
        if len(all_domains) > MAX_DOMAINS or len(state['lists']) > 25:
            raise ValueError('Limit: 300,000 cached domains total and 25 subscriptions')
        return render_config(active, state['allowed'])

    def snapshot(self):
        with _LOCK:
            result = copy.deepcopy(self.state)
            _, result['effective_count'] = self._compile(self.state)
            result['managed_file'] = str(self.target)
            result['initialized'] = self.target.is_file() and not self.target.is_symlink()
            for item in result['lists']:
                item['count'] = len(item.pop('domains'))
            return result

    def _transaction(self, state, activate=True, create=False):
        with _LOCK:
            if self.target.is_symlink() or (not create and not self.target.is_file()):
                raise ValueError('Managed config missing or symlink; administrator must initialize it')
            if self.target.exists() and not self.target.read_text().startswith(HEADER):
                raise ValueError('Managed filter header missing; refusing to overwrite an unrelated config')
            content, _ = self._compile(state)
            original = self.target.read_bytes() if self.target.exists() else None
            old_state = self.state_path.read_bytes() if self.state_path.exists() else None
            with tempfile.TemporaryDirectory(prefix='.filter-validate-', dir=self.base) as tmp:
                stage = Path(tmp) / 'unbound'
                shutil.copytree(self.root, stage, symlinks=False)
                staged = stage / self.target.relative_to(self.root)
                staged.write_text(content)
                for conf in stage.rglob('*.conf'):
                    conf.write_text(re.sub(r'(?m)^(\s*include(?:-toplevel)?:\s*)(.*)$',
                        lambda m: m.group(1) + m.group(2).replace(str(self.root) + '/', str(stage) + '/'), conf.read_text()))
                self._check(stage / self.main.relative_to(self.root))
                self._check(staged)
            backup = self.backups / ('filters_' + str(time.time_ns()) + '.tgz')
            with tarfile.open(backup, 'x:gz') as archive:
                archive.add(self.root, arcname='unbound')
                if self.state_path.exists():
                    archive.add(self.state_path, arcname='filter-state.json')
            backup.chmod(0o600)
            attempted = False
            try:
                _atomic(self.target, content.encode(), mode=0o644)
                self._check(self.main)
                if activate:
                    attempted = True
                    self.activate()
                _atomic(self.state_path, (json.dumps(state, ensure_ascii=True) + '\n').encode())
            except Exception as error:
                if original is None:
                    self.target.unlink(missing_ok=True)
                else:
                    _atomic(self.target, original)
                if old_state is None:
                    self.state_path.unlink(missing_ok=True)
                else:
                    _atomic(self.state_path, old_state)
                if attempted:
                    try:
                        self.activate()
                    except Exception as rollback:
                        raise RuntimeError(f'Activation failed and rollback activation failed: {rollback}; restore from {backup.name}') from error
                raise
            finally:
                for stale in sorted(self.backups.glob('filters_*.tgz'), key=lambda p: p.stat().st_mtime_ns)[:-10]:
                    stale.unlink()
            self.state = copy.deepcopy(state)
            return self.snapshot()

    def initialize_empty(self):
        """Parent calls once, explicitly: creates/checks only, never reloads DNS."""
        with _LOCK:
            if self.target.exists():
                if self.target.is_symlink() or self.target.read_text() != HEADER:
                    raise ValueError('Refusing to initialize over an existing nonempty config')
                return self.snapshot()
            if self.state['blocked'] or self.state['allowed'] or self.state['lists']:
                raise ValueError('Nonempty state exists; recover instead of resetting filters')
            return self._transaction(self.state, activate=False, create=True)

    def set_domains(self, kind, domains):
        if kind not in {'blocked', 'allowed'} or not isinstance(domains, list):
            raise ValueError('Expected blocked/allowed and a domain array')
        values = sorted({normalize_domain(d) for d in domains})
        with _LOCK:
            state = copy.deepcopy(self.state)
            state[kind] = values
            # Allowlist wins permanently over overlapping manual entries.
            state['blocked'] = [d for d in state['blocked'] if not _covered(d, set(state['allowed']))]
            return self._transaction(state)

    def _save_metadata(self, state):
        self._compile(state)
        _atomic(self.state_path, (json.dumps(state, ensure_ascii=True) + '\n').encode())
        self.state = copy.deepcopy(state)
        return self.snapshot()

    def _find(self, state, identifier):
        for item in state['lists']:
            if item['id'] == identifier:
                return item
        raise ValueError('Subscription not found')

    def add_list(self, name, url):
        validate_url(url)
        if not isinstance(name, str) or not name.strip() or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise ValueError('Use a subscription name between 1 and 100 characters')
        with _LOCK:
            state = copy.deepcopy(self.state)
            if any(item['url'] == url for item in state['lists']):
                raise ValueError('This subscription URL already exists')
            state['lists'].append({'id': uuid.uuid4().hex, 'name': name.strip(), 'url': url,
                'enabled': False, 'domains': [], 'last_updated': None, 'last_error': None,
                'last_attempt': None, 'unsupported': 0, 'samples': []})
            return self._save_metadata(state)

    def enable_list(self, identifier, enabled):
        if not isinstance(enabled, bool):
            raise ValueError('enabled must be a boolean')
        with _LOCK:
            state = copy.deepcopy(self.state)
            item = self._find(state, identifier)
            if enabled and not item['domains']:
                raise ValueError('Refresh successfully before enabling a subscription')
            item['enabled'] = enabled
            return self._transaction(state)

    def delete_list(self, identifier):
        with _LOCK:
            state = copy.deepcopy(self.state)
            self._find(state, identifier)
            state['lists'] = [item for item in state['lists'] if item['id'] != identifier]
            return self._transaction(state)

    def refresh_list(self, identifier):
        with _LOCK:
            url = self._find(self.state, identifier)['url']
        attempted = datetime.now(timezone.utc).isoformat()
        try:
            parsed = parse_list(self.downloader(url))
            with _LOCK:
                state = copy.deepcopy(self.state)
                item = self._find(state, identifier)
                if item['url'] != url:
                    raise ValueError('Subscription changed during refresh')
                item.update(parsed)
                item.update(last_updated=datetime.now(timezone.utc).isoformat(), last_attempt=attempted, last_error=None)
                self._compile(state)
                return self._transaction(state) if item['enabled'] else self._save_metadata(state)
        except Exception as exc:
            with _LOCK:
                state = copy.deepcopy(self.state)
                try:
                    item = self._find(state, identifier)
                except ValueError:
                    raise exc
                item.update(last_attempt=attempted, last_error=str(exc)[:1000])
                self._save_metadata(state)
            raise



from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, StrictBool


class DomainsPayload(BaseModel):
    kind: str = Field(max_length=10)
    domains: list[str] = Field(max_length=MAX_DOMAINS)


class SubscriptionPayload(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(min_length=1, max_length=2048)


class EnabledPayload(BaseModel):
    enabled: StrictBool


def install(upstream, manager=None):
    """Mount authenticated sync/threadpool routes; no DNS creation/reload here."""
    manager = manager or FilterManager(upstream.BASE_DIR, upstream.DEFAULT_CONFIG_FILE,
        Path(upstream.DEFAULT_CONFIG_DIR) / 'webui-filters.conf')
    upstream.filter_manager = manager
    read = [Depends(upstream._login_required)]
    write = read + [Depends(upstream._verify_csrf)]

    def respond(fn, *args):
        try:
            return {'success': True, 'state': fn(*args)}
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(500, str(exc)[:1000]) from exc

    @upstream.app.get('/filters', dependencies=read)
    def filters_page(request: Request):
        return upstream._template(request, 'filters.html', {'active_tab': 'filters'})

    @upstream.app.get('/api/filters', dependencies=read)
    def filters_status():
        return respond(manager.snapshot)

    @upstream.app.post('/api/filters/domains', dependencies=write)
    def domains(payload: DomainsPayload):
        return respond(manager.set_domains, payload.kind, payload.domains)

    @upstream.app.post('/api/filters/lists', dependencies=write)
    def subscription(payload: SubscriptionPayload):
        return respond(manager.add_list, payload.name, payload.url)

    @upstream.app.post('/api/filters/lists/{identifier}/enabled', dependencies=write)
    def enabled(identifier: str, payload: EnabledPayload):
        return respond(manager.enable_list, identifier, payload.enabled)

    @upstream.app.post('/api/filters/lists/{identifier}/delete', dependencies=write)
    def delete(identifier: str):
        return respond(manager.delete_list, identifier)

    @upstream.app.post('/api/filters/lists/{identifier}/refresh', dependencies=write)
    def refresh(identifier: str):
        return respond(manager.refresh_list, identifier)

    return manager
