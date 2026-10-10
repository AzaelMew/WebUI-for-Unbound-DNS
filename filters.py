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
import hashlib
import io
import logging
import gzip
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from safety import _LOCK
from urllib.parse import urlsplit, urljoin
from filter_store import DomainStore, check_deadline
import filter_resources
import filter_activation


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


def _resolve_public(host, timeout=5):
    # Run libc resolution in a bounded subprocess, not an indefinitely stuck thread.
    script = 'import socket,json,sys; print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],443,type=socket.SOCK_STREAM)})))'
    try:
        result = subprocess.run([sys.executable, '-c', script, host], capture_output=True, text=True, timeout=timeout, check=True)
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise ValueError('Subscription hostname resolution failed') from exc


class DownloadLimitError(ValueError):
    def __init__(self, maximum, observed_bytes):
        super().__init__(f'Download exceeds {maximum:,} bytes (observed {observed_bytes:,} bytes)')
        self.observed_bytes = observed_bytes


def _https_get(url, host, address, timeout, destination, max_bytes):
    deadline = time.monotonic() + timeout
    parts = urlsplit(url)
    connection = http.client.HTTPSConnection(host, timeout=min(10, timeout), context=ssl.create_default_context())
    sock = None
    try:
        sock = socket.create_connection((address, 443), timeout=min(10, timeout))
        sock.settimeout(max(.01, min(10, deadline - time.monotonic())))
        connection.sock = connection._context.wrap_socket(sock, server_hostname=host)
        sock = connection.sock
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Download timeout')
        sock.settimeout(min(5, remaining))
        connection.request('GET', (parts.path or '/') + ('?' + parts.query if parts.query else ''), headers={
            'Host': host, 'User-Agent': 'Unbound-WebUI-DomainFilters/1', 'Accept': 'text/plain, application/octet-stream', 'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = connection.getresponse()
        headers = dict((k.lower(), v) for k, v in response.getheaders())
        if response.status != 200:
            return response.status, headers, 0
        _response_headers(headers, max_bytes)
        size = 0
        with Path(destination).open('wb') as output:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('Download timeout')
                sock.settimeout(min(5, remaining))
                chunk = response.read1(min(65536, max_bytes + 1 - size))
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise DownloadLimitError(max_bytes, size)
                output.write(chunk)
        if 'content-length' in headers and size != int(headers['content-length']):
            raise ValueError('Incomplete HTTPS download')
        return response.status, headers, size
    except (OSError, http.client.HTTPException) as exc:
        raise ValueError('HTTPS download failed: ' + str(exc)) from exc
    finally:
        connection.close()
        if sock:
            sock.close()


def _response_headers(headers, max_bytes):
    try:
        length = int(headers.get('content-length', '0'))
    except ValueError as exc:
        raise ValueError('Invalid download Content-Length') from exc
    if length < 0:
        raise ValueError('Invalid download Content-Length')
    if length > max_bytes:
        raise DownloadLimitError(max_bytes, length)
    kind = headers.get('content-type', '').split(';')[0].strip().lower()
    if kind not in {'', 'text/plain', 'application/octet-stream', 'text/x-hosts', 'text/dns', 'application/x-dns'} or headers.get('content-encoding', 'identity').lower() not in {'', 'identity'}:
        raise ValueError('Unexpected content type/encoding; use a raw text list URL')


def download_file(url, destination, max_bytes=None, timeout=120, resolver=None, transport=None):
    """Download to a bounded temporary file, revalidating every redirect hop.

    The optional four-argument transport preserves the byte-returning test API;
    real HTTPS reads at most 64 KiB at a time and connects only to a pinned IP.
    """
    max_bytes = MAX_BYTES if max_bytes is None else max_bytes
    deadline, seen = time.monotonic() + timeout, set()
    for _hop in range(6):
        host = validate_url(url)
        if url in seen:
            raise ValueError('Redirect loop')
        seen.add(url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ValueError('Download timeout')
        addresses = resolver(host) if resolver else _resolve_public(host, min(5, remaining))
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
        if transport:
            status, headers, body = transport(url, host, addresses[0], remaining)
        else:
            status, headers, body = _https_get(url, host, addresses[0], remaining, destination, max_bytes)
        if time.monotonic() > deadline:
            raise ValueError('Download timeout')
        headers = {key.lower(): value for key, value in headers.items()}
        if status in {301, 302, 303, 307, 308}:
            if not headers.get('location'):
                raise ValueError('Redirect without Location')
            url = urljoin(url, headers['location'])
            continue
        if status != 200:
            raise ValueError(f'Subscription returned HTTP {status}')
        _response_headers(headers, max_bytes)
        if transport:
            if not isinstance(body, bytes):
                raise ValueError('Download body must be bytes')
            if len(body) > max_bytes:
                raise DownloadLimitError(max_bytes, len(body))
            Path(destination).write_bytes(body)
            return len(body)
        return body
    raise ValueError('Too many redirects')


def download_list(url, resolver=None, transport=None):
    """Compatibility byte API; manager production refresh uses download_file."""
    with tempfile.TemporaryDirectory(prefix='filter-download-') as tmp:
        path = Path(tmp) / 'list'
        download_file(url, path, resolver=resolver, transport=transport)
        return path.read_bytes()

MAX_BYTES = 96 * 1024 * 1024
MAX_DOMAINS = 3_000_000
HEADER = '# Managed by Unbound WebUI domain filters; do not edit.\nserver:\n'


def parse_list(body, max_domains=MAX_DOMAINS):
    if not isinstance(body, bytes) or len(body) > MAX_BYTES:
        raise ValueError(f'List exceeds {MAX_BYTES:,} bytes')
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
            raise ValueError(f'Domain count limit exceeded ({max_domains:,})')
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
        raise ValueError(f'Total cached domain limit exceeded ({max_domains:,})')
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
            os.fchmod(handle.fileno(), stat.S_IMODE(info.st_mode) if info else mode)
            if info:
                os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            os.fsync(handle.fileno())
        os.replace(name, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _durable_unlink(path):
    path = Path(path)
    path.unlink(missing_ok=True)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _atomic_copy(source, target, mode=0o644, expected_digest=None, compressed=False, deadline=None, max_bytes=None):
    """Same atomic replacement guarantees without reading a giant fragment."""
    if target.is_symlink():
        raise ValueError('Refusing symlink')
    info = target.stat() if target.exists() else None
    fd, name = tempfile.mkstemp(prefix='.filters-', dir=target.parent)
    try:
        with os.fdopen(fd, 'wb') as output, (gzip.open(source, 'rb') if compressed else Path(source).open('rb')) as input_file:
            digest = hashlib.sha256()
            size = 0
            if expected_digest is not None:
                header = input_file.read(len(HEADER))
                if header != HEADER.encode():
                    raise ValueError('Backup managed filter header missing')
                output.write(header)
                digest.update(header)
                size = len(header)
            for chunk in iter(lambda: input_file.read(65536), b''):
                check_deadline(deadline)
                size += len(chunk)
                if max_bytes is not None and size > max_bytes:
                    raise ValueError('Backup policy exceeds validated fragment size bound')
                output.write(chunk)
                digest.update(chunk)
            if expected_digest is not None and digest.hexdigest() != expected_digest:
                raise ValueError('Backup blob content hash mismatch')
            output.flush()
            os.fchmod(output.fileno(), stat.S_IMODE(info.st_mode) if info else mode)
            if info:
                os.fchown(output.fileno(), info.st_uid, info.st_gid)
            os.fsync(output.fileno())
        os.replace(name, target)
        directory_fd = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _restore_blob(source, target, deadline=None, max_bytes=None):
    source = Path(source)
    match = re.fullmatch(r'([0-9a-f]{64})\.conf(\.gz)?', source.name)
    if not match or source.is_symlink() or source.parent.is_symlink() or not source.is_file():
        raise ValueError('Backup blob missing, symlink or invalid hash name')
    try:
        _atomic_copy(source, target, expected_digest=match[1], compressed=bool(match[2]), deadline=deadline, max_bytes=max_bytes)
    except (OSError, EOFError) as exc:
        raise ValueError('Corrupt backup blob: ' + str(exc)) from exc


def _compress_blob(source, blob, deadline=None):
    fd, name = tempfile.mkstemp(prefix='.blob-', dir=blob.parent)
    try:
        with os.fdopen(fd, 'wb') as output, Path(source).open('rb') as input_file:
            with gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as compressed:
                for chunk in iter(lambda: input_file.read(65536), b''):
                    check_deadline(deadline)
                    compressed.write(chunk)
            output.flush()
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
        # No replacement: existing content-addressed blobs are immutable.
        os.link(name, blob)
        fd = os.open(blob.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        Path(name).unlink(missing_ok=True)


def _verify_blob(blob, maximum, deadline=None):
    """Certify an existing deduplicated rollback artifact before live writes."""
    digest = hashlib.sha256()
    size = 0
    try:
        with gzip.GzipFile(filename=str(blob), mode='rb') as source:
            header = source.read(len(HEADER))
            if header != HEADER.encode():
                raise ValueError('Rollback blob managed header missing')
            size = len(header)
            digest.update(header)
            for chunk in iter(lambda: source.read(65536), b''):
                check_deadline(deadline)
                size += len(chunk)
                if size > maximum:
                    raise ValueError('Rollback blob exceeds original policy size')
                digest.update(chunk)
        if size != maximum or digest.hexdigest() != Path(blob).name.split('.', 1)[0]:
            raise ValueError('Rollback blob content hash/size mismatch')
    except (OSError, EOFError) as exc:
        raise ValueError('Corrupt rollback blob: ' + str(exc)) from exc


def _check_config_tree(root, deadline=None):
    """Reject entries that cannot be represented by offline recovery."""
    for directory, names, files in os.walk(root, followlinks=False):
        check_deadline(deadline)
        for name in names + files:
            check_deadline(deadline)
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError('Refusing symlink or special config file: ' + str(path))


def _file_digest(path, deadline=None):
    digest = hashlib.sha256()
    with Path(path).open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            check_deadline(deadline)
            digest.update(chunk)
    return digest.hexdigest()


def _text_lines(path, deadline=None):
    with Path(path).open('rb') as source:
        lineno = 0
        while True:
            check_deadline(deadline)
            raw = source.readline(65537)
            if not raw:
                return
            lineno += 1
            if len(raw) > 65536:
                raise ValueError('List line exceeds 64 KiB')
            try:
                line = raw.decode('utf-8-sig' if lineno == 1 else 'utf-8')
            except UnicodeError as exc:
                raise ValueError('List is not UTF-8 text') from exc
            if any(ord(c) < 32 and c not in '\n\r\t' for c in line) or re.search(r'<(?:html|!doctype|body|script)\b', line, re.I):
                raise ValueError('Unexpected binary or HTML list content')
            yield lineno, line


def _parse_source(path, format, statistics, deadline=None):
    if format == 'auto':
        for _, raw in _text_lines(path, deadline):
            line = raw.split(';', 1)[0].strip()
            if line.startswith('$') or (not line.startswith(('#', '!')) and re.search(r'\s(?:IN\s+)?(?:SOA|NS|CNAME)\s', line, re.I)):
                format = 'rpz'
                break
    if format == 'rpz':
        yield from _parse_rpz(path, deadline)
        return
    supported = 0
    ignored = {'localhost', 'localhost.localdomain', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters'}
    for lineno, raw in _text_lines(path, deadline):
        line = raw.strip()
        if not line or line.startswith(('#', '!', '[')):
            continue
        try:
            if re.fullmatch(r'\|\|[^\^]+\^', line) and format in {'auto', 'adblock'}:
                values = [normalize_domain(line[2:-1])]
            else:
                if '##' in line or '#@#' in line or format == 'adblock':
                    raise ValueError('Unsupported Adblock syntax')
                values = line.split('#', 1)[0].split()
                if len(values) > 1:
                    if format == 'domains':
                        raise ValueError('Not a domain line')
                    address = ipaddress.ip_address(values[0])
                    if str(address) not in {'0.0.0.0', '127.0.0.1', '::', '::1'}:
                        raise ValueError('Non-blocking hosts address')
                    values = values[1:]
                elif format == 'hosts':
                    raise ValueError('Not a hosts line')
                values = [normalize_domain(value) for value in values if value.lower() not in ignored]
        except ValueError:
            statistics['unsupported'] += 1
            if len(statistics['samples']) < 5:
                statistics['samples'].append(f'Line {lineno}: {line[:160]}')
            continue
        for domain in values:
            supported += 1
            yield domain
    if not supported:
        raise ValueError('No supported domains found; existing cache was not replaced')


def _parse_rpz(path, deadline=None):
    """A deliberately narrow masterfile reader: QNAME -> NXDOMAIN only.

    Wildcards collapse to the apex because local-zone blocks already cover
    children. Every other RPZ action or trigger fails the entire generation.
    Remote directives never reach the generated Unbound configuration.
    """
    origin, pending, depth, supported = None, '', 0, 0
    previous_owner = None
    # Unit separators make the compound form linear-time on malicious tokens.
    ttl = re.compile(r'(?:[0-9]+|(?:[0-9]+[wdhmsWDHMS])+)\Z')
    def dns_name(name):
        if name == '.':
            return ''
        value = name.lower().rstrip('.')
        if not value or len(value) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
            raise ValueError('Invalid RPZ metadata name')
        return value
    for lineno, raw in _text_lines(path, deadline):
        line = raw.split(';', 1)[0].strip()
        if not line:
            continue
        if any(c in line for c in '\\"'):
            raise ValueError(f'Unsupported RPZ quoting/escape at line {lineno}')
        if line.startswith('$'):
            if pending:
                raise ValueError('Directive inside RPZ record')
            fields = line.split()
            directive = fields[0].upper()
            if len(fields) != 2:
                raise ValueError('Malformed RPZ directive')
            if directive == '$ORIGIN':
                if not fields[1].endswith('.'):
                    raise ValueError('RPZ origin must be absolute')
                origin = dns_name(fields[1])
            elif directive == '$TTL' and ttl.fullmatch(fields[1]):
                pass
            else:
                raise ValueError('Unsupported RPZ directive: ' + directive)
            continue
        # Masterfiles omit the owner only at a NEW indented record, never
        # inside an already pending parenthesized SOA continuation.
        if not pending and raw[:1].isspace():
            if previous_owner is None:
                raise ValueError('Omitted RPZ owner without a previous owner')
            line = previous_owner + ' ' + line
        pending = (pending + ' ' + line).strip()
        if len(pending) > 4096:
            raise ValueError('RPZ record exceeds 4096 characters')
        for char in line:
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            if depth < 0 or depth > 1:
                raise ValueError('Malformed RPZ parentheses')
        if depth:
            continue
        fields = pending.replace('(', ' ').replace(')', ' ').split()
        parenthesized = '(' in pending or ')' in pending
        pending = ''
        if len(fields) < 3:
            raise ValueError(f'Malformed RPZ record at line {lineno}')
        owner = fields.pop(0).lower()
        previous_owner = owner
        seen_ttl, seen_class = False, False
        while fields:
            if fields[0].upper() == 'IN' and not seen_class:
                fields.pop(0)
                seen_class = True
            elif ttl.fullmatch(fields[0]) and not seen_ttl:
                fields.pop(0)
                seen_ttl = True
            else:
                break
        if not fields:
            raise ValueError('Missing RPZ record type')
        kind, values = fields[0].upper(), fields[1:]
        apex = owner == '@' or (origin is not None and owner == origin + '.')
        if kind == 'SOA':
            if not apex or len(values) != 7 or not values[2].isdigit() or not all(ttl.fullmatch(v) for v in values[3:]):
                raise ValueError('Malformed RPZ SOA metadata')
            dns_name(values[0])
            dns_name(values[1])
            continue
        if kind == 'NS':
            if parenthesized or not apex or len(values) != 1:
                raise ValueError('Malformed RPZ NS metadata')
            dns_name(values[0])
            continue
        if parenthesized or kind != 'CNAME' or values != ['.'] or apex:
            raise ValueError('Unsupported RPZ action; only QNAME CNAME . is accepted')
        if owner.endswith('.'):
            owner = owner[:-1]
            if origin:
                if not owner.endswith('.' + origin):
                    raise ValueError('RPZ policy owner outside origin')
                owner = owner[:-(len(origin) + 1)]
        if any(label.startswith('rpz-') for label in owner.split('.')):
            raise ValueError('Unsupported non-QNAME RPZ trigger')
        if owner.startswith('*.'):
            owner = owner[2:]
        supported += 1
        yield normalize_domain(owner)
    if pending or depth:
        raise ValueError('Unterminated RPZ record')
    if not supported:
        raise ValueError('No supported RPZ QNAME NXDOMAIN policies found')


class FilterManager:
    def __init__(self, base, main, target, activate=None, downloader=None,
                 max_bytes=None, max_entries=None, max_subscriptions=None,
                 max_sources=None, download_timeout=None, refresh_timeout=None,
                 max_total_bytes=None, verifier=None):
        self.base, self.main, self.target = Path(base), Path(main), Path(target)
        self.root = self.main.resolve().parent
        if self.target.name != 'webui-filters.conf' or not self.target.parent.resolve().is_relative_to(self.root):
            raise ValueError('Managed filter file must be webui-filters.conf inside Unbound config directory')
        self.data = self.base / 'filter-data'
        self.backups = self.base / 'filter-backups'
        self.state_path = self.data / 'state.json'
        self.journal_path = self.data / 'transaction.json'
        self.activate = activate or self._activate
        self.verifier = verifier if verifier is not None else (filter_activation.verify_policy if activate is None else None)
        self.downloader = downloader
        defaults = {'max_bytes': MAX_BYTES, 'max_total_bytes': 192 * 1024 * 1024, 'max_entries': MAX_DOMAINS,
                    'max_subscriptions': 25, 'max_sources': 8}
        supplied = {'max_bytes': max_bytes, 'max_total_bytes': max_total_bytes, 'max_entries': max_entries,
                    'max_subscriptions': max_subscriptions, 'max_sources': max_sources}
        self.limits = {}
        for key, default in defaults.items():
            value = supplied[key] if supplied[key] is not None else os.environ.get('WEBUI_FILTER_' + key.upper(), default)
            if isinstance(value, bool) or not isinstance(value, (int, str)):
                raise ValueError('Filter limits must be integers: ' + key)
            try:
                value = int(value)
            except (ValueError, TypeError) as exc:
                raise ValueError('Invalid filter limit: ' + key) from exc
            if value < 1:
                raise ValueError('Filter limits must be positive: ' + key)
            self.limits[key] = value
        self.download_timeout = self._timeout(download_timeout, 'DOWNLOAD_TIMEOUT', 120)
        self.refresh_timeout = self._timeout(refresh_timeout, 'REFRESH_TIMEOUT', 600)
        self.refresh_interval_seconds = 0
        raw_checkconf_limit = os.environ.get('WEBUI_FILTER_CHECKCONF_MAX_BYTES', filter_resources.DEFAULT_CHECKCONF_MAX_BYTES)
        if isinstance(raw_checkconf_limit, bool) or not isinstance(raw_checkconf_limit, (int, str)):
            raise ValueError('Invalid validator memory limit')
        try:
            self.checkconf_max_bytes = int(raw_checkconf_limit)
        except ValueError as exc:
            raise ValueError('Invalid validator memory limit') from exc
        if self.checkconf_max_bytes <= 0:
            raise ValueError('Validator memory limit must be positive')
        self._refreshing = set()
        for directory in (self.data, self.backups):
            if directory.is_symlink():
                raise ValueError('Refusing symlink directory')
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_path.is_symlink():
            raise ValueError('Refusing symlink state')
        self._ready()
        self.store = DomainStore(self.data)
        self.state = self._load_state()

    def _ready(self):
        if getattr(self, '_recovery_required', False) or self.journal_path.exists() or self.journal_path.is_symlink():
            raise ValueError('Interrupted filter transaction; recover using filter-data/transaction.json and its backup before further changes')

    def _sync_memory(self):
        """On uncertain durability, reflect the visible state and block writes."""
        if hasattr(self, 'state'):
            self.state = (json.loads(self.state_path.read_text()) if self.state_path.exists() else
                          {'version': 2, 'blocked': [], 'allowed': [], 'lists': [], 'effective_count': 0})

    def _discard_candidate(self, reference):
        # Any journal protects ALL candidates: even its publication/fsync may
        # have failed. Never unlink a generation during uncertain recovery.
        if getattr(self, '_recovery_required', False) or self.journal_path.exists() or self.journal_path.is_symlink():
            return
        persisted = json.loads(self.state_path.read_text()) if self.state_path.exists() else {}
        if any(item.get('cache') == reference for item in persisted.get('lists', [])):
            return
        self.store.path(reference).unlink(missing_ok=True)

    def _restore_state(self, raw):
        if raw is None:
            _durable_unlink(self.state_path)
        else:
            _atomic(self.state_path, raw)
        self._sync_memory()

    def _publish_metadata(self, state):
        previous = self.state_path.read_bytes() if self.state_path.exists() else None
        journal = {'kind': 'metadata',
                   'previous_state': json.loads(previous) if previous is not None else None,
                   'previous_state_text': previous.decode('utf-8') if previous is not None else None,
                   'candidate_caches': [item['cache'] for item in state['lists'] if item.get('cache')]}
        try:
            _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
            _atomic(self.state_path, (json.dumps(state, ensure_ascii=True) + '\n').encode())
            self._clear_journal()
        except Exception as error:
            try:
                self._restore_state(previous)
                self._clear_journal()
            except Exception as rollback:
                self._retain_journal(journal)
                self._sync_memory()
                raise RuntimeError(f'Metadata restoration failed; requires recovery: {rollback}') from error
            raise

    def _retain_journal(self, journal):
        self._recovery_required = True
        if not self.journal_path.exists():
            try:
                _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
            except Exception:
                # In-memory exclusion and all candidate references remain
                # protected even if the filesystem cannot publish a journal.
                logging.exception('Cannot durably retain recovery journal; preserve all filter data')

    def _clear_journal(self):
        _durable_unlink(self.journal_path)

    @staticmethod
    def _timeout(value, name, default):
        import math
        try:
            result = float(value if value is not None else os.environ.get('WEBUI_FILTER_' + name, default))
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid filter timeout: ' + name) from exc
        if not math.isfinite(result) or result <= 0:
            raise ValueError('Filter timeout must be finite and positive: ' + name)
        return result

    def _validate_state(self, state, legacy=False, deadline=None):
        if not isinstance(state, dict) or type(state.get('version')) is not int or state['version'] != (1 if legacy else 2):
            raise ValueError('Unsupported or malformed filter state')
        for kind in ('blocked', 'allowed'):
            values = state.get(kind)
            if not isinstance(values, list) or len(values) > self.limits['max_entries']:
                raise ValueError('Invalid manual domains')
            state[kind] = sorted({normalize_domain(d) for d in values})
        items = state.get('lists')
        if not isinstance(items, list) or len(items) > self.limits['max_subscriptions']:
            raise ValueError('Invalid subscription count')
        identifiers, urls = set(), set()
        for item in items:
            check_deadline(deadline)
            if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,100}', item['id']) or item['id'] in identifiers:
                raise ValueError('Invalid subscription identifier')
            identifiers.add(item['id'])
            self._name(item.get('name'))
            sources = [item.get('url')] if legacy else item.get('sources')
            sources = self._sources(sources)
            if urls.intersection(sources):
                raise ValueError('Duplicate subscription URL')
            urls.update(sources)
            if type(item.get('enabled')) is not bool:
                raise ValueError('Invalid subscription enabled flag')
            for field in ('last_updated', 'last_attempt', 'last_error'):
                if item.get(field) is not None and (not isinstance(item[field], str) or len(item[field]) > 1000):
                    raise ValueError('Invalid subscription metadata')
            if type(item.get('unsupported')) is not int or item['unsupported'] < 0 or not isinstance(item.get('samples'), list) or len(item['samples']) > 5 or any(not isinstance(s, str) or len(s) > 200 for s in item['samples']):
                raise ValueError('Invalid subscription parser metadata')
            if legacy:
                if not isinstance(item.get('domains'), list):
                    raise ValueError('Invalid legacy subscription domains')
                for domain in item['domains']:
                    check_deadline(deadline)
                    normalize_domain(domain)
            else:
                if 'domains' in item or item.get('format') not in {'auto', 'domains', 'hosts', 'adblock', 'rpz'} or item.get('url') != sources[0]:
                    raise ValueError('Invalid subscription format/sources')
                for field in ('count', 'downloaded_bytes'):
                    if type(item.get(field)) is not int or item[field] < 0:
                        raise ValueError('Invalid subscription count/bytes')
                if item['count'] > self.limits['max_entries'] or item['downloaded_bytes'] > self.limits['max_total_bytes']:
                    raise ValueError('Subscription exceeds configured limits')
                if item.get('cache') is None:
                    if item['count'] or item['enabled']:
                        raise ValueError('Enabled subscription has no cache')
                else:
                    self.store.validate(item['cache'], item['count'], normalize_domain, deadline)
        if not legacy and (type(state.get('effective_count')) is not int or not 0 <= state['effective_count'] <= self.limits['max_entries']):
            raise ValueError('Invalid effective count')

    @staticmethod
    def _name(name):
        if not isinstance(name, str) or not name.strip() or len(name) > 100 or any(ord(c) < 32 for c in name):
            raise ValueError('Use a subscription name between 1 and 100 characters')
        return name.strip()

    def _sources(self, sources):
        if not isinstance(sources, list) or not sources or len(sources) > self.limits['max_sources']:
            raise ValueError(f'Use between 1 and {self.limits["max_sources"]} subscription sources')
        result = []
        for url in sources:
            host = validate_url(url)
            parts = urlsplit(url)
            canonical = 'https://' + host + (parts.path or '/') + ('?' + parts.query if parts.query else '')
            if canonical in result:
                raise ValueError('Duplicate subscription URL')
            result.append(canonical)
        return result

    def _load_state(self):
        deadline = time.monotonic() + self.refresh_timeout
        if not self.state_path.exists():
            return {'version': 2, 'blocked': [], 'allowed': [], 'lists': [], 'effective_count': 0}
        try:
            state = json.loads(self.state_path.read_text())
        except (ValueError, UnicodeError) as exc:
            raise ValueError('Malformed filter state; original preserved') from exc
        legacy = isinstance(state, dict) and state.get('version') == 1
        self._validate_state(state, legacy=legacy, deadline=deadline)
        if not legacy:
            # A bounded disk union checks disabled caches against the aggregate limit.
            effective = self.store.union(state, None, self.limits['max_entries'], HEADER, _covered, deadline)
            if effective != state['effective_count']:
                raise ValueError('Stored effective count does not match filter policy')
            return state
        backup = self.data / 'state.v1.backup.json'
        if backup.is_symlink():
            raise ValueError('Refusing symlink migration backup')
        if backup.exists() and _file_digest(backup, deadline) != _file_digest(self.state_path, deadline):
            raise ValueError('Conflicting existing v1 migration backup; recover before migrating')
        generated = []
        try:
            filter_resources.check_disk_headroom(self.base, 16 * 1024 * 1024 +
                4 * sum(len(domain) + 64 for item in state['lists'] for domain in item['domains']))
            for item in state['lists']:
                domains = item.pop('domains')
                reference, count = self.store.build((normalize_domain(d) for d in domains), self.limits['max_entries'], deadline)
                generated.append(reference)
                item.update(cache=reference, count=count, downloaded_bytes=0,
                            sources=self._sources([item['url']]), format='auto')
                item['url'] = item['sources'][0]
                if not count:
                    item['cache'] = None
                    if item['enabled']:
                        raise ValueError('Legacy enabled subscription has no cache')
            state['version'] = 2
            state['effective_count'] = self.store.union(state, None, self.limits['max_entries'], HEADER, _covered, deadline)
            if not backup.exists():
                _atomic_copy(self.state_path, backup, mode=0o600)
            self._publish_metadata(state)
            return state
        except Exception:
            for reference in generated:
                self._discard_candidate(reference)
            raise

    def _activate(self):
        result = subprocess.run(['systemctl', 'reload-or-restart', 'unbound'], capture_output=True, text=True, timeout=20)
        if result.returncode:
            raise RuntimeError('Unbound activation failed: ' + (result.stderr or result.stdout)[:600])
        active = subprocess.run(['systemctl', 'is-active', '--quiet', 'unbound'], timeout=10)
        if active.returncode:
            raise RuntimeError('Unbound is not active after activation')

    def _check(self, path, deadline=None):
        check_deadline(deadline)
        timeout = min(180, deadline - time.monotonic()) if deadline is not None else 180
        path = Path(path)
        managed = path if path.name == self.target.name else path.parent / self.target.relative_to(self.root)
        budget = filter_resources.validation_budget(managed.stat().st_size if managed.exists() else 0,
            available=filter_resources.available_memory(), service_available=filter_resources.process_headroom(),
            maximum=self.checkconf_max_bytes)
        executable = shutil.which('unbound-checkconf')
        if executable is None:
            raise ValueError('unbound-checkconf is not installed')
        result = subprocess.run(filter_resources.validator_command(executable, path, budget),
            capture_output=True, text=True, timeout=max(.01, timeout))
        if result.returncode:
            raise ValueError('Unbound config validation failed: ' + (result.stderr or result.stdout)[:1000])

    def _compile(self, state, destination=None, deadline=None):
        if len(state['lists']) > self.limits['max_subscriptions']:
            raise ValueError(f'Subscription limit exceeded ({self.limits["max_subscriptions"]})')
        filter_resources.check_disk_headroom(self.base, self._disk_requirement(state))
        count = self.store.union(state, destination, self.limits['max_entries'], HEADER, _covered, deadline)
        state['effective_count'] = count
        return count

    def _disk_requirement(self, state):
        # SQLite union, staged text and compressed rollback temporarily coexist.
        # Cache size is a conservative measured proxy for variable domain widths;
        # budget five copies plus both old fragment and worst-case gzip blob.
        caches = sum(self.store.path(item['cache']).stat().st_size for item in state['lists'] if item.get('cache'))
        manual = sum(len(domain) + 64 for kind in ('blocked', 'allowed') for domain in state[kind])
        old = self.target.stat().st_size if self.target.exists() else 0
        return 16 * 1024 * 1024 + 5 * caches + 3 * manual + 2 * old

    def snapshot(self):
        with _LOCK:
            result = copy.deepcopy(self.state)
            result['limits'] = dict(self.limits)
            result['refresh_interval_seconds'] = getattr(self, 'refresh_interval_seconds', 0)
            result['managed_file'] = str(self.target)
            result['initialized'] = self.target.is_file() and not self.target.is_symlink()
            return result

    def _backup(self, deadline=None):
        """Small full-tree archive + shared immutable fragment blob + cache refs.

        Archives contain a manifest instead of repeatedly compressing the managed
        fragment. Restore uses manifest.managed_blob and the cached generations
        referenced by filter-state.json, both retained until the archive expires.
        """
        _check_config_tree(self.root, deadline)
        filter_resources.check_disk_headroom(self.base, 16 * 1024 * 1024 + (self.target.stat().st_size if self.target.exists() else 0))
        blobs = self.backups / 'blobs'
        if blobs.is_symlink():
            raise ValueError('Refusing symlink backup blob directory')
        blobs.mkdir(mode=0o700, exist_ok=True)
        blob = None
        if self.target.exists():
            blob = blobs / (_file_digest(self.target, deadline) + '.conf.gz')
            if blob.is_symlink():
                raise ValueError('Refusing symlink backup blob')
            if not blob.exists():
                _compress_blob(self.target, blob, deadline)
            _verify_blob(blob, self.target.stat().st_size, deadline)
        manifest = {'managed_file': str(self.target.relative_to(self.root)),
                    'config_root': str(self.root),
                    'managed_blob': str(blob.relative_to(self.backups)) if blob else None}
        state_present = self.state_path.exists()
        if self.state_path.is_symlink() or (state_present and not self.state_path.is_file()):
            raise ValueError('Refusing symlink or special filter state')
        descriptor, temporary_name = tempfile.mkstemp(prefix='.backup-', suffix='.tgz', dir=self.backups)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            # Dereference regular hardlinks so strict offline recovery sees
            # each archived entry as an independent regular file.
            with tarfile.open(temporary, 'w:gz', dereference=True) as archive:
                def include(info):
                    check_deadline(deadline)
                    if info.name == 'unbound/' + str(self.target.relative_to(self.root)):
                        return None
                    if not (info.isfile() or info.isdir()):
                        raise ValueError('Refusing special config archive member: ' + info.name)
                    return info
                archive.add(self.root, arcname='unbound', filter=include)
                if state_present:
                    archive.add(self.state_path, arcname='filter-state.json')
                body = json.dumps(manifest).encode()
                info = tarfile.TarInfo('filter-manifest.json')
                info.size, info.mode = len(body), 0o600
                archive.addfile(info, io.BytesIO(body))
            temporary.chmod(0o600)
            with temporary.open('rb') as source:
                os.fsync(source.fileno())
            self._verify_backup_archive(temporary, manifest, state_present, deadline)
            backup = self.backups / ('filters_' + str(time.time_ns()) + '_' + uuid.uuid4().hex + '.tgz')
            os.replace(temporary, backup)
            fd = os.open(self.backups, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)
        return backup, blob

    def _verify_backup_archive(self, backup, expected_manifest, state_required, deadline=None):
        """Fully consume and validate an archive before its final name exists."""
        try:
            # Tar parsing stops at its end marker, before the gzip trailer.
            # Consuming the stream separately certifies the completed CRC.
            with gzip.open(backup, 'rb') as source:
                for chunk in iter(lambda: source.read(65536), b''):
                    check_deadline(deadline)
            with tarfile.open(backup, 'r:gz') as archive:
                names = set()
                for member in archive:
                    check_deadline(deadline)
                    path = PurePosixPath(member.name)
                    if (path.is_absolute() or '..' in path.parts or '\\' in member.name or
                            member.name in names or not (member.isfile() or member.isdir()) or
                            not (member.name in {'unbound', 'filter-state.json', 'filter-manifest.json'} or
                                 member.name.startswith('unbound/'))):
                        raise ValueError('Invalid backup archive member: ' + member.name)
                    names.add(member.name)
                if 'filter-manifest.json' not in names or (state_required and 'filter-state.json' not in names):
                    raise ValueError('Backup archive missing required metadata')
                manifest_member = archive.getmember('filter-manifest.json')
                if not manifest_member.isfile() or manifest_member.size > 16 * 1024 * 1024:
                    raise ValueError('Invalid backup manifest')
                with archive.extractfile(manifest_member) as source:
                    if json.load(source) != expected_manifest:
                        raise ValueError('Backup manifest content mismatch')
                if 'filter-state.json' in names:
                    state_member = archive.getmember('filter-state.json')
                    if not state_member.isfile() or state_member.size > 16 * 1024 * 1024:
                        raise ValueError('Invalid backup state')
                    with archive.extractfile(state_member) as source:
                        state = json.load(source)
                    self._validate_state(state, legacy=isinstance(state, dict) and state.get('version') == 1,
                                         deadline=deadline)
        except (tarfile.TarError, OSError, EOFError, ValueError, UnicodeError) as exc:
            raise ValueError('Invalid completed backup archive: ' + str(exc)) from exc

    def _gc(self):
        # Refresh builds occur outside _LOCK. Keep every candidate until all
        # refreshes have committed/failed, not just those already in metadata.
        if self._refreshing or getattr(self, '_recovery_required', False) or self.journal_path.exists():
            return
        backups = sorted(self.backups.glob('filters_*.tgz'), key=lambda p: p.stat().st_mtime_ns)
        for stale in backups[:-10]:
            stale.unlink()
        references = {item['cache'] for item in self.state['lists'] if item['cache']}
        blobs = set()
        for backup in backups[-10:]:
            if backup.is_symlink():
                raise ValueError('Refusing symlink backup')
            with tarfile.open(backup) as archive:
                if 'filter-state.json' in archive.getnames():
                    previous = json.load(archive.extractfile('filter-state.json'))
                    references.update(item.get('cache') for item in previous['lists'] if item.get('cache'))
                if 'filter-manifest.json' in archive.getnames():
                    manifest = json.load(archive.extractfile('filter-manifest.json'))
                    if manifest['managed_blob']:
                        blobs.add(manifest['managed_blob'])
        for cache in self.store.directory.glob('*.sqlite'):
            if str(cache.relative_to(self.data)) not in references:
                cache.unlink()
        for blob in (self.backups / 'blobs').glob('*.conf*'):
            if str(blob.relative_to(self.backups)) not in blobs:
                blob.unlink()

    def _transaction(self, state, activate=True, create=False, deadline=None):
        with _LOCK:
            self._ready()
            if self.target.is_symlink() or (not create and not self.target.is_file()):
                raise ValueError('Managed config missing or symlink; administrator must initialize it')
            if self.target.exists():
                with self.target.open('r') as current:
                    if current.read(len(HEADER)) != HEADER:
                        raise ValueError('Managed filter header missing; refusing to overwrite an unrelated config')
            old_state = self.state_path.read_bytes() if self.state_path.exists() else None
            filter_resources.check_disk_headroom(self.base, self._disk_requirement(state))
            filter_resources.check_disk_headroom(self.root, self._disk_requirement(state))
            _check_config_tree(self.root, deadline)
            with tempfile.TemporaryDirectory(prefix='.filter-validate-', dir=self.base) as tmp:
                stage = Path(tmp) / 'unbound'
                def ignore(directory, names):
                    check_deadline(deadline)
                    return [self.target.name] if Path(directory) == self.target.parent else []
                shutil.copytree(self.root, stage, symlinks=False, ignore=ignore)
                staged = stage / self.target.relative_to(self.root)
                for conf in stage.rglob('*.conf'):
                    replacement = conf.with_suffix('.relocate')
                    with conf.open() as source, replacement.open('w') as output:
                        for line in source:
                            check_deadline(deadline)
                            output.write(re.sub(r'^(\s*include(?:-toplevel)?:\s*)(.*)$',
                                lambda m: m.group(1) + m.group(2).replace(str(self.root) + '/', str(stage) + '/'), line))
                    os.replace(replacement, conf)
                self._compile(state, staged, deadline)
                candidate_profile = filter_activation.stamp_policy(staged) if activate and self.verifier is not None else (None, None)
                old_profile = filter_activation.read_profile(self.target) if self.verifier is not None and self.target.exists() else (None, None)
                self._check(stage / self.main.relative_to(self.root), deadline)
                self._check(staged, deadline)
                backup, original = self._backup(deadline)
                journal = {'backup': backup.name,
                    'previous_blob': str(original.relative_to(self.backups)) if original else None,
                    'candidate_caches': [item['cache'] for item in state['lists'] if item['cache']]}
                _atomic(self.journal_path, (json.dumps(journal) + '\n').encode())
                attempted = False
                try:
                    check_deadline(deadline)
                    _atomic_copy(staged, self.target)
                    self._check(self.main, deadline)
                    if activate:
                        attempted = True
                        self.activate()
                        if self.verifier is not None:
                            self.verifier(*candidate_profile)
                    check_deadline(deadline)
                    _atomic(self.state_path, (json.dumps(state, ensure_ascii=True) + '\n').encode())
                    self._clear_journal()
                except Exception as error:
                    try:
                        if original is None:
                            _durable_unlink(self.target)
                        else:
                            _restore_blob(original, self.target)
                        self._restore_state(old_state)
                        if attempted:
                            self.activate()
                            if self.verifier is not None:
                                self.verifier(*old_profile)
                        self._clear_journal()
                    except Exception as rollback:
                        self._retain_journal(journal)
                        self._sync_memory()
                        raise RuntimeError(f'Rollback failed; requires recovery from {backup.name}: {rollback}') from error
                    raise
            self.state = copy.deepcopy(state)
            self._try_gc()
            return self.snapshot()

    def _try_gc(self):
        # Maintenance failures cannot turn a committed transaction into a
        # reported refresh failure or erase its now-referenced generation.
        try:
            self._gc()
        except Exception:
            logging.exception('Filter garbage collection deferred; retained all referenced generations')

    def initialize_empty(self):
        """Parent calls once, explicitly: creates/checks only, never reloads DNS."""
        with _LOCK:
            if self.target.exists():
                if self.target.is_symlink() or self.target.stat().st_size != len(HEADER) or self.target.read_text() != HEADER:
                    raise ValueError('Refusing to initialize over an existing nonempty config')
                return self.snapshot()
            if self.state['blocked'] or self.state['allowed'] or self.state['lists']:
                raise ValueError('Nonempty state exists; recover instead of resetting filters')
            return self._transaction(self.state, activate=False, create=True)

    def set_domains(self, kind, domains):
        if kind not in {'blocked', 'allowed'} or not isinstance(domains, list):
            raise ValueError('Expected blocked/allowed and a domain array')
        if len(domains) > self.limits['max_entries']:
            raise ValueError(f'Domain count limit exceeded ({self.limits["max_entries"]:,})')
        values = sorted({normalize_domain(d) for d in domains})
        with _LOCK:
            state = copy.deepcopy(self.state)
            state[kind] = values
            # Allowlist wins permanently over overlapping manual entries.
            allowed = set(state['allowed'])
            state['blocked'] = [d for d in state['blocked'] if not _covered(d, allowed)]
            return self._transaction(state)

    def _save_metadata(self, state, verify=False, deadline=None):
        self._ready()
        if verify:
            self._compile(state, deadline=deadline)
        check_deadline(deadline)
        self._publish_metadata(state)
        self.state = copy.deepcopy(state)
        return self.snapshot()

    def _find(self, state, identifier):
        for item in state['lists']:
            if item['id'] == identifier:
                return item
        raise ValueError('Subscription not found')

    def add_list(self, name, url=None, sources=None, format='auto'):
        name = self._name(name)
        if sources is not None and url is not None:
            raise ValueError('Specify url or sources, not both')
        sources = self._sources(sources if sources is not None else [url])
        if format not in {'auto', 'domains', 'hosts', 'adblock', 'rpz'}:
            raise ValueError('Unsupported subscription format')
        with _LOCK:
            state = copy.deepcopy(self.state)
            if len(state['lists']) >= self.limits['max_subscriptions']:
                raise ValueError(f'Subscription limit exceeded ({self.limits["max_subscriptions"]})')
            if any(set(item['sources']).intersection(sources) for item in state['lists']):
                raise ValueError('This subscription URL already exists')
            state['lists'].append({'id': uuid.uuid4().hex, 'name': name, 'url': sources[0], 'sources': sources, 'format': format,
                'enabled': False, 'cache': None, 'count': 0, 'downloaded_bytes': 0, 'last_updated': None, 'last_error': None,
                'last_attempt': None, 'unsupported': 0, 'samples': []})
            return self._save_metadata(state)

    def edit_list(self, identifier, name, sources, format='auto'):
        name, sources = self._name(name), self._sources(sources)
        if format not in {'auto', 'domains', 'hosts', 'adblock', 'rpz'}:
            raise ValueError('Unsupported subscription format')
        with _LOCK:
            if identifier in self._refreshing:
                raise ValueError('Subscription refresh in progress')
            state = copy.deepcopy(self.state)
            item = self._find(state, identifier)
            if any(other['id'] != identifier and set(other['sources']).intersection(sources) for other in state['lists']):
                raise ValueError('This subscription URL already exists')
            changed = item['sources'] != sources or item['format'] != format
            item.update(name=name, sources=sources, url=sources[0], format=format)
            if changed:
                enabled = item['enabled']
                item.update(enabled=False, cache=None, count=0, downloaded_bytes=0,
                            last_updated=None, last_attempt=None, last_error=None, unsupported=0, samples=[])
                if enabled:
                    return self._transaction(state)
            return self._save_metadata(state)

    def enable_list(self, identifier, enabled):
        if not isinstance(enabled, bool):
            raise ValueError('enabled must be a boolean')
        with _LOCK:
            state = copy.deepcopy(self.state)
            item = self._find(state, identifier)
            if enabled and (not item['cache'] or not item['count']):
                raise ValueError('Refresh successfully before enabling a subscription')
            item['enabled'] = enabled
            return self._transaction(state)

    def delete_list(self, identifier):
        with _LOCK:
            if identifier in self._refreshing:
                raise ValueError('Subscription refresh in progress')
            state = copy.deepcopy(self.state)
            self._find(state, identifier)
            state['lists'] = [item for item in state['lists'] if item['id'] != identifier]
            return self._transaction(state)

    def _download_bounds(self, size, downloaded):
        if size > self.limits['max_bytes']:
            raise ValueError(f'Download exceeds {self.limits["max_bytes"]:,} bytes per source')
        if downloaded + size > self.limits['max_total_bytes']:
            raise ValueError(f'Download {downloaded + size:,} bytes exceeds {self.limits["max_total_bytes"]:,} bytes aggregate')

    def refresh_list(self, identifier):
        with _LOCK:
            self._ready()
            previous = copy.deepcopy(self._find(self.state, identifier))
            if identifier in self._refreshing:
                raise ValueError('Subscription refresh in progress')
            self._refreshing.add(identifier)
        attempted = datetime.now(timezone.utc).isoformat()
        deadline = time.monotonic() + self.refresh_timeout
        reference = None
        try:
            filter_resources.check_disk_headroom(self.base, min(self.limits['max_total_bytes'],
                len(previous['sources']) * self.limits['max_bytes']))
            statistics = {'unsupported': 0, 'samples': []}
            downloaded = 0
            with tempfile.TemporaryDirectory(prefix='.filter-download-', dir=self.data) as tmp:
                paths = []
                for index, url in enumerate(previous['sources']):
                    check_deadline(deadline)
                    path = Path(tmp) / str(index)
                    if self.downloader is None:
                        cap = min(self.limits['max_bytes'], self.limits['max_total_bytes'] - downloaded)
                        try:
                            if cap <= 0:
                                raise ValueError('No remaining aggregate download budget')
                            size = download_file(url, path, cap,
                                                 min(self.download_timeout, deadline - time.monotonic()))
                        except ValueError as exc:
                            observed = (f'; observed aggregate {downloaded + exc.observed_bytes:,} bytes'
                                        if isinstance(exc, DownloadLimitError) else '')
                            raise ValueError(f'{exc}{observed}; configured {self.limits["max_bytes"]:,} bytes per source, '
                                             f'{self.limits["max_total_bytes"]:,} bytes aggregate') from exc
                        downloaded += size
                        paths.append(path)
                        continue
                    body = self.downloader(url)
                    check_deadline(deadline)
                    if isinstance(body, bytes):
                        self._download_bounds(len(body), downloaded)
                        path.write_bytes(body)
                    elif isinstance(body, Path):
                        self._download_bounds(body.stat().st_size, downloaded)
                        shutil.copyfile(body, path)
                    else:
                        raise ValueError('Injected downloader must return bytes or a file path')
                    downloaded += path.stat().st_size
                    paths.append(path)
                def domains():
                    for path in paths:
                        yield from _parse_source(path, previous['format'], statistics, deadline)
                filter_resources.check_disk_headroom(self.base, 16 * 1024 * 1024 + 4 * downloaded)
                reference, count = self.store.build(domains(), self.limits['max_entries'], deadline)
            with _LOCK:
                state = copy.deepcopy(self.state)
                item = self._find(state, identifier)
                if item['sources'] != previous['sources'] or item['format'] != previous['format']:
                    raise ValueError('Subscription changed during refresh')
                item.update(statistics)
                item.update(cache=reference, count=count, downloaded_bytes=downloaded,
                            last_updated=datetime.now(timezone.utc).isoformat(), last_attempt=attempted, last_error=None)
                return self._transaction(state, deadline=deadline) if item['enabled'] else self._save_metadata(state, verify=True, deadline=deadline)
        except Exception as exc:
            with _LOCK:
                if getattr(self, '_recovery_required', False) or self.journal_path.exists():
                    raise
                state = copy.deepcopy(self.state)
                try:
                    item = self._find(state, identifier)
                except ValueError:
                    raise exc
                item.update(last_attempt=attempted, last_error=str(exc)[:1000])
                self._save_metadata(state)
            raise
        finally:
            with _LOCK:
                self._refreshing.discard(identifier)
                if reference and not any(item['cache'] == reference for item in self.state['lists']):
                    self._discard_candidate(reference)
                self._try_gc()



from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, StrictBool


class DomainsPayload(BaseModel):
    kind: str = Field(max_length=10)
    # The manager enforces its actual configured finite bound, not a frozen
    # module default that can disagree with the limits displayed by the API.
    domains: list[str]


class SubscriptionPayload(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    sources: list[str] | None = None
    format: str = Field(default='auto', max_length=20)


class SubscriptionEditPayload(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    sources: list[str]
    format: str = Field(default='auto', max_length=20)


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
        return respond(manager.add_list, payload.name, payload.url, payload.sources, payload.format)

    @upstream.app.post('/api/filters/lists/{identifier}/edit', dependencies=write)
    def edit(identifier: str, payload: SubscriptionEditPayload):
        return respond(manager.edit_list, identifier, payload.name, payload.sources, payload.format)

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
