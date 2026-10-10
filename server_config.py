"""Structured, transactional editor for Unbound's own server settings.

The configuration *files* stay the single source of truth: there is no shadow
state to drift.  Form edits are turned into minimal line patches of the files
that already define each directive, so comments, ordering, includes, repeated
directives and the remote-control block survive untouched.  Every change runs
the same pipeline as the filter and rewrite managers: parse -> plan -> staged
validation -> backup + journal -> atomic replace -> live validation ->
reload -> wire-DNS/`get_option` verification -> commit, with full rollback.

Generated ``webui-*.conf`` fragments are owned by the Filters/Rewrites pages
and are never parsed, edited or rewritten here.
"""
import argparse
import base64
import concurrent.futures
import glob
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
from collections import defaultdict
from contextlib import contextmanager
from pathlib import Path, PurePosixPath

try:  # Share the process-wide config lock with the filter/rewrite managers.
    from safety import _LOCK
except ImportError:  # Stand-alone recovery CLI: no concurrent in-process writers.
    _LOCK = threading.RLock()

MIB = 1 << 20
MAX_FILE = MIB
MAX_FILES = 64
MAX_ITEMS = 256
MAX_ZONES = 64
BACKUP_KEEP = 10
INCLUDE_KEYS = {'include', 'include-toplevel'}
CLAUSES = {'server', 'remote-control', 'forward-zone', 'stub-zone', 'auth-zone', 'view',
           'python', 'dynlib', 'rpz', 'cachedb', 'dnstap', 'ipset'}
ACCESS_ACTIONS = {'deny', 'refuse', 'allow', 'allow_setrd', 'allow_snoop', 'allow_cookie',
                  'deny_non_local', 'refuse_non_local'}
MODULES = {'subnetcache', 'respip', 'validator', 'iterator', 'dns64', 'ipsecmod', 'cachedb',
           'python', 'dynlib', 'ipset'}
TLS_KEYS = ('forward-tls-upstream', 'forward-ssl-upstream')
REWRITE_PROBE = 'rewrite-policy-check._webui.invalid'
KEY_LINE = re.compile(r'^([ \t]*)([A-Za-z][A-Za-z0-9_-]*):(.*)$')


class ConfigError(ValueError):
    """Rejected input or an unsafe configuration (HTTP 422)."""


class RevisionConflict(ConfigError):
    """The form was based on files that have since changed (HTTP 409)."""


# --------------------------------------------------------------------------- #
#  Schema: the single description used by validation, the API and the UI.
# --------------------------------------------------------------------------- #

def _f(key, kind, label, desc, **extra):
    return dict(key=key, kind=kind, label=label, desc=desc, **extra)


_BOOL_SECURITY = [
    ('hide-identity', 'Hide identity', 'Refuse id.server / hostname.bind queries.'),
    ('hide-version', 'Hide version', 'Refuse version.server / version.bind queries.'),
    ('hide-trustanchor', 'Hide trust anchors', 'Refuse trustanchor.unbound queries.'),
    ('harden-glue', 'Harden glue', 'Only trust glue that is within the server\'s authority.'),
    ('harden-dnssec-stripped', 'Require DNSSEC data', 'Treat missing DNSSEC data for trust-anchored zones as bogus.'),
    ('harden-below-nxdomain', 'Harden below NXDOMAIN', 'Return NXDOMAIN for names below a known NXDOMAIN (RFC 8020).'),
    ('harden-referral-path', 'Harden referral path', 'Validate the whole referral path (extra queries, more security).'),
    ('harden-algo-downgrade', 'Harden algorithm downgrade', 'Refuse validation if a weaker algorithm is offered alongside a stronger one. Can break some zones.'),
    ('harden-short-bufsize', 'Reject short buffer sizes', 'Ignore EDNS buffer sizes below 512.'),
    ('harden-large-queries', 'Reject large queries', 'Refuse queries larger than 0.5 KB.'),
    ('use-caps-for-id', 'Use 0x20 case randomisation', 'Randomise query case to resist spoofing. Some servers break with this.'),
    ('qname-minimisation', 'QNAME minimisation', 'Send only as much of the name as upstreams need (privacy).'),
    ('qname-minimisation-strict', 'Strict QNAME minimisation', 'Fail resolution instead of falling back. Breaks misconfigured zones.'),
    ('aggressive-nsec', 'Aggressive NSEC', 'Synthesise negative answers from cached DNSSEC NSEC records (RFC 8198).'),
    ('minimal-responses', 'Minimal responses', 'Leave out unneeded authority/additional sections.'),
    ('do-not-query-localhost', 'Do not query localhost', 'Never send upstream queries to 127.0.0.1.'),
    ('deny-any', 'Refuse ANY queries', 'Answer ANY queries with a minimal response.'),
    ('ignore-cd-flag', 'Ignore CD flag', 'Always validate, even when a client asks for checking disabled. Weakens client control.'),
]

SECTIONS = [
    {'id': 'network', 'title': 'Network', 'lists': ['interface'], 'fields': [
        _f('port', 'int', 'Port', 'UDP/TCP port clients use to reach this resolver.', min=1, max=65535, disruptive=True),
        _f('do-ip4', 'bool', 'IPv4', 'Answer queries over IPv4.', disruptive=True),
        _f('do-ip6', 'bool', 'IPv6', 'Answer queries over IPv6.', disruptive=True),
        _f('do-udp', 'bool', 'UDP', 'Accept UDP queries. The WebUI verifies activation over UDP, so it cannot be turned off here.', disruptive=True, lock_on='no'),
        _f('do-tcp', 'bool', 'TCP', 'Accept TCP queries.', disruptive=True),
        _f('num-threads', 'int', 'Worker threads', 'Match the number of CPU cores. Caches are per-thread slabs.', min=1, max=64),
        _f('edns-buffer-size', 'int', 'EDNS buffer size', 'Advertised UDP size. 1232 avoids fragmentation (DNS flag day 2020).', min=512, max=4096),
    ]},
    {'id': 'access', 'title': 'Access control', 'lists': ['access-control'], 'fields': [],
     'intro': 'The most specific matching network decides. Clients matching nothing are refused once any rule exists. Loopback must stay allowed so the WebUI can verify DNS.'},
    {'id': 'security', 'title': 'Security & privacy', 'lists': ['private-address'], 'fields':
        [_f(k, 'bool', l, d) for k, l, d in _BOOL_SECURITY] + [
        _f('identity', 'str', 'Identity string', 'Replies to id.server queries. Only used while identity is not hidden.'),
        _f('version', 'str', 'Version string', 'Replies to version.server queries. Only used while version is not hidden.'),
        _f('ratelimit', 'int', 'Rate limit (per zone)', 'Max recursive queries per second per zone. 0 disables.', min=0, max=2147483647),
        _f('ip-ratelimit', 'int', 'Rate limit (per client IP)', 'Max queries per second per client IP. 0 disables.', min=0, max=2147483647),
        _f('unwanted-reply-threshold', 'int', 'Unwanted reply threshold', 'Flush caches when this many unsolicited replies arrive. 0 disables.', min=0, max=2147483647),
    ]},
    {'id': 'performance', 'title': 'Performance & cache', 'lists': [], 'fields': [
        _f('prefetch', 'bool', 'Prefetch', 'Refresh popular records shortly before they expire.'),
        _f('prefetch-key', 'bool', 'Prefetch DNSKEY', 'Fetch DNSKEYs earlier to speed up validation.'),
        _f('serve-expired', 'bool', 'Serve expired', 'Answer from stale cache while refreshing in the background.'),
        _f('serve-expired-ttl', 'int', 'Serve expired TTL', 'Seconds past expiry that stale data may be served. 0 = unlimited.', min=0, max=2147483647),
        _f('cache-min-ttl', 'int', 'Minimum TTL', 'Raise shorter record TTLs to this many seconds.', min=0, max=2147483647),
        _f('cache-max-ttl', 'int', 'Maximum TTL', 'Cap longer record TTLs at this many seconds.', min=1, max=2147483647),
        _f('cache-max-negative-ttl', 'int', 'Maximum negative TTL', 'Cap TTL of NXDOMAIN/NODATA answers.', min=0, max=2147483647),
        _f('msg-cache-size', 'size', 'Message cache', 'Size such as 128m. Combined caches must fit comfortably in available RAM.', min=65536, max=64 << 30),
        _f('rrset-cache-size', 'size', 'RRset cache', 'Size such as 256m. Normally about twice the message cache.', min=65536, max=64 << 30),
        _f('neg-cache-size', 'size', 'Aggressive NSEC cache', 'Size such as 4m.', min=65536, max=64 << 30),
        _f('rrset-roundrobin', 'bool', 'Round-robin RRsets', 'Rotate the order of records in answers.'),
        _f('outgoing-range', 'int', 'Outgoing range', 'Number of outgoing ports per thread. Unbound lowers the running value on its own when the open-file limit is smaller; that is not a pending change.', min=16, max=65535, clamped=True),
        _f('num-queries-per-thread', 'int', 'Queries per thread', 'Concurrent requests per thread before queueing.', min=1, max=1000000),
        _f('so-rcvbuf', 'size', 'Socket receive buffer', 'Larger values avoid drops under bursts. May need a higher net.core.rmem_max.', min=0, max=1 << 30),
        _f('so-sndbuf', 'size', 'Socket send buffer', 'Send-buffer size. 0 keeps the OS default.', min=0, max=1 << 30),
        _f('so-reuseport', 'bool', 'SO_REUSEPORT', 'Distribute queries across threads in the kernel.'),
        _f('infra-cache-numhosts', 'int', 'Infra cache hosts', 'Number of upstream hosts tracked for RTT/lameness.', min=1, max=100000000),
        _f('infra-host-ttl', 'int', 'Infra host TTL', 'Seconds upstream RTT data is kept.', min=1, max=2147483647),
        _f('jostle-timeout', 'int', 'Jostle timeout (ms)', 'Under overload, drop requests older than this.', min=0, max=100000),
        _f('target-fetch-policy', 'policy', 'Target fetch policy', 'Space-separated depth list such as "3 2 1 1 1". Use -1 to disable a level.'),
    ]},
    {'id': 'logging', 'title': 'Logging', 'lists': [], 'fields': [
        _f('verbosity', 'enum', 'Verbosity', '0 errors, 1 operational, 2+ per-query detail. 4 and above are very noisy.', options=['0', '1', '2', '3', '4', '5']),
        _f('use-syslog', 'bool', 'Use syslog', 'Log through syslog instead of a file.'),
        _f('logfile', 'path', 'Log file', 'Absolute path. Overrides syslog while set.'),
        _f('log-queries', 'bool', 'Log queries', 'Log every query. Privacy-sensitive and verbose.'),
        _f('log-replies', 'bool', 'Log replies', 'Log every reply with client and RCODE.'),
        _f('log-tag-queryreply', 'bool', 'Tag query/reply lines', 'Prefix lines with "query:" / "reply:".'),
        _f('log-local-actions', 'bool', 'Log local actions', 'Log answers produced by local-zone/local-data (filters and rewrites).'),
        _f('log-servfail', 'bool', 'Log SERVFAIL reasons', 'Explain why SERVFAIL replies happened.'),
        _f('extended-statistics', 'bool', 'Extended statistics', 'Collect per-type and per-RCODE counters.'),
        _f('statistics-cumulative', 'bool', 'Cumulative statistics', 'Do not reset counters after each read.'),
        _f('statistics-interval', 'int', 'Statistics interval', 'Seconds between statistics log lines. 0 disables.', min=0, max=86400),
    ]},
    {'id': 'dnssec', 'title': 'DNSSEC', 'lists': [], 'fields': [
        _f('module-config', 'modules', 'Modules', 'Processing order. Must end with "iterator". Example: validator iterator.', disruptive=True),
        _f('auto-trust-anchor-file', 'path', 'Auto trust anchor file', 'RFC 5011-managed root key. Unbound must be able to write it.'),
        _f('trust-anchor-file', 'path', 'Trust anchor file', 'Static trust anchors in DS/DNSKEY format.'),
        _f('val-permissive-mode', 'bool', 'Permissive validation', 'Validate but still serve bogus answers. Defeats DNSSEC protection.'),
        _f('val-clean-additional', 'bool', 'Clean additional section', 'Remove unvalidated data from the additional section.'),
    ]},
    {'id': 'advanced', 'title': 'Advanced', 'lists': [], 'fields': [
        _f('tls-cert-bundle', 'path', 'TLS CA bundle', 'CA certificates used to verify DNS-over-TLS upstreams, e.g. /etc/ssl/certs/ca-certificates.crt.'),
        _f('tls-upstream', 'bool', 'TLS to all upstreams', 'Use DNS-over-TLS for every upstream query. Most authorities do not support it.', disruptive=True),
        _f('unblock-lan-zones', 'bool', 'Unblock LAN zones', 'Resolve private reverse zones upstream instead of answering locally.'),
        _f('insecure-lan-zones', 'bool', 'Insecure LAN zones', 'Skip DNSSEC validation for private reverse zones.'),
        _f('ip-transparent', 'bool', 'IP transparent', 'Allow binding to addresses that are not yet configured.'),
        _f('delay-close', 'int', 'Delay close (ms)', 'Delay closing UDP ports after a query to absorb late replies.', min=0, max=10000),
    ]},
]

LISTS = {
    'interface': {'label': 'Listen addresses', 'placeholder': '0.0.0.0\n::',
                  'desc': 'One address per line, optionally address@port. Empty keeps Unbound\'s default (loopback only). Unbound treats 0.0.0.0 and :: as separate IPv4/IPv6 wildcards.',
                  'disruptive': True},
    'access-control': {'label': 'Client access rules', 'placeholder': '192.168.0.0/16 allow',
                       'desc': 'One "network action" rule per line. Actions: ' + ', '.join(sorted(ACCESS_ACTIONS)) + '.',
                       'disruptive': True},
    'private-address': {'label': 'Private address ranges', 'placeholder': '10.0.0.0/8',
                        'desc': 'Ranges stripped from public answers (DNS rebinding protection). One network per line.',
                        'disruptive': False},
}
FIELDS = {field['key']: field for section in SECTIONS for field in section['fields']}
DISRUPTIVE = {key for key, field in FIELDS.items() if field.get('disruptive')} | \
    {key for key, spec in LISTS.items() if spec['disruptive']}
SCHEMA_KEYS = list(FIELDS)
LIST_KEYS = list(LISTS)
INVARIANT_KEYS = ['port', 'do-udp', 'do-ip4', 'do-ip6', 'cache-min-ttl', 'cache-max-ttl',
                  'msg-cache-size', 'rrset-cache-size', 'neg-cache-size']


# --------------------------------------------------------------------------- #
#  Value handling
# --------------------------------------------------------------------------- #

def size_bytes(text):
    match = re.fullmatch(r'(\d+)([kKmMgG]?)', str(text).strip())
    if not match:
        raise ConfigError('Use a size such as 4m, 256m or 1g')
    return int(match[1]) * {'': 1, 'k': 1 << 10, 'm': 1 << 20, 'g': 1 << 30}[match[2].lower()]


def humanize_size(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return str(value)
    for suffix, unit in (('g', 1 << 30), ('m', 1 << 20), ('k', 1 << 10)):
        if number and number % unit == 0:
            return f'{number // unit}{suffix}'
    return str(number)


def comparable(field, text):
    """Canonical string for comparing file, checkconf and running values."""
    text = ' '.join(str(text).split())
    kind = field['kind']
    if kind == 'bool':
        return 'yes' if text.lower() in {'yes', 'on', 'true', '1'} else 'no'
    if kind == 'int':
        try:
            return str(int(text))
        except ValueError:
            return text
    if kind == 'size':
        try:
            return str(size_bytes(text))
        except ConfigError:
            return text
    return text


def in_sync(field, file_text, running_text):
    """True when the running value is what the file asks for.

    Unbound may legitimately run a *lower* value than configured for options that
    it clamps to system limits (outgoing-range vs the open-file limit).
    """
    want, got = comparable(field, file_text), comparable(field, running_text)
    if want == got:
        return True
    if field.get('clamped'):
        try:
            return 0 < int(got) <= int(want)
        except ValueError:
            return False
    return False


def display(field, text):
    text = ' '.join(str(text).split())
    kind = field['kind']
    if kind == 'bool':
        return comparable(field, text) == 'yes'
    if kind == 'int':
        try:
            return int(text)
        except ValueError:
            return text
    if kind == 'size':
        try:
            return humanize_size(size_bytes(text))
        except ConfigError:
            return text
    return text


_SAFE_TEXT = re.compile(r'[^\x00-\x1f\x7f"\'\\#]{1,200}')


def wire_value(field, value):
    """Validate a JSON value against the schema; return the canonical config text."""
    kind, key = field['kind'], field['key']
    label = field['label']
    if kind == 'bool':
        if type(value) is not bool:
            raise ConfigError(f'{label}: expected on/off')
        if field.get('lock_on') == ('no' if not value else 'yes'):
            raise ConfigError(f'{label} must stay enabled: the WebUI verifies activation over it')
        return 'yes' if value else 'no'
    if kind == 'int':
        if type(value) is not int or not field['min'] <= value <= field['max']:
            raise ConfigError(f'{label}: enter a whole number from {field["min"]} to {field["max"]}')
        return str(value)
    if kind == 'enum':
        if str(value) not in field['options']:
            raise ConfigError(f'{label}: choose one of {", ".join(field["options"])}')
        return str(value)
    if kind == 'size':
        if not isinstance(value, str):
            raise ConfigError(f'{label}: use a size such as 256m')
        number = size_bytes(value)
        if not field['min'] <= number <= field['max']:
            raise ConfigError(f'{label}: size must be between {humanize_size(field["min"])} and {humanize_size(field["max"])}')
        return value.strip().lower()
    if not isinstance(value, str) or not _SAFE_TEXT.fullmatch(value.strip()):
        raise ConfigError(f'{label}: use plain text without quotes, backslashes, # or control characters')
    value = ' '.join(value.split())
    if kind == 'path':
        parts = PurePosixPath(value).parts
        if not value.startswith('/') or '..' in parts:
            raise ConfigError(f'{label}: use an absolute path without ".."')
    elif kind == 'policy':
        numbers = value.split()
        if not 1 <= len(numbers) <= 11 or not all(re.fullmatch(r'-?\d{1,4}', n) and -1 <= int(n) <= 1000 for n in numbers):
            raise ConfigError(f'{label}: use 1-11 integers from -1 to 1000, e.g. 3 2 1 1 1')
    elif kind == 'modules':
        names = value.split()
        if not names or names[-1] != 'iterator' or len(set(names)) != len(names) or not set(names) <= MODULES:
            raise ConfigError(f'{label}: list known modules ({", ".join(sorted(MODULES))}) ending with "iterator"')
    return value


def render_directive(field, wire):
    return f'"{wire}"' if field['kind'] in {'str', 'path', 'policy', 'modules'} else wire


def norm_item(key, text):
    """Canonical form of one list entry, or ConfigError."""
    text = ' '.join(str(text).split())
    try:
        if key == 'interface':
            match = re.fullmatch(r'([0-9A-Fa-f:.]+)(?:@(\d{1,5}))?', text)
            if not match:
                raise ValueError
            address = ipaddress.ip_address(match[1])
            if match[2] and not 1 <= int(match[2]) <= 65535:
                raise ValueError
            return str(address) + (f'@{int(match[2])}' if match[2] else '')
        if key == 'access-control':
            network, action = text.split(' ')
            if action.lower() not in ACCESS_ACTIONS:
                raise ValueError
            return f'{ipaddress.ip_network(network, strict=False)} {action.lower()}'
        if key == 'private-address':
            return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        pass
    raise ConfigError(f'{LISTS[key]["label"]}: invalid entry "{text[:60]}"')


def norm_list(key, items):
    if not isinstance(items, list) or len(items) > MAX_ITEMS or not all(isinstance(i, str) for i in items):
        raise ConfigError(f'{LISTS[key]["label"]}: expected at most {MAX_ITEMS} entries')
    result = []
    for item in items:
        if item.strip():
            value = norm_item(key, item)
            if value not in result:
                result.append(value)
    return result


def _yes(text):
    return ' '.join(str(text).split()).lower() in {'yes', 'on', 'true', '1'}


def _zone_key(name):
    try:
        return norm_zone_name(name)
    except ConfigError:
        return str(name).strip().lower().rstrip('.') or '.'


def norm_zone_name(name):
    if not isinstance(name, str):
        raise ConfigError('Forward zone: name must be text')
    name = name.strip().lower()
    if name == '.':
        return '.'
    if not name.rstrip('.'):
        raise ConfigError('Forward zone: enter a zone name (use "." to forward everything)')
    name = name.rstrip('.')
    try:
        ascii_name = name.encode('idna').decode('ascii')
    except UnicodeError as exc:
        raise ConfigError('Forward zone: invalid name') from exc
    if (len(ascii_name) > 253 or not all(re.fullmatch(r'[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?', label)
                                         for label in ascii_name.split('.'))):
        raise ConfigError(f'Forward zone: invalid name "{name[:60]}"')
    return ascii_name


def norm_forward_addr(text):
    match = re.fullmatch(r'([0-9A-Fa-f:.]+)(?:@(\d{1,5}))?(?:#([A-Za-z0-9.-]{1,253}))?', str(text).strip())
    try:
        if not match:
            raise ValueError
        address = ipaddress.ip_address(match[1])
        if match[2] and not 1 <= int(match[2]) <= 65535:
            raise ValueError
    except ValueError:
        raise ConfigError(f'Forward zone: invalid upstream "{str(text)[:60]}" (use IP[@port][#tls-name])') from None
    return str(address) + (f'@{int(match[2])}' if match[2] else '') + (f'#{match[3]}' if match[3] else '')


def norm_zones(zones):
    if not isinstance(zones, list) or len(zones) > MAX_ZONES:
        raise ConfigError(f'Forwarding: at most {MAX_ZONES} zones')
    result, seen = [], set()
    for zone in zones:
        if (not isinstance(zone, dict) or set(zone) - {'name', 'addrs', 'tls', 'first'} or
                type(zone.get('tls', False)) is not bool or type(zone.get('first', False)) is not bool or
                not isinstance(zone.get('addrs'), list)):
            raise ConfigError('Forwarding: malformed zone')
        name = norm_zone_name(zone.get('name'))
        if name in seen:
            raise ConfigError(f'Forwarding: duplicate zone "{name}"')
        seen.add(name)
        addrs = []
        for addr in zone['addrs']:
            if str(addr).strip():
                value = norm_forward_addr(addr)
                if value not in addrs:
                    addrs.append(value)
        if not 1 <= len(addrs) <= 16:
            raise ConfigError(f'Forwarding: zone "{name}" needs 1-16 upstream addresses')
        result.append({'name': name, 'addrs': addrs, 'tls': zone.get('tls', False), 'first': zone.get('first', False)})
    return sorted(result, key=lambda z: z['name'])


# --------------------------------------------------------------------------- #
#  Line-preserving parser
# --------------------------------------------------------------------------- #

class Line:
    __slots__ = ('path', 'index', 'text', 'clause', 'key', 'value', 'start', 'end', 'odd', 'header', 'tokens')

    def __init__(self, path, index, text):
        self.path, self.index, self.text = path, index, text
        self.clause: str | None = None
        self.key: str | None = None
        self.value: str = ''
        self.start = self.end = 0
        self.odd = self.header = False
        self.tokens = 0


def _scan(rest):
    """Tokens of a directive's argument text (Unbound lexer rules)."""
    tokens, i, n, first, last, odd = [], 0, len(rest), None, None, False
    while True:
        while i < n and rest[i] in ' \t':
            i += 1
        if i >= n or rest[i] == '#':
            break
        start = i
        if rest[i] in '"\'':
            close = rest.find(rest[i], i + 1)
            if close < 0:
                odd = True
                break
            tokens.append(rest[i + 1:close])
            i = close + 1
        else:
            while i < n and rest[i] not in ' \t':
                i += 1
            tokens.append(rest[start:i])
        first = start if first is None else first
        last = i
    return tokens, (first or 0), (last or 0), odd


def parse_lines(path, text):
    lines, clause = [], None
    body = text.split('\n')
    if body and body[-1] == '':
        body.pop()
    for index, raw in enumerate(body):
        line = Line(path, index, raw)
        match = KEY_LINE.match(raw)
        if match:
            key = match[2].lower()
            tokens, first, last, odd = _scan(match[3])
            offset = len(match[1]) + len(match[2]) + 1
            line.key, line.value = key, ' '.join(tokens)
            line.start, line.end, line.odd, line.tokens = offset + first, offset + last, odd, len(tokens)
            if key in CLAUSES and not tokens and not odd:
                line.header, clause = True, key
            elif key not in INCLUDE_KEYS:
                line.clause = clause
            else:
                line.clause = None
            if line.header:
                line.clause = key
        lines.append(line)
    return lines


class FileInfo:
    def __init__(self, path, rel, role, text='', reason='', size=0):
        self.path, self.rel, self.role, self.text, self.reason, self.size = path, rel, role, text, reason, size
        self.lines = parse_lines(path, text) if role in {'main', 'editable'} else []

    @property
    def directives(self):
        return sum(1 for line in self.lines if line.key and not line.header and line.key not in INCLUDE_KEYS)

    @property
    def editable(self):
        return self.role in {'main', 'editable'}


class Model:
    """The effective include graph of the configuration, in Unbound's order."""

    def __init__(self, root, main, overrides=None):
        self.root, self.main = Path(root), Path(main)
        self.overrides = overrides or {}
        self.files, self.sequence, self.blockers = {}, [], []
        self._walk(self.main, ())

    def _load(self, path, role):
        rel = str(path.relative_to(self.root))
        if path.name.startswith('webui-') and role != 'main':
            return FileInfo(path, rel, 'managed', reason='Generated by the Filters / DNS rewrites pages')
        if path.is_symlink() or (path.exists() and not path.is_file()):
            return FileInfo(path, rel, 'readonly', reason='symbolic link or special file')
        if path in self.overrides:
            data = self.overrides[path].encode()
        elif path.exists():
            if path.stat().st_size > MAX_FILE:
                return FileInfo(path, rel, 'readonly', reason='larger than the 1 MiB structured-editor limit', size=path.stat().st_size)
            data = path.read_bytes()
        else:
            return FileInfo(path, rel, 'readonly', reason='file does not exist')
        try:
            text = data.decode('utf-8')
        except UnicodeError:
            return FileInfo(path, rel, 'readonly', reason='not valid UTF-8', size=len(data))
        if '\r' in text or '\0' in text or len(data) > MAX_FILE:
            return FileInfo(path, rel, 'readonly', reason='CRLF/binary content or too large', size=len(data))
        return FileInfo(path, rel, role, text, size=len(data))

    def _expand(self, line):
        pattern = Path(line.value)
        if not pattern.is_absolute() or '..' in pattern.parts or not pattern.is_relative_to(self.root):
            self.blockers.append(f'{line.path}:{line.index + 1}: include must be an absolute path inside {self.root}')
            return []
        return [Path(match) for match in sorted(glob.glob(str(pattern)))]

    def _walk(self, path, stack):
        if len(self.files) >= MAX_FILES:
            self.blockers.append('Too many included configuration files')
            return
        if path in self.files:
            self.blockers.append(f'{path} is included more than once')
            return
        info = self._load(path, 'main' if path == self.main else 'editable')
        self.files[path] = info
        if info.role == 'readonly':
            self.blockers.append(f'{info.rel}: {info.reason}')
        for line in info.lines:
            self.sequence.append(line)
            if line.key in INCLUDE_KEYS and line.value:
                for match in self._expand(line):
                    if match in stack or match == path:
                        self.blockers.append(f'{match}: include cycle')
                    elif match.name.startswith('webui-') and match.is_file():
                        self.files.setdefault(match, self._load(match, 'editable'))
                    else:
                        self._walk(match, stack + (path,))

    @property
    def editable_files(self):
        return [info for info in self.files.values() if info.editable]

    def occurrences(self, key):
        return [line for line in self.sequence if line.clause == 'server' and line.key == key and not line.odd]

    def zones(self):
        """Forward-zone blocks as ``{'name', 'header', 'lines', 'path'}`` (document order)."""
        blocks, current = [], None
        for info in self.files.values():
            current = None
            for line in info.lines:
                if line.header:
                    current = {'header': line, 'lines': [], 'path': info.path, 'name': None} if line.key == 'forward-zone' else None
                    if current:
                        blocks.append(current)
                elif current is not None and line.key:
                    current['lines'].append(line)
                    if line.key == 'name' and current['name'] is None:
                        current['name'] = line.value
        return [b for b in blocks if b['name']]

    def revision(self):
        digest = hashlib.sha256()
        for info in self.files.values():
            digest.update(f'{info.rel}\0{info.role}\0'.encode())
            if info.role != 'managed':
                digest.update(hashlib.sha256(info.text.encode()).digest() if info.role != 'readonly' else b'readonly')
        return digest.hexdigest()


# --------------------------------------------------------------------------- #
#  Patch builder
# --------------------------------------------------------------------------- #

class Patch:
    def __init__(self, model):
        self.model, self.ops = model, {}

    def _op(self, path):
        return self.ops.setdefault(path, {'replace': {}, 'delete': set(), 'after': defaultdict(list),
                                          'tail_server': [], 'tail': []})

    def replace(self, line, text):
        self._op(line.path)['replace'][line.index] = text

    def delete(self, line):
        self._op(line.path)['delete'].add(line.index)

    def insert_after(self, line, text):
        self._op(line.path)['after'][line.index].append(text)

    def indent(self, path):
        for line in self.model.files[path].lines:
            if line.clause == 'server' and line.key and not line.header:
                return KEY_LINE.match(line.text)[1]
        return '    '

    def target_file(self):
        """The file that new server directives are appended to: the editable
        file that already holds the most server directives (else the main file)."""
        best, score = None, 0
        for info in self.model.editable_files:
            count = sum(1 for line in info.lines if line.clause == 'server' and line.key and not line.header)
            if count and count >= score:
                best, score = info, count
        return best or self.model.files[self.model.main]

    def add_server(self, text, path=None):
        info = self.model.files[path] if path else self.target_file()
        directives = [line for line in info.lines if line.clause == 'server' and line.key and not line.header]
        headers = [line for line in info.lines if line.header and line.key == 'server']
        indent = self.indent(info.path)
        if directives:
            self.insert_after(directives[-1], indent + text)
        elif headers:
            self.insert_after(headers[-1], indent + text)
        else:
            self._op(info.path)['tail_server'].append('    ' + text)

    def add_block(self, lines):
        info = self.target_file()
        self._op(info.path)['tail'].append(lines)

    def texts(self):
        result = {}
        for path, op in self.ops.items():
            info = self.model.files[path]
            body = info.text.split('\n')
            if body and body[-1] == '':
                body.pop()
            out = []
            for index, raw in enumerate(body):
                if index not in op['delete']:
                    out.append(op['replace'].get(index, raw))
                out.extend(op['after'].get(index, []))
            if op['tail_server']:
                out += [''] * bool(out and out[-1].strip()) + ['server:'] + op['tail_server']
            for block in op['tail']:
                out += [''] * bool(out and out[-1].strip()) + block
            result[path] = '\n'.join(out) + '\n' if out else ''
        return result


# --------------------------------------------------------------------------- #
#  File helpers
# --------------------------------------------------------------------------- #

def _fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic(path, data, mode=None, like=None):
    path = Path(path)
    reference = (like or path)
    info = reference.stat() if reference.exists() else None
    descriptor, name = tempfile.mkstemp(prefix='.webui-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fchmod(handle.fileno(), mode if mode is not None else (info.st_mode & 0o7777 if info else 0o600))
            if info is not None and os.geteuid() == 0:
                os.fchown(handle.fileno(), info.st_uid, info.st_gid)
            os.fsync(handle.fileno())
        os.replace(name, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _durable_unlink(path):
    path = Path(path)
    try:
        path.unlink()
    except FileNotFoundError:
        return
    _fsync_dir(path.parent)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _relocate(data, root, dest):
    def swap(match):
        return match.group(1) + match.group(2).replace((str(root) + '/').encode(), (str(dest) + '/').encode())
    return b'\n'.join(re.sub(rb'^(\s*include(?:-toplevel)?:\s*)(.*)$', swap, line) for line in data.split(b'\n'))


def run(command, timeout=20):
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    return result.returncode, result.stdout, result.stderr


# --------------------------------------------------------------------------- #
#  Default external backends (all injectable for tests)
# --------------------------------------------------------------------------- #

def checkconf_option(config, key):
    code, out, err = run(['unbound-checkconf', '-o', key, str(config)])
    if code:
        raise ConfigError('unbound-checkconf rejected the candidate: ' + (err or out)[:500])
    return out.rstrip('\n').split('\n') if out.strip() else ['']


def control_option(config, key):
    code, out, err = run(['unbound-control', '-c', str(config), 'get_option', key], timeout=10)
    if code:
        raise RuntimeError('unbound-control get_option failed: ' + (err or out)[:300])
    return out.rstrip('\n').split('\n') if out.strip() else ['']


def control_forwards(config):
    code, out, err = run(['unbound-control', '-c', str(config), 'list_forwards'], timeout=10)
    if code:
        raise RuntimeError('unbound-control list_forwards failed: ' + (err or out)[:300])
    return out.splitlines()


def systemd_activate():
    result = subprocess.run(['systemctl', 'reload-or-restart', 'unbound'], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError('Unbound activation failed: ' + (result.stderr or result.stdout)[:600])
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'unbound'], timeout=10).returncode:
        raise RuntimeError('Unbound is not active after activation')


def available_memory():
    try:
        import filter_resources
        return filter_resources.available_memory()
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Manager
# --------------------------------------------------------------------------- #

class ConfigManager:
    def __init__(self, base, main, *, option_reader=None, running_reader=None, forwards_reader=None,
                 checker=None, activate=None, verifier=None, memory=None, probes=None, _offline=False):
        self.base, self.main = Path(base).absolute(), Path(main).absolute()
        self.root = self.main.parent
        for path in (self.base, self.main):
            if '..' in path.parts or any(parent.is_symlink() for parent in (path, *path.parents)):
                raise ValueError('Refusing symlink path: ' + str(path))
        if self.base.is_relative_to(self.root):
            raise ValueError('Config data directory must be outside the Unbound config root')
        self.data, self.backups = self.base / 'config-data', self.base / 'config-backups'
        self.journal_path = self.data / 'transaction.json'
        for directory in (self.data, self.backups):
            if directory.is_symlink():
                raise ValueError('Refusing symlink config directory')
            if _offline:
                if not directory.is_dir():
                    raise ValueError('Offline recovery requires existing config-data/config-backups directories')
            else:
                directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                directory.chmod(0o700)
        self.option_reader = option_reader or checkconf_option
        self.running_reader = running_reader or control_option
        self.forwards_reader = forwards_reader or control_forwards
        self.checker = checker or self._check
        self.activate = activate or systemd_activate
        self.memory = memory or available_memory
        self.probes = probes or self._policy_probes
        self.verifier = verifier or self._verify
        self._recovery_required = False

    # ----- inspection ------------------------------------------------------ #

    def _model(self, overrides=None):
        return Model(self.root, self.main, overrides)

    def _ready(self):
        if self._recovery_required or self.journal_path.exists() or self.journal_path.is_symlink():
            raise ValueError('Interrupted configuration transaction; preserve files and run explicit recovery')

    def _tree_guard(self):
        for path in [self.root, *self.root.rglob('*')]:
            if path.is_symlink() or not (path.is_dir() or path.is_file()):
                raise ConfigError('Refusing a config tree containing symlinks or special files: ' + str(path))

    def _build_tree(self, dest, overrides, big):
        """Copy the config tree to ``dest`` with includes relocated.

        ``big='empty'`` blanks generated/large files (enough for option reads);
        ``big='link'`` hard-links (or copies) them for full-tree validation.
        """
        dest = Path(dest)
        for path in sorted(self.root.rglob('*')):
            target = dest / path.relative_to(self.root)
            if path.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            large = path.stat().st_size > MAX_FILE and path not in overrides
            if large or (path.name.startswith('webui-') and big == 'empty'):
                if big == 'empty':
                    target.write_bytes(b'')
                else:
                    try:
                        os.link(path, target)
                    except OSError:
                        shutil.copyfile(path, target)
                continue
            data = overrides[path].encode() if path in overrides else path.read_bytes()
            target.write_bytes(_relocate(data, self.root, dest))
        for path, text in overrides.items():
            target = dest / path.relative_to(self.root)
            if not target.exists():
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(_relocate(text.encode(), self.root, dest))
        return dest / self.main.relative_to(self.root)

    @contextmanager
    def _light(self, overrides=None):
        with tempfile.TemporaryDirectory(prefix='.config-light-', dir=self.base) as tmp:
            yield self._build_tree(Path(tmp) / 'unbound', overrides or {}, 'empty')

    def _read_many(self, reader, config, keys, tolerate=False):
        def one(key):
            try:
                return key, reader(config, key)
            except Exception as exc:
                if tolerate:
                    return key, exc
                raise
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            return dict(pool.map(one, keys))

    @staticmethod
    def _text(lines):
        return ' '.join(' '.join(lines).split())

    def _scalar_value(self, key, lines):
        return comparable(FIELDS[key], self._text(lines))

    def _list_value(self, key, lines):
        return sorted(norm_item(key, line) for line in lines if line.strip())

    def snapshot(self):
        with _LOCK:
            return self._snapshot()

    def _snapshot(self):
        model = self._model()
        with self._light() as config:
            keys = SCHEMA_KEYS + LIST_KEYS
            files = self._read_many(self.option_reader, config, keys, tolerate=True)
            running = self._read_many(self.running_reader, config, keys, tolerate=True)
            running_error = next((str(v) for v in running.values() if isinstance(v, Exception)), None)
            forwards = None
            try:
                forwards = self.forwards_reader(config)
            except Exception:
                pass
        values, pending = {}, []
        for key in SCHEMA_KEYS:
            field = FIELDS[key]
            file_lines, run_lines = files[key], running[key]
            if isinstance(file_lines, Exception):
                raise ConfigError('unbound-checkconf could not read the current configuration: ' + str(file_lines))
            line = (model.occurrences(key) or [None])[-1]
            file_text = self._text(file_lines)
            run_text = None if isinstance(run_lines, Exception) else self._text(run_lines)
            differs = run_text is not None and not in_sync(field, file_text, run_text)
            reduced = run_text is not None and not differs and comparable(field, file_text) != comparable(field, run_text)
            if differs:
                pending.append(key)
            values[key] = {'value': display(field, file_text), 'configured': line is not None, 'reduced': reduced,
                           'source': f'{model.files[line.path].rel}:{line.index + 1}' if line else None,
                           'running': None if run_text is None else display(field, run_text), 'pending': differs}
        lists = {}
        for key in LIST_KEYS:
            lines = model.occurrences(key)
            items = []
            for line in lines:
                try:
                    items.append(norm_item(key, line.value))
                except ConfigError:
                    items.append(line.value)
            run_lines = running[key]
            run_items = None if isinstance(run_lines, Exception) else [i for i in run_lines if i.strip()]
            try:
                differs = run_items is not None and sorted(set(items)) != self._list_value(key, run_items)
            except ConfigError:
                differs = True
            if differs:
                pending.append(key)
            lists[key] = {'items': items, 'running': run_items, 'pending': differs,
                          'sources': sorted({f'{model.files[l.path].rel}:{l.index + 1}' for l in lines})[:20]}
        zones = []
        for block in model.zones():
            addrs = [l.value for l in block['lines'] if l.key == 'forward-addr']
            others = sorted({l.key for l in block['lines'] if l.key not in {'name', 'forward-addr', 'forward-first', *TLS_KEYS}})
            zones.append({'name': block['name'], 'addrs': addrs, 'others': others,
                          'tls': any(l.key in TLS_KEYS and _yes(l.value) for l in block['lines']),
                          'first': any(l.key == 'forward-first' and _yes(l.value) for l in block['lines']),
                          'source': f'{model.files[block["path"]].rel}:{block["header"].index + 1}'})
        return {
            'revision': model.revision(), 'main': str(self.main), 'schema': SECTIONS, 'list_specs': LISTS,
            'values': values, 'lists': lists, 'forward_zones': sorted(zones, key=lambda z: z['name']),
            'running_available': running_error is None, 'running_error': running_error,
            'forwards_running': forwards,
            'pending': pending, 'editable': not model.blockers, 'blockers': model.blockers,
            'disruptive': sorted(DISRUPTIVE),
            'files': [{'path': i.rel, 'role': i.role, 'reason': i.reason, 'size': i.size,
                       'directives': i.directives} for i in model.files.values()],
            'limits': {'max_items': MAX_ITEMS, 'max_zones': MAX_ZONES, 'max_file_bytes': MAX_FILE},
            'recovery_required': self._recovery_required or self.journal_path.exists(),
        }

    def read_file(self, rel):
        with _LOCK:
            info = self._editable(self._model(), rel)
            return {'path': info.rel, 'content': info.text, 'revision': self._model().revision()}

    def _editable(self, model, rel):
        for info in model.files.values():
            if info.rel == rel and info.editable:
                return info
        raise ConfigError('Only existing, regular, UTF-8 configuration files in the include graph can be edited here')

    # ----- planning -------------------------------------------------------- #

    def _plan(self, model, changes, lists, zones):
        if model.blockers:
            raise ConfigError('Structured editing is unavailable: ' + '; '.join(model.blockers[:3]))
        changes, lists = changes or {}, lists or {}
        if not isinstance(changes, dict) or not isinstance(lists, dict):
            raise ConfigError('Malformed change request')
        patch, changed, disruptive = Patch(model), [], set()
        for key in sorted(changes, key=lambda k: SCHEMA_KEYS.index(k) if k in FIELDS else 10 ** 6):
            field = FIELDS.get(key)
            if field is None:
                raise ConfigError(f'Unknown or unsupported option "{key}"')
            value, occurrences = changes[key], model.occurrences(key)
            if value is None:
                if occurrences:
                    for line in occurrences:
                        patch.delete(line)
                    changed.append(key)
            else:
                wire = wire_value(field, value)
                text = f'{key}: {render_directive(field, wire)}'
                if occurrences:
                    last = occurrences[-1]
                    if comparable(field, last.value) == comparable(field, wire) and len(occurrences) == 1:
                        continue
                    if last.tokens != 1 or last.odd:
                        raise ConfigError(f'{key} is written in an unsupported way at line {last.index + 1}; use the raw editor')
                    patch.replace(last, last.text[:last.start] + render_directive(field, wire) + last.text[last.end:])
                    for extra in occurrences[:-1]:
                        patch.delete(extra)  # Overridden duplicates would only confuse the next reader.
                else:
                    patch.add_server(text)
                changed.append(key)
            if key in DISRUPTIVE:
                disruptive.add(key)
        for key in sorted(lists):
            if key not in LISTS:
                raise ConfigError(f'Unknown list option "{key}"')
            if self._plan_list(model, patch, key, norm_list(key, lists[key])):
                changed.append(key)
                if LISTS[key]['disruptive']:
                    disruptive.add(key)
        zone_names = []
        if zones is not None:
            zone_names, zone_changed = self._plan_zones(model, patch, norm_zones(zones))
            if zone_changed:
                changed.append('forward-zones')
                disruptive.add('forward-zones')
        return patch, changed, disruptive, zone_names

    @staticmethod
    def _plan_list(model, patch, key, want):
        existing = model.occurrences(key)
        keep, used, dirty = [], set(), False
        for line in existing:
            if line.odd or line.tokens < 1:
                raise ConfigError(f'{key} line {line.index + 1} cannot be parsed; use the raw editor')
            try:
                canonical = norm_item(key, line.value)
            except ConfigError:
                canonical = None
            if canonical in want and canonical not in used:
                used.add(canonical)
                keep.append(line)
            else:
                patch.delete(line)
                dirty = True
        missing = [item for item in want if item not in used]
        for index, item in enumerate(missing):
            dirty = True
            if keep or existing:
                anchor = keep[-1] if keep else existing[-1]
                patch.insert_after(anchor, patch.indent(anchor.path) + f'{key}: {item}')
            else:
                patch.add_server(f'{key}: {item}')
        return dirty

    def _plan_zones(self, model, patch, want):
        blocks = {}
        for block in model.zones():
            blocks.setdefault(_zone_key(block['name']), block)
        wanted = {zone['name']: zone for zone in want}
        dirty = False
        for name, block in blocks.items():
            if name not in wanted:
                directives = [block['header']] + block['lines']
                for line in directives:
                    patch.delete(line)
                dirty = True
                continue
            zone, lines = wanted[name], block['lines']
            indent = KEY_LINE.match(lines[0].text)[1] if lines else '    '
            last = lines[-1] if lines else block['header']
            current = []
            for line in lines:
                if line.key == 'forward-addr':
                    try:
                        canonical = norm_forward_addr(line.value)
                    except ConfigError:
                        canonical = None
                    if canonical in zone['addrs'] and canonical not in current:
                        current.append(canonical)
                    else:
                        patch.delete(line)
                        dirty = True
            anchor_addr = next((l for l in reversed(lines) if l.key == 'forward-addr' and l.index not in
                                patch._op(l.path)['delete']), None) or last
            for addr in (a for a in zone['addrs'] if a not in current):
                patch.insert_after(anchor_addr, f'{indent}forward-addr: {addr}')
                dirty = True
            for keys, wanted_flag, default_key in ((TLS_KEYS, zone['tls'], 'forward-tls-upstream'),
                                                   (('forward-first',), zone['first'], 'forward-first')):
                present = [l for l in lines if l.key in keys]
                is_on = any(_yes(l.value) for l in present)
                if wanted_flag and not is_on:
                    if present:
                        patch.replace(present[0], present[0].text[:present[0].start] + 'yes' + present[0].text[present[0].end:])
                    else:
                        patch.insert_after(last, f'{indent}{default_key}: yes')
                    dirty = True
                elif not wanted_flag and present:
                    for l in present:
                        patch.delete(l)
                    dirty = dirty or is_on
        for name, zone in wanted.items():
            if name not in blocks:
                indent = patch.indent(patch.target_file().path)
                block = ['forward-zone:', f'{indent}name: "{name}"'] + [f'{indent}forward-addr: {a}' for a in zone['addrs']]
                block += [f'{indent}forward-tls-upstream: yes'] * zone['tls'] + [f'{indent}forward-first: yes'] * zone['first']
                patch.add_block(block)
                dirty = True
        return sorted(wanted), dirty

    # ----- public mutations ------------------------------------------------- #

    def save(self, revision, changes=None, lists=None, zones=None, *, apply=True, acknowledge=False):
        with _LOCK:
            self._ready()
            model = self._model()
            self._check_revision(model, revision)
            patch, changed, disruptive, zone_names = self._plan(model, changes, lists, zones)
            if disruptive and apply and not acknowledge:
                raise ConfigError('Acknowledge the connectivity risk to apply: ' + ', '.join(sorted(disruptive)))
            texts = patch.texts()
            keys = [k for k in changed if k in FIELDS or k in LISTS]
            removed = sorted(set(_zone_key(b['name']) for b in model.zones()) - set(zone_names)) if zones is not None else []
            result = self._commit(model, texts, keys, zone_names, removed, apply)
            result.update(changed=changed)
            return result

    def save_file(self, revision, rel, content, *, apply=True, acknowledge=False):
        with _LOCK:
            self._ready()
            model = self._model()
            self._check_revision(model, revision)
            info = self._editable(model, rel)
            if not isinstance(content, str) or len(content.encode()) > MAX_FILE or '\0' in content or '\r' in content:
                raise ConfigError('Content must be UTF-8 text under 1 MiB without NUL or CR characters')
            if content and not content.endswith('\n'):
                content += '\n'
            if apply and not acknowledge:
                raise ConfigError('Acknowledge that a raw edit can interrupt DNS to apply it')
            result = self._commit(model, {info.path: content}, SCHEMA_KEYS + LIST_KEYS, None, [], apply)
            result.update(changed=[rel])
            return result

    def apply_pending(self, revision):
        """Reload Unbound so it matches files already saved without applying."""
        with _LOCK:
            self._ready()
            model = self._model()
            self._check_revision(model, revision)
            return self._commit(model, {}, SCHEMA_KEYS + LIST_KEYS, None, [], True, force=True)

    @staticmethod
    def _check_revision(model, revision):
        if not isinstance(revision, str) or revision != model.revision():
            raise RevisionConflict('Configuration files changed since this page loaded; reload before saving')

    # ----- transaction ---------------------------------------------------- #

    def _commit(self, model, texts, keys, zone_names, removed, apply, force=False):
        changed = {p: t for p, t in texts.items() if t != model.files[p].text}
        if not changed and not force:
            return {'success': True, 'unchanged': True, 'applied': False, 'backup': None, 'state': self._snapshot()}
        self._tree_guard()
        tree_bytes = sum(p.stat().st_size for p in self.root.rglob('*') if p.is_file())
        self._disk(tree_bytes)
        with tempfile.TemporaryDirectory(prefix='.config-validate-', dir=self.base) as tmp:
            tmp = Path(tmp)
            new_model = self._model(changed)
            if new_model.blockers and changed:
                blockers = [b for b in new_model.blockers if b not in model.blockers]
                if blockers:
                    raise ConfigError('Candidate configuration is unsafe to manage: ' + '; '.join(blockers[:3]))
            light = self._build_tree(tmp / 'light', changed, 'empty')
            expected_keys = sorted(set(keys) | set(INVARIANT_KEYS))
            expected = self._read_many(self.option_reader, light, expected_keys)
            warnings = self._invariants(model, new_model, expected, changed, tmp)
            stage = self._build_tree(tmp / 'stage', changed, 'link')
            self.checker(stage)
            backup = self._backup(model, changed) if changed else None
            if changed:
                self._transact(model, changed, backup, light, expected, keys, zone_names, removed, apply)
                applied = apply
            else:  # apply_pending: files already hold the candidate; only reload + verify.
                self.activate()
                self._verify_ctx(light, expected, keys, zone_names, removed, 'apply')
                applied = True
        self._prune()
        return {'success': True, 'unchanged': False, 'applied': applied, 'backup': backup.name if backup else None,
                'warnings': warnings, 'state': self._snapshot()}

    def _disk(self, tree_bytes):
        try:
            import filter_resources
            filter_resources.check_disk_headroom(self.base, tree_bytes + 16 * MIB)
        except ImportError:
            pass

    def _check(self, config):
        import filter_resources
        policy_bytes = sum(p.stat().st_size for p in Path(config).parent.rglob('*') if p.is_file())
        budget = filter_resources.validation_budget(
            policy_bytes, available=filter_resources.available_memory(),
            service_available=filter_resources.process_headroom(),
            maximum=int(os.environ.get('WEBUI_FILTER_CHECKCONF_MAX_BYTES', filter_resources.DEFAULT_CHECKCONF_MAX_BYTES)))
        executable = shutil.which('unbound-checkconf')
        if executable is None:
            raise ValueError('unbound-checkconf is not installed')
        result = subprocess.run(filter_resources.validator_command(executable, config, budget),
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise ConfigError('Unbound config validation failed: ' + (result.stderr or result.stdout)[:1000])

    def _invariants(self, old_model, new_model, expected, changed, tmp):
        """Refuse results that would lock out the WebUI or exhaust memory."""
        def scalar(key):
            return comparable(FIELDS[key], self._text(expected[key]))

        host = os.environ.get('WEBUI_FILTER_VERIFY_HOST', '127.0.0.1')
        address = ipaddress.ip_address(host)
        warnings = []
        if scalar('do-udp') != 'yes':
            raise ConfigError('UDP must stay enabled: the WebUI verifies activation over UDP')
        if scalar(f'do-ip{address.version}') != 'yes':
            raise ConfigError(f'IPv{address.version} must stay enabled so the WebUI can verify DNS at {host}')
        interfaces = []
        for line in new_model.occurrences('interface'):
            try:
                interfaces.append(norm_item('interface', line.value))
            except ConfigError:
                pass  # Unusual forms stay Unbound's (and checkconf's) business.
        if interfaces and not any(ipaddress.ip_address(i.split('@')[0]) in {address, ipaddress.ip_address('0.0.0.0' if address.version == 4 else '::')}
                                  for i in interfaces):
            raise ConfigError(f'Listen addresses must include {host} or the {"IPv4" if address.version == 4 else "IPv6"} wildcard so the WebUI can verify DNS')
        rules = []
        for line in new_model.occurrences('access-control'):
            try:
                network, action = norm_item('access-control', line.value).split(' ')
            except ConfigError:
                continue
            rules.append((ipaddress.ip_network(network), action))
        if rules:
            matching = [r for r in rules if r[0].version == address.version and address in r[0]]
            best = max(matching, key=lambda r: r[0].prefixlen, default=None)
            if best is None or not best[1].startswith('allow'):
                raise ConfigError(f'Access rules must allow {host}; otherwise the WebUI cannot verify DNS and clients on this host are refused')
        if int(scalar('cache-min-ttl')) > int(scalar('cache-max-ttl')):
            raise ConfigError('Minimum TTL cannot exceed maximum TTL')
        cache = {key: int(scalar(key)) for key in ('msg-cache-size', 'rrset-cache-size', 'neg-cache-size')}
        if any(line.key in cache for info in new_model.files.values() for line in info.lines if info.path in changed):
            available = self.memory()
            if available:
                total = sum(cache.values())
                if total > available // 2:
                    raise ConfigError(f'Caches total {humanize_size(total)}, more than half of the {humanize_size(available)} of available memory')
        return warnings

    def _backup(self, model, changed):
        manifest = {'version': 1, 'config_root': str(self.root), 'files': {}}
        descriptor, name = tempfile.mkstemp(prefix='.backup-', suffix='.tgz', dir=self.backups)
        os.close(descriptor)
        temporary = Path(name)
        try:
            with tarfile.open(temporary, 'w:gz') as archive:
                for path in sorted(changed):
                    data = model.files[path].text.encode()
                    rel = 'unbound/' + str(path.relative_to(self.root))
                    manifest['files'][rel] = {'sha256': _sha(data), 'size': len(data)}
                    info = tarfile.TarInfo(rel)
                    info.size, info.mode = len(data), 0o600
                    archive.addfile(info, io.BytesIO(data))
                body = json.dumps(manifest).encode()
                info = tarfile.TarInfo('manifest.json')
                info.size, info.mode = len(body), 0o600
                archive.addfile(info, io.BytesIO(body))
            temporary.chmod(0o600)
            with temporary.open('rb') as stream:
                os.fsync(stream.fileno())
            self._verify_backup(temporary)
            final = self.backups / f'config_{time.time_ns()}_{uuid.uuid4().hex}.tgz'
            os.replace(temporary, final)
            _fsync_dir(self.backups)
            return final
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _verify_backup(path):
        try:
            with gzip.open(path, 'rb') as source:
                while source.read(65536):
                    pass
            with tarfile.open(path, 'r:gz') as archive:
                members = {m.name: m for m in archive}
                manifest = json.load(archive.extractfile(members['manifest.json']))
                if set(members) != set(manifest['files']) | {'manifest.json'}:
                    raise ValueError('member mismatch')
                for name, meta in manifest['files'].items():
                    member = members[name]
                    parts = PurePosixPath(name).parts
                    if not member.isfile() or '..' in parts or name.startswith('/'):
                        raise ValueError('unsafe member')
                    if _sha(archive.extractfile(member).read()) != meta['sha256']:
                        raise ValueError('hash mismatch')
        except (OSError, EOFError, tarfile.TarError, ValueError, KeyError) as exc:
            raise ValueError('Invalid configuration backup: ' + str(exc)) from exc

    def _prune(self):
        try:
            for stale in sorted(self.backups.glob('config_*.tgz'))[:-BACKUP_KEEP]:
                _durable_unlink(stale)
        except OSError:
            logging.warning('Config backup retention deferred; committed configuration is intact')

    def _transact(self, model, changed, backup, light, expected, keys, zone_names, removed, apply):
        journal = {'version': 1, 'backup': backup.name, 'root': str(self.root), 'files': {
            str(path.relative_to(self.root)): {'previous_b64': base64.b64encode(model.files[path].text.encode()).decode(),
                                              'previous_sha256': _sha(model.files[path].text.encode()),
                                              'new_sha256': _sha(text.encode())}
            for path, text in changed.items()}}
        _atomic(self.journal_path, (json.dumps(journal) + '\n').encode(), mode=0o600)
        activated = False
        try:
            for path, text in changed.items():
                _atomic(path, text.encode())
            self.checker(self.main)
            if apply:
                activated = True
                self.activate()
                self._verify_ctx(light, expected, keys, zone_names, removed, 'apply')
            _durable_unlink(self.journal_path)
        except Exception as error:
            try:
                for path in changed:
                    _atomic(path, model.files[path].text.encode())
                self.checker(self.main)
                if activated:
                    self.activate()
                    with self._light() as old_light:
                        old = {'port': self.option_reader(old_light, 'port')}
                        self._verify_ctx(old_light, old, [], [], [], 'rollback')
                _durable_unlink(self.journal_path)
            except Exception as rollback:
                self._recovery_required = True
                raise RuntimeError('Configuration rollback failed; run explicit recovery: ' + str(rollback)) from error
            raise

    # ----- verification --------------------------------------------------- #

    def _policy_probes(self):
        import filter_activation
        found = []
        for name, probe in (('webui-filters.conf', filter_activation.PROBE_NAME), ('webui-rewrites.conf', REWRITE_PROBE)):
            path = self.root / name
            if path.is_file():
                token = filter_activation.read_profile(path)[0]
                if token:
                    found.append((token, probe))
        return found

    def _endpoint(self, expected):
        host = os.environ.get('WEBUI_FILTER_VERIFY_HOST', '127.0.0.1')
        port = os.environ.get('WEBUI_FILTER_VERIFY_PORT') or self._text(expected.get('port', ['53']))
        return host, int(port)

    def _verify_ctx(self, light, expected, keys, zone_names, removed, phase):
        host, port = self._endpoint(expected)
        timeout = min(60.0, float(os.environ.get('WEBUI_CONFIG_VERIFY_TIMEOUT', '30')))
        context = {'phase': phase, 'host': host, 'port': port, 'timeout': timeout, 'control_config': light,
                   'options': {k: expected[k] for k in keys if k in expected} if phase == 'apply' else {},
                   'zones': zone_names, 'removed_zones': removed}
        self.verifier(context)

    def _verify(self, context):
        import filter_activation
        host, port, timeout = context['host'], context['port'], context['timeout']
        deadline = time.monotonic() + timeout
        probes = self.probes()
        for token, probe in probes:
            filter_activation.verify_policy(token, host=host, port=port, timeout=max(1.0, deadline - time.monotonic()), probe_name=probe)
        if not probes:
            reason = 'No DNS response'
            while time.monotonic() < deadline:
                try:
                    rcode, _ = filter_activation.query(host, port, 'localhost', 1, min(.5, max(.05, deadline - time.monotonic())))
                    if rcode == 0:
                        break
                    reason = f'Unexpected RCODE {rcode}'
                except (OSError, ValueError) as exc:
                    reason = str(exc)
                time.sleep(.1)
            else:
                raise RuntimeError('Unbound did not answer DNS after activation: ' + reason)
        reason = None
        while True:
            reason = self._mismatch(context)
            if reason is None:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError('Unbound is running a different configuration than the candidate: ' + reason)
            time.sleep(.25)

    def _mismatch(self, context):
        config = context['control_config']
        for key, want in context['options'].items():
            try:
                got = self.running_reader(config, key)
            except Exception as exc:
                return f'cannot read {key}: {exc}'
            if key in LISTS:
                try:
                    if self._list_value(key, want) != self._list_value(key, got):
                        return f'{key} is {self._text(got)!r}'
                except ConfigError as exc:
                    return str(exc)
            elif not in_sync(FIELDS[key], self._text(want), self._text(got)):
                return f'{key} is {self._text(got)!r}, expected {self._text(want)!r}'
        if context['zones'] or context['removed_zones']:
            try:
                lines = self.forwards_reader(config)
            except Exception as exc:
                return f'cannot list forwards: {exc}'
            present = {_zone_key(line.split(' ', 1)[0]) for line in lines if line.strip()}
            for name in context['zones']:
                if name not in present:
                    return f'forward zone {name} is not loaded'
            for name in context['removed_zones']:
                if name in present:
                    return f'forward zone {name} is still loaded'
        return None


# --------------------------------------------------------------------------- #
#  Offline recovery (never activates DNS)
# --------------------------------------------------------------------------- #

def recover(base, main, apply=False):
    manager = ConfigManager(base, main, _offline=True)
    if not manager.journal_path.exists():
        return {'journal': False, 'actions': []}
    journal = json.loads(manager.journal_path.read_text())
    if journal.get('version') != 1 or journal.get('root') != str(manager.root):
        raise ValueError('Unrecognised or foreign configuration journal; preserve it')
    actions = []
    for rel, meta in journal['files'].items():
        path = (manager.root / rel).absolute()
        if '..' in Path(rel).parts or not path.is_relative_to(manager.root):
            raise ValueError('Unsafe path in journal')
        previous = base64.b64decode(meta['previous_b64'])
        if _sha(previous) != meta['previous_sha256']:
            raise ValueError('Journal previous content does not match its hash')
        current = _sha(path.read_bytes()) if path.exists() else None
        action = 'already previous' if current == meta['previous_sha256'] else 'restore previous'
        actions.append({'file': rel, 'action': action, 'current_sha256': current})
        if apply and action == 'restore previous':
            _atomic(path, previous)
    if apply:
        for rel, meta in journal['files'].items():
            if _sha((manager.root / rel).read_bytes()) != meta['previous_sha256']:
                raise ValueError('Recovery verification failed; journal preserved')
        _durable_unlink(manager.journal_path)
    return {'journal': True, 'applied': apply, 'actions': actions}


# --------------------------------------------------------------------------- #
#  FastAPI integration
# --------------------------------------------------------------------------- #

def install(upstream, manager=None):
    """Authenticated threadpool routes replacing the upstream /config form."""
    from typing import Any
    from fastapi import Depends, HTTPException, Request
    from pydantic import BaseModel, ConfigDict, StrictBool

    manager = manager or ConfigManager(upstream.BASE_DIR, upstream.DEFAULT_CONFIG_FILE)
    upstream.config_manager = manager
    upstream.app.router.routes[:] = [r for r in upstream.app.router.routes
                                    if not (getattr(r, 'path', '') == '/config' and 'GET' in getattr(r, 'methods', set()))]
    read = [Depends(upstream._login_required)]
    write = read + [Depends(upstream._verify_csrf)]

    class ChangePayload(BaseModel):
        model_config = ConfigDict(extra='forbid')
        revision: str
        changes: dict[str, Any] = {}
        lists: dict[str, list[str]] = {}
        zones: list[dict[str, Any]] | None = None
        apply: StrictBool = True
        acknowledge: StrictBool = False

    class FilePayload(BaseModel):
        model_config = ConfigDict(extra='forbid')
        revision: str
        path: str
        content: str
        apply: StrictBool = False
        acknowledge: StrictBool = False

    class PendingPayload(BaseModel):
        model_config = ConfigDict(extra='forbid')
        revision: str

    def respond(fn, *args, **kwargs):
        try:
            result = fn(*args, **kwargs)
        except RevisionConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        except Exception as exc:
            raise HTTPException(500, str(exc)[:1000]) from exc
        return {'success': True, **result} if isinstance(result, dict) and 'state' in result else {'success': True, 'state': result}

    @upstream.app.get('/config', dependencies=read)
    def config_page(request: Request):
        return upstream._template(request, 'server_config.html', {'active_tab': 'config'})

    @upstream.app.get('/api/server-config', dependencies=read)
    def config_state():
        return respond(manager.snapshot)

    @upstream.app.post('/api/server-config', dependencies=write)
    def config_save(payload: ChangePayload):
        return respond(manager.save, payload.revision, payload.changes, payload.lists, payload.zones,
                       apply=payload.apply, acknowledge=payload.acknowledge)

    @upstream.app.get('/api/server-config/file', dependencies=read)
    def config_file(path: str):
        return respond(manager.read_file, path)

    @upstream.app.post('/api/server-config/file', dependencies=write)
    def config_file_save(payload: FilePayload):
        return respond(manager.save_file, payload.revision, payload.path, payload.content,
                       apply=payload.apply, acknowledge=payload.acknowledge)

    @upstream.app.post('/api/server-config/apply-pending', dependencies=write)
    def config_apply_pending(payload: PendingPayload):
        return respond(manager.apply_pending, payload.revision)

    return manager


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline recovery for interrupted WebUI configuration transactions. '
                                                 'Stop the WebUI first; this never reloads Unbound.')
    parser.add_argument('--base', required=True, help='WebUI application directory (holds config-data/)')
    parser.add_argument('--main', required=True, help='Main unbound.conf path')
    parser.add_argument('--apply', action='store_true', help='Restore previous file contents (default: dry run)')
    args = parser.parse_args(argv)
    print(json.dumps(recover(args.base, args.main, args.apply), indent=2))


if __name__ == '__main__':
    main()
