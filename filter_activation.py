"""Verify activated managed policy with bounded wire-DNS probes, not PID state."""
import hashlib
import ipaddress
import math
import os
import re
import secrets
import socket
import struct
import time
from pathlib import Path

# normalize_domain() rejects underscore labels, reserving this private canary.
PROBE_NAME = 'policy-check._webui.invalid'
TOKEN_PREFIX = '# WebUI policy verification token: '
BLOCK = re.compile(r'^\s*local-zone:\s*"([a-z0-9.-]+)\."\s+always_nxdomain\s*$')


def read_profile(path):
    path = Path(path)
    if not path.exists():
        return None, None
    blocked = None
    with path.open(encoding='ascii') as source:
        for line in source:
            match = BLOCK.fullmatch(line.rstrip('\n'))
            if match:
                blocked = match[1]
                break
    with path.open('rb') as source:
        source.seek(max(0, path.stat().st_size - 1024))
        tail = source.read(1024).decode('ascii')
    tokens = [line[len(TOKEN_PREFIX):] for line in tail.splitlines() if line.startswith(TOKEN_PREFIX)]
    if tokens and (len(tokens) != 1 or not re.fullmatch(r'[0-9a-f]{64}', tokens[0])):
        raise ValueError('Malformed managed policy verification token')
    return tokens[0] if tokens else None, blocked


def stamp_policy(path):
    path = Path(path)
    previous, blocked = read_profile(path)
    if previous is not None:
        raise ValueError('Refusing to stamp an already stamped policy')
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            digest.update(chunk)
    token = digest.hexdigest()
    with path.open('a', encoding='ascii') as output:
        output.write(TOKEN_PREFIX + token + '\n')
        output.write(f'    local-zone: "{PROBE_NAME}." static\n')
        output.write(f'    local-data: \'{PROBE_NAME}. IN TXT "{token}"\'\n')
        output.flush()
        os.fsync(output.fileno())
    return token, blocked


def _name_end(packet, offset):
    for _ in range(128):
        if offset >= len(packet):
            raise ValueError('Truncated DNS name')
        size = packet[offset]
        offset += 1
        if size & 0xc0 == 0xc0:
            if offset >= len(packet):
                raise ValueError('Truncated DNS pointer')
            return offset + 1
        if size & 0xc0 or size > 63 or offset + size > len(packet):
            raise ValueError('Invalid DNS label')
        if size == 0:
            return offset
        offset += size
    raise ValueError('DNS name too long')


def _answer(packet, identifier, question):
    if len(packet) < 12:
        raise ValueError('Short DNS response')
    identity, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', packet[:12])
    if identity != identifier or not flags & 0x8000 or flags & 0x7a00 or questions != 1:
        raise ValueError('Invalid DNS response header')
    offset = _name_end(packet, 12) + 4
    if packet[12:offset] != question:
        raise ValueError('DNS verification question mismatch')
    texts = []
    for _ in range(answers):
        offset = _name_end(packet, offset)
        if offset + 10 > len(packet):
            raise ValueError('Truncated DNS record')
        kind, cls, _, size = struct.unpack('!HHIH', packet[offset:offset + 10])
        start, end = offset + 10, offset + 10 + size
        if end > len(packet):
            raise ValueError('Truncated DNS data')
        if kind == 16 and cls == 1:
            value = bytearray()
            while start < end:
                length = packet[start]
                start += 1
                if start + length > end:
                    raise ValueError('Truncated TXT value')
                value.extend(packet[start:start + length])
                start += length
            texts.append(value.decode('ascii'))
        offset = end
    return flags & 15, texts


def query(host, port, name, kind, timeout):
    labels = name.rstrip('.').encode('ascii').split(b'.')
    if len(name) > 253 or any(not 0 < len(label) <= 63 for label in labels):
        raise ValueError('Invalid DNS verification name')
    question = b''.join(bytes([len(label)]) + label for label in labels) + b'\0' + struct.pack('!HH', kind, 1)
    identifier = secrets.randbelow(65536)
    request = struct.pack('!HHHHHH', identifier, 0x0100, 1, 0, 0, 0) + question
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.send(request)
        packet = sock.recv(4096)
    return _answer(packet, identifier, question)


def verify_policy(token, blocked_domain=None, host=None, port=None, timeout=None):
    host = host if host is not None else os.environ.get('WEBUI_FILTER_VERIFY_HOST', '127.0.0.1')
    port = int(port if port is not None else os.environ.get('WEBUI_FILTER_VERIFY_PORT', '53'))
    timeout = float(timeout if timeout is not None else os.environ.get('WEBUI_FILTER_VERIFY_TIMEOUT', '10'))
    if not 1 <= port <= 65535 or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError('Invalid DNS verification endpoint/timeout')
    ipaddress.ip_address(host)  # Numeric only: no unbounded libc hostname lookup.
    if token is not None and not re.fullmatch(r'[0-9a-f]{64}', token):
        raise ValueError('Invalid expected policy token')
    deadline = time.monotonic() + timeout
    reason = 'No DNS response'
    while time.monotonic() < deadline:
        try:
            rcode, texts = query(host, port, PROBE_NAME, 16, min(.5, deadline - time.monotonic()))
            loaded = (rcode in {0, 3} and not texts) if token is None else (rcode == 0 and texts == [token])
            if not loaded:
                raise ValueError('DNS serves a different managed policy token')
            if blocked_domain:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or query(host, port, blocked_domain, 1, min(.5, remaining))[0] != 3:
                    raise ValueError('DNS does not enforce the candidate blocked policy')
            return
        except (OSError, ValueError, UnicodeError) as exc:
            reason = str(exc)
        time.sleep(min(.05, max(0, deadline - time.monotonic())))
    raise RuntimeError('Unbound policy activation verification failed: ' + reason)
