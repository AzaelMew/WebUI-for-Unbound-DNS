"""Standalone, opt-in resolver benchmarks. Never imports the deployment backend."""
import argparse
import ast
import contextlib
import gzip
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import socket
import sqlite3
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from datetime import datetime, timezone

TARGET_WORKSPACE = Path('/opt/unbound-filter-development/benchmark')


def safe_workspace(path):
    root = Path(path).resolve()
    if root == TARGET_WORKSPACE or root.is_relative_to(TARGET_WORKSPACE):
        root.mkdir(parents=True, exist_ok=True)
        return root
    # TMPDIR is caller-controlled; never let it authorize a production path.
    scratch = (Path.home() / '.hermes/cache/scratch').resolve()
    if root == scratch or root.is_relative_to(scratch):
        root.mkdir(parents=True, exist_ok=True)
        return root
    raise ValueError('Benchmark workspace must be development/benchmark or controlled scratch, never production')


@contextlib.contextmanager
def managed_process(command, *, stop_timeout=3, **kwargs):
    """Reap children on success, exceptions, timeouts and KeyboardInterrupt."""
    proc = subprocess.Popen(command, **kwargs)
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=stop_timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        else:
            proc.wait()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def normalize_domain(value):
    domain = value.strip().rstrip('.').lower().encode('idna').decode('ascii')
    if len(domain) > 253 or '.' not in domain or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in domain.split('.')):
        raise ValueError('Invalid domain')
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError('IP is not a domain')


def covered(domain, allowed):
    labels = domain.split('.')
    return any('.'.join(labels[i:]) in allowed for i in range(len(labels) - 1))


def parse_source(source, database):
    """Bounded, file-backed adblock/domains/hosts parser for comparisons."""
    started = time.monotonic()
    unsupported, records = 0, 0
    with contextlib.closing(sqlite3.connect(database)) as db:
        db.execute('PRAGMA cache_size=-4096')
        db.execute('PRAGMA journal_mode=OFF')
        db.execute('CREATE TABLE domains (domain TEXT PRIMARY KEY) WITHOUT ROWID')
        with open(source, encoding='utf-8-sig') as handle:
            for raw in handle:
                line = raw.strip()
                if not line or line.startswith(('#', '!', '[')):
                    continue
                try:
                    if re.fullmatch(r'\|\|[^\^]+\^', line):
                        values = [line[2:-1]]
                    else:
                        if '##' in line or '#@#' in line:
                            raise ValueError('Cosmetic')
                        values = line.split('#', 1)[0].split()
                        if len(values) > 1:
                            if str(ipaddress.ip_address(values[0])) not in {'0.0.0.0', '127.0.0.1', '::', '::1'}:
                                raise ValueError('Not blocking hosts')
                            values = values[1:]
                    normalized = [normalize_domain(d) for d in values if d.lower() not in {'localhost', 'localhost.localdomain', 'broadcasthost', 'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters'}]
                    db.executemany('INSERT OR IGNORE INTO domains VALUES (?)', ((d,) for d in normalized))
                    records += len(normalized)
                except (ValueError, UnicodeError):
                    unsupported += 1
                if records % 10000 == 0:
                    db.commit()
        db.commit()
        count = db.execute('SELECT COUNT(*) FROM domains').fetchone()[0]
    if not count:
        raise ValueError('No supported domains')
    return {'unique_domains': count, 'records': records, 'unsupported': unsupported, 'parse_s': time.monotonic() - started}


def render_domains(database, output, kind, allowed=()):
    allowed = {normalize_domain(d) for d in allowed}
    if kind not in {'localzone', 'rpz'}:
        raise ValueError('Unknown representation')
    count = 0
    with contextlib.closing(sqlite3.connect(database)) as db, open(output, 'w') as handle:
        if kind == 'localzone':
            handle.write('# Isolated filter benchmark\nserver:\n')
        else:
            handle.write('$ORIGIN benchmark-rpz.invalid.\n$TTL 60\n@ IN SOA localhost. root.localhost. (1 60 60 3600 60)\n@ IN NS localhost.\n')
        for (domain,) in db.execute('SELECT domain FROM domains ORDER BY domain'):
            if covered(domain, allowed):
                continue
            count += 1
            if kind == 'localzone':
                handle.write(f'    local-zone: "{domain}." always_nxdomain\n')
            else:
                handle.write(f'{domain} CNAME .\n*.{domain} CNAME .\n')
        for domain in sorted(allowed):
            if kind == 'localzone':
                handle.write(f'    local-zone: "{domain}." transparent\n')
            else:
                handle.write(f'{domain} CNAME rpz-passthru.\n*.{domain} CNAME rpz-passthru.\n')
    return count


def latency_summary(samples, errors):
    ordered = sorted(samples)
    return {'count': len(samples), 'errors': errors, 'median_ms': statistics.median(ordered) if ordered else None,
            'p95_ms': ordered[max(0, math.ceil(len(ordered) * .95) - 1)] if ordered else None,
            'max_ms': max(ordered) if ordered else None, 'samples_ms': samples}


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        tcp.bind(('127.0.0.1', 0))
        port = tcp.getsockname()[1]
        udp.bind(('127.0.0.1', port))
        if port < 1024:
            raise RuntimeError('Expected high port')
        return port


def skip_name(data, offset):
    while data[offset]:
        size = data[offset]
        if size & 0xc0 == 0xc0:
            return offset + 2
        offset += size + 1
    return offset + 1


def query(port, name, timeout=.5):
    if port < 1024:
        raise ValueError('Never query production DNS')
    transaction = int.from_bytes(os.urandom(2), 'big')
    encoded = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.rstrip('.').split('.')) + b'\x00'
    packet = struct.pack('!HHHHHH', transaction, 0x0100, 1, 0, 0, 0) + encoded + struct.pack('!HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        started = time.perf_counter_ns()
        sock.sendto(packet, ('127.0.0.1', port))
        data, peer = sock.recvfrom(65535)
        elapsed = (time.perf_counter_ns() - started) / 1e6
    ident, flags, questions, answers, _, _ = struct.unpack('!HHHHHH', data[:12])
    if ident != transaction or not flags & 0x8000 or peer != ('127.0.0.1', port):
        raise ValueError('Invalid DNS response')
    offset = 12
    for _ in range(questions):
        offset = skip_name(data, offset) + 4
    values = []
    for _ in range(answers):
        offset = skip_name(data, offset)
        kind, cls, ttl, size = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10
        if kind == 1 and cls == 1 and size == 4:
            values.append(socket.inet_ntoa(data[offset:offset+4]))
        offset += size
    return {'rcode': flags & 15, 'answers': values, 'ms': elapsed}


@contextlib.contextmanager
def mock_upstream():
    """Deterministic loopback-only DNS authority, no network recursion."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    sock.settimeout(.1)
    stop = threading.Event()
    state = argparse.Namespace(port=sock.getsockname()[1], queries=0, names=[])
    def serve():
        while not stop.is_set():
            try:
                data, peer = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            end = skip_name(data, 12) + 4
            name = []
            offset = 12
            while data[offset]:
                size = data[offset]
                name.append(data[offset+1:offset+1+size].decode('ascii'))
                offset += size + 1
            state.queries += 1
            state.names.append('.'.join(name))
            qtype = struct.unpack('!H', data[end-4:end-2])[0]
            count = 1 if qtype == 1 else 0
            response = data[:2] + struct.pack('!HHHHH', 0x8580, 1, count, 0, 0) + data[12:end]
            if count:
                response += b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + socket.inet_aton('192.0.2.123')
            sock.sendto(response, peer)
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        thread.join(timeout=2)
        sock.close()
        if thread.is_alive():
            raise RuntimeError('Mock upstream failed to exit')


def memory_available_mib():
    fields = dict((line.split(':')[0], int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines())
    available = fields['MemAvailable'] / 1024
    cg = Path('/sys/fs/cgroup')
    try:
        limit = int((cg / 'memory.max').read_text())
        current = int((cg / 'memory.current').read_text())
        stats = dict(line.split() for line in (cg / 'memory.stat').read_text().splitlines())
        available = min(available, (limit - current + int(stats.get('inactive_file', 0))) / 2**20)
    except (OSError, ValueError):
        pass
    return available


def check_headroom(minimum=384, disk_path=None, disk_minimum_mib=256):
    available = memory_available_mib()
    if available < minimum:
        raise RuntimeError(f'Headroom guard: {available:.1f} MiB available, need {minimum}')
    if disk_path is not None and shutil.disk_usage(disk_path).free < disk_minimum_mib * 2**20:
        raise RuntimeError('Disk headroom guard')
    return available


def limited(command, limit_mib=1024, cpu_seconds=180):
    cpu = min(os.sched_getaffinity(0))
    return ['prlimit', f'--as={limit_mib * 2**20}', f'--cpu={cpu_seconds}', '--', 'taskset', '-c', str(cpu)] + list(command)


def rss_mib(pid):
    try:
        values = dict((line.split(':')[0], line.split(':')[1].strip()) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
        return int(values.get('VmRSS', '0 kB').split()[0]) / 1024
    except (OSError, ValueError):
        return 0


def write_config(root, kind, fragment, port, upstream_port):
    root = Path(root).resolve()
    safe_workspace(root)
    if min(port, upstream_port) < 1024:
        raise ValueError('Only isolated high ports are allowed')
    if fragment is not None and not Path(fragment).resolve().is_relative_to(root):
        raise ValueError('Fragment outside isolated tree')
    config = root / f'{kind}-unbound.conf'
    modules = 'respip validator iterator' if kind == 'rpz' else 'validator iterator'
    config.write_text(f'''server:
    interface: 127.0.0.1
    port: {port}
    access-control: 127.0.0.0/8 allow
    username: ""
    directory: "{root}"
    chroot: ""
    pidfile: "{root}/{kind}.pid"
    use-syslog: no
    logfile: ""
    verbosity: 0
    num-threads: 1
    module-config: "{modules}"
    do-ip6: no
    do-not-query-localhost: no
    auto-trust-anchor-file: ""
    harden-dnssec-stripped: no
    qname-minimisation: no
    msg-cache-size: 4m
    rrset-cache-size: 4m
remote-control:
    control-enable: yes
    control-interface: "{root}/control.sock"
    control-use-cert: no
forward-zone:
    name: "."
    forward-addr: 127.0.0.1@{upstream_port}
''')
    with config.open('a') as out:
        if kind == 'localzone':
            out.write(f'include: "{fragment}"\n')
        elif kind == 'rpz':
            out.write(f'rpz:\n    name: "benchmark-rpz.invalid"\n    zonefile: "{fragment}"\n')
        elif kind != 'baseline':
            raise ValueError('Unknown representation')
    return config


def wait_dns(proc, port, timeout=90, guard=None):
    started = time.monotonic()
    while time.monotonic() - started < timeout:
        if proc.poll() is not None:
            raise RuntimeError(f'Unbound exited with {proc.returncode}')
        if guard:
            guard()
        try:
            answer = query(port, 'ready.benchmark-unfiltered.net', timeout=.1)
            if answer['rcode'] == 0 and answer['answers'] == ['192.0.2.123']:
                return time.monotonic() - started
        except (OSError, ValueError):
            pass
        time.sleep(.025)
    raise TimeoutError('No valid DNS answer before readiness deadline')


class BenchmarkFailure(RuntimeError):
    def __init__(self, message, metrics):
        super().__init__(message)
        self.metrics = dict(metrics)


@contextlib.contextmanager
def process_monitor(proc, disk_path=None):
    stop = threading.Event()
    state = {'peak_rss_mib': 0., 'minimum_headroom_mib': memory_available_mib(), 'guard_error': None}
    def sample():
        while not stop.wait(.01):
            state['peak_rss_mib'] = max(state['peak_rss_mib'], rss_mib(proc.pid))
            available = memory_available_mib()
            state['minimum_headroom_mib'] = min(state['minimum_headroom_mib'], available)
            if available < 384:
                state['guard_error'] = f'Headroom guard stopped child at {available:.1f} MiB'
                proc.terminate()
                break
            if disk_path is not None and shutil.disk_usage(disk_path).free < 256 * 2**20:
                state['guard_error'] = 'Disk headroom guard stopped child below 256 MiB free'
                proc.terminate()
                break
    thread = threading.Thread(target=sample, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        stop.set()
        thread.join(timeout=2)


@contextlib.contextmanager
def isolated_resolver(root, kind, fragment, upstream_port, timeout=90):
    port = free_port()
    config = write_config(root, kind, fragment, port, upstream_port)
    check_headroom(disk_path=root)
    before = time.monotonic()
    with managed_process(limited(['unbound-checkconf', str(config)]), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as check_proc, process_monitor(check_proc) as check_metrics:
        check_out, check_err = check_proc.communicate(timeout=timeout)
    check_s = time.monotonic() - before
    if check_proc.returncode:
        raise BenchmarkFailure('checkconf failed: ' + check_err.decode(errors='replace')[:2000], {'checkconf_s': check_s, 'checkconf_peak_rss_mib': check_metrics['peak_rss_mib'], 'checkconf_minimum_headroom_mib': check_metrics['minimum_headroom_mib'], 'checkconf_exit': check_proc.returncode})
    stop = threading.Event()
    state = {'port': port, 'config': str(config), 'checkconf_s': check_s, 'checkconf_peak_rss_mib': check_metrics['peak_rss_mib'], 'checkconf_minimum_headroom_mib': check_metrics['minimum_headroom_mib'], 'peak_rss_mib': 0., 'minimum_headroom_mib': memory_available_mib(), 'guard_error': None}
    log = Path(root) / f'{kind}.log'
    with log.open('wb') as output, managed_process(limited(['unbound', '-d', '-c', str(config)]), stdout=output, stderr=output) as proc:
        state['pid'] = proc.pid
        def sample():
            while not stop.wait(.01):
                state['peak_rss_mib'] = max(state['peak_rss_mib'], rss_mib(proc.pid))
                available = memory_available_mib()
                state['minimum_headroom_mib'] = min(state['minimum_headroom_mib'], available)
                if available < 384:
                    state['guard_error'] = f'Memory guard stopped isolated child: {available:.1f} MiB'
                    proc.terminate()
                    break
        thread = threading.Thread(target=sample, daemon=True)
        thread.start()
        def guard():
            if state['guard_error']:
                raise RuntimeError(state['guard_error'])
        try:
            started = time.monotonic()
            wait_dns(proc, port, timeout, guard)
            state['startup_dns_ready_s'] = time.monotonic() - started
            state['startup_peak_rss_mib'] = state['peak_rss_mib']
            state['steady_rss_mib'] = rss_mib(proc.pid)
            yield state
            guard()
        except Exception as exc:
            raise RuntimeError(f'{exc}; isolated log: {log.read_text(errors="replace")[-2000:]}') from exc
        finally:
            stop.set()
            thread.join(timeout=2)


FEED_URLS = {
    'mini': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.mini.txt',
    'full': 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/tif.txt',
}


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()


def source_info(source, url=None):
    headers = []
    with open(source, encoding='utf-8-sig') as handle:
        for _ in range(30):
            line = handle.readline().rstrip()
            if line.startswith(('!', '#', '[')):
                headers.append(line)
    return {'url': url, 'bytes': Path(source).stat().st_size, 'sha256': sha256_file(source), 'feed_headers': headers}


def cached_source_info(source, url=None):
    metadata_path = Path(str(source) + '.metadata.json')
    if metadata_path.is_symlink():
        raise ValueError('Refusing symlink metadata')
    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else source_info(source, url)
    actual = source_info(source, metadata.get('url', url))
    if metadata.get('sha256') != actual['sha256']:
        raise ValueError('Cached source hash mismatch; refusing stale provenance')
    return {**metadata, **actual, 'download_reused': True}


def download_source(url, output, max_bytes=100 * 2**20, timeout=90):
    if not url.startswith('https://'):
        raise ValueError('Only HTTPS sources')
    safe_workspace(Path(output).parent)
    check_headroom(disk_path=Path(output).parent, disk_minimum_mib=512)
    started = time.monotonic()
    count = 0
    partial = Path(str(output) + '.partial')
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'Unbound-Isolated-Benchmark/1', 'Accept-Encoding': 'identity'}), timeout=20) as response, partial.open('wb') as destination:
            if int(response.headers.get('Content-Length', '0')) > max_bytes:
                raise ValueError('Source too large')
            response_headers = dict(response.headers)
            final_url = response.url
            while True:
                if time.monotonic() - started > timeout:
                    raise TimeoutError('Download deadline exceeded')
                chunk = response.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > max_bytes:
                    raise ValueError('Source too large')
                destination.write(chunk)
        os.replace(partial, output)
    finally:
        partial.unlink(missing_ok=True)
    return {**source_info(output, url), 'final_url': final_url, 'download_s': time.monotonic() - started, 'response_headers': response_headers, 'downloaded_at_utc': datetime.now(timezone.utc).isoformat()}


def domain_digest(database, output=None):
    digest = hashlib.sha256()
    with contextlib.closing(sqlite3.connect(database)) as db, (open(output, 'wb') if output else contextlib.nullcontext()) as cache:
        for (domain,) in db.execute('SELECT domain FROM domains ORDER BY domain'):
            data = (domain + '\n').encode()
            digest.update(data)
            if cache is not None:
                cache.write(data)
    return digest.hexdigest()


def original_functions(source):
    """Load only original pure algorithm AST, never import filters/safety/app."""
    tree = ast.parse(Path(source).read_text())
    wanted = {'parse_list', 'normalize_domain', '_covered', 'render_config'}
    nodes = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in wanted]
    if {node.name for node in nodes} != wanted:
        raise ValueError('Original algorithm snapshot incomplete')
    namespace = {'re': re, 'ipaddress': ipaddress, 'MAX_BYTES': 100 * 2**20, 'MAX_DOMAINS': 3_000_000,
                 'HEADER': '# Managed by Unbound WebUI domain filters; do not edit.\nserver:\n'}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), '<original-pure-algorithm>', 'exec'), namespace)
    return namespace


def worker(mode, source, root, original_source=None):
    root = safe_workspace(root)
    before = time.monotonic()
    if mode == 'bounded':
        database = root / 'domains.sqlite'
        result = parse_source(source, database)
        result['domain_sha256'] = domain_digest(database, root / 'canonical-domains.txt')
        result['parse_peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        for kind in ('localzone', 'rpz'):
            started = time.monotonic()
            count = render_domains(database, root / f'{kind}.rules', kind)
            result[kind] = {'render_s': time.monotonic() - started, 'rules_domains': count, 'bytes': (root / f'{kind}.rules').stat().st_size}
        result['sqlite_cache_bytes'] = database.stat().st_size
    elif mode == 'original':
        funcs = original_functions(original_source)
        started = time.monotonic()
        parsed = funcs['parse_list'](Path(source).read_bytes(), max_domains=3_000_000)
        result = {'parse_s': time.monotonic() - started, 'unique_domains': len(parsed['domains']), 'unsupported': parsed['unsupported'], 'parse_peak_rss_mib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}
        digest = hashlib.sha256()
        for domain in parsed['domains']:
            digest.update((domain + '\n').encode())
        result['domain_sha256'] = digest.hexdigest()
        started = time.monotonic()
        config, count = funcs['render_config'](parsed['domains'], [], max_domains=3_000_000)
        (root / 'original.rules').write_text(config)
        result['localzone'] = {'render_s': time.monotonic() - started, 'rules_domains': count, 'bytes': len(config.encode())}
    else:
        raise ValueError('Unknown worker')
    result['worker_s'] = time.monotonic() - before
    result['python_peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    return result


def run_worker(mode, source, root, original_source=None, timeout=240):
    check_headroom(disk_path=root, minimum=1280 if mode == 'original' else 384)
    command = [sys.executable, str(Path(__file__).resolve()), '--worker', mode, '--source', str(source), '--workspace', str(root)]
    if original_source:
        command += ['--original-source', str(original_source)]
    with managed_process(limited(command, 1024 if mode == 'original' else 256, 220), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc, process_monitor(proc, root) as monitor:
        try:
            # communicate is bounded; the worker returns only small JSON, not feed data.
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            raise TimeoutError(f'{mode} worker timed out')
        if proc.returncode:
            raise RuntimeError(f'{mode} worker failed ({proc.returncode}); guard={monitor["guard_error"]}: {err.decode(errors="replace")[-1600:]}')
        result = json.loads(out)
        result['minimum_headroom_mib'] = monitor['minimum_headroom_mib']
        result['sampled_peak_rss_mib'] = monitor['peak_rss_mib']
        return result


def production_identity():
    # Read-only /proc inspection; no supervisor operations or production DNS queries.
    result = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            if (path / 'comm').read_text().strip() != 'unbound':
                continue
            cmdline = (path / 'cmdline').read_bytes().replace(b'\0', b' ').decode()
            if str(TARGET_WORKSPACE) in cmdline:
                continue
            stat = (path / 'stat').read_text().split(') ', 1)[1].split()
            result.append({'pid': int(path.name), 'start_ticks': int(stat[19]), 'cmdline': cmdline})
        except (OSError, ValueError):
            pass
    return sorted(result, key=lambda item: item['pid'])


def measure_queries(port, names, rcode, answers, upstream):
    samples, errors, failures = [], 0, []
    before = upstream.queries
    deadline = time.monotonic() + 30
    for name in names:
        if time.monotonic() > deadline:
            raise TimeoutError('Query batch exceeded 30 seconds')
        started = time.perf_counter_ns()
        try:
            answer = query(port, name, timeout=1)
            samples.append(answer['ms'])
            if answer['rcode'] != rcode or answer['answers'] != answers:
                errors += 1
                failures.append({'name': name, 'response': answer})
        except (OSError, ValueError, struct.error) as exc:
            samples.append((time.perf_counter_ns() - started) / 1e6)
            errors += 1
            failures.append({'name': name, 'error': str(exc)})
    return {**latency_summary(samples, errors), 'upstream_queries': upstream.queries - before, 'failures': failures[:10]}


def reload_isolated(state, timeout=90):
    started = time.monotonic()
    root = Path(state['config']).parent
    safe_workspace(root)
    # Both explicit config AND explicit private UNIX socket; cannot hit production.
    command = ['unbound-control', '-c', state['config'], '-s', str(root / 'control.sock'), 'reload']
    reply = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    if reply.returncode:
        return {'error': (reply.stderr or reply.stdout)[:1600], 'mode': 'isolated UNIX control reload'}
    # reload response arrives after config reload; fresh uncached query proves activation.
    answer = query(state['port'], f'activated-{time.time_ns()}.benchmark-unfiltered.net', timeout=timeout)
    if answer['rcode'] != 0 or answer['answers'] != ['192.0.2.123']:
        raise RuntimeError('Reload did not activate valid DNS')
    return {'seconds': time.monotonic() - started, 'mode': 'isolated UNIX control reload', 'response': reply.stdout.strip(), 'dns': answer}


def artifact_sizes(path, root):
    gz = root / (path.name + '.gz')
    with path.open('rb') as source, gzip.open(gz, 'wb', compresslevel=6) as output:
        shutil.copyfileobj(source, output, length=65536)
    hardlink = root / (path.name + '.backup')
    os.link(path, hardlink)
    result = {'bytes': path.stat().st_size, 'gzip_bytes': gz.stat().st_size,
              'hardlink_backup_additional_data_bytes': 0 if hardlink.stat().st_ino == path.stat().st_ino else hardlink.stat().st_blocks * 512}
    hardlink.unlink()
    gz.unlink()
    return result


def benchmark(root, source, original_source=None, cached_count=150, uncached_count=50):
    root = safe_workspace(root)
    if cached_count < 100 or uncached_count < 30:
        raise ValueError('At least 100 cached/blocked and 30 uncached samples')
    identity = production_identity()
    cpu_available = sorted(os.sched_getaffinity(0))
    nproc = int(subprocess.check_output(['nproc'], text=True).strip())
    os.sched_setaffinity(0, {cpu_available[0]})
    result = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'method': 'sequential isolated resolvers, deterministic loopback upstream, socket nanosecond timer; validator without trust anchors; no real-network latency claim',
              'affinity_before': cpu_available, 'affinity_benchmark': sorted(os.sched_getaffinity(0)), 'nproc_reported': nproc, 'host_logical_cpus': os.cpu_count(), 'pinning': 'taskset -c for all workers/checkconf/resolvers plus inherited benchmark affinity',
              'limits': {'resolver_as_mib': 1024, 'bounded_python_as_mib': 256, 'original_python_as_mib': 1024, 'minimum_headroom_mib': 384, 'resolver_ready_timeout_s': 90},
              'production_before': identity, 'environment_before': environment_info(), 'source': source_info(source), 'resolvers': [],
              'original_algorithm': {'source_sha256': sha256_file(original_source), 'limits_overridden_for_comparison': '100 MiB and 3,000,000 domains; production original defaults are 20 MiB/300,000'} if original_source else None}
    try:
        result['parser'] = run_worker('bounded', source, root)
        if original_source:
            try:
                result['original_parser'] = run_worker('original', source, root, original_source)
                result['same_domain_set'] = result['original_parser']['domain_sha256'] == result['parser']['domain_sha256']
                if not result['same_domain_set']:
                    raise ValueError('Original and bounded parser differ; cannot compare')
            except (RuntimeError, TimeoutError) as exc:
                result['original_parser'] = {'error': str(exc)}
        database = root / 'domains.sqlite'
        with contextlib.closing(sqlite3.connect(database)) as db:
            blocked = [row[0] for row in db.execute('SELECT domain FROM domains ORDER BY domain LIMIT ?', (cached_count,))]
        for kind in ('localzone', 'rpz'):
            result['parser'][kind]['storage'] = artifact_sizes(root / f'{kind}.rules', root)
        result['parser']['cache_storage'] = artifact_sizes(database, root)
        result['parser']['canonical_domain_cache_storage'] = artifact_sizes(root / 'canonical-domains.txt', root)
        result['parser']['source_storage'] = artifact_sizes(Path(source), root)
        for kind in ('baseline', 'localzone', 'rpz'):
            state = {'kind': kind}
            try:
                check_headroom(disk_path=root)
                with mock_upstream() as upstream:
                    fragment = None if kind == 'baseline' else root / f'{kind}.rules'
                    with isolated_resolver(root, kind, fragment, upstream.port) as resolver:
                        state = resolver
                        state['kind'] = kind
                        query(state['port'], 'cached.benchmark-unfiltered.net')
                        state['cached'] = measure_queries(state['port'], ['cached.benchmark-unfiltered.net'] * cached_count, 0, ['192.0.2.123'], upstream)
                        state['uncached'] = measure_queries(state['port'], [f'unique-{i}.benchmark-unfiltered.net' for i in range(uncached_count)], 0, ['192.0.2.123'], upstream)
                        block_names = (blocked * math.ceil(cached_count / len(blocked)))[:cached_count]
                        state['blocked'] = measure_queries(state['port'], block_names, 0 if kind == 'baseline' else 3, ['192.0.2.123'] if kind == 'baseline' else [], upstream)
                        state['descendant_blocked'] = measure_queries(state['port'], ['descendant.' + blocked[0]] * cached_count, 0 if kind == 'baseline' else 3, ['192.0.2.123'] if kind == 'baseline' else [], upstream)
                        state['reload'] = reload_isolated(state)
                        state['post_reload_rss_mib'] = rss_mib(state['pid'])
                result['resolvers'].append(state)
            except (RuntimeError, TimeoutError, subprocess.SubprocessError, OSError) as exc:
                result['resolvers'].append({**state, **getattr(exc, 'metrics', {}), 'error': str(exc)})
            print(json.dumps({'progress': kind, 'startup_s': state.get('startup_dns_ready_s'), 'rss_mib': state.get('steady_rss_mib'), 'error': result['resolvers'][-1].get('error')}), file=sys.stderr, flush=True)
    finally:
        result['production_after'] = production_identity()
        result['environment_after'] = environment_info()
        result['production_unchanged'] = result['production_after'] == identity
        os.sched_setaffinity(0, set(cpu_available))
    if not result['production_unchanged']:
        raise RuntimeError('Production PID/start identity changed during benchmark')
    return result


def environment_info():
    memory = dict((line.split(':')[0], int(line.split()[1])) for line in Path('/proc/meminfo').read_text().splitlines())
    return {'unbound_version': subprocess.check_output(['unbound', '-V'], stderr=subprocess.STDOUT, text=True, timeout=5),
            'memory_total_mib': memory['MemTotal'] / 1024, 'memory_available_mib': memory['MemAvailable'] / 1024,
            'swap_total_mib': memory['SwapTotal'] / 1024, 'swap_used_mib': (memory['SwapTotal'] - memory['SwapFree']) / 1024,
            'production_ps': subprocess.run(['ps', '-C', 'unbound', '-o', 'pid,lstart,args'], capture_output=True, text=True, timeout=5).stdout,
            'disk_free_mib': shutil.disk_usage(TARGET_WORKSPACE if TARGET_WORKSPACE.exists() else Path.home()).free / 2**20}


def main(default_feed=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=TARGET_WORKSPACE)
    parser.add_argument('--source', type=Path, help='Use cached source file; never downloads again')
    parser.add_argument('--feed', choices=FEED_URLS, default=default_feed or 'mini')
    parser.add_argument('--url', help='Override public HTTPS source')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--original-source', type=Path, help='Original filters.py snapshot; extracts pure AST only')
    parser.add_argument('--worker', choices=('bounded', 'original'), help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = safe_workspace(args.workspace)
    if args.worker:
        print(json.dumps(worker(args.worker, args.source, root, args.original_source)))
        return
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'signal {signum}')
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        source = args.source.absolute() if args.source else root / f'tif-{args.feed}.source.txt'
        safe_workspace(source.parent)
        if source.is_symlink():
            raise ValueError('Refusing symlink source')
        output = args.output or root / f'{args.feed}-result.json'
        safe_workspace(output.parent)
        if output.is_symlink():
            raise ValueError('Refusing symlink result')
        url = args.url or FEED_URLS[args.feed]
        metadata_path = Path(str(source) + '.metadata.json')
        if source.exists():
            metadata = cached_source_info(source, url if not args.source else None)
        else:
            metadata = download_source(url, source)
            metadata_path.write_text(json.dumps(metadata, indent=2) + '\n')
        with tempfile.TemporaryDirectory(prefix=f'run-{args.feed}-', dir=root) as td:
            result = benchmark(Path(td), source, args.original_source)
            result['source'] = metadata
        # Results are small; source downloads never enter the repository.
        output.write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'result_path': str(output), 'source': metadata, 'parser': result['parser'], 'original_parser': result.get('original_parser'), 'production_unchanged': result['production_unchanged']}))
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    main()
