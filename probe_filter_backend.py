"""Opt-in FINAL FilterManager benchmark; cached sources only, no production activation.

Run with the deployment venv inside the separate final-backend workspace. Every
configuration is created below an owned TemporaryDirectory. Child AS limits are
safety bounds, NOT an emulation of systemd MemoryMax (which counts a cgroup).
"""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch
import filter_benchmark as bench

WORKSPACE = Path('/opt/unbound-filter-development/final-backend')


def safe_workspace(path):
    root = Path(path).resolve()
    scratch = (Path.home() / '.hermes/cache/scratch').resolve()
    if not any(root == allowed or root.is_relative_to(allowed) for allowed in (WORKSPACE, scratch)):
        raise ValueError('Only final-backend development workspace or controlled scratch allowed')
    root.mkdir(parents=True, exist_ok=True)
    return root


@contextlib.contextmanager
def owned_process(command, *, own_group=True, stop_timeout=3, **kwargs):
    """Own/reap children. Worker children inherit the launcher's kill group."""
    proc = subprocess.Popen(command, start_new_session=own_group, **kwargs)
    def send(sig):
        try:
            if own_group:
                os.killpg(proc.pid, sig)
            elif proc.poll() is None:
                proc.send_signal(sig)
        except ProcessLookupError:
            pass
    try:
        yield proc
    finally:
        send(signal.SIGTERM)
        try:
            proc.wait(timeout=stop_timeout)
        except subprocess.TimeoutExpired:
            send(signal.SIGKILL)
            proc.wait(timeout=5)
        if own_group:
            send(signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                stream.close()


def compact(database, output, root):
    """Exact ancestor pruning via disk-backed reverse-label sort.

    A trailing dot separates labels. Descendants form a contiguous key range;
    after discarding that range the most recent retained key is sufficient.
    No set of feed domains is materialized. Only pure block policies apply.
    """
    import sqlite3
    started = time.monotonic()
    safe_workspace(root)
    if not Path(output).resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Compact output must stay inside isolated tree')
    temporary = Path(root) / 'compact.sqlite'
    kept = total = 0
    try:
        with contextlib.closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=ro', uri=True)) as source, contextlib.closing(sqlite3.connect(temporary)) as dest:
            source.execute('PRAGMA cache_size=-2048')
            source.execute('PRAGMA temp_store=FILE')
            source.execute("PRAGMA temp_store_directory='" + str(Path(root).resolve()).replace("'", "''") + "'")
            source.create_function('reverse_labels', 1, lambda d: '.'.join(reversed(d.split('.'))) + '.')
            dest.execute('PRAGMA cache_size=-2048')
            dest.execute('PRAGMA journal_mode=OFF')
            dest.execute('CREATE TABLE domains(domain TEXT PRIMARY KEY) WITHOUT ROWID')
            previous = None
            for domain, key in source.execute('SELECT domain, reverse_labels(domain) AS reversed FROM domains ORDER BY reversed'):
                total += 1
                if previous is not None and key.startswith(previous):
                    continue
                dest.execute('INSERT INTO domains VALUES (?)', (domain,))
                previous = key
                kept += 1
            dest.commit()
            with Path(output).open('w') as handle:
                handle.write('# Isolated ancestor-pruned block policy\nserver:\n')
                for domain, in dest.execute('SELECT domain FROM domains ORDER BY domain'):
                    handle.write(f'    local-zone: "{domain}." always_nxdomain\n')
        return {'domains': kept, 'input_domains': total, 'redundant_domains': total - kept,
                'reduction_percent': 100 * (total - kept) / total if total else 0,
                'seconds': time.monotonic() - started, 'bytes': Path(output).stat().st_size,
                'sha256': bench.sha256_file(output), 'equivalence': 'Identical always_nxdomain apex/descendant policy; no allowlist in this compact experiment'}
    finally:
        temporary.unlink(missing_ok=True)


def production_identity():
    return [i for i in bench.production_identity() if '/opt/unbound-filter-development/' not in i['cmdline'] and '.hermes/cache/scratch/' not in i['cmdline']]


def filedata(root):
    seen, files = set(), []
    for path in sorted(Path(root).rglob('*')):
        if path.is_file() and not path.is_symlink():
            st = path.stat()
            key = (st.st_dev, st.st_ino)
            files.append({'path': str(path.relative_to(root)), 'bytes': st.st_size,
                          'allocated_unique_bytes': 0 if key in seen else st.st_blocks * 512, 'links': st.st_nlink})
            seen.add(key)
    return {'allocated_unique_bytes': sum(f['allocated_unique_bytes'] for f in files), 'files': files}


def config_tree(root, upstream_port, port):
    if min(upstream_port, port) < 1024:
        raise ValueError('Only isolated high ports')
    tree = root / 'unbound'
    (tree / 'unbound.conf.d').mkdir(parents=True)
    target = tree / 'unbound.conf.d/webui-filters.conf'
    main = tree / 'unbound.conf'
    main.write_text(f'''server:
    interface: 127.0.0.1
    port: {port}
    access-control: 127.0.0.0/8 allow
    username: ""
    directory: "{tree}"
    chroot: ""
    pidfile: "{tree}/isolated.pid"
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
    forward-addr: 127.0.0.1@{upstream_port}
include: "{target}"
''')
    return main, target


def run_backend(workspace, source, url, compact_probe=False):
    """Run the actual backend; its _check is unchanged, only child run is bounded.

    Activation is a verified isolated cold start AFTER real transaction checks,
    not a hot-refresh/headroom claim. No large resolver overlaps a checker.
    """
    import filters
    import itertools
    from types import SimpleNamespace
    root = safe_workspace(workspace)
    source = Path(source).absolute()
    source_roots = (WORKSPACE, Path('/opt/unbound-filter-development/benchmark'), (Path.home() / '.hermes/cache/scratch').resolve())
    if source.is_symlink() or not any(source.resolve().is_relative_to(p) for p in source_roots):
        raise ValueError('Only cached development or controlled scratch sources')
    bench.check_headroom(disk_path=root, disk_minimum_mib=384)
    result = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'source': bench.source_info(source, url),
              'events': [], 'owned_pids': [], 'activation_verifications': [], 'affinity': sorted(os.sched_getaffinity(0)),
              'production_before': production_identity(), 'environment_before': bench.environment_info(),
              'source_code_sha256': {n: bench.sha256_file(Path(__file__).parent / n) for n in ('filters.py', 'filter_store.py', 'safety.py', 'filter_benchmark.py', 'filter_resources.py', 'container_memory.py')},
              'method': 'Actual FilterManager; cached Path downloader; sequential real staged main/fragment/live checks; test callback cold-starts isolated Unbound and verifies DNS',
              'limits': {'python_worker_as_mib': 512, 'validation_as_mib': 'backend preflight-selected, <=1280', 'resolver_as_mib': 1024, 'servicecap_comparison_as_mib': 512, 'minimum_memory_headroom_mib': 384, 'minimum_disk_headroom_mib': 384}}
    phase = ['initialize']
    started = time.monotonic()
    old_tempdir = tempfile.tempdir
    owned_root = None
    def guard():
        return bench.check_headroom(disk_path=owned_root or root, disk_minimum_mib=384)

    @contextlib.contextmanager
    def monitor(proc):
        stop = threading.Event()
        state = {'peak_rss_mib': bench.rss_mib(proc.pid), 'minimum_headroom_mib': guard(), 'guard_error': None}
        def sample():
            while not stop.wait(.01):
                state['peak_rss_mib'] = max(state['peak_rss_mib'], bench.rss_mib(proc.pid))
                try:
                    state['minimum_headroom_mib'] = min(state['minimum_headroom_mib'], guard())
                except RuntimeError as exc:
                    state['guard_error'] = str(exc)
                    proc.terminate()
                    break
        thread = threading.Thread(target=sample, daemon=True)
        thread.start()
        try:
            yield state
        finally:
            state['peak_rss_mib'] = max(state['peak_rss_mib'], bench.rss_mib(proc.pid))
            stop.set()
            thread.join(2)

    def check(path, cap=1024, timeout=180, command=None):
        path = Path(path).resolve()
        if owned_root is None or not path.is_relative_to(owned_root):
            raise ValueError('Checker escaped owned temporary tree')
        guard()
        before = time.monotonic()
        with owned_process(command or bench.limited(['unbound-checkconf', str(path)], cap), own_group=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc, monitor(proc) as state:
            result['owned_pids'].append(proc.pid)
            out, err = proc.communicate(timeout=timeout)
        result['events'].append(dict(state, operation='checkconf', phase=phase[0], path=str(path.relative_to(owned_root)), as_limit_mib=cap,
                                     seconds=time.monotonic() - before, returncode=proc.returncode, stderr=err.decode(errors='replace')[-1200:]))
        if state['guard_error']:
            raise RuntimeError(state['guard_error'])
        return subprocess.CompletedProcess(['unbound-checkconf', str(path)], proc.returncode, out.decode(errors='replace'), err.decode(errors='replace'))

    def backend_run(command, **kwargs):
        import filter_resources
        if len(command) == 2 and command[0] == 'unbound-checkconf':
            return check(command[1], timeout=kwargs.get('timeout', 180))
        if len(command) != 6 or command != filter_resources.validator_command(command[4], Path(command[5]), int(command[3])) or Path(command[4]).name != 'unbound-checkconf':
            raise RuntimeError('Backend probe forbids service/network commands')
        # Preserve the actual new backend's preflight and fresh exec wrapper.
        return check(command[5], cap=int(command[3]) / 2**20, timeout=kwargs.get('timeout', 180), command=command)

    def timed(operation, fn):
        def wrapped(*a, **kw):
            before = time.monotonic()
            try:
                return fn(*a, **kw)
            finally:
                result['events'].append({'operation': operation, 'phase': phase[0], 'seconds': time.monotonic() - before,
                                         'python_self_peak_rss_mib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024})
        return wrapped

    @contextlib.contextmanager
    def resolver(main, port, label, names, cap=1024):
        guard()
        before = time.monotonic()
        log = owned_root / (label + '.log')
        with log.open('wb') as output, owned_process(bench.limited(['unbound', '-d', '-c', str(main)], cap), own_group=False, stdout=output, stderr=output) as proc, monitor(proc) as metrics:
            result['owned_pids'].append(proc.pid)
            try:
                bench.wait_dns(proc, port, timeout=90, guard=guard)
                state = {'startup_s': time.monotonic() - before, 'startup_peak_rss_mib': metrics['peak_rss_mib'],
                         'steady_rss_mib': bench.rss_mib(proc.pid), 'port': port, 'pid': proc.pid, 'as_limit_mib': cap, 'queries': {}}
                groups = {'unfiltered': ([f'allowed-{i}.benchmark-unfiltered.net' for i in range(10)], 0, ['192.0.2.123'])}
                if names:
                    groups.update(blocked=(names, 3, []), descendant=(['descendant.' + names[0]], 3, []))
                for name, (queries, code, answers) in groups.items():
                    response = bench.measure_queries(port, queries, code, answers, upstream)
                    response.pop('samples_ms', None)
                    state['queries'][name] = response
                    if response['errors']:
                        raise RuntimeError('Isolated DNS verification failed: ' + repr(response))
                yield state
                state.update(metrics, steady_rss_mib=bench.rss_mib(proc.pid))
            except Exception as exc:
                raise RuntimeError(str(exc) + '; isolated log: ' + log.read_text(errors='replace')[-1200:]) from exc

    try:
        with tempfile.TemporaryDirectory(prefix='backend-', dir=root) as td:
            owned_root = Path(td).resolve()
            tempfile.tempdir = str(owned_root)
            base = owned_root / 'app'
            base.mkdir()
            with bench.mock_upstream() as upstream, contextlib.ExitStack() as activation_stack:
                port = bench.free_port()
                main, target = config_tree(owned_root, upstream.port, port)
                target.write_text(filters.HEADER)
                with resolver(main, port, 'baseline', []) as baseline:
                    result['baseline'] = baseline
                target.unlink()
                names = []
                def activate():
                    if activation_stack._exit_callbacks:
                        raise RuntimeError('Refusing overlap with earlier test resolver')
                    phase[0] = 'service-preflight-comparison'
                    import filter_resources
                    before_children = len(result['owned_pids'])
                    try:
                        with patch.object(filter_resources, 'process_headroom', return_value=512 * 2**20):
                            manager._check(main)
                        preflight = {'accepted': True}
                    except ValueError as exc:
                        preflight = {'accepted': False, 'error': str(exc)}
                    result['service_preflight_512_remaining'] = dict(preflight, validator_children_launched=len(result['owned_pids']) - before_children,
                        caveat='Injected remaining service budget of 512 MiB, an optimistic bound; actual service available memory is lower. No production/cgroup change.')
                    phase[0] = 'servicecap-comparison'
                    capped = check(main, 512)
                    result['servicecap_512_as_check'] = {'returncode': capped.returncode, 'stderr': capped.stderr,
                                                        'caveat': 'RLIMIT_AS comparison, NOT actual systemd 512 MiB MemoryMax cgroup test'}
                    phase[0] = 'activation'
                    result['resolver'] = activation_stack.enter_context(resolver(main, port, 'final', names))
                    phase[0] = 'enable'
                def verify(token, blocked):
                    filters.filter_activation.verify_policy(token, blocked, port=port)
                    previous = json.loads(manager.state_path.read_text())
                    result['activation_verifications'].append({'token': token, 'blocked': blocked,
                        'verified_before_state_commit': not previous['lists'][0]['enabled']})
                manager = filters.FilterManager(base, main, target, activate=activate, verifier=verify,
                    downloader=lambda requested: source if requested == url else (_ for _ in ()).throw(ValueError('Unexpected URL')))
                proxy_shutil = SimpleNamespace(**{n: getattr(shutil, n) for n in dir(shutil) if not n.startswith('__')})
                proxy_shutil.copyfile = timed('cached_download_copy', shutil.copyfile)
                with patch.object(filters, 'subprocess', SimpleNamespace(run=backend_run)), patch.object(filters, 'shutil', proxy_shutil), patch.object(filters, '_atomic_copy', timed('atomic_copy', filters._atomic_copy)), patch.object(manager, '_compile', timed('compile_union', manager._compile)), patch.object(manager.store, 'build', timed('parse_build_sqlite', manager.store.build)), patch.object(manager, '_backup', timed('backup_transaction', manager._backup)):
                    manager.initialize_empty()
                    phase[0] = 'add'
                    item = manager.add_list('Cached isolated feed', url, format='auto')['lists'][0]
                    phase[0] = 'disabled-refresh'
                    before = time.monotonic()
                    refreshed = manager.refresh_list(item['id'])
                    result['disabled_refresh_s'] = time.monotonic() - before
                    cached = manager.store.path(refreshed['lists'][0]['cache'])
                    metadata = refreshed['lists'][0]
                    result['cache'] = {'count': metadata['count'], 'downloaded_bytes': metadata['downloaded_bytes'], 'unsupported': metadata['unsupported'],
                                       'sqlite_bytes': cached.stat().st_size, 'allocated_bytes': cached.stat().st_blocks * 512, 'domain_sha256': bench.domain_digest(cached)}
                    names = list(itertools.islice(manager.store.domains(metadata['cache']), 20))
                    phase[0] = 'enable'
                    before = time.monotonic()
                    enabled = manager.enable_list(item['id'], True)
                    result['enable_total_s'] = time.monotonic() - before
                    diagnostic_s = sum(e['seconds'] for e in result['events'] if e['operation'] == 'checkconf' and e['phase'] in {'servicecap-comparison', 'service-preflight-comparison'})
                    result['enable_total_includes_diagnostic_checks'] = True
                    result['enable_diagnostic_check_s'] = diagnostic_s
                    result['enable_excluding_diagnostic_check_s'] = result['enable_total_s'] - diagnostic_s
                    activation_stack.close()  # Stop before any further Full check/transaction.
                    result['backend_python_self_peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
                    digest = hashlib.sha256(filters.HEADER.encode())
                    count = 0
                    for domain in manager.store.domains(enabled['lists'][0]['cache']):
                        digest.update(f'    local-zone: "{domain}." always_nxdomain\n'.encode())
                        count += 1
                    token = digest.hexdigest()
                    marker = (filters.filter_activation.TOKEN_PREFIX + token + '\n' +
                        f'    local-zone: "{filters.filter_activation.PROBE_NAME}." static\n' +
                        f'    local-data: \'{filters.filter_activation.PROBE_NAME}. IN TXT "{token}"\'\n')
                    digest.update(marker.encode())
                    result['rendered'] = {'domains': count, 'bytes': target.stat().st_size, 'sha256': bench.sha256_file(target), 'canonical_sha256': digest.hexdigest()}
                    result['canonical_match'] = result['rendered']['sha256'] == digest.hexdigest()
                    if not result['canonical_match']:
                        raise RuntimeError('Canonical local-zone output mismatch')
                    before = time.monotonic()
                    for _ in range(25):
                        serialized = json.dumps(manager.snapshot(), separators=(',', ':')).encode()
                    result['snapshot'] = {'bytes': len(serialized), 'mean_snapshot_serialize_s': (time.monotonic() - before) / 25,
                                          'state_json_bytes': manager.state_path.stat().st_size, 'effective_count': manager.state['effective_count'],
                                          'subscription_domain_arrays': sum('domains' in i for i in manager.state['lists'])}
                    phase[0] = 'backup-current-fragment'
                    before = time.monotonic()
                    archive, blob = manager._backup()
                    assert blob is not None
                    first_s = time.monotonic() - before
                    before_data = filedata(base)
                    before_blobs = filedata(manager.backups / 'blobs')
                    before = time.monotonic()
                    _, blob2 = manager._backup()
                    assert blob2 is not None
                    after_data = filedata(base)
                    after_blobs = filedata(manager.backups / 'blobs')
                    same_inode = blob.stat().st_ino == target.stat().st_ino and blob.stat().st_dev == target.stat().st_dev
                    result['backup'] = {'seconds': first_s, 'repeated_seconds': time.monotonic() - before, 'archive_bytes': archive.stat().st_size,
                                        'blob_bytes': blob.stat().st_size, 'same_inode_as_managed': same_inode, 'same_blob_reused': blob == blob2,
                                        'compression': 'gzip', 'additional_data_bytes': blob.stat().st_blocks * 512,
                                        'repeated_blob_allocated_delta_bytes': after_blobs['allocated_unique_bytes'] - before_blobs['allocated_unique_bytes'],
                                        'repeated_backup_allocated_delta_bytes': after_data['allocated_unique_bytes'] - before_data['allocated_unique_bytes']}
                    result['disk'] = filedata(owned_root)
                    # Fault recovery is proven on a small independent policy;
                    # never overlap a Full resolver with a Full validator.
                    phase[0] = 'rollback-fixture'
                    rollback_root = owned_root / 'rollback-fixture'
                    rollback_base = rollback_root / 'app'
                    rollback_base.mkdir(parents=True)
                    rollback_port = bench.free_port()
                    rollback_main, rollback_target = config_tree(rollback_root, upstream.port, rollback_port)
                    with contextlib.ExitStack() as rollback_stack:
                        reject = [False]
                        def rollback_activate():
                            rollback_stack.close()
                            _, first = filters.filter_activation.read_profile(rollback_target)
                            rollback_stack.enter_context(resolver(rollback_main, rollback_port, 'rollback-fixture', [first] if first else []))
                        def rollback_verify(token, blocked):
                            filters.filter_activation.verify_policy(token, blocked, port=rollback_port)
                            if reject[0]:
                                reject[0] = False
                                raise RuntimeError('Injected candidate verification failure')
                        rollback_manager = filters.FilterManager(rollback_base, rollback_main, rollback_target,
                            activate=rollback_activate, verifier=rollback_verify)
                        rollback_manager.initialize_empty()
                        rollback_manager.set_domains('blocked', ['old.example'])
                        rollback_stack.close()
                        old_policy = rollback_target.read_bytes()
                        old_metadata = rollback_manager.state_path.read_bytes()
                        reject[0] = True
                        try:
                            rollback_manager.set_domains('blocked', ['new.example'])
                        except RuntimeError as exc:
                            if 'Injected candidate' not in str(exc):
                                raise
                        else:
                            raise RuntimeError('Expected candidate verification failure')
                        token, blocked = filters.filter_activation.read_profile(rollback_target)
                        filters.filter_activation.verify_policy(token, blocked, port=rollback_port)
                        result['rollback'] = {'policy_bytes_restored': old_policy == rollback_target.read_bytes(),
                            'state_bytes_restored': old_metadata == rollback_manager.state_path.read_bytes(),
                            'canary_verified': True, 'scope': 'small independent actual DNS fixture, not Full hot refresh'}
                    if compact_probe:
                        phase[0] = 'compact'
                        output = owned_root / 'compact.conf'
                        result['compact'] = compact(cached, output, owned_root)
                        capped = check(output, 512)
                        result['compact']['check_512_as'] = {'returncode': capped.returncode, 'stderr': capped.stderr}
                        if capped.returncode:
                            expanded = check(output, 1024)
                            result['compact']['check_1024_as'] = {'returncode': expanded.returncode, 'stderr': expanded.stderr}
                        else:
                            compact_main = main.parent / 'compact-main.conf'
                            compact_main.write_text(main.read_text().replace(str(target), str(output)))
                            with resolver(compact_main, port, 'compact', names, 512) as state:
                                result['compact']['resolver'] = state
                    result['worker_python_self_peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        result['temporary_tree_removed'] = not owned_root.exists()
    finally:
        tempfile.tempdir = old_tempdir
        result['production_after'] = production_identity()
        result['production_unchanged'] = result['production_before'] == result['production_after']
        result['environment_after'] = bench.environment_info()
    if not result['production_unchanged']:
        raise RuntimeError('Production resolver identity changed')
    result['total_s'] = time.monotonic() - started
    result['not_measured'] = ['Production hot refresh/full resolver concurrent with checker: unsafe on 2 GiB LXC', 'Actual systemd 512 MiB service cgroup; RLIMIT_AS is not MemoryMax', 'External-network download/recursion latency; cached copies and deterministic loopback DNS only']
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=WORKSPACE)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--url', required=True)
    parser.add_argument('--sha256')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--compact', action='store_true')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = safe_workspace(args.workspace)
    if args.sha256 and bench.sha256_file(args.source) != args.sha256:
        raise ValueError('Cached source hash mismatch')
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    if args.worker:
        print(json.dumps(run_backend(root, args.source, args.url, args.compact)))
        return
    output = args.output or root / 'final-backend-result.json'
    if output.is_symlink() or not output.absolute().parent.resolve().is_relative_to(root):
        raise ValueError('Output must remain in safe workspace')
    affinity = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(affinity)})
    command = [sys.executable, str(Path(__file__).resolve()), '--worker', '--workspace', str(root), '--source', str(args.source), '--url', args.url]
    if args.compact:
        command.append('--compact')
    if args.sha256:
        command += ['--sha256', args.sha256]
    worker_command = bench.limited(command, 512, 590)
    # Keep Python soft-AS bounded while allowing a checker to raise to 1 GiB.
    worker_command[1] = f'--as={512 * 2**20}:{1280 * 2**20}'
    try:
        with owned_process(worker_command, stop_timeout=10, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
            stop = threading.Event()
            sampled = {'python_sampled_peak_rss_mib': 0., 'minimum_headroom_mib': bench.memory_available_mib(), 'guard_error': None}
            def sample_worker():
                while not stop.wait(.02):
                    sampled['python_sampled_peak_rss_mib'] = max(sampled['python_sampled_peak_rss_mib'], bench.rss_mib(proc.pid))
                    try:
                        available = bench.check_headroom(disk_path=root, disk_minimum_mib=384)
                        sampled['minimum_headroom_mib'] = min(sampled['minimum_headroom_mib'], available)
                    except RuntimeError as exc:
                        sampled['guard_error'] = str(exc)
                        proc.terminate()
                        break
            thread = threading.Thread(target=sample_worker, daemon=True)
            thread.start()
            try:
                out, err = proc.communicate(timeout=600)
            finally:
                stop.set()
                thread.join(2)
        if proc.returncode:
            raise RuntimeError(f'Backend worker failed ({proc.returncode}); guard={sampled["guard_error"]}: ' + err.decode(errors='replace')[-4000:])
        data = json.loads(out)
        data['launcher_monitor'] = sampled
        data['launcher_python_self_peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
        output.write_text(json.dumps(data, indent=2) + '\n')
        print(json.dumps({'result_path': str(output), 'cache': data['cache'], 'python_peak_rss_mib': data['backend_python_self_peak_rss_mib'], 'resolver_rss_mib': data['resolver']['steady_rss_mib'], 'production_unchanged': data['production_unchanged']}))
    finally:
        os.sched_setaffinity(0, affinity)


if __name__ == '__main__':
    main()
