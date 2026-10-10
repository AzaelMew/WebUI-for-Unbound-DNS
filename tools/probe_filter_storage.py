"""Bounded cached multi-source import and ten-generation rollback disk probe.

Never activates DNS. Retention variants add one synthetic domain each to the
actual feed's cache/rules, measuring DIFFERENT generations, not ten hardlinks.
Only the initial empty configuration is checked; full disk measurement does not
pretend to be ten real network refreshes or ten resolver activations.
"""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))  # repo root: filters, filter_benchmark, run
import argparse
import contextlib
import copy
import json
import os
import resource
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import filters
import filter_benchmark as bench
import probe_filter_backend as backend


def run_storage(workspace, sources, urls, format='rpz', generations=10):
    root = backend.safe_workspace(workspace)
    if type(generations) is not int or not 1 <= generations <= 10 or not sources or len(sources) != len(urls):
        raise ValueError('Use matching source/URL arrays and 1–10 generations')
    allowed = (root, backend.WORKSPACE, bench.TARGET_WORKSPACE, Path.home() / '.hermes/cache/scratch')
    sources = [Path(source).absolute() for source in sources]
    for source, url in zip(sources, urls):
        if source.is_symlink() or not source.is_file() or not any(source.resolve().is_relative_to(parent.resolve()) for parent in allowed):
            raise ValueError('Only cached files in a controlled development workspace')
        filters.validate_url(url)
    production = backend.production_identity()
    result = {'timestamp_utc': datetime.now(timezone.utc).isoformat(), 'activated': False,
              'method': 'Actual disabled multi-source refresh, then synthetic one-domain variants with real cache copies/compressed backups; no resolver activation',
              'sources': [dict(url=url, bytes=source.stat().st_size, sha256=bench.sha256_file(source)) for source, url in zip(sources, urls)],
              'source_code_sha256': {name: bench.sha256_file(Path(__file__).resolve().parent.parent / name) for name in ['filters.py', 'filter_store.py', 'filter_resources.py', 'filter_activation.py']},
              'affinity': sorted(os.sched_getaffinity(0))}
    mapping = dict(zip(urls, sources))
    stop = threading.Event()
    minimum_free = [shutil.disk_usage(root).free]
    with tempfile.TemporaryDirectory(prefix='storage-', dir=root) as name:
        owned = Path(name)
        base = owned / 'app'
        base.mkdir()
        config = owned / 'unbound'
        config.mkdir()
        zones = config / 'unbound.conf.d'
        zones.mkdir()
        target = zones / 'webui-filters.conf'
        main = config / 'unbound.conf'
        main.write_text('server:\n    chroot: ""\n    username: ""\ninclude: "' + str(zones / '*.conf') + '"\n')
        def sample():
            while not stop.wait(.02):
                minimum_free[0] = min(minimum_free[0], shutil.disk_usage(root).free)
        monitor = threading.Thread(target=sample, daemon=True)
        monitor.start()
        try:
            manager = filters.FilterManager(base, main, target, activate=lambda: (_ for _ in ()).throw(RuntimeError('Probe forbids activation')), downloader=lambda url: mapping[url])
            manager.initialize_empty()
            identifier = manager.add_list('Cached multi-source feed', sources=urls, format=format)['lists'][0]['id']
            before = time.monotonic()
            state = manager.refresh_list(identifier)
            item = state['lists'][0]
            # Exclude the measurement setup's empty-policy rollback archive.
            for archive in manager.backups.glob('*.tgz'):
                archive.unlink()
            source_cache = manager.store.path(item['cache'])
            result['import'] = {'seconds': time.monotonic() - before, 'count': item['count'], 'unsupported': item['unsupported'],
                'downloaded_bytes': item['downloaded_bytes'], 'sqlite_bytes': source_cache.stat().st_size,
                'domain_sha256': bench.domain_digest(source_cache), 'python_self_peak_rss_mib': resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
                'snapshot_bytes': len(json.dumps(manager.snapshot(), separators=(',', ':')).encode()),
                'state_bytes': manager.state_path.stat().st_size}
            # Compile exactly once, without activating/validating a giant resolver.
            active = copy.deepcopy(manager.state)
            active['lists'][0]['enabled'] = True
            before = time.monotonic()
            manager._compile(active, target)
            result['render'] = {'seconds': time.monotonic() - before, 'bytes': target.stat().st_size}
            canonical = owned / (filters._file_digest(target) + '.conf.gz')
            filters._compress_blob(target, canonical)
            result['render']['gzip_bytes'] = canonical.stat().st_size
            # Each iteration copies the previous cache before GC can remove it.
            retention = []
            blob = None
            before = time.monotonic()
            for index in range(generations):
                filters.filter_resources.check_disk_headroom(base, source_cache.stat().st_size + target.stat().st_size + canonical.stat().st_size)
                reference = 'cache/' + uuid.uuid4().hex + '.sqlite'
                cache = manager.data / reference
                shutil.copyfile(source_cache, cache)
                domain = f'benchmark-storage-variant{index}.invalid'
                with contextlib.closing(sqlite3.connect(cache)) as db:
                    db.execute('PRAGMA cache_size=-2048')
                    db.execute('INSERT INTO domains VALUES (?)', (domain,))
                    db.commit()
                cache.chmod(0o400)
                filters._restore_blob(canonical, target)
                with target.open('a') as output:
                    # Later variants replace, rather than accumulate, their rule.
                    output.write(f'    local-zone: "{domain}." always_nxdomain\n')
                    output.flush()
                    os.fsync(output.fileno())
                updated = copy.deepcopy(active)
                updated['lists'][0].update(cache=reference, count=item['count'] + 1)
                updated['effective_count'] = item['count'] + 1
                manager._save_metadata(updated)
                archive, blob = manager._backup()
                assert blob is not None
                retention.append({'archive_bytes': archive.stat().st_size, 'compressed_fragment_bytes': blob.stat().st_size,
                                  'cache_bytes': cache.stat().st_size})
                # Keep original input cache only until its next copy is prepared;
                # no archived state references it. Copies each start from the
                # original data by dropping the prior synthetic variant.
                if source_cache != cache:
                    source_cache = cache
                active = copy.deepcopy(manager.state)
                # Next iteration source includes the current synthetic domain;
                # remove that only in the NEXT COPY below, never archived cache.
                if index + 1 < generations:
                    clean = owned / 'next-source.sqlite'
                    shutil.copyfile(cache, clean)
                    clean.chmod(0o600)
                    with contextlib.closing(sqlite3.connect(clean)) as db:
                        db.execute('DELETE FROM domains WHERE domain=?', (domain,))
                        db.commit()
                    source_cache = clean
                manager._gc()
            restored = owned / 'restored.conf'
            assert blob is not None
            filters._restore_blob(blob, restored)
            result['rollback_restored_exact_bytes'] = filters._file_digest(restored) == filters._file_digest(target)
            blobs = list((manager.backups / 'blobs').glob('*.conf.gz'))
            caches = list(manager.store.directory.glob('*.sqlite'))
            result['retention'] = {'archives': len(list(manager.backups.glob('*.tgz'))), 'distinct_blobs': len(blobs),
                'retained_caches': len(caches), 'compressed_blob_bytes': sum(p.stat().st_size for p in blobs),
                'cache_bytes': sum(p.stat().st_size for p in caches), 'allocated_data_bytes': backend.filedata(base)['allocated_unique_bytes'],
                'seconds': time.monotonic() - before, 'generations': retention,
                'scope': 'distinct synthetic minor changes to the actual feed; retained caches plus compressed rollback fragments, not ten remote snapshots'}
        finally:
            stop.set()
            monitor.join(2)
    result['minimum_disk_free_bytes_sampled'] = minimum_free[0]
    result['production_unchanged'] = production == backend.production_identity()
    if not result['production_unchanged']:
        raise RuntimeError('Production resolver identity changed')
    result['temporary_tree_removed'] = not owned.exists()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=backend.WORKSPACE)
    parser.add_argument('--source', type=Path, action='append', required=True)
    parser.add_argument('--url', action='append', required=True)
    parser.add_argument('--format', choices=['auto', 'domains', 'hosts', 'adblock', 'rpz'], default='rpz')
    parser.add_argument('--generations', type=int, default=10)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = backend.safe_workspace(args.workspace)
    if args.output.is_symlink() or not args.output.absolute().parent.resolve().is_relative_to(root):
        raise ValueError('Output must stay in the development workspace')
    os.sched_setaffinity(0, {min(os.sched_getaffinity(0))})
    result = run_storage(root, args.source, args.url, args.format, args.generations)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: value for key, value in result.items() if key not in ['source_code_sha256']}, indent=2))


if __name__ == '__main__':
    main()
