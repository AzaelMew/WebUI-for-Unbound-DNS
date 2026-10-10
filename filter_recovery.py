"""Explicit offline filter recovery. Stop the WebUI before running this CLI.

Restores only managed policy and metadata, never unrelated Unbound files and
never reloads a resolver. Archives require their external blobs/cache files.
"""
import argparse
import gzip
import copy
import json
import os
import re
import shutil
import tarfile
import tempfile
import time
from pathlib import Path, PurePosixPath
import filters
from safety import _LOCK


_EMPTY = {'version': 2, 'blocked': [], 'allowed': [], 'lists': [], 'effective_count': 0}


def _confined(path, root=None, regular=False):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('Recovery refuses symlink paths: ' + str(path))
    if root is not None and not path.resolve().is_relative_to(Path(root).resolve()):
        raise ValueError('Recovery path outside approved directory')
    if regular and not path.is_file():
        raise ValueError('Recovery artifact missing or not a regular file: ' + str(path))
    return path.resolve()


def _json_member(archive, name, required=False):
    try:
        member = archive.getmember(name)
    except KeyError:
        if required:
            raise ValueError('Backup missing ' + name) from None
        return None
    if not member.isfile() or member.size > 16 * 1024 * 1024:
        raise ValueError('Invalid or oversized backup metadata')
    try:
        with archive.extractfile(member) as source:
            return json.load(source)
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Malformed backup metadata: ' + name) from exc


def _read_backup(backup, manager, deadline=None):
    # Do not extract any archived config: it is reference material only. Reject
    # unsafe entries even though this path never calls tar.extract/extractall.
    try:
        # tarfile stops at the tar end marker before the gzip CRC/footer; read
        # the entire compressed stream separately to certify its integrity.
        with gzip.open(backup, 'rb') as source:
            for chunk in iter(lambda: source.read(65536), b''):
                filters.check_deadline(deadline)
        with tarfile.open(backup, 'r:gz') as archive:
            names = set()
            for member in archive:
                filters.check_deadline(deadline)
                path = PurePosixPath(member.name)
                if (path.is_absolute() or '..' in path.parts or '\\' in member.name or
                        member.name in names or not (member.isfile() or member.isdir()) or
                        not (member.name in {'unbound', 'filter-state.json', 'filter-manifest.json'} or
                             member.name.startswith('unbound/'))):
                    raise ValueError('Unsafe or duplicate backup archive member: ' + member.name)
                names.add(member.name)
            manifest = _json_member(archive, 'filter-manifest.json', required=True)
            state = _json_member(archive, 'filter-state.json')
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise ValueError('Corrupt backup archive') from exc
    if not isinstance(manifest, dict) or manifest.get('managed_file') != str(manager.target.relative_to(manager.root)):
        raise ValueError('Backup manifest managed path does not match selected target')
    reference = manifest.get('managed_blob')
    if reference is not None and (not isinstance(reference, str) or
            not re.fullmatch(r'blobs/[0-9a-f]{64}\.conf(?:\.gz)?', reference)):
        raise ValueError('Invalid backup blob reference')
    blob = _confined(manager.backups / reference, manager.backups, regular=True) if reference else None
    return state if state is not None else copy.deepcopy(_EMPTY), blob


def _check_tree(root):
    _confined(root)
    for directory, names, files in os.walk(root, followlinks=False):
        for name in names + files:
            path = Path(directory) / name
            if path.is_symlink() or (not path.is_dir() and not path.is_file()):
                raise ValueError('Recovery refuses symlink or special config file: ' + str(path))


def _stage_current(manager, stage):
    _check_tree(manager.root)
    def ignore(directory, names):
        return [manager.target.name] if Path(directory) == manager.target.parent else []
    shutil.copytree(manager.root, stage, ignore=ignore)
    # Validate the CURRENT complete tree with the recovered managed fragment.
    # Only includes are relocated; certificates and trust anchors stay intact.
    for conf in stage.rglob('*.conf'):
        replacement = conf.with_suffix('.relocate')
        with conf.open() as source, replacement.open('w') as output:
            for line in source:
                output.write(re.sub(r'^(\s*include(?:-toplevel)?:\s*)(.*)$',
                    lambda m: m.group(1) + m.group(2).replace(str(manager.root) + '/', str(stage) + '/'), line))
        os.replace(replacement, conf)


class _RecoveryManager(filters.FilterManager):
    def _ready(self):
        # Explicit offline recovery is the only permitted bypass of this guard.
        pass

    def _load_state(self):
        # The current state may be incomplete; never silently migrate/reset it.
        return copy.deepcopy(_EMPTY)


def recover(base, main, target, backup=None, restore=False, checker=None, journal=False):
    base = _confined(base)
    main = _confined(main, regular=True)
    target = _confined(target, main.parent)
    manager = _RecoveryManager(base, main, target, activate=lambda: None)
    _confined(manager.state_path, manager.data)
    _confined(manager.journal_path, manager.data)
    metadata_recovery = False
    recovered_state, selected = None, None
    recovered_raw = None
    if journal:
        if backup is not None:
            raise ValueError('Select a backup or the pending journal, not both')
        _confined(manager.journal_path, manager.data, regular=True)
        pending = json.loads(manager.journal_path.read_text())
        if not isinstance(pending, dict):
            raise ValueError('Malformed recovery journal')
        metadata_recovery = pending.get('kind') == 'metadata'
        if metadata_recovery:
            if 'previous_state' not in pending:
                raise ValueError('Metadata journal missing previous state')
            recovered_state = pending['previous_state']
            text = pending.get('previous_state_text')
            if text is not None:
                if not isinstance(text, str) or json.loads(text) != recovered_state:
                    raise ValueError('Metadata journal previous state text mismatch')
                recovered_raw = text.encode('utf-8')
        else:
            backup = pending.get('backup')
    if not metadata_recovery:
        if not isinstance(backup, str) or not re.fullmatch(r'filters_[A-Za-z0-9_-]+\.tgz', backup):
            raise ValueError('Select a retained backup basename, not a path')
        selected = _confined(manager.backups / backup, manager.backups, regular=True)
    deadline = time.monotonic() + manager.refresh_timeout
    with _LOCK, tempfile.TemporaryDirectory(prefix='.filter-recover-', dir=base) as tmp:
        state, blob = ((recovered_state if recovered_state is not None else copy.deepcopy(_EMPTY), None)
                       if metadata_recovery else _read_backup(selected, manager, deadline))
        legacy = isinstance(state, dict) and state.get('version') == 1
        manager._validate_state(state, legacy=legacy, deadline=deadline)
        if legacy and not metadata_recovery:
            raise ValueError('Legacy archive requires prior explicit migration')
        if not legacy:
            filters.filter_resources.check_disk_headroom(base, manager._disk_requirement(state))
            filters.filter_resources.check_disk_headroom(manager.root, manager._disk_requirement(state))
            effective = manager.store.union(state, None, manager.limits['max_entries'], filters.HEADER, filters._covered, deadline)
            if effective != state['effective_count']:
                raise ValueError('Backup effective count does not match cached policy')
        stage = Path(tmp) / 'unbound'
        _stage_current(manager, stage)
        staged = stage / target.relative_to(manager.root)
        staged.parent.mkdir(parents=True, exist_ok=True)
        canonical = Path(tmp) / 'canonical.conf'
        if not legacy:
            manager._compile(state, canonical, deadline)
        if metadata_recovery:
            if target.exists():
                _confined(target, manager.root, regular=True)
                filters._atomic_copy(target, staged)
            elif recovered_state is None:
                filters._atomic(staged, filters.HEADER.encode(), mode=0o644)
            else:
                raise ValueError('Managed fragment missing for metadata recovery')
        elif blob:
            filters._restore_blob(blob, staged, deadline, max_bytes=canonical.stat().st_size + 512)
        else:
            if state['blocked'] or state['allowed'] or state['lists']:
                raise ValueError('Nonempty backup state has no managed fragment')
            filters._atomic(staged, filters.HEADER.encode(), mode=0o644)
        if not legacy:
            token, _ = filters.filter_activation.read_profile(staged)
            if token is not None:
                filters.filter_activation.stamp_policy(canonical)
            if filters._file_digest(canonical, deadline) != filters._file_digest(staged, deadline):
                raise ValueError('Backup fragment does not match canonical cached policy')
        check = checker or (lambda path: manager._check(path, deadline))
        check(stage / main.relative_to(manager.root))
        check(staged)
        result = {'backup': backup, 'restored': False, 'activated': False,
                  'effective_count': state.get('effective_count')}
        if not restore:
            return result
        # Reject unrelated current fragments before the first persistent write.
        if target.exists():
            with target.open('rb') as source:
                if source.read(len(filters.HEADER)) != filters.HEADER.encode():
                    raise ValueError('Current managed header missing; refusing unrelated config')
        current_state = manager.state_path.read_bytes() if manager.state_path.exists() else None
        original_journal = manager.journal_path.read_bytes() if manager.journal_path.exists() else None
        current_backup, current_blob = manager._backup(deadline)
        journal = {'kind': 'recovery', 'backup': current_backup.name,
                   'restoring_backup': backup,
                   'previous_blob': str(current_blob.relative_to(manager.backups)) if current_blob else None,
                   'candidate_caches': [item['cache'] for item in state['lists'] if item.get('cache')],
                   'previous_journal': json.loads(original_journal) if original_journal else None}
        filters._atomic(manager.journal_path, (json.dumps(journal) + '\n').encode())
        try:
            if not metadata_recovery:
                filters._atomic_copy(staged, target)
            check(main)
            if metadata_recovery and recovered_state is None:
                manager._restore_state(None)
            else:
                filters._atomic(manager.state_path, recovered_raw if metadata_recovery and recovered_raw is not None else
                                (json.dumps(state) + '\n').encode())
                manager._validate_state(json.loads(manager.state_path.read_text()), legacy=legacy, deadline=deadline)
            if not (metadata_recovery and recovered_state is None and not target.exists()) and filters._file_digest(staged) != filters._file_digest(target):
                raise ValueError('Restored live fragment differs from validated candidate')
            manager._clear_journal()
        except Exception as error:
            try:
                if current_blob:
                    filters._restore_blob(current_blob, target)
                else:
                    filters._durable_unlink(target)
                manager._restore_state(current_state)
                # Keep the recovery journal even after a successful rollback.
                if not manager.journal_path.exists():
                    filters._atomic(manager.journal_path, (json.dumps(journal) + '\n').encode())
            except Exception as rollback:
                manager._retain_journal(journal)
                raise RuntimeError(f'Recovery rollback failed; preserve {current_backup.name} and journal: {rollback}') from error
            raise
        result['restored'] = True
        result['safety_backup'] = current_backup.name
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description='Offline validated filter restore; stop WebUI first. Resolver is never activated.')
    for name in ('base', 'main', 'target'):
        parser.add_argument('--' + name, required=True)
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument('--backup', help='Retained backup basename')
    selection.add_argument('--journal', action='store_true', help='Recover the pending transaction/metadata journal')
    parser.add_argument('--restore', action='store_true', help='Explicitly replace only managed fragment and metadata; default is validation only')
    args = parser.parse_args(argv)
    try:
        result = recover(args.base, args.main, args.target, args.backup, restore=args.restore, journal=args.journal)
    except Exception as exc:
        parser.exit(1, 'Recovery refused: ' + str(exc) + '\n')
    print(json.dumps(result, sort_keys=True))
    print('Restored and validated; resolver not activated.' if args.restore else 'Validated dry run; nothing restored or activated.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
