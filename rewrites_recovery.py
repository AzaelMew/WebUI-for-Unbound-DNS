"""Explicit OFFLINE rewrite recovery. Default dry-run; NEVER activates DNS.

Stop the WebUI before --apply. After recovery, validate/reload/verify Unbound
explicitly before restarting the UI. Only the rewrite fragment and state are
restored; archived unrelated configuration and omitted filters are context.
"""
import argparse
import json
import re
import tarfile
import tempfile
from pathlib import Path
from safety import _LOCK
from rewrites import RewriteManager, HEADER, MAX_FRAGMENT, _regular, _validate_state
from filters import _atomic, _durable_unlink, _check_config_tree


BACKUP_NAME = re.compile(r'rewrites_[0-9]+_[0-9a-f]{32}\.tgz')


def _state(raw):
    if raw is None:
        return {'version': 1, 'revision': 0, 'records': [], 'last_updated': None}
    if not isinstance(raw, str) or len(raw.encode()) > 2 * 1024 * 1024:
        raise ValueError('Malformed recovery journal state')
    return _validate_state(json.loads(raw))


def _archive(manager, backup):
    backup = Path(backup).absolute()
    if backup.parent != manager.backups or not BACKUP_NAME.fullmatch(backup.name):
        raise ValueError('Recovery backup must be an owned rewrite archive')
    manager._verify_backup(backup)
    own = 'unbound/' + str(manager.target.relative_to(manager.root))
    with tarfile.open(backup, 'r:gz') as archive:
        names = archive.getnames()
        state = archive.extractfile('rewrite-state.json').read().decode() if 'rewrite-state.json' in names else None
        fragment = archive.extractfile(own).read().decode('ascii') if own in names else None
    return state, fragment


def _journal(manager):
    _regular(manager.journal_path, 16 * 1024 * 1024)
    try:
        journal = json.loads(manager.journal_path.read_text())
        common = {'version', 'kind', 'config_root', 'managed_file', 'previous_state_text'}
        if (not isinstance(journal, dict) or type(journal.get('version')) is not int or journal['version'] != 1 or
                journal.get('kind') not in {'metadata', 'policy'} or journal.get('config_root') != str(manager.root) or
                journal.get('managed_file') != str(manager.target.relative_to(manager.root)) or
                set(journal) != (common if journal['kind'] == 'metadata' else common | {'backup', 'previous_fragment_text'})):
            raise ValueError('Malformed recovery journal schema/path')
        _state(journal['previous_state_text'])
        if journal['kind'] == 'policy':
            state, fragment = _archive(manager, manager.backups / journal['backup'])
            if (state, fragment) != (journal['previous_state_text'], journal['previous_fragment_text']):
                raise ValueError('Recovery journal does not match verified backup')
        return journal
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        raise ValueError('Invalid rewrite recovery journal: ' + str(exc)) from exc


def recover(base, main, target, *, backup=None, apply=False, webui_stopped=False):
    """Validate recovery against CURRENT config; no extraction of unrelated files.

    backup=None uses the interrupted journal. A backup path selects an older
    snapshot. apply requires an explicit assertion that the WebUI was stopped;
    a process-local lock cannot protect against another running UI process.
    """
    if apply and not webui_stopped:
        raise ValueError('The WebUI must be stopped before offline recovery --apply')
    with _LOCK:
        manager = RewriteManager(base, main, target, activate=lambda: None, _offline=True)
        _check_config_tree(manager.root)
        _regular(manager.state_path, 2 * 1024 * 1024)
        if backup is None:
            journal = _journal(manager)
        else:
            # Never silently discard a malformed pre-existing journal.
            if manager.journal_path.exists():
                _journal(manager)
            state_text, fragment_text = _archive(manager, backup)
            journal = {'version': 1, 'kind': 'policy', 'config_root': str(manager.root),
                       'managed_file': str(manager.target.relative_to(manager.root)), 'backup': Path(backup).name,
                       'previous_state_text': state_text, 'previous_fragment_text': fragment_text}
        state = _state(journal['previous_state_text'])
        fragment = (journal['previous_fragment_text'] if journal['kind'] == 'policy' else
                    (manager._managed_bytes().decode('ascii') if manager.target.exists() else None))
        if fragment is not None:
            if not isinstance(fragment, str) or len(fragment.encode('ascii')) > MAX_FRAGMENT or not fragment.startswith(HEADER):
                raise ValueError('Invalid recovery fragment managed header/size')
        elif manager._enabled(state['records']):
            raise ValueError('Recovery state has enabled records but no fragment')
        manager._validate_policy(state, fragment.encode('ascii') if fragment is not None else None)
        manager._conflicts(state['records'])
        with tempfile.TemporaryDirectory(prefix='.rewrite-recovery-', dir=manager.base) as directory:
            stage = Path(directory) / 'unbound'
            staged = manager._stage(stage, (fragment if fragment is not None else HEADER).encode('ascii'))
            if fragment is None:
                staged.unlink()
            manager._check(stage / manager.main.relative_to(manager.root))
        result = {'applied': False, 'revision': state['revision'], 'records': len(state['records']),
                  'managed_file': str(manager.target), 'activation_required': journal['kind'] == 'policy',
                  'message': 'Validated against current config. No DNS activation. Reload/verify explicitly before restarting WebUI.'}
        if not apply:
            return result
        # Preserve a complete retry source BEFORE any recovery live write.
        _atomic(manager.journal_path, (json.dumps(journal) + '\n').encode())
        try:
            if journal['kind'] == 'policy':
                if fragment is None:
                    _durable_unlink(manager.target)
                else:
                    _atomic(manager.target, fragment.encode('ascii'), mode=0o644)
            if journal['previous_state_text'] is None:
                _durable_unlink(manager.state_path)
            else:
                _atomic(manager.state_path, journal['previous_state_text'].encode(), mode=0o600)
            manager._check(manager.main)
            manager._clear_journal()
        except Exception:
            # A journal unlink followed by fsync failure may already be visible.
            if not manager.journal_path.exists():
                try:
                    _atomic(manager.journal_path, (json.dumps(journal) + '\n').encode())
                except OSError:
                    pass
            raise
        result['applied'] = True
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', required=True, help='WebUI data base directory')
    parser.add_argument('--main', required=True, help='Main Unbound config file')
    parser.add_argument('--target', required=True, help='Owned webui-rewrites.conf file')
    parser.add_argument('--backup', help='Owned archive; omit to recover transaction journal')
    parser.add_argument('--apply', action='store_true', help='Restore only rewrite fragment/state; NEVER reload DNS')
    parser.add_argument('--webui-stopped', action='store_true', help='Explicitly confirm that the WebUI is stopped')
    args = parser.parse_args()
    try:
        print(json.dumps(recover(args.base, args.main, args.target, backup=args.backup,
                                 apply=args.apply, webui_stopped=args.webui_stopped), indent=2))
    except (ValueError, OSError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
