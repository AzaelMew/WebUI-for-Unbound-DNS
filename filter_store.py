"""Immutable SQLite domain generations and bounded, disk-backed unions.

The state file stores only relative cache references, never subscription domains.
Generation files are published after fsync; callers own metadata transactions.
"""
import os
import re
import sqlite3
import tempfile
import time
import uuid
from pathlib import Path


def check_deadline(deadline):
    if deadline is not None and time.monotonic() >= deadline:
        raise ValueError('Filter refresh timeout')


def connect(path, readonly=False):
    db = sqlite3.connect(path.as_uri() + '?mode=ro' if readonly else str(path), uri=readonly)
    db.execute('PRAGMA cache_size=-2048')
    db.execute('PRAGMA temp_store=FILE')
    if not readonly:
        db.execute('PRAGMA journal_mode=DELETE')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS domains (domain TEXT PRIMARY KEY) WITHOUT ROWID')
    return db


class DomainStore:
    def __init__(self, data):
        self.data = Path(data).resolve()
        self.directory = self.data / 'cache'
        if self.directory.is_symlink():
            raise ValueError('Refusing symlink cache directory')
        self.directory.mkdir(mode=0o700, exist_ok=True)

    def path(self, reference):
        if not isinstance(reference, str) or not re.fullmatch(r'cache/[0-9a-f]{32}\.sqlite', reference):
            raise ValueError('Invalid cache reference')
        path = self.data / reference
        if self.directory.is_symlink() or path.is_symlink() or not path.is_file():
            raise ValueError('Cache missing or symlink')
        if not path.resolve().is_relative_to(self.directory):
            raise ValueError('Cache outside filter-data')
        return path

    def domains(self, reference):
        db = None
        try:
            db = connect(self.path(reference), readonly=True)
            for row in db.execute('SELECT domain FROM domains ORDER BY domain'):
                yield row[0]
        except sqlite3.DatabaseError as exc:
            raise ValueError('Invalid subscription cache') from exc
        finally:
            if db is not None:
                db.close()

    def validate(self, reference, count, normalize, deadline=None):
        actual, previous = 0, None
        try:
            for domain in self.domains(reference):
                check_deadline(deadline)
                if normalize(domain) != domain:
                    raise ValueError('Invalid cached domain')
                if domain == previous:
                    raise ValueError('Duplicate cached domain')
                previous = domain
                actual += 1
                if actual > count:
                    raise ValueError('Subscription cache count mismatch')
        except sqlite3.DatabaseError as exc:
            raise ValueError('Invalid subscription cache') from exc
        if actual != count:
            raise ValueError('Subscription cache count mismatch')

    def build(self, domains, maximum, deadline=None):
        fd, name = tempfile.mkstemp(prefix='.build-', dir=self.directory)
        os.close(fd)
        path = Path(name)
        count = 0
        db = None
        try:
            db = connect(path)
            for domain in domains:
                check_deadline(deadline)
                count += db.execute('INSERT OR IGNORE INTO domains VALUES (?)', (domain,)).rowcount
                if count > maximum:
                    raise ValueError(f'Domain count limit exceeded ({maximum:,})')
            db.commit()
            db.close()
            db = None
            path.chmod(0o400)
            with path.open('rb') as handle:
                os.fsync(handle.fileno())
            destination = self.directory / (uuid.uuid4().hex + '.sqlite')
            os.replace(path, destination)
            fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            return str(destination.relative_to(self.data)), count
        finally:
            if db is not None:
                db.close()
            path.unlink(missing_ok=True)

    def union(self, state, destination, maximum, header, covered, deadline=None):
        """Stream active rules while bounding the union of ALL cached domains."""
        fd, name = tempfile.mkstemp(prefix='.union-', dir=self.data)
        os.close(fd)
        path = Path(name)
        db = None
        try:
            db = connect(path)
            db.execute('ALTER TABLE domains ADD COLUMN active INTEGER NOT NULL DEFAULT 0')
            count = 0
            def insert(domain, active):
                nonlocal count
                check_deadline(deadline)
                changed = db.execute('INSERT OR IGNORE INTO domains VALUES (?, ?)', (domain, active)).rowcount
                count += changed
                if not changed and active:
                    db.execute('UPDATE domains SET active=1 WHERE domain=?', (domain,))
                if count > maximum:
                    raise ValueError(f'Total cached domain limit exceeded ({maximum:,})')
            for domain in state['allowed']:
                insert(domain, 0)
            for domain in state['blocked']:
                insert(domain, 1)
            for item in state['lists']:
                if item['cache']:
                    for domain in self.domains(item['cache']):
                        insert(domain, int(item['enabled']))
            effective = 0
            allowed = set(state['allowed'])
            if destination is not None:
                with Path(destination).open('w', encoding='ascii') as output:
                    output.write(header)
                    for domain, in db.execute('SELECT domain FROM domains WHERE active=1 ORDER BY domain'):
                        check_deadline(deadline)
                        if not covered(domain, allowed):
                            output.write(f'    local-zone: "{domain}." always_nxdomain\n')
                            effective += 1
                    for domain in state['allowed']:
                        check_deadline(deadline)
                        output.write(f'    local-zone: "{domain}." transparent\n')
                    output.flush()
                    os.fsync(output.fileno())
            else:
                for domain, in db.execute('SELECT domain FROM domains WHERE active=1'):
                    check_deadline(deadline)
                    effective += not covered(domain, allowed)
            return effective
        finally:
            if db is not None:
                db.close()
            path.unlink(missing_ok=True)
