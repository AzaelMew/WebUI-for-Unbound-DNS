"""Single-process, explicitly opt-in subscription refresh for the TLS launcher.

No thread or download starts at import/install time. FastAPI startup starts one
worker, shutdown signals it. The manager owns per-subscription exclusion,
network/parse deadlines, last-known-good preservation and activation rollback.
"""
import logging
import os
import threading
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)


def _interval(value):
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError('Refresh interval must be 0 (off) or 300–604800 seconds')
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError('Refresh interval must be 0 (off) or 300–604800 seconds') from exc
    if number != 0 and not 300 <= number <= 604800:
        raise ValueError('Refresh interval must be 0 (off) or 300–604800 seconds')
    return number


class RefreshWorker:
    def __init__(self, manager, interval: int | str = 0):
        self.manager = manager
        self.interval = _interval(interval)
        self.thread = None
        self._stop = threading.Event()
        self._tick_lock = threading.Lock()
        self._attempts = {}

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def start(self):
        if not self.interval or self.running:
            return
        self._stop.clear()
        self.thread = threading.Thread(target=self._run, name='filter-refresh', daemon=True)
        self.thread.start()

    def stop(self):
        self._stop.set()
        # Do not hold up server shutdown for a remote download. Transactions
        # remain in the manager's bounded operation and are crash recoverable.
        if self.thread is not None:
            self.thread.join(timeout=2)

    def _run(self):
        # Avoid issuing remote requests during startup itself. Afterwards poll
        # deadlines, not network: the configured interval applies per list.
        while not self._stop.wait(min(30, self.interval)):
            try:
                self.tick()
            except Exception:
                LOG.exception('Cannot inspect filters for scheduled refresh')

    def tick(self, now=None):
        if not self.interval or self._stop.is_set() or not self._tick_lock.acquire(blocking=False):
            return
        try:
            now = now or datetime.now(timezone.utc)
            lists = self.manager.snapshot()['lists']
            identifiers = {item['id'] for item in lists}
            self._attempts = {key: value for key, value in self._attempts.items() if key in identifiers}
            for item in lists:
                if self._stop.is_set():
                    break
                if not item['enabled']:
                    continue
                last = self._attempts.get(item['id'])
                try:
                    recorded = datetime.fromisoformat(item.get('last_attempt') or '')
                    if recorded.tzinfo is None:
                        recorded = recorded.replace(tzinfo=timezone.utc)
                    last = max(last, recorded) if last else recorded
                except (TypeError, ValueError):
                    pass
                if last and (now - last).total_seconds() < self.interval:
                    continue
                self._attempts[item['id']] = now
                try:
                    self.manager.refresh_list(item['id'])
                except Exception:
                    # The manager persists the error while keeping old cache
                    # and rules. Continue other due lists, without hot retrying.
                    LOG.exception('Scheduled filter refresh failed: %s', item['id'])
        finally:
            self._tick_lock.release()


def install(app, manager, interval=None):
    value = interval if interval is not None else os.environ.get('WEBUI_FILTER_REFRESH_INTERVAL_SECONDS', '0')
    worker = RefreshWorker(manager, interval=value)
    manager.refresh_interval_seconds = worker.interval
    app.router.add_event_handler('startup', worker.start)
    app.router.add_event_handler('shutdown', worker.stop)
    return worker
