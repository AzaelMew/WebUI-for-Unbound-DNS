"""Opt-in refresh scheduling; fake managers never download or activate DNS."""
import importlib.util
import pathlib
import threading
import unittest
from datetime import datetime, timezone, timedelta

ROOT = pathlib.Path(__file__).resolve().parent


class Manager:
    def __init__(self, items):
        self.items = items
        self.calls = []
        self.gate: threading.Event | None = None
        self.refresh_interval_seconds = 0

    def snapshot(self):
        return {'lists': self.items}

    def refresh_list(self, identifier):
        self.calls.append(identifier)
        if self.gate:
            self.gate.wait(1)
        if identifier == 'bad':
            raise ValueError('download failed')


class App:
    def __init__(self):
        self.events = {}
        self.router = self

    def add_event_handler(self, name, fn):
        self.events[name] = fn


class SchedulerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('isolated_filter_refresh', ROOT / 'filter_refresh.py')
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_disabled_default_does_not_start_or_download(self):
        manager, app = Manager([{'id': 'a', 'enabled': True}]), App()
        worker = self.module.install(app, manager, interval=0)
        self.assertEqual(manager.refresh_interval_seconds, 0)
        self.assertFalse(worker.running)
        app.events['startup']()
        worker.tick()
        self.assertEqual(manager.calls, [])
        app.events['shutdown']()

    def test_due_enabled_lists_only_and_failure_does_not_stop_next(self):
        now = datetime.now(timezone.utc)
        manager = Manager([
            {'id': 'bad', 'enabled': True, 'last_attempt': None},
            {'id': 'next', 'enabled': True, 'last_attempt': (now - timedelta(seconds=600)).isoformat()},
            {'id': 'fresh', 'enabled': True, 'last_attempt': now.isoformat()},
            {'id': 'disabled', 'enabled': False},
        ])
        worker = self.module.RefreshWorker(manager, interval=300)
        with self.assertLogs('isolated_filter_refresh', level='ERROR') as errors:
            worker.tick(now=now)
        self.assertIn('Scheduled filter refresh failed: bad', errors.output[0])
        self.assertEqual(manager.calls, ['bad', 'next'])
        worker.tick(now=now)
        self.assertEqual(manager.calls, ['bad', 'next'], 'failed attempts must also be throttled')

    def test_scheduler_ticks_never_overlap_and_stop_is_prompt(self):
        manager = Manager([{'id': 'a', 'enabled': True}])
        manager.gate = threading.Event()
        worker = self.module.RefreshWorker(manager, interval=300)
        first = threading.Thread(target=worker.tick)
        first.start()
        try:
            # refresh_list appends before waiting, so wait deterministically.
            for _ in range(100):
                if manager.calls:
                    break
                threading.Event().wait(.01)
            worker.tick()
            self.assertEqual(manager.calls, ['a'])
        finally:
            assert manager.gate is not None
            manager.gate.set()
            first.join(2)
            worker.stop()
        self.assertFalse(first.is_alive())

    def test_lifecycle_is_idempotent_and_no_import_side_effects(self):
        manager = Manager([])
        worker = self.module.install(App(), manager, interval=300)
        self.assertFalse(worker.running)
        worker.start()
        try:
            thread = worker.thread
            worker.start()
            self.assertIs(worker.thread, thread)
            self.assertTrue(worker.running)
        finally:
            worker.stop()
        self.assertFalse(worker.running)
        self.assertEqual(manager.calls, [])

    def test_interval_is_finite_and_explicit(self):
        for value in [-1, 1, 299, 604801, True, 300.5, 'oops']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.module.RefreshWorker(Manager([]), interval=value)

    def test_naive_or_bad_timestamp_is_due_without_killing_worker(self):
        manager = Manager([{'id': 'a', 'enabled': True, 'last_attempt': 'bad'},
                           {'id': 'b', 'enabled': True, 'last_attempt': '2020-01-01T00:00:00'}])
        worker = self.module.RefreshWorker(manager, interval=300)
        worker.tick()
        self.assertEqual(manager.calls, ['a', 'b'])

    def test_real_fastapi_startup_shutdown_uses_supported_router_api(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        manager = Manager([])
        app = FastAPI()
        worker = self.module.install(app, manager, interval=300)
        with TestClient(app):
            self.assertTrue(worker.running)
        self.assertFalse(worker.running)
        self.assertEqual(manager.calls, [])


if __name__ == '__main__':
    unittest.main()
