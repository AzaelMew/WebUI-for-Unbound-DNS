"""Resource policy fixtures; no production processes/configuration are used."""
import importlib.util
import pathlib
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
MIB = 1024 * 1024


class ResourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('isolated_filter_resources', ROOT / 'filter_resources.py')
        assert spec is not None and spec.loader is not None
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_service_limit_covers_validator_children(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            (root / 'memory.max').write_text('max')
            service = root / 'system.slice' / 'fixture.service'
            service.mkdir(parents=True)
            (service / 'memory.max').write_text(str(512 * MIB))
            (service / 'memory.current').write_text(str(60 * MIB))
            result = self.module.cgroup_headroom(root, '/system.slice/fixture.service')
            self.assertEqual(result, 452 * MIB)
            # The hidden LXC parent limit is not fabricated from the service.
            (service / 'memory.max').write_text('max')
            self.assertIsNone(self.module.cgroup_headroom(root, '/system.slice/fixture.service'))

    def test_small_policy_budget_passes_and_large_checker_is_refused_before_launch(self):
        self.module.validation_budget(1000, available=1600 * MIB, service_available=452 * MIB, maximum=1280 * MIB)
        with self.assertRaisesRegex(ValueError, 'validation.*headroom'):
            self.module.validation_budget(125_388_648, available=1600 * MIB, service_available=452 * MIB, maximum=1280 * MIB)
        # Enlarging service cap does not magically permit overlapping two Full
        # resolvers/validators in a 2 GiB container.
        with self.assertRaisesRegex(ValueError, 'validation.*headroom'):
            self.module.validation_budget(125_388_648, available=700 * MIB, service_available=1200 * MIB, maximum=1280 * MIB)

    def test_budget_preserves_container_reserve_and_is_finite(self):
        budget = self.module.validation_budget(1000, available=1600 * MIB, service_available=452 * MIB, maximum=1280 * MIB)
        self.assertEqual(budget, 452 * MIB)
        for maximum in [0, -1, float('inf'), True, 1.5]:
            with self.subTest(maximum=maximum), self.assertRaises(ValueError):
                self.module.validation_budget(1000, available=1600 * MIB, maximum=maximum)

    def test_current_cgroup_cannot_escape_root(self):
        with tempfile.TemporaryDirectory() as name:
            root = pathlib.Path(name)
            for group in ['/../../outside', 'relative', '/system.slice/../../outside']:
                with self.subTest(group=group), self.assertRaises(ValueError):
                    self.module.cgroup_headroom(root, group)

    def test_validator_command_uses_exec_wrapper_not_thread_unsafe_preexec(self):
        command = self.module.validator_command('/usr/sbin/unbound-checkconf', '/fixture/unbound.conf', 452 * MIB)
        self.assertIn('resource.setrlimit', command[2])
        self.assertEqual(command[-2:], ['/usr/sbin/unbound-checkconf', '/fixture/unbound.conf'])
        self.assertIn(str(452 * MIB), command)

    def test_disk_headroom_is_checked_before_staging_or_activation(self):
        from types import SimpleNamespace
        with patch('shutil.disk_usage', return_value=SimpleNamespace(free=200 * MIB)):
            with self.assertRaisesRegex(ValueError, 'disk headroom'):
                self.module.check_disk_headroom('/fixture', required=100 * MIB)
        with patch('shutil.disk_usage', return_value=SimpleNamespace(free=400 * MIB)):
            self.module.check_disk_headroom('/fixture', required=100 * MIB)


if __name__ == '__main__':
    unittest.main()
