"""Storage probe uses tiny generated fixtures and owned paths only."""
import importlib
import pathlib
import tempfile
import unittest


class StorageProbeTests(unittest.TestCase):
    def test_production_workspace_is_refused(self):
        module = importlib.import_module('probe_filter_storage')
        with self.assertRaises(ValueError):
            module.run_storage('/etc/unbound', [], [], generations=1)

    def test_multisource_cache_and_distinct_compressed_retention(self):
        module = importlib.import_module('probe_filter_storage')
        root = pathlib.Path.home() / '.hermes/cache/scratch'
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as name:
            workspace = pathlib.Path(name)
            first, second = workspace / 'a.txt', workspace / 'b.txt'
            first.write_text('one.example\nshared.example\n')
            second.write_text('two.example\nshared.example\n')
            before = set(workspace.iterdir())
            result = module.run_storage(workspace, [first, second], ['https://lists.example/a', 'https://lists.example/b'], format='domains', generations=3)
            self.assertEqual(result['import']['count'], 3)
            self.assertEqual(result['import']['downloaded_bytes'], first.stat().st_size + second.stat().st_size)
            self.assertEqual(result['retention']['archives'], 3)
            self.assertEqual(result['retention']['distinct_blobs'], 3)
            self.assertEqual(result['retention']['retained_caches'], 3)
            self.assertTrue(result['rollback_restored_exact_bytes'])
            self.assertTrue(result['production_unchanged'])
            self.assertFalse(result['activated'])
            self.assertEqual(before, set(workspace.iterdir()))


if __name__ == '__main__':
    unittest.main()
