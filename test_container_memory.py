import importlib.util
import os
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('isolated_memory_app', ROOT / 'app.py')
if spec is None or spec.loader is None:
    raise RuntimeError('Cannot load isolated application module')
upstream = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = upstream
spec.loader.exec_module(upstream)
os.environ['WEBUI_CONTAINER_MEMORY_BYTES'] = str(2048*1024**2)
from container_memory import install
install(upstream)
app = upstream



class ContainerMemoryTests(unittest.TestCase):
    def test_hidden_lxc_limit_uses_container_cgroup_parent_memory_not_host_or_service(self):
        with TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp)
            (root / 'memory.max').write_text('max\n')
            (root / 'memory.current').write_text(str(700 * 1024**2))
            (root / 'memory.stat').write_text('inactive_file 419430400\nslab_reclaimable 20971520\n')
            with patch.dict(os.environ, {'WEBUI_CONTAINER_MEMORY_BYTES': str(2048*1024**2), 'WEBUI_CGROUP_ROOT': tmp}):
                info = app.get_system_info()
            self.assertEqual(info['mem_total'], 2048*1024**2)
            self.assertEqual(info['mem_used'], 280*1024**2)
            self.assertEqual(info['mem_avail'], 1768*1024**2)
            self.assertEqual(info['mem_source'], 'container cgroup working set')
    def test_visible_root_cgroup_limit_takes_precedence_over_stale_override(self):
        from container_memory import container_memory
        with TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp)
            (root / 'memory.max').write_text(str(1024*1024**2))
            (root / 'memory.current').write_text(str(100*1024**2))
            (root / 'memory.stat').write_text('inactive_file 0\n')
            info = container_memory(tmp, 2048*1024**2)
            self.assertEqual(info['mem_total'], 1024*1024**2)
            self.assertEqual(info['mem_pct'], 9.8)

    def test_reclaimable_exceeding_current_is_clamped(self):
        from container_memory import container_memory
        with TemporaryDirectory(dir=ROOT) as tmp:
            root = Path(tmp)
            (root / 'memory.max').write_text(str(1024*1024**2))
            (root / 'memory.current').write_text('10')
            (root / 'memory.stat').write_text('inactive_file 20\n')
            self.assertEqual(container_memory(tmp)['mem_used'], 0)


if __name__ == '__main__':
    unittest.main()
