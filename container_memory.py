"""Read container-wide memory, not the WebUI service's own 512 MiB cgroup."""
import os
from pathlib import Path


def container_memory(root=None, configured_limit=None):
    root = Path(root or os.environ.get('WEBUI_CGROUP_ROOT', '/sys/fs/cgroup'))
    override = configured_limit if configured_limit is not None else os.environ.get('WEBUI_CONTAINER_MEMORY_BYTES')
    limits = []
    if override:
        value = int(override)
        if value > 0:
            limits.append(value)
    raw = (root / 'memory.max').read_text().strip()
    if raw != 'max':
        value = int(raw)
        if 0 < value < 2**60:
            limits.append(value)
    if not limits:
        return None
    total = min(limits)
    current = max(0, int((root / 'memory.current').read_text()))
    stats = {}
    for line in (root / 'memory.stat').read_text().splitlines():
        key, value = line.split()
        stats[key] = int(value)
    # Reclaimable page/slab caches aren't application working memory.
    reclaimable = stats.get('inactive_file', 0) + stats.get('slab_reclaimable', 0)
    used = min(total, max(0, current - reclaimable))
    avail = total - used
    return {'mem_total': total, 'mem_used': used, 'mem_avail': avail,
            'mem_free': max(0, total - current),
            'mem_pct': round(used / total * 100, 1),
            'mem_current': current, 'mem_source': 'container cgroup working set'}


def install(upstream):
    original = upstream.get_system_info

    def get_system_info():
        info = original()
        try:
            metrics = container_memory()
        except (OSError, ValueError):
            metrics = None
        if metrics:
            info.update(metrics)
        else:
            info['mem_source'] = 'proc meminfo'
        return info

    upstream.get_system_info = get_system_info
