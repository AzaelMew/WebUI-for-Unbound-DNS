"""Conservative validator memory preflight and an enforced child address cap.

These bounds do not certify a feed's safety: cache growth, reload transients and
external workloads still need measured headroom. They prevent starting a known
~1 GiB validator beneath a 512 MiB service or beside an already-large resolver.
"""
import os
import sys
import shutil
from pathlib import Path, PurePosixPath

MIB = 1024 * 1024
RESERVE_BYTES = 384 * MIB
DEFAULT_CHECKCONF_MAX_BYTES = 1280 * MIB


def check_disk_headroom(base, required=0):
    if type(required) is not int or required < 0:
        raise ValueError('Invalid filter disk-space budget')
    free = shutil.disk_usage(base).free
    reserve = 256 * MIB
    if free < required + reserve:
        raise ValueError(f'Insufficient filter disk headroom: operation budget '
                         f'{required // MIB:,} MiB plus {reserve // MIB} MiB reserve; '
                         f'{free // MIB:,} MiB free. Existing rules are retained.')


def cgroup_headroom(root, group):
    root = Path(root).resolve()
    parts = PurePosixPath(group)
    if not parts.is_absolute() or '..' in parts.parts:
        raise ValueError('Invalid process cgroup path')
    current = root.joinpath(*parts.parts[1:])
    if not current.resolve().is_relative_to(root):
        raise ValueError('Process cgroup outside configured root')
    values = []
    while True:
        try:
            raw = (current / 'memory.max').read_text().strip()
            if raw != 'max':
                limit = int(raw)
                usage = int((current / 'memory.current').read_text())
                if 0 < limit < 2**60:
                    values.append(max(0, limit - usage))
        except FileNotFoundError:
            pass
        if current == root:
            break
        current = current.parent
    return min(values) if values else None


def process_headroom():
    root = Path(os.environ.get('WEBUI_CGROUP_ROOT', '/sys/fs/cgroup'))
    for line in Path('/proc/self/cgroup').read_text().splitlines():
        if line.startswith('0::'):
            return cgroup_headroom(root, line[3:])
    return None


def available_memory():
    from container_memory import container_memory
    metrics = container_memory()
    if metrics is not None:
        return metrics['mem_avail']
    values = {}
    for line in Path('/proc/meminfo').read_text().splitlines():
        key, value = line.split(':', 1)
        values[key] = int(value.split()[0]) * 1024
    if 'MemAvailable' not in values:
        raise ValueError('Cannot determine filter validation memory headroom')
    return values['MemAvailable']


def validation_budget(policy_bytes, available, service_available=None, maximum=DEFAULT_CHECKCONF_MAX_BYTES):
    if type(maximum) is not int or maximum <= 0:
        raise ValueError('Validator memory limit must be a positive finite integer')
    # Full local-zone checkconf measured 1000 MiB for 125.4 MB text. 9x text
    # plus 32 MiB is deliberately conservative, not a predicted RSS metric.
    estimate = 32 * MIB + 9 * max(0, policy_bytes)
    budgets = [maximum, max(0, available - RESERVE_BYTES)]
    if service_available is not None:
        budgets.append(service_available)
    budget = min(budgets)
    if estimate > budget:
        raise ValueError(f'Insufficient filter validation memory headroom: conservative requirement '
                         f'{estimate // MIB:,} MiB, available validator budget {budget // MIB:,} MiB. '
                         'Existing rules are retained. Review container/service memory limits; '
                         'do not enable a huge feed solely because its import succeeds.')
    return budget


def validator_command(executable, config, budget):
    # preexec_fn is unsafe in the threaded FastAPI server. Apply RLIMIT_AS in a
    # fresh interpreter and exec the validator, keeping ownership/timeout in
    # subprocess.run. No credential/config content is interpolated into code.
    wrapper = ('import os,resource,sys; cap=int(sys.argv[1]); '
               'resource.setrlimit(resource.RLIMIT_AS,(cap,cap)); '
               'os.execv(sys.argv[2],sys.argv[2:])')
    return [sys.executable, '-c', wrapper, str(budget), str(executable), str(config)]
