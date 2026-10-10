"""Safe opt-in TIF Full comparison; see filter_benchmark.py --help."""
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))  # repo root: filters, filter_benchmark, run
from filter_benchmark import main


if __name__ == '__main__':
    main(default_feed='full')
