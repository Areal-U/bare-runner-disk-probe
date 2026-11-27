"""Fresh, complete repository inventory immediately before each new artifact."""
import argparse
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preflight28/bridge'))
import bridge
import storage_admission as storage


def main():
    p = argparse.ArgumentParser()
    p.add_argument('stage', choices=['peer','outcome','terminal','lease'])
    p.add_argument('paths', type=Path, nargs='*')
    a = p.parse_args()
    if a.stage == 'lease':
        size, days, lead = storage.lease_size(os.environ), 1, 350*60
    else:
        if not a.paths or any(not f.is_file() or f.is_symlink() for f in a.paths):
            raise ValueError('Missing or indirect upload payload')
        size = sum(f.stat().st_size for f in a.paths) + 256*1024
        days, lead = (3 if a.stage == 'terminal' else 1), 0
    # Pagination can temporarily lag expiry; only a completely new, successful
    # authenticated view can pass. Bound the wait by the actual job clocks.
    stop = time.monotonic()+180
    while True:
        try:
            storage.admit(bridge.api_json, os.environ, size, days, stage=a.stage, lead=lead)
            return
        except storage.StorageUnconfirmed as exc:
            if time.monotonic()+65 >= stop:
                raise
            print('Inventory requires fresh view:', exc, flush=True)
            time.sleep(8)


if __name__ == '__main__':
    main()
