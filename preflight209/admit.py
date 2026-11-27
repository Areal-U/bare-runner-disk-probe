"""Fresh, complete repository inventory immediately before each new artifact."""
import argparse
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preflight28/bridge'))
import bridge
import storage_admission as storage


def current_view(get, env, size, days, *, stage, lead=0, exact_name=None, deadline=None):
    # Each retry starts with a fresh complete inventory including earlier
    # observations. A partial or unstable layout never reserves any bytes.
    stop = min(time.time()+155, deadline) if deadline is not None else time.time()+155
    while True:
        try:
            return storage.admit(get, env, size, days, stage=stage, lead=lead, exact_name=exact_name)
        except storage.StorageUnconfirmed as exc:
            if 'inventory' not in str(exc).lower() or time.time()+storage.INVENTORY_SECONDS+10 >= stop:
                raise
            print('Inventory requires fresh view:', exc, flush=True)
            time.sleep(8)


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
    current_view(bridge.api_json, os.environ, size, days, stage=a.stage, lead=lead)


if __name__ == '__main__':
    main()
