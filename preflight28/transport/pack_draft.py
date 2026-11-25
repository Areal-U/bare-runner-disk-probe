"""Pack a quiescent Bare tree into one bounded Draft checkpoint."""
import argparse
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import tempfile
import time

from stream import CompressedSizeExceeded, store

# The independently received S2 successor had a 9,630,842,880-byte tar.
# Its level-4 output occupied 1,979,111,588 bytes vs 1,745,316,602 at -9.
# Apparent tree size is only a scheduling hint. Enforce the real compressed cap.
MEASURED_TAR_BYTES = 9_630_842_880
CHECKPOINT_CAP = 7 * 1024**3 // 2
PART_BYTES = 2_000_000_000


def encode(command, level, candidate, cap):
    with ExitStack() as children:
        source = children.enter_context(subprocess.Popen(command, stdout=subprocess.PIPE))
        children.callback(source.kill)
        try:
            encoder = children.enter_context(subprocess.Popen(
                ['zstd', '-q', '-T2', f'-{level}', '-c'], stdin=source.stdout, stdout=subprocess.PIPE))
        finally:
            source.stdout.close()
        children.callback(encoder.kill)
        overflow = None
        with encoder.stdout as compressed:
            try:
                store(compressed, candidate, cap)
            except CompressedSizeExceeded as error:
                overflow = error
                # A late tar error must not be confused with a safe size retry.
                while compressed.read(1024**2):
                    pass
        if encoder.wait() != 0 or source.wait() != 0:
            raise RuntimeError('Tar producer or zstd failed; refusing partial checkpoint')
        if overflow:
            raise overflow


def pack(destination, profile, tree_bytes, producer, *, deadline=None, cap=CHECKPOINT_CAP):
    if profile not in ('auto', 'compact') or tree_bytes <= 0 or not producer:
        raise ValueError('Invalid checkpoint compression inputs')
    if destination.exists() or destination.is_symlink():
        raise FileExistsError(destination)
    levels = (4, 9) if profile == 'auto' and tree_bytes <= MEASURED_TAR_BYTES else (9,)
    with tempfile.TemporaryDirectory(prefix='.pack-', dir=destination.parent) as tmp:
        candidate = Path(tmp) / 'checkpoint.tar.zst'
        for level in levels:
            started = time.monotonic()
            try:
                encode(producer, level, candidate, cap)
            except CompressedSizeExceeded:
                if level == 9:
                    raise
                candidate.unlink()
                elapsed = time.monotonic() - started
                # Historical upper-size packing extrapolation: 1,496s. Local
                # full-generation -9/-4 was <=3.43x; allow 4x observed here.
                # Leave 3 x 25s for the three checks (one observed tar check was 24.81s).
                # These are admission estimates; the shared outer deadline is absolute.
                needed = max(1496, 4 * elapsed) + 75
                if deadline is None or deadline - time.time() < needed:
                    raise CompressedSizeExceeded('Compressed size exceeded; insufficient time for -9 and validation')
                print('Level 4 exceeded the compressed byte cap; retrying the quiescent source at level 9', flush=True)
                continue
            size = candidate.stat().st_size
            os.link(candidate, destination)
            print(f'Draft checkpoint: zstd -{level}, {size} bytes, {(size + PART_BYTES - 1) // PART_BYTES} part(s)', flush=True)
            return level


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--deadline', type=int, help='Absolute end of packing and validation')
    parser.add_argument('destination', type=Path)
    parser.add_argument('profile', choices=('auto', 'compact'))
    parser.add_argument('tree_bytes', type=int)
    parser.add_argument('producer', nargs='+')
    args = parser.parse_args()
    pack(args.destination, args.profile, args.tree_bytes, args.producer, deadline=args.deadline)
