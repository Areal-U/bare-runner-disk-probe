"""Host disk reservations for the physical Linux cache SDK and bounded packet extractor."""
import json
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "preflight28/limits"))
import guard


MIB = 1024**2
METADATA = 64*1024 + 1024  # piece.json + piece.sig maxima in checkpoint_packets.BOUNDS
TAR_PADDING = 128*1024  # matches packet_tar.unpack's expanded tar byte bound
ARCHIVE_OVERHEAD = MIB  # matches checkpoint_packets.archive_bound
FILES = 20
ALLOCATION = 128*1024  # directory entries, block rounding and small SDK bookkeeping


def reserve(stage, temporary, workspace):
    """Accumulate future bytes once per physical volume; existing files already consume free space."""
    devices = {}
    for key, extra in (("RUNNER_TEMP", temporary), ("GITHUB_WORKSPACE", workspace)):
        if type(extra) is not int or extra < 0:
            raise ValueError("Invalid future packet allocation")
        sample = guard.disk(Path(os.environ[key]))
        dev = sample["device"]
        if key == "RUNNER_TEMP":
            temporary_device = dev
        if dev not in devices:
            devices[dev] = [sample, 0]
        first, count = devices[dev]
        devices[dev] = [dict(device=dev, free_bytes=min(first["free_bytes"], sample["free_bytes"]),
                             free_inodes=min(first["free_inodes"], sample["free_inodes"])), count + extra]
    for dev, (space, future) in devices.items():
        result = guard.reserve(space, future + ALLOCATION, FILES)
        print("R209_PACKET_SPACE " + json.dumps(dict(stage=stage, **result), sort_keys=True), flush=True)
    return guard.FLOOR + devices[temporary_device][1] + ALLOCATION


def before_compile(max_plain, max_sealed, max_piece):
    # Build products/current source already consume their own blocks when measured.
    # Keep the subsequent compressed candidate, its CMS, and simultaneous slice/archive
    # available through the build_trial free-space stop condition.
    return reserve("before-compile", max_plain + max_sealed + max_piece + METADATA + ARCHIVE_OVERHEAD,
                   max_piece + METADATA)


def before_piece(size):
    # The completed CMS is already present. Reserve the new slice and its SDK archive.
    return reserve("before-piece-staging", size + METADATA + ARCHIVE_OVERHEAD, size + METADATA)


def before_save(measured):
    # The measured files are already on disk. GNU tar streams into cache.tzst.
    return reserve("before-cache-save", measured + ARCHIVE_OVERHEAD, 0)


def before_restore(compressed, expanded_file_cap):
    # The runtime holds cache.tzst plus the bounded, decompressed tar in RUNNER_TEMP.
    # File members can be highly compressible, so archive length alone cannot bound extraction.
    return reserve("before-cache-restore", compressed + expanded_file_cap + TAR_PADDING, expanded_file_cap)


def before_assembly(total, previously_written):
    if not 0 <= previously_written <= total:
        raise ValueError("Invalid unfinished ciphertext extent")
    return reserve("before-private-ciphertext-read", total - previously_written, 0)
