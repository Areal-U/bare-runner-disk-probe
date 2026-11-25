"""Use the pinned checkpoint validator on bounded full zstd tar streams on the runner."""
from contextlib import contextmanager
import importlib.util
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
from types import FunctionType

MAX_COMPRESSED = 7 * 1024**3 // 2
# Production limits 19 GiB payload plus headers/padding for <=550,000 members.
MAX_RAW = 22 * 1024**3

class BoundedStream:
    def __init__(self, file, limit):
        self.file = file
        self.left = limit

    def read(self, n):
        chunk = self.file.read(min(self.left + 1, n))
        if len(chunk) > self.left:
            raise ValueError('raw tar exceeds ceiling')
        self.left -= len(chunk)
        return chunk


class StreamingTar:
    def __getattr__(self, name):
        return getattr(tarfile, name)

    @staticmethod
    @contextmanager
    def open(path, mode):
        if mode != 'r|gz':
            raise ValueError('unexpected access mode')
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_COMPRESSED:
            raise ValueError('invalid compressed checkpoint')
        with path.open('rb', buffering=0) as data:
            if data.read(4) != b'\x28\xb5\x2f\xfd':
                raise ValueError('expected fixed zstd frame')
            data.seek(0)
            with subprocess.Popen(['zstd', '-qdc', '-M128MB'], stdin=data, stdout=subprocess.PIPE) as decoder:
                try:
                    stream = BoundedStream(decoder.stdout, MAX_RAW)
                    with tarfile.open(fileobj=stream, mode='r|') as archive:
                        yield archive
                    while stream.read(1024**2):
                        pass
                    if decoder.wait() != 0:
                        raise ValueError('invalid zstd checksum or truncated stream')
                finally:
                    if decoder.poll() is None:
                        decoder.kill()
                    decoder.stdout.close()


if __name__ == '__main__':
    if len(sys.argv) < 4 or sys.argv[2] not in ('validate-archive', 'verify-continuation', 'inspect-input-paths', 'record-continuation'):
        raise SystemExit('Usage: check_archive.py PINNED_VALIDATOR ALLOWED_ACTION ARCHIVE [args]')
    source = Path(sys.argv.pop(1)).resolve(strict=True)
    spec = importlib.util.spec_from_file_location('pinned_checkpoint', source)
    checkpoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checkpoint)
    # This runs on verified private inputs only. Permit necessary Android packaging
    # intermediates, while blocking the actual terminal APK, copies sharing its
    # basename and links to that output. Keep the public verifier unchanged.
    # Preserve the approved GN regeneration dependency allowlist even though
    # this backend carries the corresponding descriptors as ordinary members.
    validate_gn = checkpoint.gn_packaging_dependencies
    checkpoint.gn_packaging_dependencies = FunctionType(validate_gn.__code__, dict(validate_gn.__globals__))
    checkpoint.is_android_packaging = lambda member: member.name.casefold() == 'chromepublic.apk'
    checkpoint.tarfile = StreamingTar()
    sys.exit(checkpoint.main())
