"""Report bounded observations from a rejected candidate, without making a release decision."""

import hashlib
import json
from pathlib import Path
import re
import stat
import sys
import zipfile
import zlib


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
        result.update(chunk)
    return result.hexdigest()


def output(path):
    # These are SDK outputs on the runner. Never copy their free-form text into public logs.
    if not path.is_file():
        return ''
    with path.open('rb') as stream:
        return stream.read(256 * 1024).decode(errors='replace')


def observe(apk, temp):
    info = apk.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 450 * 1024**2:
        raise ValueError('Invalid APK type or size for diagnostics')
    with apk.open('rb') as stream:
        report = {'apk_bytes': info.st_size, 'apk_sha256': digest(stream)}
    badging = output(temp / 'badging.txt')
    known_abis = {'arm64-v8a', 'armeabi-v7a', 'armeabi', 'x86', 'x86_64', 'mips', 'mips64', 'riscv64'}
    report['abi'] = [abi if abi in known_abis else 'unknown'
                     for line in badging.splitlines() if line.startswith('native-code:')
                     for abi in re.findall(r"'([^']*)'", line)][:16]
    signing = output(temp / 'signing.txt')
    pattern = r'^(?:Signer #\d+ certificate|V\d+(?:\.\d+)? Signer(?: #\d+)?: certificate) SHA-256 digest: ([0-9a-f]{64})\s*$'
    report['certificate_sha256'] = sorted({s.lower() for s in re.findall(pattern, signing, re.I | re.M)})[:16]
    report['number_of_signers'] = re.findall(r'^Number of signers: (\d{1,5})\s*$', signing, re.M)[:2]

    crx, core = 'assets/bare/ublock_origin.crx', 'lib/arm64-v8a/libchrome.so'
    try:
        with zipfile.ZipFile(apk) as archive:
            entries = archive.namelist()
            report['ubo_members'], report['arm64_library_members'] = entries.count(crx), entries.count(core)
            if report['ubo_members'] == 1 and archive.getinfo(crx).file_size <= 16 * 1024**2:
                with archive.open(crx) as stream:
                    report['ubo_sha256'] = digest(stream)
            if report['arm64_library_members'] == 1:
                with archive.open(core) as stream:
                    header = stream.read(20)
                if len(header) == 20:
                    report['elf'] = {'magic_ok': header[:4] == b'\x7fELF', 'class': header[4],
                                     'data': header[5],
                                     'machine': int.from_bytes(header[18:20], 'big' if header[5] == 2 else 'little')}
    except (EOFError, OSError, RuntimeError, ValueError, zipfile.BadZipFile, zlib.error):
        report['zip_read_error'] = True
    return report


if __name__ == '__main__':
    print('BARE_REJECTED_APK_QC ' + json.dumps(observe(Path(sys.argv[1]), Path(sys.argv[2])), sort_keys=True),
          file=sys.stderr)
