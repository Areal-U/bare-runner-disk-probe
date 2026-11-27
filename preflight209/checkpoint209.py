"""Private, content-addressed Bare Personal 2.0.9 checkpoints."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

import retained209

CAP = 7 * 1024**3 // 2
UNPACKED = 18 * 1024**3 + 192 * 1024**2
MAX_ENTRIES = 525_000
PROOF = 'out/Bare/.r209/proof.json'
INPUTS = 'out/Bare/.r209/inputs.gz'
PLAN = 'out/Bare/.r209/frontier.json'
SCHEMA = 'bare-personal-209-checkpoint-v1'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        while block := f.read(1024**2):
            h.update(block)
    return h.hexdigest()


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()


def identity(proof):
    return hashlib.sha256(encode(proof)).hexdigest()


def valid_hex(value, size=64):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{'+str(size)+'}', value) is not None


def check_proof(proof, record):
    require(proof['schema'] == SCHEMA and record['schema'] == SCHEMA
            and all(proof[k] == record[k] for k in ('run', 'ordinal', 'producer_sha', 'parent_sha'))
            and record['attempt'] == 1 and 1 <= proof['ordinal'] <= 99
            and valid_hex(proof['producer_sha'],40) and valid_hex(proof['genesis'])
            and valid_hex(proof['parent_sha']) and valid_hex(proof['graph'])
            and type(proof['next_has_headroom']) is bool and valid_hex(proof['git_heads'])
            and valid_hex(proof['plan']) and valid_hex(proof['inputs'])
            and proof['before'] > proof['remaining'] > 0
            and proof['target'] == 'chrome_public_apk' and proof['quiescent'] is True
            and proof['genesis'] == digest(Path(__file__).with_name('upstream-lock.json'))
            and identity(proof) == record['identity'], 'Unbound or non-advancing proof')


def check_archive(archive, record):
    """Verify every member before any tar extraction, also on the independent VM."""
    require(archive.is_file() and not archive.is_symlink() and 0 < archive.stat().st_size <= CAP
            and archive.stat().st_size == record['bytes'] and digest(archive) == record['sha256'],
            'Compressed checkpoint mismatch')
    known = {}
    files = {}
    members = {}
    rows = {}
    docs = {
        PROOF: 8192,
        PLAN: 384*1024**2,
        'out/Bare/.r209/closed.json': 384*1024**2,
        'out/Bare/checkpoint-trial-restore.json': 128*1024**2,
    }
    total = 0
    proof = None
    with subprocess.Popen(['zstd', '-dc', '--', str(archive)], stdout=subprocess.PIPE) as z:
        try:
            with tarfile.open(fileobj=z.stdout, mode='r|') as tar:
                for m in tar:
                    p = PurePosixPath(m.name)
                    require(p.parts[:2] == ('out','Bare') and p.as_posix() == m.name
                            and '..' not in p.parts and '\\' not in m.name and len(m.name) < 4096
                            and not any(ord(c) < 32 for c in m.name) and m.name not in known
                            and len(known) < MAX_ENTRIES + 64 and m.mode & 0o7000 == 0
                            and (m.name == 'out/Bare' or known.get(str(p.parent)) == 'dir'),
                            'Unsafe, duplicated or unordered checkpoint member')
                    total += m.size
                    require(total <= UNPACKED and not m.sparse, 'Oversized or sparse checkpoint')
                    if m.isdir():
                        known[m.name] = 'dir'
                        retained209.add(rows,m.name,m.mode,'dir',0,None)
                    elif m.issym():
                        require(m.name == 'out/Bare/devil_util_host' and m.linkname == 'clang_x64/devil_util_bin',
                                'Unrecognized checkpoint link')
                        known[m.name] = 'link'
                        retained209.add(rows,m.name,m.mode,'link',0,m.linkname)
                    else:
                        require(m.isreg() and m.name != 'out/Bare/apks/ChromePublic.apk',
                                'Invalid or terminal checkpoint member')
                        known[m.name] = 'file'
                        f = tar.extractfile(m)
                        if m.name == INPUTS:
                            # Validate the complete gzip and input schema without
                            # requiring the receiver to install Chromium.
                            from input_state import validate
                            with tempfile.TemporaryDirectory(prefix='r209-input-') as d:
                                target = Path(d)/'inputs.gz'
                                with target.open('xb') as out:
                                    h = hashlib.sha256()
                                    while block := f.read(1024**2):
                                        out.write(block)
                                        h.update(block)
                                validate(target)
                                value = h.hexdigest()
                        elif m.name in docs:
                            require(0 < m.size <= docs[m.name], 'Unbounded checkpoint evidence')
                            raw = f.read()
                            value = hashlib.sha256(raw).hexdigest()
                            members[m.name] = json.loads(raw)
                            if m.name == PROOF:
                                proof = members[m.name]
                            del raw
                        else:
                            value = retained209.digest_stream(f)
                        retained209.add(rows,m.name,m.mode,'file',m.size,value)
                        if m.name in (PROOF, INPUTS, PLAN, 'out/Bare/.r209/git-heads.json'):
                            files[m.name] = value
            while z.stdout.read(1024**2):
                pass
        finally:
            z.stdout.close()
        require(z.wait() == 0, 'Invalid zstd stream')
    require(proof and files.get(PROOF) == record['proof_sha']
            and files.get(INPUTS) == proof['inputs'] and files.get(PLAN) == proof['plan']
            and files.get('out/Bare/.r209/git-heads.json') == proof['git_heads']
            and known.get('out/Bare/checkpoint-trial-restore.json') == 'file'
            and known.get('out/Bare/build.ninja') == 'file'
            and ('out/Bare/devil_util_host' not in known or
                 known.get('out/Bare/clang_x64/devil_util_bin') == 'file'), 'Incomplete checkpoint')
    check_proof(proof, record)
    retained209.verify(rows,proof,members['out/Bare/.r209/closed.json'],members[PLAN],members['out/Bare/checkpoint-trial-restore.json'])
    return proof
