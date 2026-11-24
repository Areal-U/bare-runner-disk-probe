"""One encrypted, byte-limited S2 delta for an explicitly refused full Artifact."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
import bridge
import frames

MIB = 1024**2
GIB = 1024**3
BASE_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
BASE_GZIP_BYTES = 2_753_879_385
BASE_RAW_BYTES = 9_673_482_240
FULL_CAP = 7*GIB//2
RAW_CAP = 22*GIB
ARTIFACT_CAP = 256*MIB
# Explicit reserve for the two-member uncompressed ZIP and CMS frame metadata.
DELTA_CAP = ARTIFACT_CAP-2*MIB
SIGNATURE_CAP = 128*MIB
FRAME_SCRATCH = 160*MIB


def size(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0:
        raise ValueError("Invalid fallback input")
    return info.st_size


def disk(path, future):
    fs = os.statvfs(path)
    available = fs.f_bavail * fs.f_frsize
    print(f"delta_space device={path.stat().st_dev} free={available} incremental={future} free_inodes={fs.f_favail}",flush=True)
    if available < 20*GIB + future or fs.f_favail < 20_020:
        raise ValueError("Insufficient measured delta workspace")


def validate_basis(path):
    if size(path) != BASE_GZIP_BYTES or bridge.digest(path) != BASE_SHA:
        raise ValueError("Fallback basis differs from fixed R27 S2")


def context():
    sha=os.environ["TRIAL_SHA"]
    if (os.environ["GITHUB_REPOSITORY"] != bridge.REPO or bridge.env_int("GITHUB_RUN_ATTEMPT") != 1
            or not re.fullmatch("[0-9a-f]{40}",sha)):
        raise ValueError("Fallback outside initial fixed test attempt")
    return {"format":"bare-s2-rdiff-framed-v1", "head":sha, "run":bridge.env_int("GITHUB_RUN_ID"),
            "attempt":1, "basis_sha":BASE_SHA, "basis_bytes":BASE_GZIP_BYTES, "basis_raw_bytes":BASE_RAW_BYTES}


def bounded_copy(limit):
    if not 1 <= limit <= RAW_CAP:
        raise ValueError("Invalid fallback stream limit")
    copied=0
    while block := sys.stdin.buffer.read(MIB):
        copied += len(block)
        if copied > limit:
            raise ValueError("Fallback stream exceeds its budget")
        sys.stdout.buffer.write(block)
    if not copied:
        raise ValueError("Empty fallback stream")


def pipe(code, *paths):
    # The timeout owns the complete pipe process group; a failed writer never leaves
    # a decoder consuming the large S2 input in the background.
    subprocess.run(["timeout", "--kill-after=10s", "25m", "bash", "-euo", "pipefail", "-c", code,
                    "r28-s2-delta", *map(str,paths)],check=True)


@contextmanager
def frame_directory(path):
    prior = bridge.ROOT
    bridge.ROOT = path
    try:
        yield
    finally:
        bridge.ROOT = prior


def seal(basis, full, cert, out):
    receipt = context()
    validate_basis(basis)
    count = size(full)
    if count > FULL_CAP or out.exists() or out.is_symlink():
        raise ValueError("Invalid full child or occupied fallback destination")
    digest = bridge.digest(full)
    disk(out.parent, SIGNATURE_CAP+2*ARTIFACT_CAP+FRAME_SCRATCH)
    with tempfile.TemporaryDirectory(dir=out.parent) as td:
        local=Path(td)
        sig=local/"signature"
        patch=local/"diff.zst"
        encrypted=local/"packet"
        encrypted.mkdir(mode=0o700)
        script=Path(__file__).resolve()
        pipe('gzip -dc -- "$1" | rdiff --block-size=4096 -- signature - - | "$2" "$3" pipe "$4" > "$5"',
             basis,sys.executable,script,SIGNATURE_CAP,sig)
        pipe('zstd -qdc -M128MB -- "$1" | "$2" "$3" pipe "$4" | rdiff -- delta "$5" | zstd -q -T2 -3 -c | "$2" "$3" pipe "$6" > "$7"',
             full,sys.executable,script,RAW_CAP,sig,DELTA_CAP,patch)
        patch_size=size(patch)
        patch_sha=bridge.digest(patch)
        sealed=encrypted/"delta.cms"
        with frame_directory(local):
            frames.seal(cert,patch,sealed,patch_sha)
        receipt.update(target_bytes=count,target_sha=digest,delta_bytes=patch_size,delta_sha=patch_sha,
                       sealed_bytes=size(sealed),sealed_sha=bridge.digest(sealed),recipient=bridge.fingerprint(cert))
        record=encrypted/"delta.json"
        record.write_text(json.dumps(receipt,sort_keys=True)+"\n")
        if size(sealed)+size(record)+MIB > ARTIFACT_CAP:
            raise ValueError("Sealed fallback including ZIP allowance exceeds 256 MiB")
        # The caller uploads this directory only after this successful return.
        out.mkdir(mode=0o700)
        os.link(sealed,out/sealed.name)
        os.link(record,out/record.name)
    print(f"delta_ready full_bytes={count} sealed_bytes={receipt['sealed_bytes']} target_sha={digest}",flush=True)
    return receipt


def restore(basis, packet, output, keys, expected_sha, expected_bytes):
    binding=context()
    validate_basis(basis)
    names={p.name for p in packet.iterdir()}
    if names!={"delta.cms","delta.json"} or output.exists() or output.is_symlink():
        raise ValueError("Unexpected fallback payload or occupied output")
    meta=packet/"delta.json"
    sealed=packet/"delta.cms"
    if size(meta)>16384 or size(sealed)+size(meta)+MIB > ARTIFACT_CAP:
        raise ValueError("Oversized fallback Artifact")
    record=json.loads(meta.read_bytes())
    if (any(record.get(k)!=v for k,v in binding.items()) or not bridge.sha(expected_sha)
            or not 0<expected_bytes<=FULL_CAP or (record["target_sha"],record["target_bytes"])!=(expected_sha,expected_bytes)
            or type(record["delta_bytes"]) is not int or not 0<record["delta_bytes"]<=DELTA_CAP
            or not bridge.sha(record["delta_sha"]) or record["sealed_bytes"]!=size(sealed)
            or record["sealed_sha"]!=bridge.digest(sealed) or record["recipient"]!=bridge.fingerprint(keys/"public.pem")):
        raise ValueError("Fallback differs from independent source receipt")
    if keys.stat().st_dev != output.parent.stat().st_dev:
        raise ValueError("Delta key staging and output must use the same measured filesystem")
    disk(output.parent, BASE_RAW_BYTES+expected_bytes+record["delta_bytes"]+FRAME_SCRATCH)
    with tempfile.TemporaryDirectory(dir=output.parent) as td:
        local=Path(td)
        raw=local/"basis.tar"
        patch=local/"diff.zst"
        rebuilt=local/"full.zst"
        with frame_directory(keys):
            frames.receive(sealed,patch,record["delta_bytes"],record["delta_sha"])
        script=Path(__file__).resolve()
        pipe('gzip -dc -- "$1" | "$2" "$3" pipe "$4" > "$5"',basis,sys.executable,script,BASE_RAW_BYTES,raw)
        if size(raw)!=BASE_RAW_BYTES:
            raise ValueError("Wrong decompressed S2 tar length")
        pipe('zstd -qdc -M128MB -- "$1" | "$2" "$3" pipe "$4" | rdiff -- patch "$5" | "$2" "$3" pipe "$4" | zstd -q -T2 -9 -c | "$2" "$3" pipe "$6" > "$7"',
             patch,sys.executable,script,RAW_CAP,raw,expected_bytes,rebuilt)
        if size(rebuilt)!=expected_bytes or bridge.digest(rebuilt)!=expected_sha:
            raise ValueError("Reconstructed full zstd differs from original full successor")
        os.link(rebuilt,output)
    print(f"delta_rebuilt full_bytes={expected_bytes} target_sha={expected_sha}",flush=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    actions=p.add_subparsers(dest="action",required=True)
    bounded=actions.add_parser("pipe")
    bounded.add_argument("limit",type=int)
    for op, labels in (("seal",("basis","target","cert","out")),("restore",("basis","packet","out"))):
        cmd=actions.add_parser(op)
        for key in labels:
            cmd.add_argument(key,type=Path)
        if op=="restore":
            cmd.add_argument("--key-dir",type=Path,required=True)
            cmd.add_argument("--expected-sha",required=True)
            cmd.add_argument("--expected-bytes",type=int,required=True)
    args=p.parse_args()
    if args.action=="pipe":
        bounded_copy(args.limit)
    elif args.action=="seal":
        seal(args.basis,args.target,args.cert,args.out)
    else:
        restore(args.basis,args.packet,args.out,args.key_dir,args.expected_sha,args.expected_bytes)


if __name__=="__main__":
    main()
