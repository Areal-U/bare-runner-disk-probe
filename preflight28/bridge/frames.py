"""Bound OpenSSL ASN.1 decoding and memory per authenticated checkpoint chunk."""
from contextlib import contextmanager
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import time

import bridge as b

MAGIC = b"BARE-R28-CMS-V1\x00"
FRAME = 64 * 1024**2
# Encrypted per-frame header commits to the exact whole object and position.
INNER = struct.Struct(">16sQII32s")
OUTER = struct.Struct(">16sQ32s")
LENGTH = struct.Struct(">I")
OVERHEAD = 128 * 1024


def layout(size):
    b.require(0 < size <= b.CAP, "Checkpoint outside storage limit")
    return (size+FRAME-1)//FRAME


def exact(stream, size):
    data=stream.read(size)
    b.require(len(data)==size,"Truncated checkpoint frame")
    return data


@contextmanager
def staged(path):
    fd,name=tempfile.mkstemp(prefix=".r28-cms-",dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as output:
            yield output
        os.link(name,path)  # atomic, and cannot overwrite an existing receipt
    finally:
        Path(name).unlink(missing_ok=True)


def frame_budget(deadline):
    remaining=deadline-time.monotonic()
    b.require(remaining>=1,"Checkpoint encryption or decryption exceeded its total budget")
    return min(remaining,180)


def seal(public, file, enc, expected):
    size = file.stat().st_size
    count = layout(size)
    digest = bytes.fromhex(expected)
    b.require(len(digest)==32,"Expected fixed whole-file digest")
    deadline=time.monotonic()+18*60
    with tempfile.TemporaryDirectory(dir=b.ROOT) as scratch, file.open("rb") as source, staged(enc) as dest:
        plain, cipher = Path(scratch)/"plain", Path(scratch)/"cipher"
        dest.write(OUTER.pack(MAGIC,size,digest))
        total=hashlib.sha256()
        for index in range(count):
            length = min(FRAME,size-index*FRAME)
            data = exact(source,length)
            total.update(data)
            with plain.open("wb") as f:
                f.write(INNER.pack(MAGIC,size,index,count,digest))
                f.write(data)
            del data
            b.encrypt(public,plain,cipher,timeout=frame_budget(deadline))
            clen=cipher.stat().st_size
            b.require(length<clen<=length+OVERHEAD,"Unexpected sealed frame length")
            dest.write(LENGTH.pack(clen))
            with cipher.open("rb") as f:
                while block:=f.read(1024**2):
                    dest.write(block)
        b.require(not source.read(1) and total.digest()==digest,"Input changed during checkpoint sealing")
    print(f"checkpoint_frames_sent={count} max_frame_payload={FRAME}",flush=True)


def receive(enc, file, expected_size, expected_sha):
    count=layout(expected_size)
    digest=bytes.fromhex(expected_sha)
    deadline=time.monotonic()+18*60
    with tempfile.TemporaryDirectory(dir=b.ROOT) as scratch, enc.open("rb") as source, staged(file) as dest:
        plain,cipher=Path(scratch)/"plain",Path(scratch)/"cipher"
        b.require(OUTER.unpack(exact(source,OUTER.size))==(MAGIC,expected_size,digest),
                  "Sealed checkpoint header differs from expected generation")
        whole=hashlib.sha256()
        for index in range(count):
            length=min(FRAME,expected_size-index*FRAME)
            clen,=LENGTH.unpack(exact(source,LENGTH.size))
            b.require(length<clen<=length+OVERHEAD,"Unexpected incoming frame length")
            with cipher.open("wb") as f:
                left=clen
                while left:
                    block=exact(source,min(1024**2,left))
                    f.write(block)
                    left-=len(block)
            # OpenSSL may write provisional plaintext before authentication. Only
            # copy from this disposable file after a successful verified exit.
            b.decrypt(cipher,plain,timeout=frame_budget(deadline))
            b.require(plain.stat().st_size==INNER.size+length,"Wrong decrypted frame length")
            with plain.open("rb") as f:
                b.require(INNER.unpack(exact(f,INNER.size))==(MAGIC,expected_size,index,count,digest),
                          "Reordered or substituted authenticated frame")
                while block:=f.read(1024**2):
                    whole.update(block)
                    dest.write(block)
        b.require(not source.read(1) and whole.digest()==digest,"Extra frame or reordered object")
    print(f"checkpoint_frames_received={count} max_frame_payload={FRAME}",flush=True)
