"""CMS frame alignment, corruption, and optional >INT_MAX OpenSSL boundary."""
import hashlib
import json
import os
from pathlib import Path
import resource
import struct
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import bridge as b
import frames


class TestFrames(unittest.TestCase):
    def test_boundaries_and_damage(self):
        with tempfile.TemporaryDirectory() as temp,patch.dict(os.environ,GITHUB_JOB="fixture",GITHUB_RUN_ID="41"),patch.object(frames,"FRAME",1024):
            root=Path(temp);b.ROOT=root;b.keygen()
            with self.assertRaises(ValueError):frames.layout(0)
            with self.assertRaises(ValueError):frames.layout(b.CAP+1)
            for n in (1,1023,1024,1025,2048,2049):
                plain=root/f"input-{n}";plain.write_bytes(os.urandom(n))
                cipher=root/f"enc-{n}";out=root/f"out-{n}"
                dig=b.digest(plain)
                frames.seal(root/"public.pem",plain,cipher,dig)
                frames.receive(cipher,out,n,dig)
                self.assertEqual(out.read_bytes(),plain.read_bytes())
            raw=cipher.read_bytes()
            body=[];off=frames.OUTER.size
            while off<len(raw):
                length,=frames.LENGTH.unpack_from(raw,off)
                body.append(raw[off:off+frames.LENGTH.size+length])
                off+=frames.LENGTH.size+length
            header=raw[:frames.OUTER.size]
            failures=[raw[:-1],raw+b"trailing",header+body[1]+body[0]+body[2],
                      header+body[0]+body[0]+body[2],
                      header+frames.LENGTH.pack(frames.OVERHEAD+frames.FRAME+1)+b"p",
                      header+frames.LENGTH.pack(0),raw[:-15]+bytes([raw[-15]^1])+raw[-14:]]
            for i,bad in enumerate(failures):
                bad_path=root/f"bad-{i}";bad_path.write_bytes(bad)
                bad_out=root/f"failed-{i}"
                with self.assertRaises((ValueError,subprocess.CalledProcessError)):
                    frames.receive(bad_path,bad_out,n,dig)
                self.assertFalse(bad_out.exists())
            b.keygen()
            with self.assertRaises(subprocess.CalledProcessError):
                frames.receive(cipher,root/"wrong-key",n,dig)
            self.assertFalse((root/"wrong-key").exists())
            with self.assertRaises(ValueError):
                frames.frame_budget(time.monotonic()-1)

    @unittest.skipUnless(os.getenv("R28_LARGE_FRAME_TEST_ROOT"),"set R28_LARGE_FRAME_TEST_ROOT to a volume with 7 GiB free")
    def test_open_ssl_intmax_plus_one(self):
        mount=Path(os.environ["R28_LARGE_FRAME_TEST_ROOT"]).resolve(strict=True)
        usage=os.statvfs(mount)
        self.assertGreater(usage.f_bavail*usage.f_frsize,7*1024**3)
        with tempfile.TemporaryDirectory(dir=mount) as temp,patch.dict(os.environ,GITHUB_RUN_ID="42",GITHUB_JOB="local-size-boundary"):
            b.ROOT=Path(temp);b.keygen()
            size=2**31+1
            original=b.ROOT/"sparse-source";cipher=b.ROOT/"sealed";result=b.ROOT/"recovered"
            with original.open("wb") as f:
                f.write(b"prefix-r28");f.seek(2**31-2);f.write(b"end")
            dig=b.digest(original)
            start=time.monotonic()
            frames.seal(b.ROOT/"public.pem",original,cipher,dig)
            mid=time.monotonic()
            frames.receive(cipher,result,size,dig)
            end=time.monotonic()
            self.assertEqual(b.digest(result),dig)
            self.assertEqual(result.stat().st_size,size)
            print(json.dumps(dict(plain_bytes=size,sealed_bytes=cipher.stat().st_size,frames=frames.layout(size),
                sha256=dig,encrypt_seconds=mid-start,decrypt_seconds=end-mid,
                parent_peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
                child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)),flush=True)


if __name__=="__main__":unittest.main()
