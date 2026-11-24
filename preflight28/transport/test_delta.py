"""Use the actual R27 rdiff executable, GNU zstd and the limited peer's test certificate."""
from contextlib import ExitStack
import gzip
import os
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP",tempfile.gettempdir())
import delta


class DeltaTests(unittest.TestCase):
    def test_single_private_delta_roundtrip_and_failure_boundaries(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root=Path(folder)
            keys=root/"keys"; keys.mkdir(mode=0o700)
            env={"GITHUB_RUN_ID":"2002","GITHUB_RUN_ATTEMPT":"1","GITHUB_JOB":"limited",
                 "TRIAL_SHA":"a"*40, "GITHUB_REPOSITORY":delta.bridge.REPO, "RUNNER_TEMP":folder}
            stack.enter_context(patch.dict(os.environ,env))
            stack.enter_context(patch.object(delta.bridge,"ROOT",keys))
            delta.bridge.keygen()
            raw=random.Random(38).randbytes(2*delta.MIB)
            basis=root/"s2.gz"; basis.write_bytes(gzip.compress(raw,mtime=0))
            data=raw[:400000]+b"a small new graph output\n"*1000+raw[400000:]
            full=root/"full.zst"
            full.write_bytes(subprocess.run(["zstd","-q","-T2","-9","-c"],input=data,capture_output=True,check=True).stdout)
            for key,value in (("BASE_GZIP_BYTES",basis.stat().st_size),("BASE_SHA",delta.bridge.digest(basis)),
                              ("BASE_RAW_BYTES",len(raw))):
                stack.enter_context(patch.object(delta,key,value))
            def space(path,needed):
                self.assertGreater(needed,0)
            stack.enter_context(patch.object(delta,"disk",space))
            packet=root/"fallback"
            receipt=delta.seal(basis,full,keys/"public.pem",packet)
            self.assertEqual({p.name for p in packet.iterdir()},{"delta.cms","delta.json"})
            self.assertLess(receipt["sealed_bytes"],full.stat().st_size//10)
            self.assertNotIn(b"a small new graph", (packet/"delta.cms").read_bytes())
            target=root/"rebuilt.zst"
            delta.restore(basis,packet,target,keys,receipt["target_sha"],receipt["target_bytes"])
            self.assertEqual(target.read_bytes(),full.read_bytes())
            with self.assertRaises(ValueError):
                delta.restore(basis,packet,root/"wrong.zst",keys,"e"*64,receipt["target_bytes"])
            with patch.object(delta,"DELTA_CAP",4), self.assertRaises(subprocess.CalledProcessError):
                delta.seal(basis,full,keys/"public.pem",root/"oversize")
            self.assertFalse((root/"oversize").exists())
            with patch.object(delta,"ARTIFACT_CAP",delta.MIB), self.assertRaises(ValueError):
                delta.restore(basis,packet,root/"oversize.zst",keys,receipt["target_sha"],receipt["target_bytes"])
            with self.assertRaises(FileNotFoundError):
                delta.restore(root/"missing.gz",packet,root/"invalid.zst",keys,receipt["target_sha"],receipt["target_bytes"])
            sealed=packet/"delta.cms"; blob=bytearray(sealed.read_bytes());blob[-20]^=3;sealed.write_bytes(blob)
            with self.assertRaises(ValueError):
                delta.restore(basis,packet,root/"tampered.zst",keys,receipt["target_sha"],receipt["target_bytes"])


if __name__=="__main__":
    unittest.main(verbosity=2)
