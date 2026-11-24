"""Archived S2 migration uses the same retention rules as the live filesystem."""
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import retained


class ArchiveTest(unittest.TestCase):
    def write(self, root, name, bodies, proof=None):
        raw = root / (name + ".tar")
        with tarfile.open(raw, "w") as out:
            for rel, data in bodies.items():
                member = tarfile.TarInfo("out/Bare/" + rel)
                if data == "hardlink":
                    member.type = tarfile.LNKTYPE
                    member.linkname = "out/Bare/obj/a"
                    out.addfile(member)
                elif data == "symlink":
                    member.type = tarfile.SYMTYPE
                    member.linkname = "a"
                    out.addfile(member)
                else:
                    buff = io.BytesIO(data)
                    member.size = len(data)
                    member.mode = 0o644
                    out.addfile(member, buff)
            if proof:
                data = json.dumps(proof).encode()
                member = tarfile.TarInfo("out/Bare/" + retained.PROOF)
                member.size = len(data)
                out.addfile(member, io.BytesIO(data))
        encoded = root / (name + (".gz" if name=="parent" else ".zst"))
        with encoded.open("wb") as fd:
            subprocess.run(["gzip" if name=="parent" else "zstd", "-c", str(raw)],stdout=fd,check=True)
        return encoded, hashlib.sha256(encoded.read_bytes()).hexdigest()

    def test_compare_both_codecs_and_detect_historical_substitution(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            bodies = {"obj/a":b"A", "obj/link":"symlink", "obj/hard":"hardlink",
                      "obj/siso_output":b"protect a nested diagnostic-like payload",
                      ".ninja_log":b"rotated"}
            parent, psha = self.write(root,"parent",bodies)
            bodies[".ninja_log"] = b"new diagnostics"
            bodies["obj/b.o"] = b"B"
            proof = {"format":"bare-28-apk-frontier-1","target":"chrome_public_apk",
                     "target_path":"obj/b.o","outputs":{"obj/b.o":[1,hashlib.sha256(b"B").hexdigest()]}}
            child, csha = self.write(root,"child",bodies,proof)
            with patch.object(retained,"S2",psha):
                row = retained.archives(parent,child,psha,csha)
                self.assertEqual((row["matched_before"],row["replaced"],row["new_files"]),(4,[],1))
                proof.update(format="bare-28-apk-frontier-2",child_content=row["child_content"])
                child2,sha2=self.write(root,"child2",bodies,proof)
                self.assertEqual(retained.archives(parent,child2,psha,sha2)["matched_before"],4)
                bodies["obj/unknown"]=b"uncommitted addition"
                extra,extra_sha=self.write(root,"extra",bodies,proof)
                with self.assertRaisesRegex(ValueError,"complete producer"):
                    retained.archives(parent,extra,psha,extra_sha)
                del bodies["obj/unknown"]
                proof["format"]="bare-28-apk-frontier-1"
                bodies["obj/a"] = b"X"
                bad, bsha = self.write(root,"bad",bodies,proof)
                with self.assertRaisesRegex(ValueError,"Unaccounted retained"):
                    retained.archives(parent,bad,psha,bsha)
                with self.assertRaisesRegex(ValueError,"SHA mismatch"):
                    retained.archives(parent,bad,psha,csha)


if __name__ == "__main__":
    unittest.main()
