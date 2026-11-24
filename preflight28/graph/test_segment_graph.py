"""Normal segment production/recovery entry points against native pinned Siso."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from graph import run
from segment_graph import begin, finish, PROOF

SISO = os.environ.get("SISO")
GRAPH = """rule make
  command = python3 ../../build.py $in $out
rule pair
  command = python3 ../../build.py ../../b.h obj/b.o implicit.dat
  depfile = b.d
  deps = gcc
build obj/a.o: make ../../a.h
build obj/b.o | implicit.dat: pair ../../b.h
build obj/c.o: make ../../c.h
build apk: make obj/a.o obj/b.o obj/c.o
build chrome_public_apk: phony apk
"""

@unittest.skipUnless(SISO, "set SISO to the pinned Chromium Siso executable")
class NormalSegmentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        old = Path.cwd()
        os.chdir(root)
        self.addCleanup(os.chdir, old)
        (root / ".gclient").touch()
        self.out = root / "out/Bare"
        self.out.mkdir(parents=True)
        (self.out / "build.ninja").write_text(GRAPH)
        for n in "abc":
            Path(n + ".h").write_text(n)
        Path("included.h").write_text("old")
        Path("build.py").write_text(
            "from pathlib import Path\nimport sys\n"
            "for name in sys.argv[2:]:\n"
            " p=Path(name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text('output')\n"
            "if sys.argv[2] == 'obj/b.o':\n"
            " Path('b.d').write_text('obj/b.o: ../../included.h\\n')\n")
        self.command = [SISO, "ninja", "-load="]
        self.parent = "a" * 64
        self.child = "b" * 64
        self.baseline = root / "start.json"
        self.report = root / "trial-restore.json"
        run(self.out, self.command, ["obj/a.o"], dry=False)

    def advance(self):
        original = begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        self.assertEqual(original, {"pending": 3, "parent_frontier_verified": False})
        metrics = self.report.parent / "siso-metrics-restore.json"
        subprocess.run([*self.command, "-C", str(self.out), "-metrics_json", str(metrics),
                        "obj/b.o", "obj/c.o"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.report.write_text(json.dumps({"target":"chrome_public_apk", "phase":"restore",
                          "container_quiescence_verified":True, "ready_for_restore_test":True,
                          "failed_step_count":0, "forced_kill":False,"metrics_path":str(metrics)}))
        evidence = finish(self.out, self.baseline, self.report, self.command)
        self.assertEqual(evidence["advanced_edges"], 2)
        stored = self.out.parent / "archive-copy"
        self.out.rename(stored)
        shutil.copytree(stored, self.out, symlinks=True)
        self.assertFalse((self.out / "apk").exists())

    def receive(self, name):
        return begin(self.out, self.report.parent/name, self.child, self.command, verify_only=True)

    def test_two_steps_and_independent_recovery(self):
        self.advance()
        self.assertEqual(self.receive("next.json"), {"pending":1, "parent_frontier_verified":True})
        (self.out / "obj/a.o").unlink()
        with self.assertRaisesRegex(ValueError, "regressed|different"):
            self.receive("rolled-back.json")

    def test_missing_implicit(self):
        self.advance()
        (self.out / "implicit.dat").unlink()
        with self.assertRaises((FileNotFoundError,ValueError)):
            self.receive("missing.json")

    def test_changed_discovered_input(self):
        self.advance()
        Path("included.h").write_text("changed")
        with self.assertRaisesRegex(ValueError, "dirty"):
            self.receive("invalid-deps.json")

    def test_missing_proof_cannot_bootstrap_recovery(self):
        with self.assertRaisesRegex(ValueError, "lacks"):
            begin(self.out, self.baseline, self.child, self.command, bootstrap=True,verify_only=True)
        self.assertFalse((self.out/PROOF).exists())

if __name__ == "__main__":
    unittest.main()
