"""Exercise the application verifier with Chromium's own pinned Siso executable."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

from graph import compare, produce, receive, run, sha

SISO = os.environ.get("SISO")
GRAPH = """rule copy
  command = python3 ../../edge.py $in $out
rule pair
  command = python3 ../../edge.py $in obj/b.o implicit.dat
  deps = gcc
  depfile = b.d
build obj/a.o: copy ../../a.in
build obj/b.o | implicit.dat: pair ../../b.in
build apk.out: copy obj/a.o obj/b.o
build chrome_public_apk: phony apk.out
build obj/outside.o: copy ../../a.in
"""


@unittest.skipUnless(SISO, "set SISO to Chromium's pinned Siso binary")
class FrontierTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="r28-frontier-test-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.old = Path.cwd()
        os.chdir(root)
        self.addCleanup(os.chdir, self.old)
        (root / ".gclient").touch()
        self.out = root / "out/Bare"
        self.out.mkdir(parents=True)
        (self.out / "build.ninja").write_text(GRAPH)
        self.proof = self.out / "proof.json"
        self.command = [SISO, "ninja", "-load="]
        (root / "a.in").write_text("A")
        (root / "b.in").write_text("B")
        (root / "private-header.h").write_text("original input")
        (root / "edge.py").write_text(
            "import pathlib, sys\n"
            "data = pathlib.Path(sys.argv[1]).read_bytes()\n"
            "for n in sys.argv[2:]:\n"
            "    p = pathlib.Path(n); p.parent.mkdir(exist_ok=True, parents=True)\n"
            "    p.write_bytes(data)\n"
            "if sys.argv[2] == 'obj/b.o':\n"
            "    pathlib.Path('b.d').write_text('obj/b.o: ../../private-header.h\\n')\n")
        run(self.out, self.command, ["obj/a.o"], dry=False)
        self.assertFalse((self.out / "obj/b.o").exists())

    def test_independent_restore_and_damage(self):
        # The same absolute source/output path as on two standard runners.
        # Snapshot after generation, replace ALL output, then verify afresh.
        log = self.out / ".ninja_log"
        before = sha(log)
        plan = run(self.out, self.command, ["chrome_public_apk"], dry=True)
        self.assertEqual(sha(log), before)
        self.assertNotIn(("obj/outside.o",), plan)
        self.assertIn(("implicit.dat", "obj/b.o"), plan)
        evidence = produce(self.out, self.proof, self.command)
        self.assertEqual(evidence["new_target"], "obj/b.o")
        self.assertFalse((self.out / "apk.out").exists())
        source = self.out.parent / "stored"
        self.out.rename(source)
        shutil.copytree(source, self.out, symlinks=True)
        result = receive(self.out, self.proof, self.command)
        self.assertEqual(result["restored_dirty"], 1)
        (self.out / "implicit.dat").unlink()
        with self.assertRaises((FileNotFoundError, ValueError)):
            receive(self.out, self.proof, self.command)
        shutil.copy2(source / "implicit.dat", self.out / "implicit.dat")
        (self.out / "obj/a.o").unlink()
        with self.assertRaisesRegex(ValueError, "different APK plan"):
            receive(self.out, self.proof, self.command)

    def test_same_mtime_same_size_inherited_substitution(self):
        produce(self.out, self.proof, self.command)
        path = self.out / "obj/a.o"
        before = path.stat()
        path.write_bytes(b"X" * before.st_size)
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        with self.assertRaisesRegex(ValueError, "retained output contents"):
            receive(self.out, self.proof, self.command)

    def test_depfile_changes_without_output_change(self):
        produce(self.out, self.proof, self.command)
        hashes = [sha(self.out / n) for n in ("obj/b.o", "implicit.dat")]
        Path("private-header.h").write_text("input changed without rebuilding either output")
        with self.assertRaisesRegex(ValueError, "dependencies require work"):
            receive(self.out, self.proof, self.command)
        self.assertEqual(hashes, [sha(self.out / n) for n in ("obj/b.o", "implicit.dat")])

    def test_no_credit_for_oscillation_or_unrelated_work(self):
        for parent, child, selected in [({"a"}, {"b"}, {"a"}), ({"b"}, {"a"}, {"b"}),
                                        ({"a"}, {"a"}, {"x"}), ({"a","b"}, {"b"}, {"x"})]:
            with self.assertRaises(ValueError):
                compare(parent, child, selected)
        compare({"a", "b"}, {"b"}, {"a"})


if __name__ == "__main__":
    unittest.main()
