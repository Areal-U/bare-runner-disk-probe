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
        self.report.write_text(json.dumps({"target":"chrome_public_apk", "phase":"restore","reason":"time-limit",
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

    def corrupt(self, name):
        path = self.out / name
        st = path.stat()
        path.write_bytes(b"X" * st.st_size)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))

    def test_inherited_substitution_on_fresh_receiver(self):
        self.advance()
        self.corrupt("obj/a.o")
        with self.assertRaisesRegex(ValueError, "retained output contents"):
            self.receive("changed.json")

    def test_unattributed_same_stat_replacement_fails_at_producer(self):
        self.advance()
        self.corrupt("obj/a.o")
        with self.assertRaisesRegex(ValueError, "Unaccounted retained"):
            finish(self.out, self.baseline, self.report, self.command)

    def test_complete_apk_content_gate_including_replaced_edge(self):
        # Existing, invalidated output can change if its actual successful edge
        # is in the fixed APK plan and completed during this build.
        self.corrupt("obj/a.o")
        Path("a.h").write_text("changed input")
        begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        metrics = self.report.parent / "siso-metrics-restore.json"
        subprocess.run([*self.command, "-C",str(self.out), "-metrics_json",str(metrics),
                        "chrome_public_apk"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.report.write_text(json.dumps({"phase":"restore", "target":"chrome_public_apk",
            "returncode":0, "artifact_ready":True,"reason":"completed","forced_kill":False,
            "failed_step_count":0, "metrics_path":str(metrics)}))
        evidence = finish(self.out, self.baseline, self.report, self.command, terminal=True, host_quiesced=True)
        self.assertEqual(evidence["frontier_status"],"apk-complete")
        self.assertEqual(evidence["replacements"],["obj/a.o"])
        self.corrupt("build.ninja")
        with self.assertRaisesRegex(ValueError,"fixed graph"):
            finish(self.out, self.baseline, self.report, self.command, terminal=True, host_quiesced=True)

    def test_private_segment_retains_all_packaging_intermediates(self):
        # Bootstrap after GN has regenerated the descriptor omitted by S2 gzip.
        descriptor = self.out / "apks/gn-package.build_config.json"
        descriptor.parent.mkdir()
        descriptor.write_text('{"package":"personal"}')
        ninja = self.out / "build.ninja"
        ninja.write_text(ninja.read_text().replace("build apk: make obj/a.o obj/b.o obj/c.o",
            "build apks/partial.apk | gen/resources.ap_: make ../../c.h\n"
            "build apk: make obj/a.o obj/b.o obj/c.o apks/partial.apk gen/resources.ap_"))
        begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        metrics = self.report.parent / "siso-metrics-restore.json"
        # The fixture's command receives only explicit outputs. Create the
        # implicit resource from the very same successful build action.
        engine = Path("build.py")
        engine.write_text(engine.read_text() +
            "\nif sys.argv[2]=='apks/partial.apk':\n Path('gen').mkdir(exist_ok=True); Path('gen/resources.ap_').write_bytes(b'local package')\n")
        subprocess.run([*self.command, "-C",str(self.out), "-metrics_json",str(metrics),
                        "apks/partial.apk"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.report.write_text(json.dumps({"phase":"restore", "target":"chrome_public_apk",
            "ready_for_restore_test":True,"reason":"time-limit","forced_kill":False,
            "failed_step_count":0, "metrics_path":str(metrics)}))
        with self.assertRaisesRegex(ValueError, "no persistable success"):
            finish(self.out, self.baseline, self.report, self.command,host_quiesced=True)
        ok = finish(self.out, self.baseline, self.report, self.command,host_quiesced=True,
                    private_intermediates=True)
        self.assertEqual(ok["advanced_edges"],1)
        # Full tar stream -> zstd -> fresh output directory. No APK is executed.
        archive = self.report.parent / "private.tar.zst"
        subprocess.run(["tar","--format=posix","--pax-option=delete=atime,delete=ctime","--zstd","-cf",str(archive),"-C",str(self.out.parent),self.out.name],check=True)
        self.out.rename(self.out.parent/"previous")
        subprocess.run(["tar","--zstd","-xf",str(archive),"-C",str(self.out.parent)],check=True)
        self.assertTrue(self.receive("private-verified.json")["parent_frontier_verified"])
        descriptor.unlink()
        with self.assertRaisesRegex(ValueError, "retained output contents"):
            self.receive("lost-descriptor.json")

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

    def test_clean_interruption_without_progress_has_no_child(self):
        begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        report = {"target":"chrome_public_apk", "phase":"restore", "reason":"time-limit",
                  "ready_for_restore_test":False, "failed_step_count":0, "forced_kill":False}
        self.report.write_text(json.dumps(report))
        self.assertEqual(finish(self.out, self.baseline, self.report, self.command,
                                host_quiesced=True)["frontier_status"], "no-progress")
        self.assertFalse((self.out/PROOF).exists())
        report["reason"] = "oom-kill"
        self.report.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            finish(self.out, self.baseline, self.report, self.command, host_quiesced=True)

    def test_missing_proof_cannot_bootstrap_recovery(self):
        with self.assertRaisesRegex(ValueError, "lacks"):
            begin(self.out, self.baseline, self.child, self.command, bootstrap=True,verify_only=True)
        self.assertFalse((self.out/PROOF).exists())

if __name__ == "__main__":
    unittest.main()
