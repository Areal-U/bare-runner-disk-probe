"""Normal segment production/recovery entry points against native pinned Siso."""
from contextlib import redirect_stdout
import io
import hashlib
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

    def test_locate_unproved_retirement_without_accepting_it(self):
        metrics = self.report.parent / "siso-metrics-restore.json"
        self.report.write_text(json.dumps({"target":"chrome_public_apk", "phase":"restore", "reason":"time-limit",
            "container_quiescence_verified":True, "ready_for_restore_test":True, "failed_step_count":0,
            "forced_kill":False, "metrics_path":str(metrics)}))
        begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        base = json.loads(self.baseline.read_bytes())
        def execute(path, *targets):
            subprocess.run([*self.command, '-C',str(self.out), '-metrics_json', str(path), *targets],
                           check=True, capture_output=True)
        def rejected():
            log = io.StringIO()
            with redirect_stdout(log), self.assertRaisesRegex(ValueError, "without success evidence"):
                finish(self.out, self.baseline, self.report, self.command, private_intermediates=True)
            raw = next(s for s in log.getvalue().splitlines() if s.startswith('BARE_FRONTIER_REJECTION '))
            self.assertLess(len(raw), 4096)
            for name in ('obj/b.o', 'implicit.dat', 'obj/c.o'):
                self.assertNotIn(name, raw)
            diagnostic = json.loads(raw.split(' ',1)[1])
            self.assertEqual((diagnostic['parent_sha256'], diagnostic['graph']), (self.parent, base['graph']))
            self.assertEqual((diagnostic['removed'], diagnostic['unsupported_count']), (2, 1))
            self.assertFalse((self.out / PROOF).exists())
            return diagnostic['first_group']

        original_tree = self.report.parent / 'original-tree'
        shutil.copytree(self.out, original_tree, symlinks=True)
        # One edge belongs to a different real invocation. Only the second invocation is authorized.
        donor = metrics.with_name('other-invocation.json')
        execute(donor, 'obj/b.o')
        execute(metrics, 'obj/c.o')
        foreign = rejected()
        self.assertEqual((foreign['new'], foreign['members'], foreign['current_metric_rows']['exact_success']), (2,2,0))

        # Repeat from the same cold graph. Here BOTH edges really execute in the current invocation.
        shutil.rmtree(self.out)
        shutil.copytree(original_tree, self.out, symlinks=True)
        metrics.unlink()
        execute(metrics, 'obj/b.o', 'obj/c.o')
        original_metrics = metrics.read_bytes()
        rows = [json.loads(line) for line in original_metrics.splitlines()]
        metrics.write_text(''.join(json.dumps(row)+'\n' for row in rows if 'obj/b.o' not in row.get('outputs',[])))
        lost = rejected()
        self.assertEqual((lost['group_id'], lost['current_metric_rows']), (foreign['group_id'], foreign['current_metric_rows']))
        self.assertEqual(lost['ninja_members'],2)

        # Even a wholly missing current success table must yield a bounded diagnostic,
        # before the separate check that requires at least one persistable witness.
        metrics.write_text('')
        no_rows = io.StringIO()
        with redirect_stdout(no_rows), self.assertRaisesRegex(ValueError, 'without success evidence'):
            finish(self.out, self.baseline, self.report, self.command, private_intermediates=True)
        raw = next(s for s in no_rows.getvalue().splitlines() if s.startswith('BARE_FRONTIER_REJECTION '))
        self.assertEqual(json.loads(raw.split(' ', 1)[1])['unsupported_count'], 2)

        # A distinct failure discards one implicit-output Ninja row while the real full metrics survive.
        metrics.write_bytes(original_metrics)
        ninja = self.out/'.ninja_log'
        original_ninja = ninja.read_bytes()
        ninja.write_bytes(b''.join(row for row in original_ninja.splitlines(keepends=True) if b'\timplicit.dat\t' not in row))
        missing_log = rejected()
        self.assertEqual((missing_log['current_metric_rows']['exact_success'],missing_log['ninja_members']), (1,1))
        ninja.write_bytes(original_ninja)
        clean = finish(self.out, self.baseline, self.report, self.command, private_intermediates=True)
        self.assertEqual((clean['frontier_status'],clean['advanced_edges']), ('candidate',2))

    def test_two_steps_and_independent_recovery(self):
        self.advance()
        self.assertEqual(self.receive("next.json"), {"pending":1, "parent_frontier_verified":True})
        (self.out / "obj/a.o").unlink()
        with self.assertRaisesRegex(ValueError, "regressed|different"):
            self.receive("rolled-back.json")

    def test_deferred_terminal_retry_can_only_report_unchanged_parent(self):
        begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)
        record = {"target": "chrome_public_apk", "reason": "insufficient-terminal-retry-window",
                  "returncode": None, "forced_kill": False, "ready_for_restore_test": False,
                  "interrupted_terminal_actions": ["DEX final"]}
        self.report.write_text(json.dumps(record))
        result = finish(self.out, self.baseline, self.report, self.command, host_quiesced=True)
        self.assertEqual((result["frontier_status"], result["candidate_progress"]), ("no-progress", False))
        self.report.write_text(json.dumps(dict(record, command=["autoninja"])))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            finish(self.out, self.baseline, self.report, self.command, host_quiesced=True)
        self.report.write_text(json.dumps(record))
        (self.out/"obj/a.o").unlink()
        with self.assertRaisesRegex(ValueError, "changed the full APK frontier"):
            finish(self.out, self.baseline, self.report, self.command, host_quiesced=True)

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

    def test_two_private_successors_with_complete_progress_evidence(self):
        # First segment completes more than the three targeted no-op samples.
        ninja = self.out / "build.ninja"
        extra = ("build obj/d.o: make ../../c.h\n"
                 "build obj/e.o: make ../../c.h\n"
                 "build obj/f.o: make ../../c.h\n")
        ninja.write_text(ninja.read_text().replace("build apk: make obj/a.o obj/b.o obj/c.o",
            extra + "build apk: make obj/a.o obj/b.o obj/c.o obj/d.o obj/e.o obj/f.o"))
        self.assertEqual(begin(self.out, self.baseline, self.parent, self.command, bootstrap=True)["pending"], 6)
        metrics = self.report.parent / "siso-metrics-restore.json"
        self.report.write_text(json.dumps({"target":"chrome_public_apk","phase":"restore","reason":"time-limit",
            "container_quiescence_verified":True,"ready_for_restore_test":True,"failed_step_count":0,
            "forced_kill":False,"metrics_path":str(metrics)}))
        def execute(targets):
            metrics.unlink(missing_ok=True)
            subprocess.run([*self.command, "-C", str(self.out), "-metrics_json", str(metrics), *targets],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def independently_restore(generation):
            archive = self.report.parent / (generation + ".tar.zst")
            subprocess.run(["tar","--format=posix","--pax-option=delete=atime,delete=ctime","--zstd",
                            "-cf",str(archive),"-C",str(self.out.parent),self.out.name],check=True)
            identity = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.out.rename(self.out.parent / generation)
            subprocess.run(["tar","--zstd","-xf",str(archive),"-C",str(self.out.parent)],check=True)
            return identity
        execute(["obj/b.o", "obj/c.o", "obj/d.o", "obj/e.o"])
        original = metrics.read_bytes()
        # Omit the last actual success even though Siso now plans it as clean.
        steps = [json.loads(line) for line in original.splitlines()]
        successes = [row for row in steps if row.get("step_id")]
        self.assertEqual(len(successes),4)
        metrics.write_text("".join(json.dumps(row)+"\n" for row in steps if row is not successes[-1]))
        with self.assertRaisesRegex(ValueError,"without success evidence"):
            finish(self.out,self.baseline,self.report,self.command,private_intermediates=True)
        metrics.write_bytes(original)
        first = finish(self.out,self.baseline,self.report,self.command,private_intermediates=True)
        self.assertEqual((first["parent_dirty"],first["child_dirty"],first["advanced_edges"]),(6,2,4))
        proof = json.loads((self.out/PROOF).read_text())
        self.assertEqual(len(proof["closed_groups"]),4)
        self.assertIn(["implicit.dat","obj/b.o"],proof["closed_groups"])
        newbase = self.baseline.with_name("second-start.json")
        first_sha = independently_restore("first")
        self.assertEqual(begin(self.out,newbase,first_sha,self.command),
                         {"parent_frontier_verified":True,"pending":2})
        execute(["obj/f.o"])
        second = finish(self.out,newbase,self.report,self.command,private_intermediates=True)
        self.assertEqual((second["parent_dirty"],second["child_dirty"],second["advanced_edges"]),(2,1,1))
        second_sha = independently_restore("second")
        self.assertNotEqual(first_sha,second_sha)
        self.assertEqual(begin(self.out,self.baseline.with_name("verify-final.json"),second_sha,
                               self.command,verify_only=True),{"parent_frontier_verified":True,"pending":1})
        (self.out/"implicit.dat").unlink()
        with self.assertRaises((ValueError,FileNotFoundError)):
            begin(self.out,self.baseline.with_name("missing-from-first.json"),second_sha,self.command,verify_only=True)

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
