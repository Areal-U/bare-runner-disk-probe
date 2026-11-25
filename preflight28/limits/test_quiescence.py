"""Use both real process-group controllers with a deterministic late-write trace."""
import importlib.util
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import guard

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_trial", ROOT/"build_trial.py")
trial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trial)

# The child acknowledges SIGINT but remains alive until the controller terminates it.
CHILD = """
import os, pathlib, signal, sys, time
root=pathlib.Path(sys.argv[1])
signal.signal(signal.SIGINT, lambda *_: (root/'interrupt').touch())
(root/'ready').write_text(str(os.getpid()))
while True: time.sleep(.05)
"""


class QuiescenceTests(unittest.TestCase):
    def test_repeated_r20_bursts(self):
        for controller in ("ordinary", "preflight"):
            with self.subTest(controller=controller), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                output = root/"out/Bare"
                output.mkdir(parents=True)
                free = guard.FLOOR + 1900*guard.MIB
                applied=0
                changed=0.0
                def disk(_):
                    nonlocal applied, changed
                    now=time.monotonic()
                    marker = root/"ready"
                    if marker.is_file() and Path("/proc", marker.read_text(), "stat").is_file() and now-changed>=0.4:
                        applied+=1
                        changed=now
                    return {"device":1, "free_inodes":1_000_000, "free_bytes":free-applied*511_643_648}
                command=[sys.executable, "-c", CHILD, str(root)]
                with patch.object(guard, "disk", disk):
                    if controller == "ordinary":
                        with patch("runpy.run_path",return_value=vars(guard)), \
                             patch.object(trial.shutil, "disk_usage", return_value=SimpleNamespace(free=free)), \
                             patch.dict(os.environ, {"COMPILE_STOP_EPOCH":""}):
                            report = trial.run_trial(root, "restore", root/"report", root/"trial.log",seconds=20,
                                max_output_bytes=guard.OUT_CAP, max_output_entries=guard.ENTRY_CAP, production=True,
                                min_free_bytes=guard.FLOOR, command=command, output_stream=io.BytesIO())
                        self.assertTrue(report["forced_kill"],report)
                        self.assertFalse(report["ready_for_restore_test"])
                        self.assertFalse(report["artifact_ready"])
                        state = report["quiescence_monitor"]
                        self.assertEqual(state["kill_reason"], "free-bytes")
                        self.assertGreaterEqual(state["disk_polls"], 2)
                        self.assertGreaterEqual(state["tree_scans"],1)
                        self.assertGreater(state["min_free_bytes"],guard.FLOOR)
                        measured = report["measurements"]
                        self.assertGreater(measured["disk_polls"], 1)
                        self.assertGreater(measured["min_free_inodes"], guard.INODE_FLOOR)
                        for mode in ("initial", "stopping"):
                            self.assertGreaterEqual(measured["scan_cost"][mode]["count"], 1)
                            self.assertGreater(measured["scan_cost"][mode]["wall_seconds"], 0)
                    else:
                        args=SimpleNamespace(cmd=command, output=output, jsonl=root/"events", terminal=False,
                                             job_start=time.time(), job_minutes=350)
                        with self.assertRaisesRegex(guard.GuardError,"build-not-eligible"):
                            guard.monitor(args)
                        records = [json.loads(line) for line in args.jsonl.read_text().splitlines()]
                        self.assertEqual([s["event"] for s in records if s["event"] in {"interrupt","kill","settled"}],
                                         ["interrupt","kill","settled"])
                        kill=next(s for s in records if s["event"]=="kill")
                        self.assertEqual(kill["reason"],"free-bytes")
                        self.assertGreater(kill["free_bytes"],guard.FLOOR)
                        self.assertEqual(records[-1]["ok"],False)
                self.assertTrue((root/"interrupt").is_file())
                self.assertEqual(applied,3)

    def test_slow_live_scan_never_delays_free_space_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out/Bare"
            out.mkdir(parents=True)
            started_scan = threading.Event()
            stopped_during_scan = []
            floor = guard.FLOOR
            def disk(_):
                # Allow launch; cross the warning margin only after the child is live.
                low = started_scan.is_set() and (root / "ready").is_file()
                remaining = 1_000 * guard.MIB if low else 4 * guard.GIB
                return {"device": 1, "free_inodes": 1_000_000, "free_bytes": floor + remaining}
            def slow_tree(path):
                started_scan.set()
                limit = time.monotonic() + 3
                while time.monotonic() < limit and not (root / "interrupt").is_file():
                    time.sleep(0.05)
                stopped_during_scan.append((root / "interrupt").is_file())
                return guard.tree(path)
            with patch("runpy.run_path", return_value=dict(vars(guard), disk=disk, tree=slow_tree)), \
                 patch.object(trial.shutil, "disk_usage", return_value=SimpleNamespace(free=floor + 4*guard.GIB)), \
                 patch.dict(os.environ, {"COMPILE_STOP_EPOCH": ""}):
                report = trial.run_trial(root, "restore", root/"report", root/"log", seconds=10,
                    max_output_bytes=guard.OUT_CAP, max_output_entries=guard.ENTRY_CAP, production=True,
                    min_free_bytes=floor, stop_grace_seconds=0.5, output_stream=io.BytesIO(),
                    command=[sys.executable, "-c", CHILD, str(root)])
            self.assertEqual(report["stop_reason"], "disk-limit")
            self.assertTrue(report["forced_kill"])
            self.assertTrue(stopped_during_scan[0])
            self.assertFalse(report["ready_for_restore_test"])

    def test_staged_production_entry_counts_scan_finished_after_child_exit(self):
        # Stage the files side by side as the ordinary workflow does in /exchange.
        # Only disk availability and scan completion timing are simulated.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output = root / "out/Bare"
            output.mkdir(parents=True)
            exchange = root / "exchange"
            exchange.mkdir()
            script = Path(shutil.copy(ROOT / "build_trial.py", exchange))
            guard_path = Path(shutil.copy(ROOT / "preflight28/limits/guard.py", exchange))
            staged = importlib.util.spec_from_file_location("staged_trial", script)
            controller = importlib.util.module_from_spec(staged)
            staged.loader.exec_module(controller)

            compiler = root / "autoninja"
            compiler.write_text(
                f"#!{sys.executable}\n"
                "import os, time\nfrom pathlib import Path\n"
                "Path('compiler-pid').write_text(str(os.getpid()))\n"
                "while not Path('scan-started').exists(): time.sleep(.01)\n"
                "raise SystemExit(1)\n"
            )
            compiler.chmod(0o755)
            actual_loader = runpy.run_path
            completed = []

            def load_guard(path):
                self.assertEqual(Path(path), guard_path)
                loaded = actual_loader(path)
                scan = loaded["tree"]
                def scan_after_exit(target):
                    (root / "scan-started").touch()
                    deadline = time.monotonic() + 8
                    pid = root / "compiler-pid"
                    while not pid.is_file() or Path("/proc", pid.read_text(), "stat").exists():
                        if time.monotonic() >= deadline:
                            raise RuntimeError("test child was not reaped")
                        time.sleep(.01)
                    observed = scan(target)
                    completed.append(observed)
                    return observed
                loaded["tree"] = scan_after_exit
                loaded["disk"] = lambda _: dict(device=1, free_bytes=50*guard.GIB, free_inodes=1_000_000)
                return loaded

            report = root / "report.json"
            argv = [str(script), "--production", "--phase", "restore", "--jobs", "2",
                    "--seconds", "15", "--result", str(report), "--log", str(root / "trial.log")]
            environment = {"PATH": str(root) + os.pathsep + os.environ["PATH"], "COMPILE_STOP_EPOCH": ""}
            with patch.object(controller, "SOURCE_ROOT", root), patch.object(Path, "cwd", return_value=root), \
                 patch("runpy.run_path", side_effect=load_guard), patch.dict(os.environ, environment), \
                 patch.object(controller.shutil, "disk_usage", return_value=SimpleNamespace(free=50*guard.GIB)), \
                 patch.object(sys, "argv", argv), patch("builtins.print"):
                self.assertEqual(controller.main(), 0)
            saved = json.loads(report.read_text())
            self.assertEqual(saved["reason"], "compile-error")
            self.assertFalse(saved["artifact_ready"])
            self.assertEqual(len(completed), 1)
            costs = saved["measurements"]["scan_cost"]
            self.assertEqual(costs["initial"]["count"], 1)
            self.assertEqual(costs["30"]["count"], 1)
            self.assertEqual(costs["30"]["wall_seconds"], completed[0]["scan_seconds"])
            self.assertEqual(costs["30"]["cpu_seconds"], completed[0]["scan_cpu_seconds"])

    def test_only_a_recorded_unfinished_terminal_edge_needs_the_long_retry_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])
            prior = root / "checkpoint-trial-restore.json"
            report = {"format": trial.FORMAT, "target": trial.TARGET, "reason": "time-limit"}
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])
            progress = {}
            final_dex = "ACTION //chrome/android:chrome_public_apk__final_dex"
            trial.update_siso_status(progress, f"[1/20] 2s S {final_dex}\n[1/20] 2s S LINK libchrome.so\n".encode())
            trial.update_siso_status(progress, b"[2/20] 3s F LINK libchrome.so\n")
            self.assertEqual(progress["terminal_actions"], {final_dex})
            report["interrupted_terminal_actions"] = sorted(progress["terminal_actions"])
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 1799), [final_dex])
            self.assertEqual(trial.interrupted_terminal_retry(root, 1800), [])
            report["reason"] = "completed"
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])

    def test_chrome_final_dex_outlives_native_link(self):
        # Siso event payloads from completed job 133038781141 (old ARM64 APK).
        link = b"SOLINK ./libchrome.so"
        final_dex = b"ACTION //chrome/android:chrome_public_apk__final_dex(//build/toolchain/android:android_clang_arm64)"
        progress = {}
        android = b"(//build/toolchain/android:android_clang_arm64)"
        for other in (b"ACTION //chrome/browser/resources/family_link_user_internals:lint_css" + android,
                      b"ACTION //content/public/android:content_main_dex_jni_java__dex" + android,
                      b"ACTION //chrome/android:chrome_public_apk__final_dex__build_config" + android,
                      b"CXX obj/third_party/libunwindstack/libunwindstack/compact_dex_file.o",
                      b"LINK clang_x64/proto_extras_plugin", b"SOLINK ./libchrome_inputs.so"):
            trial.update_siso_status(progress, b"[2/54] 10s S " + other + b"\n")
        self.assertFalse(progress.get("terminal_actions"))
        trial.update_siso_status(progress, b"[7/1035] 20.15s S " + link + b"\n")
        self.assertEqual(progress["terminal_actions"], {link.decode()})
        trial.update_siso_status(progress, b"[15/30] 45.04s S " + final_dex[:31])
        trial.update_siso_status(progress, final_dex[31:] + b"\n")
        self.assertEqual(progress["terminal_actions"], {link.decode(), final_dex.decode()})
        trial.update_siso_status(progress, b"[16/29] 23m00.16s F " + link + b"\n")
        self.assertEqual(progress["terminal_actions"], {final_dex.decode()})
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp) / "checkpoint-trial-restore.json"
            prior.write_text(json.dumps({"format": trial.FORMAT, "target": trial.TARGET,
                                         "reason": "time-limit",
                                         "interrupted_terminal_actions": sorted(progress["terminal_actions"])}))
            self.assertEqual(trial.interrupted_terminal_retry(prior.parent, 1799), [final_dex.decode()])
            self.assertEqual(trial.interrupted_terminal_retry(prior.parent, 1800), [])
        trial.update_siso_status(progress, b"[17/29] 26m50.35s F " + final_dex + b"\n")
        self.assertFalse(progress["terminal_actions"])

    def test_legacy_time_limit_report_filters_only_known_nonterminal_actions(self):
        with tempfile.TemporaryDirectory() as tmp:
            prior = Path(tmp) / "checkpoint-trial-restore.json"
            report = {"format": trial.FORMAT, "target": trial.TARGET, "reason": "time-limit"}
            ordinary = [
                "CXX obj/third_party/libunwindstack/libunwindstack/compact_dex_file.o",
                "ACTION //chrome/browser/resources/family_link_user_internals:lint_css(//build/toolchain/android:android_clang_arm64)",
                "ACTION //content/public/android:content_main_dex_jni_java__dex(//build/toolchain/android:android_clang_arm64)",
                "LINK clang_x64/proto_extras_plugin", "SOLINK ./libchrome_inputs.so",
            ]
            for actions, expected in ((ordinary, []), (ordinary + ["SOLINK ./libchrome.so"], ["SOLINK ./libchrome.so"]),
                                      (ordinary + ["unclassified legacy action"], ["unclassified legacy action"])):
                with self.subTest(expected=expected):
                    report["interrupted_terminal_actions"] = actions
                    prior.write_text(json.dumps(report))
                    self.assertEqual(trial.interrupted_terminal_retry(prior.parent, 1799), expected)
                    self.assertEqual(trial.interrupted_terminal_retry(prior.parent, 1800), [])

    def test_sparse_growth_and_inode_predictions(self):
        fs = {"free_bytes":80*guard.GIB, "free_inodes":2_000_000}
        sample = {"estimate":guard.OUT_CAP-1100*guard.MIB, "entries":100}
        budget = guard.QuiescenceBudget(sample,fs)
        self.assertIsNone(budget.risk(sample,fs))
        after=dict(sample,estimate=sample["estimate"]+650*guard.MIB)
        self.assertEqual(budget.risk(after,fs),"archive-estimate")
        budget=guard.QuiescenceBudget(sample,fs)
        self.assertEqual(budget.risk(sample,dict(fs,free_inodes=guard.INODE_FLOOR+4_999)),"free-inodes")


if __name__=="__main__":
    unittest.main(verbosity=2)
