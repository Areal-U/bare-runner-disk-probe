"""Use both real process-group controllers with a deterministic late-write trace."""
import importlib.util
import io
import json
import os
from pathlib import Path
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

    def test_only_a_recorded_unfinished_terminal_edge_needs_the_long_retry_window(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])
            prior = root / "checkpoint-trial-restore.json"
            report = {"format": trial.FORMAT, "target": trial.TARGET, "reason": "time-limit"}
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])
            progress = {}
            trial.update_siso_status(progress, b"[1/20] 2s S ACTION build/dex/final\n[1/20] 2s S LINK libchrome.so\n")
            trial.update_siso_status(progress, b"[2/20] 3s F LINK libchrome.so\n")
            self.assertEqual(progress["terminal_actions"], {"ACTION build/dex/final"})
            report["interrupted_terminal_actions"] = sorted(progress["terminal_actions"])
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 1799), ["ACTION build/dex/final"])
            self.assertEqual(trial.interrupted_terminal_retry(root, 1800), [])
            report["reason"] = "completed"
            prior.write_text(json.dumps(report))
            self.assertEqual(trial.interrupted_terminal_retry(root, 8), [])

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
