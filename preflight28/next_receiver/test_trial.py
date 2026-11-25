"""Exercise the hosted role commands with separate filesystems, without GitHub or secrets."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP", tempfile.gettempdir())
import trial


class ReceiverTrial(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        env = dict(GITHUB_REPOSITORY=trial.bridge.REPO, GITHUB_RUN_ID="17011", GITHUB_RUN_ATTEMPT="1",
                   GITHUB_SHA=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
                   GITHUB_REF="refs/heads/bare-next-build-prep-20261125", GITHUB_ACTOR="Areal-U",
                   GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_OUTPUT=str(self.root / "outputs"))
        self.env = patch.dict(os.environ, env)
        self.env.start()
        self.addCleanup(self.env.stop)

    @contextlib.contextmanager
    def vm(self, name):
        root = self.root / name
        with patch.object(trial, "ROOT", root), patch.object(trial.bridge, "ROOT", root / "private"), \
             patch.dict(os.environ, {"GITHUB_JOB": name}):
            yield root

    def move(self, mode, sender, receiver, kind):
        old = self.root / (mode + "-" + sender) / kind
        dest = self.root / (mode + "-" + receiver) / kind
        shutil.copytree(old, dest)
        self.assertNotIn("key.pem", [p.name for p in dest.iterdir()])

    def test_pair_and_receipt_recovery_after_vm_exit(self):
        for mode in ("baseline", "delayed"):
            issuer = "receiver" if mode == "baseline" else "ticket"
            for role in sorted({issuer, "receiver", "producer"}):
                with self.vm(mode + "-" + role):
                    trial.init(mode)
            with self.vm(mode + "-" + issuer):
                trial.ticket(mode)
            self.move(mode, issuer, "producer", "ticket")
            with self.vm(mode + "-producer"):
                trial.claim_ticket(mode)
            with self.vm(mode + "-receiver"):
                trial.key(mode)
            self.move(mode, "receiver", "producer", "key")
            with self.vm(mode + "-producer"):
                trial.seal(mode)
            self.move(mode, "producer", "receiver", "envelope")
            with self.vm(mode + "-receiver") as dest:
                trial.receive(mode)
                shutil.copytree(dest / "receipt", self.root / "report" / mode)
            for role in {issuer, "receiver", "producer"}:
                shutil.rmtree(self.root / (mode + "-" + role))
        hosted_rows = []
        for i, name in enumerate(("baseline producer", "baseline receiver", "delayed producer",
                                  "delayed ticket", "delayed receiver"), 1):
            hosted_rows.append(dict(name="Diagnostics / RX " + name, id=i, conclusion="success",
                created_at="2026-11-25T10:00:00Z",
                started_at="2026-11-25T10:00:%02dZ" % i,
                completed_at="2026-11-25T10:01:05Z"))
        with self.vm("report"):
            jobs = trial.occupancy(hosted_rows)
            first = trial.summarize(jobs)
            self.assertEqual(first, trial.summarize(jobs))
            self.assertEqual(first["baseline"]["sha"], first["delayed"]["sha"])
            self.assertEqual(1, first["delayed"]["projected_compile_budget_delta_s"]
                             - first["baseline"]["projected_compile_budget_delta_s"])
            self.assertTrue(first["comparison"]["useful_for_deadline_bound_intervals"])
            self.assertGreater(first["comparison"]["runner_seconds_delta"], 0)

    def test_expired_wait_creates_no_envelope(self):
        with self.vm("producer") as vm:
            trial.init("delayed")
            with self.assertRaises(TimeoutError):
                trial.lookup("delayed", "key", wait=.02, lookup_artifact=lambda *a, **kw: None)
            self.assertFalse((vm / "envelope").exists())

    def test_wrong_ticket_and_repeat_attempt(self):
        with self.vm("producer") as vm:
            trial.init("baseline")
            trial.ticket("delayed")
            with self.assertRaisesRegex(ValueError, "Foreign ticket"):
                trial.claim_ticket("baseline")
            self.assertFalse((vm / "envelope").exists())
        with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT":"2"}):
            with self.assertRaises(ValueError):
                trial.binding("baseline")

    def test_actual_bytes_rechecked_at_upload(self):
        import time
        budget = trial.storage_admission
        peer = {"present": False}
        def api(path):
            if path == budget.BASE:
                return dict(id=budget.REPO_ID, full_name=budget.REPO, private=False,
                            fork=False, visibility="public")
            if "/actions/runs?" in path:
                active = [{"id":7777}] if peer["present"] and "status=in_progress" in path else []
                return dict(total_count=len(active), workflow_runs=active)
            if "/actions/artifacts?" in path:
                return dict(artifacts=[], total_count=0)
            raise AssertionError(path)
        with self.vm("test-producer"):
            trial.init("baseline")
            trial.ticket("baseline")
            bound = 8192 + (trial.ROOT / "ticket" / "ticket.json").stat().st_size
            caps = {"R28_STORAGE_CEILING": str(budget.CONTROL_RESERVE + bound),
                    "R28_STORAGE_UNTIL": str(int(time.time()) + 2*86400),
                    "RUNNER_ENVIRONMENT": "github-hosted", "R28_RELAY_BYTE_CEILING": ""}
            with patch.dict(os.environ, caps):
                trial.admit("baseline", "ticket", api)
                with patch.dict(os.environ, {"R28_RELAY_BYTE_CEILING": str(budget.CONTROL_RESERVE + bound - 1)}):
                    with self.assertRaises(budget.StorageFull): trial.admit("baseline", "ticket", api)
                with patch.dict(os.environ, {"R28_STORAGE_UNTIL": str(int(time.time()) + 86400)}):
                    with self.assertRaises(budget.StorageUnconfirmed): trial.admit("baseline", "ticket", api)
                peer["present"] = True
                with self.assertRaises(budget.StorageUnconfirmed): trial.admit("baseline", "ticket", api)
            (trial.ROOT / "ticket" / "unintended").touch()
            with self.assertRaisesRegex(ValueError, "member"): trial.admit("baseline", "ticket", api)

    def test_peer_size_bound(self):
        with self.vm("reader"):
            trial.init("delayed")
            def wrong(*args, **kwargs):
                return dict(size_in_bytes=trial.CONTROL_LIMIT+1, expires_at="2999-01-01T00:00:00Z", id=1)
            with self.assertRaisesRegex(ValueError, "size/deadline"):
                trial.lookup("delayed", "key", wait=.5, lookup_artifact=wrong)
        with self.assertRaises(ValueError):
            trial.occupancy([])


if __name__ == "__main__":
    unittest.main()
