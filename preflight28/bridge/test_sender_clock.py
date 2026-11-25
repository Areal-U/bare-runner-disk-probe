"""Run the production cutoff calculation with independently queued physical runners."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

os.environ.setdefault("RUNNER_TEMP","/tmp")
import normal
import outcome_relay

WORKFLOW = Path(__file__).resolve().parents[2]/".github/workflows/bare-arm64-probe.yml"
JOBS = yaml.safe_load(WORKFLOW.read_bytes())["jobs"]


class SenderClockTests(unittest.TestCase):
    def test_workflow_uses_verified_clock_and_earliest_runner(self):
        sender=JOBS["draft-publisher"]
        steps={step.get("id"):step for step in sender["steps"]}
        self.assertEqual(sender["timeout-minutes"],normal.JOB_MINUTES)
        fetch=next(step for step in sender["steps"] if step["name"].startswith("Fetch authenticated outcome"))
        self.assertEqual(fetch["timeout-minutes"],normal.DOWNLOAD_MINUTES)
        self.assertEqual(steps["publish"]["timeout-minutes"],normal.PUBLISH_MINUTES + 1)
        key=steps["peer_key"]["run"]
        self.assertIn('guard.py job-clock --check-run "$CHECK_RUN"',key)
        self.assertIn('keygen limited --check-run "$CHECK_RUN" --job-start "$sender_start"',key)
        ordinary={step.get("id"):step for step in JOBS["compile-probe"]["steps"]}
        upload_limit = "${{ fromJSON(steps.peer_capacity.outputs.upload_minutes || '4') }}"
        for name in ("peer_put_outcome", "retry_relay"):
            self.assertEqual(ordinary[name]["timeout-minutes"],upload_limit)
        self.assertEqual(outcome_relay.upload_minutes({"status":"candidate"}),normal.UPLOAD_MINUTES)
        self.assertEqual(outcome_relay.upload_minutes({"status":"no-progress"}),2)
        step=ordinary["trial"]
        self.assertIn("steps.peer_acquire.outputs.sender_outcome_deadline",step["env"]["SENDER_OUTCOME_DEADLINE"])
        code=step["run"]
        block=code[code.index("  reserve=130"):code.index("  requested_seconds=")]
        first=1_800_000_000
        with tempfile.TemporaryDirectory() as folder,patch.object(normal.time,"time",return_value=first+150*60):
            Path(folder,"bare-probe-start").write_text(str(first))
            def run(shift,minutes,backend,extra_seconds=0):
                now=first+minutes*60+extra_seconds
                clock=normal.sender_times(first+shift*60,9876)
                command='set -euo pipefail\ndate() { echo "$NOW"; }\n'+block+'\necho "$compile_seconds"'
                return subprocess.run(["bash","-c",command],text=True,capture_output=True,
                    env=dict(os.environ,RUNNER_TEMP=folder,NOW=str(now),SENDER_OUTCOME_DEADLINE=str(clock["sender_accept_until"]),
                             CHECKPOINT_BACKEND=backend))
            # Ordinary and sender start together; 35 min remains to download, publish and finish.
            self.assertEqual(int(run(0,36,"draft").stdout.splitlines()[-1]),219*60)
            # Restore/setup times observed on the two R27 jobs.
            self.assertEqual(int(run(0,35,"draft",47).stdout.splitlines()[-1]),219*60+13)
            self.assertEqual(int(run(0,35,"draft",56).stdout.splitlines()[-1]),219*60+4)
            self.assertEqual(int(run(-20,36,"draft").stdout.splitlines()[-1]),199*60)
            self.assertEqual(int(run(70,100,"draft").stdout.splitlines()[-1]),190*60)
            self.assertEqual(int(run(0,36,"cache").stdout.splitlines()[-1]),184*60)
            self.assertNotEqual(run(-20,235,"draft").returncode,0)

    def test_slow_poll_late_upload_and_short_publication_rejected(self):
        first=1_800_000_000
        with patch.object(normal.time,"time",return_value=first):
            clock=normal.sender_times(first,123)
        cutoff=clock["sender_accept_until"]
        with self.assertRaisesRegex(ValueError,"Invalid hosted"):
            normal.sender_times(None,123)
        with patch.object(normal.time,"time",return_value=first), self.assertRaisesRegex(ValueError,"Invalid hosted"):
            normal.sender_times(first+1,123)
        with patch.object(normal.time,"time",return_value=first), self.assertRaisesRegex(ValueError,"Changed hosted"):
            normal.sender_deadline(dict(clock,sender_accept_until=cutoff+1))
        with patch.object(normal.time,"time",return_value=cutoff-(normal.UPLOAD_MINUTES+normal.VISIBILITY_MINUTES)*60+1):
            with self.assertRaisesRegex(ValueError,"time budget"):
                normal.time_left(cutoff, (normal.UPLOAD_MINUTES+normal.VISIBILITY_MINUTES)*60, "upload")
        env={"GITHUB_RUN_ID":"5","R28_SLOT":"1","GITHUB_RUN_ATTEMPT":"1","R28_HEAD_SHA":"8"*40}
        with patch.dict(os.environ,env),patch.object(normal,"info",return_value=clock), \
             patch.object(normal.time,"time",side_effect=[cutoff-1,cutoff-1,cutoff+1]), \
             patch.object(normal.artifact_poll,"lookup",return_value={
                 "id":20, "name":"r28-5-a1-s01-outcome", "workflow_run":{"id":5},
                 "expired":False,"expires_at":"not-used","size_in_bytes":100}):
            with self.assertRaisesRegex(ValueError,"before outcome download"):
                normal.wait("outcome")
        with patch.dict(os.environ,env),patch.object(normal,"info",return_value=clock), \
             patch.object(normal.time,"time",return_value=cutoff+normal.DOWNLOAD_MINUTES*60+1):
            with self.assertRaisesRegex(ValueError,"before Draft publication"):
                normal.publish()


if __name__=="__main__":
    unittest.main(verbosity=2)
