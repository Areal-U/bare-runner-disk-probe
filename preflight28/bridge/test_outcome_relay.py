import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import normal as n
import outcome_relay as relay
from test_storage_admission import Provider, ENV


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        work=tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.root=Path(work.name)/"r28-normal"
        self.root.mkdir()
        self.provider = Provider()
        def service(path):
            if "/actions/runs/497/artifacts" in path:
                return {"total_count":0,"artifacts":[]}
            return self.provider.get(path)
        for change in (
                patch.dict(os.environ, ENV, RUNNER_TEMP=work.name,GITHUB_JOB="compile-probe",
                           GITHUB_REPOSITORY=n.b.REPO,GITHUB_RUN_ID="497",GITHUB_RUN_ATTEMPT="1",R28_SLOT="1",
                           R28_HEAD_SHA="8"*40,R28_PARENT_SHA=n.PARENT["sha"],R28_PARENT_IDENTITY=n.PARENT["identity"]),
                patch.object(n,"ROOT",self.root),patch.object(n.b,"inventory",return_value=[]),
                patch.object(n.b,"api_json",side_effect=service),
                patch.object(relay.time,"sleep")):
            change.start()
            self.addCleanup(change.stop)
        self.now=int(time.time())
        (Path(work.name)/"bare-probe-start").write_text(str(self.now))
        (self.root/"input.json").write_text(json.dumps({**n.context(),**n.sender_times(self.now,9)}))
        enc=self.root/"checkpoint.cms"
        enc.write_bytes(b"already sealed immutable candidate bytes")
        self.record={**n.context(),"status":"candidate","sealed_bytes":enc.stat().st_size,"sealed_sha":n.b.digest(enc),"sha256":"7"*64}
        (self.root/"outcome.json").write_text(json.dumps(self.record))
        _,size=relay.payload()
        self.asset=dict(name=n.stem()+"-outcome",id=73,digest="sha256:"+"a"*64,
                        workflow_run=dict(id=497,head_sha="8"*40),expired=False,size_in_bytes=size+200,
                        expires_at=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat().replace("+00:00","Z"))
        self.calls=[]

    def resolve(self, rows, sdk="transfer-unknown", attempt=1, rid="", sha="", clock=None):
        replies=[]
        for batch in rows:
            if isinstance(batch, Exception) or isinstance(batch, dict):
                replies.append(batch)
            else:
                replies.extend([dict(total_count=len(batch),artifacts=batch)]*2)
        previous=[]
        def api(url):
            self.calls.append(url)
            if url.endswith("/actions/artifacts/73"):
                return next(row for row in previous if row["id"]==73)
            answer=replies.pop(0)
            if isinstance(answer,Exception):
                raise answer
            previous[:] = answer["artifacts"]
            return answer
        return relay.resolve(attempt,sdk,rid,sha,api=api,sleep=lambda seconds:None,clock=clock or time.time)

    def test_lost_ack_then_observed_exact_original_no_retry(self):
        self.assertEqual(relay.plan()["decision"],"upload")
        result=self.resolve([[],[self.asset]])
        self.assertEqual((result["decision"],result["id"]),("present","73"))
        self.assertEqual(len(self.calls),5)
        self.assertTrue(self.calls[-1].endswith("/actions/artifacts/73"))
        self.assertEqual(self.resolve([[self.asset]],"uploaded",rid="73",sha="a"*64)["decision"],"present")

    def test_absence_permits_one_retry_of_same_bytes_and_final_stop(self):
        self.assertEqual(relay.plan()["decision"],"upload")
        self.assertEqual(self.resolve([[],[],[]])["decision"],"retry")
        self.assertEqual(self.resolve([[],[],[]],attempt=2)["decision"],"relay-missing")
        self.assertEqual(len(set(self.calls)),1)
        self.assertIn("/actions/runs/497/artifacts?per_page=100&page=1",self.calls[0])
        self.assertEqual(self.resolve([[self.asset]],"uploaded",2,"73","a"*64)["decision"],"present")
        enc=self.root/"checkpoint.cms"
        enc.write_bytes(b"x"*enc.stat().st_size)
        self.assertEqual(self.resolve([[],[],[]])["decision"],"relay-ambiguous")

    def test_propagating_rows_reset_absence_without_second_write(self):
        relay.plan()
        partial={"total_count":1,"artifacts":[]}
        self.assertEqual(self.resolve([partial,[self.asset]])["id"],"73")
        self.assertEqual(self.resolve([[],[],partial,[],[]])["decision"],"relay-ambiguous")
        self.assertEqual(self.resolve([partial]*5)["decision"],"relay-ambiguous")
        with patch.object(n.b,"api_json",return_value=partial):
            self.assertEqual(relay.plan()["decision"],"relay-ambiguous")

    def test_unreadable_ambiguous_changed_receipt_and_quota_do_not_retry(self):
        relay.plan()
        for rows,sdk,aid in (([[self.asset,dict(self.asset,id=74)]],"transfer-unknown",""),
                 ([[dict(self.asset,expired=True)]],"transfer-unknown",""),([ValueError("service unavailable")],"transfer-unknown",""),
                 ([[self.asset]],"uploaded","44"),([[],[],[]],"uploaded","73")):
            self.assertEqual(self.resolve(rows,sdk,rid=aid)["decision"],"relay-ambiguous")
        self.assertEqual(self.resolve([[],[],[]],"quota-denied")["decision"],"relay-quota-denied")

    def test_unaffordable_or_late_sealed_candidate_never_uploads(self):
        with patch.dict(os.environ,R28_RELAY_BYTE_CEILING="1"):
            self.assertEqual(relay.plan()["decision"],"relay-capacity-exceeded")
        relay.plan()
        self.assertEqual(self.resolve([[],[],[]],clock=lambda:relay.deadline()-40)["decision"],"relay-deadline")
        with patch.object(relay,"deadline",return_value=time.time()+20):
            self.assertEqual(relay.plan()["decision"],"relay-deadline")

    def test_foreign_or_mutated_metadata_never_retried(self):
        relay.plan()
        self.record["proof_sha"]="0"*64
        (self.root/"outcome.json").write_text(json.dumps(self.record))
        self.assertEqual(self.resolve([[],[],[]])["decision"],"relay-ambiguous")

    def test_preexisting_exact_outcome_is_reconciled_before_any_write(self):
        self.provider.rows = [self.asset]
        def get(path, run_rows):
            if path.endswith("/artifacts/73"):
                return self.asset
            if "/actions/runs/497/artifacts?" in path:
                return dict(total_count=len(run_rows),artifacts=run_rows)
            return self.provider.get(path)
        with patch.object(n.b,"api_json",side_effect=lambda p:get(p,[self.asset])):
            self.assertEqual(relay.plan()["id"],"73")
        with patch.object(n.b,"api_json",side_effect=lambda p:get(p,[])):
            self.assertEqual(relay.plan()["decision"],"relay-ambiguous")
        self.assertFalse((self.root/"first-upload.json").exists())

    def test_control_only_outcome_uses_a_bounded_smaller_send_window(self):
        (self.root/"outcome.json").write_text(json.dumps({**n.context(),"status":"no-progress"}))
        with patch.object(relay,"deadline",return_value=time.time()+300):
            self.assertEqual(relay.plan(),{"decision":"upload","upload_minutes":2})
