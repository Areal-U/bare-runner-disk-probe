"""Independent negative controls for the one-slot loss exception."""
from datetime import datetime, timezone, timedelta
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
import yaml

import loss_resume as loss
import receipt_journal as journal
from test_receipt_journal import HEAD, RUN, SimulatedActions, seal


def utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00","Z")


class OriginalProvenance(unittest.TestCase):
    def original(self, variant="valid"):
        s = SimulatedActions()
        now = datetime.now(timezone.utc)
        steps = [(step,"skipped") for step in (*loss.RELAY,loss.CIPHER,loss.CACHE)]
        steps += [(step,"success") for step in (loss.FRONTIER,loss.COMPILE,loss.APK,journal.SEAL_STEP)]
        if variant == "step-skipped":
            steps[-1] = (journal.SEAL_STEP,"skipped")
        job = s.job(1,"Compile or verify authenticated APK slot 1",steps)
        note = seal(1)
        if variant == "wrong-parent":
            note["accepted_parent"] = "0"*64
        if variant == "wrong-scope":
            note["run"] += 1
        import json
        a = s.asset(f"r28-{RUN}-a1-s01-apk-seal","seal.json",json.dumps(note),after=variant=="late-artifact")
        if variant == "expired":
            a["expired"] = True
            s.objects[a["id"]]["expired"] = True
        if variant == "bad-zip":
            s.raw[a["id"]] += b"junk"
        ledger = dict(producer_job_id=job["id"],parent_sha=loss.S2_SHA,pending_writes=0,
                      owner_copy="confirmed-absent",state="ledger-closed-no-durable-output",
                      observed_at=utc(now),ledger_receipt_id="owner-ledger-13",ledger_version=2,lost_product="apk")
        return s,ledger,now

    def test_positive_control_proves_same_physical_seal_can_be_validated(self):
        s,ledger,now=self.original()
        parent=loss.loss_proof(ledger,s.jobs,s.assets,[],[],[],RUN,HEAD,1,now,
                               s.objects.__getitem__,download=s.raw.__getitem__)
        self.assertEqual(parent["parent_sha"],loss.S2_SHA)

    def test_successful_nonterminal_probe_or_foreign_seal_never_admits_recompile(self):
        for variant in ("step-skipped","wrong-parent","wrong-scope","late-artifact","expired","bad-zip"):
            with self.subTest(variant=variant):
                s,ledger,now = self.original(variant)
                with patch.object(loss.recover,"download_note",s.raw.__getitem__), self.assertRaises(ValueError):
                    loss.loss_proof(ledger,s.jobs,s.assets,[],[],[],RUN,HEAD,1,now,s.objects.__getitem__)

    def test_wrong_committing_workflow_actor_and_head_never_count_as_original(self):
        row = dict(id=RUN,head_sha=HEAD,head_branch=loss.BASE_REF,path=loss.reg.WORKFLOW,
                   event="workflow_dispatch",run_attempt=1,actor=loss.reg.OWNER,
                   repository={"id":loss.REPO_ID},head_repository={"id":loss.REPO_ID})
        api = Mock()
        for altered in ({"path":".github/workflows/similar.yml"},{"actor":dict(loss.reg.OWNER,id=8)},
                        {"head_sha":"f"*40},{"event":"pull_request"},{"head_repository":{"id":7}},
                        {"run_attempt":2}):
            with self.subTest(altered=altered):
                api.metadata.return_value = dict(row,**altered)
                with self.assertRaises(ValueError):
                    loss.identity(api,RUN,HEAD,1)

    def test_reader_activity_after_loss_evidence_requires_reconciled_observation(self):
        now = datetime.now(timezone.utc)
        old = utc(now-timedelta(minutes=40))
        observed = utc(now-timedelta(minutes=15))
        current = utc(now-timedelta(minutes=5))
        attempts = [{"status":"completed","updated_at":old,"run_attempt":1},
                    {"status":"completed","updated_at":current,"run_attempt":2}]
        with patch.object(loss,"identity",side_effect=attempts),patch.object(loss,"pages") as listing:
            with self.assertRaises(ValueError):
                loss.original_parent(Mock(),{},RUN,HEAD,dict(ordinal=1),dict(observed_at=observed),now)
            listing.assert_not_called()

    def test_reused_loss_claim_must_be_emitted_by_its_first_attempt(self):
        issued = datetime.now(timezone.utc)
        step = dict(name="Claim one certified loss",conclusion="success",started_at=utc(issued-timedelta(seconds=5)),
                    completed_at=utc(issued+timedelta(seconds=2)))
        job = dict(name="Reserve one confirmed lost physical interval",run_attempt=1,run_id=RUN,head_sha=HEAD,
                   status="completed",conclusion="success",steps=[step])
        with patch.object(loss,"pages",return_value=[job]):
            loss.original_grant(Mock(),RUN,HEAD,issued)
            for wrong_time in (issued-timedelta(seconds=17),issued+timedelta(seconds=7)):
                with self.assertRaises(ValueError):loss.original_grant(Mock(),RUN,HEAD,wrong_time)
        for change in ({"steps":[dict(step,conclusion="failure")]},{"head_sha":"b"*40},
                       {"run_attempt":2},{"run_id":RUN+1}):
            with patch.object(loss,"pages",return_value=[dict(job,**change)]), self.assertRaises(ValueError):
                loss.original_grant(Mock(),RUN,HEAD,issued)

    def test_original_campaign_must_match_even_if_dispatch_carries_correct_owner_and_run(self):
        now = datetime.now(timezone.utc)
        env = dict(GITHUB_RUN_ID="130",GITHUB_RUN_ATTEMPT="2",GITHUB_SHA=HEAD,GITHUB_JOB="reread-loss-admission",
                   GITHUB_EVENT_NAME="workflow_dispatch",GITHUB_REF="refs/heads/"+loss.BASE_REF,GITHUB_REPOSITORY=loss.REPO)
        event = dict(inputs={"mode":"recover-lost-slot","loss_origin_run":str(RUN)},sender=loss.reg.OWNER,
                     repository={"id":loss.REPO_ID})
        original = dict(schema=1,campaign="different",repository_id=loss.REPO_ID,workflow=loss.reg.WORKFLOW,
                        branch=loss.BASE_REF,head=HEAD,release_id=loss.RELEASE_ID,recipient=loss.reg.RECIPIENT,
                        run_id=RUN,producer_attempt=1,initial_parent=loss.S2_SHA)
        with patch.object(loss,"PagedOwnerDraft"),patch.object(loss,"identity",return_value={"created_at":utc(now)}), \
             patch.object(loss,"named",return_value=(original,91,"a"*64,now)) as lookup:
            with self.assertRaises(ValueError):
                loss.operation(Mock(),env,event,"reread",now)
            self.assertEqual(lookup.call_count,1)

    def test_replacement_rerun_is_reachable_after_normal_build_jobs_are_skipped(self):
        path=Path(__file__).resolve().parents[2]/".github/workflows/bare-checkpoint-transfer.yml"
        jobs=yaml.safe_load(path.read_text())["jobs"]
        recovery=jobs["recover-first-attempt"]
        self.assertEqual(set(recovery["needs"]),{"reread-loss-admission","terminal-12"})
        self.assertIn("!cancelled()",recovery["if"])
        self.assertNotIn("needs.terminal-12.result",recovery["if"])
        self.assertIn("inputs.mode == 'recover-lost-slot' && needs.reread-loss-admission.result == 'success'",recovery["if"])
        self.assertNotIn("needs",jobs["reread-loss-admission"])
        self.assertIn("github.run_attempt != '1'",jobs["reread-loss-admission"]["if"])
        for name in ("loss-admission","replacement","receive-replacement"):
            if name == "receive-replacement":
                name = next(k for k,j in jobs.items() if "needs.replacement.result" in j.get("if",""))
            self.assertIn("github.run_attempt == '1'",jobs[name]["if"])


if __name__ == "__main__":
    unittest.main()
