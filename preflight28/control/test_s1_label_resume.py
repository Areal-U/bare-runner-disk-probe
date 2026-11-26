"""Read-only trial evidence and atomic physical registration for the corrected S1 path."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch

import registration
import s1_label_resume as gate
from test_registration import OwnerDraft

HEAD, TRIAL_HEAD, TRIAL_RUN = "1" * 40, "2" * 40, 82


def fixed():
    return dict(source_run_id=gate.SOURCE_RUN, initial_parent=gate.PARENT_SHA, parent_identity=gate.PARENT_IDENTITY,
                manifest_id=gate.s1.MANIFEST_ID, manifest_sha=gate.s1.MANIFEST_SHA,
                consumed_run_id=gate.CONSUMED, consumed_claim_id=gate.SOURCE_CLAIM_ID,
                consumed_claim_sha=gate.SOURCE_CLAIM_SHA, prior_owner_closure_sha=gate.CLOSURE_SHA,
                trial_run_id=TRIAL_RUN, trial_head=TRIAL_HEAD, final_certificate_sha256="6"*64)


def job(name, outcomes, conclusion="success"):
    return dict(name=name, conclusion=conclusion,
                steps=[dict(name=n, conclusion=c) for n,c in outcomes.items()])


class LabelTest(TestCase):
    def setUp(self):
        self.enterContext(patch.object(gate, "OWNER_CERT_COMMITMENT", hashlib.sha256(("6"*64).encode()).hexdigest()))


class LabelAdmission(LabelTest):
    def setUp(self):
        super().setUp()
        self.ticket = dict(fixed(), head=HEAD)
        self.jobs = {8: job(gate.COMPUTE_NAME, {gate.s1.NEGATIVE:"success", gate.s1.FRONTIER:"success",
                        gate.LABEL_STEP:"success", gate.s1.COMPILE:"skipped"}),
                     9: job(gate.CERTIFY, {"Check the independent restore result":"success"}),
                     10: job(gate.SENDER_NAME, {}), 11: dict(name="measure",conclusion="skipped")}
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for path in gate.COMMON:
            p = self.root / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("test file " + path)
        self.trial_tree = {p:gate.git_blob((self.root/p).read_bytes()) for p in gate.COMMON}
        self.trial_tree.update({gate.s1.TRIAL_WORKFLOW:"b"*40, gate.WORKER:"a"*40})
        self.normal_tree = dict(self.trial_tree)
        self.cert = dict(status="accepted", trial_run_id=TRIAL_RUN, trial_attempt=1, trial_head=TRIAL_HEAD,
                         source_sha256=gate.PARENT_SHA, raw_sha256="7"*64, optimized_sha256="8"*64,
                         trial_workflow_blob="b"*40, trial_worker_blob="a"*40,
                         helpers={Path(p).name:hashlib.sha256((self.root/p).read_bytes()).hexdigest() for p in gate.HELPERS})
        labels = dict(application=["Bare Personal"], enabled=["Main"], launchers={"Main":["Bare Personal"]})
        self.report = dict(mode="trial", parent_sha256=gate.PARENT_SHA, old_pending=1911, remaining=1911,
                           resource_sha256="7"*64, optimized_sha256="8"*64, raw_labels=labels, optimized_labels=labels)

    def verify(self):
        raw = json.dumps(self.cert).encode()
        (self.root/gate.CERT_PATH).write_bytes(raw)
        self.normal_tree[gate.CERT_PATH] = gate.git_blob(raw)
        with patch.object(gate,"ROOT",self.root), patch.object(gate,"source_tree",side_effect=[self.trial_tree,self.normal_tree]), \
             patch.object(gate.s1,"checked_run",return_value=self.jobs), patch.object(gate,"migration_report",return_value=self.report):
            gate.verify_trial(None,self.ticket)

    def test_trial_checks_migration_log_both_packages_and_excludes_failed_trial(self):
        self.verify()
        self.jobs[11]["steps"] = None
        self.verify()
        for mapping,key,wrong in [(self.cert,"raw_sha256","6"*64),(self.cert,"trial_worker_blob","f"*40),
                                 (self.cert,"status","awaiting-independent-resource-trial"),
                                 (self.report,"remaining",1920),(self.report["optimized_labels"],"application",["Bare"]),
                                 (self.normal_tree,gate.COMMON[0],"c"*40),(self.jobs[8],"conclusion","failure")]:
            with self.subTest(key=key):
                old=mapping[key]; mapping[key]=wrong
                with self.assertRaises(ValueError): self.verify()
                mapping[key]=old
        self.jobs[8]["steps"][-1]["conclusion"]="success"
        with self.assertRaises(ValueError): self.verify()
        for rid in (gate.CONSUMED, gate.FAILED_TRIAL, gate.SOURCE_RUN):
            with self.assertRaises(ValueError): gate.route(dict(self.ticket,trial_run_id=rid))

    def test_trial_log_uses_actual_emitted_line_once(self):
        def read(data):
            def output(command, *, stdout, **kwargs):
                self.assertEqual(command[-1], f"repos/{gate.REPO}/actions/jobs/8/logs")
                stdout.write(data)
            with patch("subprocess.run",side_effect=output):
                return gate.migration_report(8)
        line=b'2026-11-27T02:00:45.1234567Z BARE_LABEL_MIGRATION {"remaining":1911}\r\n'
        self.assertEqual(read(b'echo BARE_LABEL_MIGRATION fake\n'+line),{"remaining":1911})
        for bad in (b'anything else',line + line):
            with self.assertRaises(ValueError): read(bad)

    def test_consumed_claim_and_previous_owner_are_required(self):
        d = OwnerDraft()
        old = dict(d.ticket, head=gate.CONSUMED_HEAD, collector_ack_sha=gate.OLD_ACK_SHA,
                   source_run_id=gate.SOURCE_RUN, manifest_sha=gate.s1.MANIFEST_SHA, manifest_id=gate.s1.MANIFEST_ID,
                   initial_parent=gate.PARENT_SHA, trial_run_id=80, trial_head="b"*40)
        old_claim = dict(gate.s1.route(old), source_claim_id=gate.s1.SOURCE_CLAIM_ID, source_claim_sha=gate.s1.SOURCE_CLAIM_SHA,
                         run_id=gate.CONSUMED, producer_attempt=1, head=gate.CONSUMED_HEAD, ticket_asset_id=gate.OLD_TICKET_ID,
                         ticket_sha=gate.OLD_TICKET_SHA, registration_id=old["collector_registration_id"])
        new = dict(old, **self.ticket, registration_nonce="9"*40, collector_ack_sha="8"*64)
        gate.check_binding(old_claim,old,new)
        for key,value in (("owner_destination_id","different"),("registration_nonce",old["registration_nonce"]),
                          ("collector_ack_sha",gate.OLD_ACK_SHA),("final_certificate_sha256","8"*64),
                          ("artifact_ceiling_bytes",new["artifact_ceiling_bytes"]+1),("consumed_claim_id",True)):
            with self.assertRaises(ValueError): gate.check_binding(old_claim,old,dict(new, **{key:value}))
        for expiry in ("2026-12-01T00:00:00Z", "2026-11-26T00:00:00Z"):
            with self.subTest(expiry=expiry), self.assertRaisesRegex(ValueError, "expiry"):
                gate.check_binding(old_claim, old, dict(new, expires_at=expiry))
        with self.assertRaises(ValueError): gate.check_binding(dict(old_claim,run_id=70),old,new)


class PhysicalBinding(LabelTest):
    def test_new_ticket_only_old_claim_cannot_be_reissued(self):
        draft = OwnerDraft()
        draft.ticket.update(fixed())
        draft.ack.update(fixed())
        draft.ticket["collector_ack_sha"] = hashlib.sha256(draft.data(812)).hexdigest()
        draft.asset["name"] = gate.TICKET_NAME
        event = dict(repository={"id":registration.REPO_ID},sender=registration.OWNER,
                     inputs={"mode":"build-apk","build_segments":"12","apk_recipient":registration.RECIPIENT})
        env = dict(RUNNER_ENVIRONMENT="github-hosted",REGISTRATION_ASSET_ID="901",GITHUB_SHA=draft.ticket["head"],
                   GITHUB_JOB="bind-private-receiver",GITHUB_RUN_ID="81",GITHUB_RUN_ATTEMPT="1",
                   GITHUB_REPOSITORY=registration.REPO,GITHUB_EVENT_NAME="workflow_dispatch",R30_RESUME_S1="1",
                   GITHUB_REF="refs/heads/"+registration.BASE_REF)
        now = datetime(2026,11,26,tzinfo=timezone.utc)
        def enter(verify=False):
            env["REGISTRATION_SHA"]=hashlib.sha256(draft.data()).hexdigest()
            return registration.bind(draft,env,event,now,verify_only=verify)
        with patch.object(gate,"validate_source",autospec=True) as evidence,patch.object(registration,"admit",return_value=831) as claim:
            self.assertEqual(enter()[0],831)
            self.assertTrue(evidence.call_args.kwargs["initial"])
            self.assertEqual(claim.call_args.kwargs["name"],gate.CLAIM)
            self.assertNotEqual(gate.CLAIM,gate.s1.CLAIM)
            holder=claim.call_args.args[1]
            gate.check_reference(holder,draft.ticket)
            env["GITHUB_JOB"]="collection-lease"
            self.assertEqual(enter(True)[0],831)
            self.assertEqual(claim.call_args.args[0],"recover")
            self.assertFalse(evidence.call_args.kwargs["initial"])
            draft.ack["prior_owner_closure_sha"]="0"*64
            draft.ticket["collector_ack_sha"]=hashlib.sha256(draft.data(812)).hexdigest()
            with self.assertRaises(ValueError): enter(True)
            draft.asset["name"]=gate.s1.TICKET_NAME
            with self.assertRaises(ValueError): enter(True)
            self.assertEqual(claim.call_count,2)
