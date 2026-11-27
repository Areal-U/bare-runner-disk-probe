import hashlib
from unittest import TestCase
from unittest.mock import patch

import s1_inventory_resume as gate
from test_registration import OwnerDraft
from test_s1_label_resume import fixed


class InventoryHandoff(TestCase):
    def setUp(self):
        self.enterContext(patch.object(gate.label, "OWNER_CERT_COMMITMENT",
                                      hashlib.sha256(("6"*64).encode()).hexdigest()))
        self.old = dict(OwnerDraft().ticket, **fixed(), **gate.previous.failure_fields())
        self.old.update(head=gate.FAILED_HEAD, trial_run_id=gate.TRIAL_RUN, trial_head=gate.TRIAL_HEAD)
        self.claim = dict(gate.previous.route(self.old), run_id=gate.FAILED_RUN, producer_attempt=1,
                          head=gate.FAILED_HEAD, source_claim_id=gate.previous.SOURCE_CLAIM_ID,
                          source_claim_sha=gate.previous.SOURCE_CLAIM_SHA, ticket_asset_id=gate.TICKET_ID,
                          ticket_sha=gate.TICKET_SHA, registration_id=self.old["collector_registration_id"])
        self.new = dict(self.old, **gate.failure_fields(), head="e"*40,
                        registration_nonce="9"*32, collector_ack_sha="9"*64)

    def test_owner_grant_and_trial_reuse_bind_to_the_exact_closed_claim(self):
        gate.check_binding(self.claim, self.old, self.new)
        granted = dict(gate.route(self.new), run_id=987, source_claim_id=gate.SOURCE_CLAIM_ID,
                       source_claim_sha=gate.SOURCE_CLAIM_SHA)
        gate.check_reference(granted, self.new)
        cases = ((self.claim,"run_id",987), (self.claim,"producer_attempt",2), (self.claim,"head","f"*40),
                 (self.claim,"ticket_asset_id",1), (self.claim,"source_claim_id",gate.SOURCE_CLAIM_ID),
                 (self.old,"trial_head","f"*40), (self.new,"trial_run_id",gate.previous.PREVIOUS_TRIAL),
                 (self.new,"trial_head","f"*40), (self.new,"inventory_failure_run_id",True),
                 (self.new,"inventory_failure_claim_sha","f"*64), (self.new,"inventory_failure_closure_sha","f"*64),
                 (self.new,"head",self.old["head"]), (self.new,"registration_nonce",self.old["registration_nonce"]),
                 (self.new,"collector_ack_sha",self.old["collector_ack_sha"]), (self.new,"owner_destination_id","different"),
                 (self.new,"recipient","different"), (self.new,"final_certificate_sha256","f"*64),
                 (self.new,"artifact_ceiling_bytes",self.old["artifact_ceiling_bytes"]+1))
        for row, key, changed in cases:
            with self.subTest(key=key), patch.dict(row,{key:changed}), self.assertRaises(ValueError):
                gate.check_binding(self.claim, self.old, self.new)
        for reused in (gate.SOURCE_RUN, gate.label.CONSUMED, gate.previous.FAILED_RUN, gate.FAILED_RUN, gate.TRIAL_RUN):
            with self.subTest(run=reused), self.assertRaises(ValueError):
                gate.check_reference(dict(granted, run_id=reused), self.new)

    def test_every_official_terminal_job_and_step_is_bound(self):
        checks = [("Create an ephemeral ordinary transfer key","failure"), ("Deposit key in this run","skipped"),
                  ("Open restricted peer descriptor and verify the exact input archive","skipped"),
                  (gate.s1.FRONTIER,"skipped"), (gate.s1.COMPILE,"skipped"), (gate.label.SEAL,"skipped")]
        steps = [dict(number=i+1,name=name,conclusion=result) for i,(name,result) in enumerate(checks)]
        jobs = {140357901621:dict(name="producer",conclusion="failure",steps=steps),
                9:dict(name="receipt",conclusion="failure",steps=[])}
        expected = gate.terminal_jobs_sha(jobs)
        self.assertEqual(expected,gate.terminal_jobs_sha(dict(reversed(jobs.items()))))
        with patch.dict(jobs[140357901621],steps=list(reversed(steps))):
            self.assertEqual(expected,gate.terminal_jobs_sha(jobs))
        self.enterContext(patch.object(gate,"TERMINAL_JOBS_SHA",expected))
        service = self.enterContext(patch.object(gate.s1,"checked_run",return_value=jobs))
        gate.check_failed_run(None)
        service.assert_called_once()
        for record, change in ((steps[0],dict(conclusion="success")), (steps[2],dict(name="different")),
                               (steps[3],dict(number=99)), (jobs[9],dict(conclusion="success"))):
            with self.subTest(change=change), patch.dict(record,change), self.assertRaises(ValueError):
                gate.check_failed_run(None)
        for absent in (9,140357901621):
            with self.subTest(job=absent), patch.object(gate.s1,"checked_run",return_value={i:j for i,j in jobs.items() if i!=absent}), self.assertRaises(ValueError):
                gate.check_failed_run(None)
        with patch.dict(steps[4],conclusion="success"), patch.object(gate,"TERMINAL_JOBS_SHA",gate.terminal_jobs_sha(jobs)), self.assertRaises(ValueError):
            gate.check_failed_run(None)

    def test_missing_private_binder_witness_prevents_initial_grant(self):
        def download(helper, release, name, aid, size, sha, *, owner=False):
            if aid == gate.WITNESS_ID:
                self.assertEqual((size,sha),(569,gate.WITNESS_SHA))
                raise ValueError("original witness missing")
            return {gate.SOURCE_CLAIM_ID:self.claim, gate.TICKET_ID:self.old}[aid]
        with patch.object(gate,"read_fixed",side_effect=download), patch.object(gate,"check_failed_run") as ended, patch.object(gate.previous,"validate_source") as earlier:
            with self.assertRaisesRegex(ValueError,"original witness missing"):
                gate.validate_source(None,{},self.new,initial=True)
            ended.assert_not_called()
            earlier.assert_not_called()
            gate.validate_source(None,{},self.new,initial=False)
            earlier.assert_called_once()
