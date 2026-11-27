import hashlib
from unittest import TestCase
from unittest.mock import patch

import s1_setup_resume as s
from test_registration import OwnerDraft
from test_s1_label_resume import fixed


class SetupAdmission(TestCase):
    def setUp(self):
        self.enterContext(patch.object(s.previous, "OWNER_CERT_COMMITMENT", hashlib.sha256(("6"*64).encode()).hexdigest()))
        self.old = dict(OwnerDraft().ticket, **fixed())
        self.old.update(head=s.FAILED_HEAD, trial_run_id=s.PREVIOUS_TRIAL, trial_head=s.PREVIOUS_TRIAL_HEAD)
        self.claim = dict(s.previous.route(self.old), run_id=s.FAILED_RUN, producer_attempt=1, head=s.FAILED_HEAD,
                          source_claim_id=s.previous.SOURCE_CLAIM_ID, source_claim_sha=s.previous.SOURCE_CLAIM_SHA,
                          ticket_asset_id=s.TICKET_ID, ticket_sha=s.TICKET_SHA, registration_id=self.old["collector_registration_id"])
        self.new = dict(self.old, **s.failure_fields(), head="e"*40, trial_run_id=202, trial_head="d"*40,
                        registration_nonce="9"*32, collector_ack_sha="9"*64)

    def test_original_claim_is_preserved_and_next_grant_is_bound_to_its_terminal(self):
        s.check_binding(self.claim, self.old, self.new)
        self.assertNotEqual(s.CLAIM, s.previous.CLAIM)
        self.assertNotEqual(s.TICKET_NAME, s.previous.TICKET_NAME)
        new_claim = dict(s.route(self.new), run_id=208, source_claim_id=s.SOURCE_CLAIM_ID, source_claim_sha=s.SOURCE_CLAIM_SHA)
        s.check_reference(new_claim, self.new)
        for row, changes in [(self.claim, {"ticket_asset_id": 22}), (self.claim, {"head": self.new["head"]}),
                             (self.old, {"trial_head": self.new["trial_head"]}), (self.new, {"trial_run_id": s.PREVIOUS_TRIAL}),
                             (self.new, {"setup_failure_closure_sha": "b"*64}), (self.new, {"owner_destination_id":"other"}),
                             (self.new, {"collector_ack_sha":self.old["collector_ack_sha"]}),
                             (self.new, {"artifact_ceiling_bytes": self.old["artifact_ceiling_bytes"]+1})]:
            with self.subTest(changes=changes), patch.dict(row,changes), self.assertRaises(ValueError):
                s.check_binding(self.claim,self.old,self.new)
        for id in (s.FAILED_RUN, s.PREVIOUS_TRIAL, s.SOURCE_RUN, self.new["trial_run_id"]):
            with self.subTest(run=id),self.assertRaises(ValueError):
                s.check_reference(dict(new_claim,run_id=id),self.new)

    def test_upstream_setup_failure_requires_complete_claimed_but_uncompiled_run(self):
        def job(result, *steps):
            return dict(conclusion=result,steps=[dict(name=k,conclusion=v) for k,v in steps])
        jobs = {i:job("skipped") for i in range(30)}
        jobs.update({i:job("success") for i in (140317588514,140317617454,140317767829)})
        jobs[140317851385] = job("success",("Discover exact peer outcome","success"),
            ("Fetch authenticated outcome by immutable artifact ID","success"),
            ("Receive bounded ciphertext and independently verify fixed private publication","success"))
        jobs[140317851617] = job("failure",("Open restricted peer descriptor and verify the exact input archive","success"),
            ("Install build tools and apply the pinned Bare patches","failure"),(s.previous.s1.FRONTIER,"skipped"),
            (s.previous.s1.COMPILE,"skipped"),(s.previous.SEAL,"skipped"),("Pack the completed intermediate outputs","skipped"))
        jobs[140323733601]=job("failure")
        jobs[140323786254]=job("failure",("Check every causal transition and select the sole outcome","failure"))
        with patch.object(s.previous.s1,"checked_run",return_value=jobs):
            s.check_failed_run(None)
            for row in (jobs[140317851617]["steps"][3],jobs[140317851385]["steps"][1],jobs[0]):
                with self.subTest(name=row.get("name")),patch.dict(row,conclusion="cancelled"), self.assertRaises(ValueError):
                    s.check_failed_run(None)
