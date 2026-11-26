"""A successful independent trial must certify this exact candidate without compiling."""
from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch

import s1_resume as resumed
import registration


class TrialGate(TestCase):
    def setUp(self):
        self.ticket = dict(source_run_id=resumed.SOURCE_RUN, manifest_id=resumed.MANIFEST_ID,
                           manifest_sha=resumed.MANIFEST_SHA, initial_parent=resumed.PARENT_SHA,
                           trial_run_id=29, trial_head="3"*40, head="4"*40)
        self.tree={"checkpoint.py":"6"*40, "preflight28/graph":"7"*40}
        self.steps=[dict(name=resumed.NEGATIVE,conclusion="success"),
                    dict(name=resumed.FRONTIER,conclusion="success"),dict(name=resumed.COMPILE,conclusion="skipped")]
        self.jobs={1:dict(name=resumed.CERTIFICATION,conclusion="success",steps=[]),
                   2:dict(name="consumer",conclusion="success",steps=self.steps)}

    def verify(self,jobs=None,trees=None):
        with patch.object(resumed,"checked_run",return_value=self.jobs if jobs is None else jobs), \
             patch.object(resumed,"proof_source",side_effect=trees or [self.tree,self.tree]):
            resumed.validate_trial(None,self.ticket)

    def test_exact_trial(self):
        self.verify()

    def test_reject_wrong_proof(self):
        for bad in (dict(initial_parent=resumed.S2_SHA),dict(manifest_id=True),dict(trial_head=resumed.SOURCE_HEAD)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                resumed.route(dict(self.ticket,**bad))
        for index,conclusion in ((0,"skipped"),(1,"skipped"),(2,"success")):
            jobs=deepcopy(self.jobs)
            jobs[2]["steps"][index]["conclusion"]=conclusion
            with self.subTest(index=index), self.assertRaises(ValueError):
                self.verify(jobs=jobs)
        with self.assertRaises(ValueError):
            self.verify(trees=[self.tree,dict(self.tree,**{"preflight28/graph":"8"*40})])
        with self.assertRaises(ValueError):
            self.verify(jobs={2:self.jobs[2]})

    def test_gate_rejects_unrelated_parent_and_duplicate_identity(self):
        fixed=dict(checkpoint_key=f"bare-coexist-204-{resumed.SOURCE_RUN}-1-checkpoint-production-s1",
                   checkpoint_identity=resumed.PARENT_IDENTITY,checkpoint_sha=resumed.PARENT_SHA)
        registration.checked_build_route({},resume=True)
        registration.checked_build_route(fixed,resume=True)
        with self.assertRaises(ValueError):
            registration.checked_build_route(dict(fixed,checkpoint_sha=resumed.S2_SHA),resume=True)
        payload=dict(resumed.route(self.ticket),source_claim_id=resumed.SOURCE_CLAIM_ID,
                     source_claim_sha=resumed.SOURCE_CLAIM_SHA,run_id=70)
        resumed.check_reference(payload,self.ticket)
        self.assertNotEqual(resumed.CLAIM,resumed.SOURCE_CLAIM_NAME)
        for rid in (resumed.SOURCE_RUN,self.ticket["trial_run_id"],False):
            with self.subTest(rid=rid), self.assertRaises(ValueError):
                resumed.check_reference(dict(payload,run_id=rid),self.ticket)
