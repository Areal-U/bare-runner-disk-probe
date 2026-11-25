from datetime import datetime, timezone
import json
import unittest

import loss_marker
from test_receipt_journal import HEAD, RUN, SimulatedActions, stamp


class LossMarkerTests(unittest.TestCase):
    def fixture(self, **changes):
        s = SimulatedActions()
        k = 1
        parent = {"parent_sha":"a"*64, "parent_identity":"b"*64}
        job = s.job(k, "Authenticate / Compile or verify authenticated APK slot 1",
                    [(loss_marker.STOP, "success"), (loss_marker.PACK, "skipped"), (loss_marker.CANDIDATE, "skipped"),
                     (loss_marker.UPLOADS[0], "success"), (loss_marker.UPLOADS[1], "skipped")])
        note = dict(schema="bare-r28-checkpoint-private-v1", key=f"bare-coexist-204-{RUN}-1-checkpoint-production-s1",
                    run=RUN, attempt=1, ordinal=k, producer_sha=HEAD, status="apk", **parent)
        row = s.asset(f"r28-{RUN}-a1-s01-outcome", "outcome.json", json.dumps(dict(note, **changes)))
        return s, job, row, parent

    def check(self, s, job, parent):
        return loss_marker.verified(s.assets, job, RUN, HEAD, 1, parent, datetime.now(timezone.utc),
                                    s.objects.__getitem__, s.raw.__getitem__)

    def test_only_exact_hashed_single_member_marker_exempts_a_live_control_upload(self):
        s, job, row, parent = self.fixture()
        self.assertTrue(self.check(s, job, parent))
        for change in ({"status":"candidate"}, {"run":RUN+1}, {"parent_sha":"0"*64}, {"bytes":5}):
            with self.subTest(change=change):
                s, job, row, parent = self.fixture(**change)
                with self.assertRaisesRegex(ValueError, "binding"): self.check(s, job, parent)
        s, job, row, parent = self.fixture()
        s.raw[row["id"]] += b"bad"
        with self.assertRaisesRegex(ValueError, "digest"): self.check(s, job, parent)

    def test_expired_marker_requires_original_pack_and_candidate_absence_and_exact_upload(self):
        s, job, row, parent = self.fixture()
        row.update(expired=True, expires_at=stamp(-2))
        s.objects[row["id"]] = dict(row)
        s.raw.clear()
        self.assertTrue(self.check(s, job, parent))
        job["steps"][1]["conclusion"] = "success"
        with self.assertRaisesRegex(ValueError,"might contain"): self.check(s, job, parent)
        job["steps"][1]["conclusion"] = "skipped"
        row["created_at"] = stamp(2)
        with self.assertRaisesRegex(ValueError, "original APK marker upload"): self.check(s, job, parent)
        s.assets.clear()
        self.assertFalse(self.check(s, job, parent))

    def test_production_loss_gate_still_rejects_terminal_bytes_after_receiving_a_control_marker(self):
        import loss_resume as loss
        from test_loss_provenance import OriginalProvenance
        from test_receipt_journal import seal
        s, ledger, now = OriginalProvenance().original()
        job = s.jobs[0]
        for step in job["steps"]:
            if step["name"] == loss_marker.UPLOADS[0]:
                step["conclusion"] = "success"
        for name, conclusion in ((loss_marker.STOP,"success"),(loss_marker.PACK,"skipped"),(loss_marker.CANDIDATE,"skipped")):
            job["steps"].append(dict(job["steps"][0], name=name, conclusion=conclusion))
        s.job(1, "Private checkpoint receipt for slot 1", [(loss.PRIVATE_WRITES[0],"success")])
        parent = loss.parent_at([],1,RUN,HEAD)
        note = dict(schema="bare-r28-checkpoint-private-v1", key=f"bare-coexist-204-{RUN}-1-checkpoint-production-s1",
                    run=RUN, attempt=1, ordinal=1, producer_sha=HEAD, status="apk",
                    parent_sha=parent["parent_sha"], parent_identity=parent["parent_identity"])
        s.asset(f"r28-{RUN}-a1-s01-outcome","outcome.json",json.dumps(note))
        def assess():
            return loss.loss_proof(ledger,s.jobs,s.assets,[],[],[],RUN,HEAD,1,now,
                                   s.objects.__getitem__,s.raw.__getitem__)
        self.assertEqual(assess(),parent)
        for step in job["steps"]:
            if step["name"] == loss.CIPHER:
                step["conclusion"] = "success"
        s.asset(f"bare-personal-204-encrypted-{RUN}-1-s1","seal.json",json.dumps(seal(1)))
        with self.assertRaisesRegex(ValueError,"may still be recoverable"): assess()
