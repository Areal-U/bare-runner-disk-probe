import unittest
import chain
import replay_worker as worker
from admission import BASE_SHA, BRANCH, REPO_ID, S2_SHA, WORKFLOW


class History:
    def __init__(self):
        self.recjob = True
        self.sha = "e" * 40
        self.logid = 331

    def get(self, path):
        if path == f"actions/jobs/{worker.S2_READER}":
            return dict(id=worker.S2_READER, run_id=worker.RUN27, run_attempt=1,
                        head_sha=BASE_SHA, conclusion="success")
        if path == "actions/runs/72/attempts/1":
            return dict(id=72, run_attempt=1, event="pull_request", path=WORKFLOW,
                        head_sha=self.sha, head_branch=BRANCH, pull_requests=[{"number":9}],
                        repository={"id":REPO_ID}, head_repository={"id":REPO_ID})
        if path == "actions/runs/72/attempts/1/jobs?per_page=100":
            return {"total_count": 2, "jobs": [
                {"id":1,"run_id":72,"run_attempt":1,"name":worker.PRODUCER,"conclusion":"success"},
                {"id":2,"run_id":72,"run_attempt":1,"name":worker.RECEIVER,
                 "conclusion":"success" if self.recjob else "failure"}]}
        raise AssertionError(path)

    def raw(self, path):
        import json
        if path == f"actions/jobs/{worker.S2_READER}/logs":
            return (S2_SHA + f"\nVerified successor cache {worker.S2_KEY}\n" +
                    '{"archive_bytes": 2753879385, "members": 291583}')
        if path == "actions/jobs/1/logs":
            return "\n".join(("2026Z canonical_run=72 producer_attempt=1 current_attempt=1",
                              "2026Z protected_s2_id=11016400308 outer=2742685925",
                              "2026Z " + json.dumps(dict(new_target="obj/foo.o", parent_dirty=7,
                                                         child_dirty=6, proof_sha256="f"*64)),
                              "2026Z manifest_receipt=" + json.dumps(dict(name=
                                  "r28-preflight-s2-20261125-v1-run72-a1-seg01-manifest.json",
                                  id=331, bytes=122, sha256="d"*64))))
        if path == "actions/jobs/2/logs":
            return "\n".join((f"2026Z independent_draft_read_id={self.logid} archive_bytes=181 sha256="+"c"*64,
                              "2026Z " + json.dumps(dict(restored_target="obj/foo.o", parent_dirty=7,
                                                        restored_dirty=6, proof_sha256="f"*64))))
        raise AssertionError(path)


class ReplayTests(unittest.TestCase):
    def test_callable_worker_as_twelve_slot_preflight(self):
        history = History()
        jobs = {}
        parent = chain.SEED
        for index in (1, 2):
            state, receipt, received = worker.replay(history, mode="verify-and-compute",
                       ordinal=index, parent=parent, source_run=72, source_sha=history.sha,
                       receiver_attempt=1, current_attempt=1)
            jobs[chain.slot(index)] = {"result":"success","outputs":
                  dict(owner_run="91",owner_attempt="1",ordinal=str(index),status=state,
                       receipt=receipt,accepted_parent=received)}
            parent = receipt
        for index in range(3, 13):
            jobs[chain.slot(index)] = {"result":"skipped"}
        jobs["last_receipt"] = {"result":"skipped"}
        expected = ("preflight-received", parent)
        self.assertEqual(chain.summarize(jobs, 91), expected)
        self.assertEqual(worker.replay(history, mode="recover-only", ordinal=0, parent="",
                         source_run=72, source_sha=history.sha, receiver_attempt=1, current_attempt=2)[:2],
                         expected)

    def test_missing_wrong_and_foreign_receivers(self):
        h = History()
        args = dict(mode="verify-and-compute", ordinal=2, parent="draft:331:"+"d"*64,
                    source_run=72, source_sha=h.sha, receiver_attempt=1, current_attempt=1)
        h.recjob = False
        with self.assertRaises(ValueError):
            worker.replay(h, **args)
        h.recjob, h.logid = True, 777
        with self.assertRaises(ValueError):
            worker.replay(h, **args)
        h.logid = 331
        args["parent"] = chain.SEED
        with self.assertRaises(ValueError):
            worker.replay(h, **args)


if __name__ == "__main__":
    unittest.main()
