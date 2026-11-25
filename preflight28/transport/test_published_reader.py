"""Exercise GET-only publication recovery including the original canonical manifest."""
import json
import unittest
from urllib.parse import urlsplit
from unittest.mock import patch

import published_reader as reader
import thaw_claim as thaw
from test_thaw_claim import Service, WHEAD, base_run, context, original_manifest


class Published(Service):
    def __init__(self):
        super().__init__()
        self.reads = []
        self.prior_jobs = {}
        self.prior_status = {}
        self.info = {**base_run(reader.RUN), "run_attempt": 1, "head_sha": reader.HEAD,
                     "path": thaw.WORKFLOW, "status": "completed", "conclusion": "failure"}
        self.jobs = []
        for jid, (name, outcome) in reader.JOBS.items():
            stages = [dict(number=i, name=label, status="completed", conclusion=result)
                      for i, (label, result) in enumerate(reader.STEPS[jid], 1)]
            self.jobs.append(dict(id=jid, run_id=reader.RUN, run_attempt=1, head_sha=reader.HEAD,
                                  name=name, status="completed", conclusion=outcome, steps=stages))
        self.add(thaw.CLAIM, thaw.a.encode(thaw.next_holder(
            reader.RUN, reader.HEAD, reader.BEFORE, thaw.HISTORY[-1], 5)), reader.CLAIM_ID)
        self.part()
        self.rows[thaw.STEM + "p00"]["id"] = reader.PART_ID
        body = original_manifest()
        body["parts"][0]["id"] = reader.PART_ID
        self.add(thaw.STEM + "manifest.json",
                 json.dumps(body, sort_keys=True, separators=(",", ":")).encode(), reader.MANIFEST_ID)

    def metadata(self, url, **kwargs):
        route = urlsplit(url).path
        if route.startswith(f"{self.BASE}/actions/runs/{reader.RUN}"):
            if route.endswith("/jobs"):
                return {"total_count": len(self.jobs), "jobs": self.jobs}
            return self.info
        prefix = f"{self.BASE}/actions/runs/{reader.RUN + 101}/attempts/"
        if route.startswith(prefix):
            index, *suffix = route[len(prefix):].split("/")
            index = int(index)
            if suffix == ["jobs"]:
                jobs = self.prior_jobs[index]
                return {"jobs":jobs, "total_count":len(jobs)}
            if index in self.prior_jobs:
                return {**base_run(reader.RUN + 101), "head_sha":WHEAD, "path":thaw.WORKFLOW,
                        "run_attempt":index, "status":"completed", "conclusion":self.prior_status.get(index,"failure")}
        return super().metadata(url, **kwargs)

    def download(self, aid, size, sha, destination):
        self.reads.append((aid, size, sha))
        return super().download(aid, size, sha, destination)


def bound():
    env, event = context(reader.RUN + 101)
    env.update(GITHUB_JOB="issue", TRIAL_SHA=WHEAD, PRIOR_SHA=reader.HEAD,
               R28_RESUME_PUBLISHED=str(reader.RUN), MANIFEST_ID=str(reader.MANIFEST_ID),
               MANIFEST_SHA=reader.MANIFEST_SHA)
    event.update(after=WHEAD, before=reader.HEAD)
    event["pull_request"]["head"]["sha"] = WHEAD
    return env, event


class TestReadOnly(unittest.TestCase):
    def test_verified_existing_exact_source_and_immutable_manifest(self):
        h = Published()
        env, event = bound()
        for attempt in (1, 2):
            if attempt == 2:
                h.prior_jobs[1] = []
            env["GITHUB_RUN_ATTEMPT"] = str(attempt)
            result = reader.verify(h, env, event, WHEAD)
            self.assertEqual((result["claim_id"], result["part_id"], result["source_bytes"]),
                             (789516828, 789540148, 1745316602))
        self.assertIn((reader.MANIFEST_ID, 974, reader.MANIFEST_SHA), h.reads)
        self.assertIn((reader.CLAIM_ID, 1892, reader.CLAIM_SHA), h.reads)
        self.assertFalse(any(aid == reader.PART_ID for aid, _, _ in h.reads))
        self.assertEqual(h.posts, 0)

    def test_only_unfinished_delivery_can_receive_a_fresh_grant(self):
        env, event = bound()
        env["GITHUB_RUN_ATTEMPT"] = "3"
        h = Published()
        fetch, restore = (label for label, _ in reader.STEPS[reader.RECEIVE][-2:])
        steps = [dict(name=fetch, status="completed", conclusion="success"),
                 dict(name=restore, status="completed", conclusion="failure")]
        j = dict(id=100, run_id=int(env["GITHUB_RUN_ID"]), run_attempt=1, head_sha=WHEAD,
                 status="completed", conclusion="failure", name=reader.JOBS[reader.RECEIVE][0], steps=steps)
        h.prior_jobs = {1:[j], 2:[]}
        self.assertEqual(reader.verify(h, env, event, WHEAD)["manifest_id"], reader.MANIFEST_ID)
        # A successful restore remains terminal even if later job cleanup
        # failed and a more recent attempt had no receiver.
        with patch.dict(steps[1], conclusion="success"), self.assertRaisesRegex(ValueError, "already finished"):
            reader.verify(h, env, event, WHEAD)
        with patch.dict(j, run_id=reader.RUN), self.assertRaisesRegex(ValueError, "foreign"):
            reader.verify(h, env, event, WHEAD)
        with patch.dict(h.prior_status, {2:"success"}), self.assertRaisesRegex(ValueError, "no ordinary"):
            reader.verify(h, env, event, WHEAD)
        self.assertEqual(h.posts, 0)

    def test_read_client_blocks_mutation_and_get_with_body(self):
        h = Published()
        for method, opts in (("POST", {}), ("DELETE", {}), ("PATCH", {}), ("PUT", {}),
                             ("GET", {"body": b"wrong"})):
            with self.subTest(method=method), reader.read_only(h) as safe:
                with self.assertRaisesRegex(ValueError, "bodyless GET"):
                    safe.request("uploads.github.com", method, "/test", **opts)
        self.assertEqual(h.posts, 0)

    def test_source_claim_and_manifest_cannot_be_replaced_or_truncated(self):
        for key in (thaw.CLAIM, thaw.STEM+"p00", thaw.STEM+"manifest.json"):
            for attr in ("id", "size", "digest"):
                with self.subTest(key=key, attr=attr):
                    h = Published()
                    h.rows[key][attr] = 1 if attr != "digest" else "sha256:" + "0"*64
                    with self.assertRaises((ValueError, KeyError)):
                        reader.verify(h, *bound(), WHEAD)
                    self.assertEqual(h.posts, 0)
        for ident in (thaw.CLAIM_ID, reader.CLAIM_ID, reader.MANIFEST_ID):
            h = Published()
            h.files[ident] = h.files[ident][:-1]
            with self.assertRaises(ValueError):
                reader.verify(h, *bound(), WHEAD)

    def test_active_prior_successful_grant_and_historical_rerun_block(self):
        h = Published()
        for changes in ({"status":"in_progress", "conclusion":None}, {"conclusion":"success"}, {"run_attempt":2}):
            with self.subTest(changes=changes), patch.dict(h.info, changes), self.assertRaises(ValueError):
                reader.verify(h, *bound(), WHEAD)
        for job in h.jobs:
            for step in job["steps"]:
                altered = "failure" if step["conclusion"] == "success" else "success"
                with self.subTest(step=step["name"]), patch.dict(step, conclusion=altered), self.assertRaises(ValueError):
                    reader.verify(h, *bound(), WHEAD)
        self.assertEqual(h.posts, 0)

    def test_no_authority_forwarded_to_wrong_role_event_or_generation(self):
        env, event = bound()
        h = Published()
        for key, val in (("GITHUB_JOB","receive"), ("GITHUB_TRIGGERING_ACTOR","other"),
                         ("GITHUB_REF","refs/heads/main"), ("TRIAL_SHA","9"*40), ("PRIOR_SHA","0"*40),
                         ("R28_RESUME_PUBLISHED",str(thaw.SOURCE)), ("MANIFEST_ID","1"),
                         ("MANIFEST_SHA","0"*64), ("GITHUB_RUN_ID",str(reader.RUN))):
            with self.subTest(key=key), patch.dict(env, {key:val}), self.assertRaises(ValueError):
                reader.verify(h, env, event, WHEAD)
        self.assertEqual(h.reads, [])


if __name__=="__main__":
    unittest.main()
