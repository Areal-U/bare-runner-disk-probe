import hashlib
from concurrent.futures import ThreadPoolExecutor
from io import BytesIO
from threading import Barrier, Lock, local
import unittest

import admission as gate


def sample(mode="compute", attempt=1, run=71):
    before, head = "b" * 40, "c" * 40
    repo = {"id": gate.REPO_ID, "full_name": gate.REPO}
    owner = {"login": "Areal-U", "id": 292261483}
    event = {"number": 9, "action": "synchronize", "before": before, "after": head, "sender": owner,
             "repository": repo, "pull_request": {"number": 9,
                        "head": {"ref": gate.BRANCH, "sha": head, "repo": repo},
                        "base": {"ref": gate.BASE_REF, "sha": gate.BASE_SHA, "repo": repo}}}
    env = {"GITHUB_RUN_ATTEMPT": str(attempt), "GITHUB_RUN_ID": str(run),
           "GITHUB_REF": "refs/pull/9/merge", "GITHUB_EVENT_NAME": "pull_request",
           "GITHUB_JOB": "produce" if mode == "compute" else "receive",
           "GITHUB_REPOSITORY": gate.REPO}
    api = {"actor": owner, "id": run, "run_attempt": attempt, "path": gate.WORKFLOW,
           "event": "pull_request", "head_sha": head, "head_branch": gate.BRANCH,
           "head_repository": repo, "repository": repo, "pull_requests": [{"number": 9}]}
    return mode, before, env, event, api, head


class Draft:
    BASE = "/repos/test"
    UPLOAD = "uploads.github.com"

    def __init__(self):
        self.blob = None
        self.posts = 0

    def draft(self, release):
        assert release == gate.RELEASE_ID
        return {"assets": [{"name": gate.CLAIM}] if self.blob is not None else []}

    def asset_info(self, release, name, size, digest):
        assert release["assets"] == [{"name": name}]
        gate.require(size == len(self.blob) and digest == hashlib.sha256(self.blob).hexdigest(),
                     "Conflicting holder")
        return {"id": 17}

    def download(self, asset_id, size, expected_hash, destination: BytesIO):
        assert asset_id == 17
        destination.write(self.blob)

    def request(self, host, method, path, **kwargs):
        assert self.blob is None and method == "POST" and host == self.UPLOAD
        assert path.endswith("?name=" + gate.CLAIM) and kwargs["auth"]
        self.posts += 1
        self.blob = kwargs["body"]
        raise ConnectionResetError("lost response after durable upload")


class AdmissionTests(unittest.TestCase):
    def test_lost_response_recovery_and_late_duplicate_are_readonly(self):
        draft = Draft()
        holder = gate.checked_holder(*sample())
        self.assertEqual(gate.admit("compute", holder, draft), 17)
        self.assertEqual(gate.admit("recover", gate.checked_holder(*sample("recover", 2)), draft), 17)
        self.assertEqual(gate.admit("recover", gate.checked_holder(*sample("recover", 8)), draft), 17)
        self.assertEqual(draft.posts, 1)
        with self.assertRaises(ValueError):
            gate.admit("compute", gate.checked_holder(*sample(run=72)), draft)
        self.assertEqual(draft.posts, 1)

    def test_two_concurrent_physical_runs_only_one_may_compute(self):
        barrier = Barrier(2)
        lock = Lock()
        seen = local()

        class Race(Draft):
            def draft(self, release):
                snapshot = super().draft(release)
                if not getattr(seen, "entered", False):
                    seen.entered = True
                    barrier.wait(timeout=5)
                return snapshot

            def request(self, host, method, path, **kwargs):
                with lock:
                    if self.blob is not None:
                        class Response:
                            status = 422

                        return BytesIO(), Response()
                    return super().request(host, method, path, **kwargs)

        draft = Race()
        def worker(rid):
            holder = gate.checked_holder(*sample(run=rid))
            try:
                return gate.admit("compute", holder, draft)
            except ValueError:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(pool.map(worker, [71, 72]), [17, None])
        self.assertEqual(draft.posts, 1)

    def test_recovery_never_creates_a_claim(self):
        draft = Draft()
        with self.assertRaises(ValueError):
            gate.admit("recover", gate.checked_holder(*sample("recover", 2)), draft)
        self.assertEqual(draft.posts, 0)

    def test_rerun_cannot_compute(self):
        with self.assertRaises(ValueError):
            gate.checked_holder(*sample("compute", 2))

    def test_wrong_workflow_checkout_or_ordinal(self):
        args = list(sample())
        args[4]["path"] = "another-workflow.yml"
        with self.assertRaises(ValueError):
            gate.checked_holder(*args)
        args = list(sample())
        args[5] = args[1]
        with self.assertRaises(ValueError):
            gate.checked_holder(*args)
        args = list(sample())
        args[2]["GITHUB_JOB"] = "receive"
        with self.assertRaises(ValueError):
            gate.checked_holder(*args)


if __name__ == "__main__":
    unittest.main()
