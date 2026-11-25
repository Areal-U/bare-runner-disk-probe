"""Admission controls for the manual diagnostic entry. No hosted run is created."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import trials

B = trials.budget
HEAD = "b"*40
NOW = 1700000000

def api(path):
    if path == B.BASE:
        return dict(id=B.REPO_ID, full_name=B.REPO, private=False, fork=False, visibility="public")
    if "/git/ref/" in path:
        return {"object":{"sha":HEAD}}
    if "/runs?head_sha=" in path:
        return dict(total_count=0,workflow_runs=[])
    if "/actions/workflows/" in path:
        return dict(state="active", path=".github/workflows/"+trials.WORKFLOW)
    if "/actions/runs" in path:
        return dict(workflow_runs=[], total_count=0)
    if "/actions/artifacts" in path:
        return dict(artifacts=[],total_count=0)
    raise AssertionError(path)

class AdmissionTests(unittest.TestCase):
    def test_empty_replay_and_inside_run_use_same_bounds(self):
        outer=trials.check(api, "split", HEAD, 0, now=NOW)
        inner=trials.check(api,"split",HEAD,42,outer["ceiling"],outer["until"],runner="github-hosted",now=NOW+20)
        self.assertEqual(outer,inner)

    def test_active_origin_refuses_before_diagnostic_is_created(self):
        def active(path):
            if "?status=in_progress" in path:
                return dict(total_count=1, workflow_runs=[{"id":45549494619}])
            return api(path)
        with self.assertRaisesRegex(ValueError,"Another"):
            trials.check(active,"source-v8",HEAD,0,now=NOW)

    def test_lower_limits_fail_including_missing_expired_inputs(self):
        for ceil,until in [(str(6*B.MIB),str(NOW+2*86400)),("",""),(str(10*B.MIB),str(NOW+86400))]:
            with self.subTest(ceil=ceil,until=until),self.assertRaises(ValueError):
                trials.check(api,"receiver",HEAD,42,ceil,until,runner="github-hosted",now=NOW)
        with patch.dict("os.environ",{"R28_RELAY_BYTE_CEILING":"17"}),self.assertRaises(ValueError):
            trials.check(api,"receiver",HEAD,0,now=NOW)

    def test_late_repeat_finds_previous_issued_run(self):
        def previous(path):
            if "/runs?head_sha=" in path:
                return dict(total_count=1,workflow_runs=[dict(display_title=f"Bare next-build trial receiver {HEAD}",head_sha=HEAD,id=13)])
            return api(path)
        with self.assertRaisesRegex(ValueError,"issued trial 13"):
            trials.check(previous,"receiver",HEAD,0,now=NOW)

    def test_other_head_or_host_cannot_run(self):
        with self.assertRaises(ValueError):
            trials.check(api,"receiver","a"*40,0,now=NOW)
        with self.assertRaises(ValueError):
            trials.check(api,"receiver",HEAD,42,str(20*B.MIB),str(NOW+2*86400),runner="self-hosted",now=NOW)
