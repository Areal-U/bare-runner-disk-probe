"""Replays complete five-filter views delivered by the GitHub Actions run API."""
import contextlib
import io
import unittest
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch
import storage_admission as gate


def page(*rows, total=None):
    return {"total_count": len(rows) if total is None else total, "workflow_runs": list(rows)}


class DiagnosticGate(unittest.TestCase):
    def run_views(self, views, run=7):
        calls = []
        def get(path):
            params = parse_qs(urlsplit(path).query)
            calls.append((params["status"][0], int(params["per_page"][0])))
            i = len(calls) - 1
            observation = views[min(i // 5, len(views)-1)].get(calls[-1][0], page())
            if isinstance(observation, Exception):
                raise observation
            return observation
        log = io.StringIO()
        with contextlib.redirect_stderr(log):
            gate.diagnostic_active_runs(get, {"GITHUB_RUN_ID":str(run)}, delays=(0,)*4)
        return calls,log.getvalue()

    def test_clean_scope_and_own_current_run(self):
        for stage in gate.RUN_STATES:
            calls,_ = self.run_views([{stage:page({"id":7,"status":stage})}])
            self.assertEqual([s for s,n in calls], list(gate.RUN_STATES))

    def test_other_run_ends_and_self_status_converges(self):
        first={"queued":page({"id":54, "status":"completed"}), "requested":page(total=1)}
        second={"in_progress":page({"id":7, "status":"in_progress"}), "queued":page({"id":7,"status":"queued"})}
        own={"in_progress":page({"id":7,"status":"in_progress"})}
        calls, log = self.run_views([first, second, own, own])
        self.assertEqual([n for s,n in calls[::5]],[2,3,4,5])
        for value in ('"id": 54','"status": "completed"','"requested"','"queued"'):
            self.assertIn(value,log)

    def test_not_admitted_after_single_clean_flicker(self):
        other={"in_progress":page({"id":9,"status":"in_progress"})}
        for views in ((other,), (other,{},other,{}), ({"queued":page({"id":8})},),
                      ({"pending":page({"id":7,"status":"waiting"})},), ({"queued":OSError("unavailable")},)):
            with self.subTest(views=views), self.assertRaises(gate.StorageUnconfirmed):
                self.run_views(views)

    def test_predispatch_requires_no_other_run_in_all_states(self):
        for stage in gate.RUN_STATES:
            with self.assertRaises(gate.StorageUnconfirmed):
                self.run_views([{stage:page({"id":7,"status":stage})}],run=0)
        self.assertEqual(len(self.run_views([{}],run=0)[0]),5)

    def test_existing_production_keeps_one_pass_and_fails_immediately(self):
        with patch.object(gate, "diagnostic_active_runs", side_effect=AssertionError("unexpected alternate guard")):
            with self.assertRaises(gate.StorageUnconfirmed):
                gate.check_active_runs(lambda path: page({"id":62}), {"GITHUB_RUN_ID":"7"})

if __name__=="__main__":
    unittest.main()
