"""Attempt-wide identity and server clock resolution with concurrent nested jobs."""
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import guard


class ClockTest(unittest.TestCase):
    suffix="Private checkpoint receipt for slot 12"
    env={"GITHUB_REPOSITORY":guard.REPO,"JOB_READ_TOKEN":"unit-test","GITHUB_RUN_ID":"345",
         "GITHUB_RUN_ATTEMPT":"2","GITHUB_SHA":"d"*40,"GITHUB_EVENT_NAME":"workflow_dispatch",
         "CLOCK_SUFFIX":suffix}

    def job(self,id):
        return {"run_id":345,"run_attempt":2,"head_sha":"d"*40,"name":"orchestration / inactive",
                "status":"completed","id":id,"check_run_url":f"https://api.github.com/repos/{guard.REPO}/check-runs/{id+11000}",
                "started_at":"2025-01-01T00:00:00Z"}

    def pages(self):
        rows=[self.job(i) for i in range(1,124)]
        rows[-1].update(name="worker / "+self.suffix,status="in_progress")
        return [{"total_count":123,"jobs":rows[:100]},{"total_count":123,"jobs":rows[100:]}]

    def lookup(self, pages, call):
        paths=[]
        def get(path, headers):
            self.assertEqual(headers["Authorization"],"Bearer unit-test")
            prefix=f"/repos/{guard.REPO}/actions/runs/345/attempts/2/jobs?per_page=100&page="
            self.assertTrue(path.startswith(prefix))
            p=int(path[len(prefix):])
            paths.append(p)
            return pages[p-1]
        with patch.dict(os.environ,self.env),patch.object(guard,"get_job_page",side_effect=get),patch.object(guard.time,"sleep"):
            result=call()
        return result,paths

    def test_both_fallback_and_native_clock_resolve_late_slot(self):
        self.assertEqual(self.lookup(self.pages(),lambda:guard.active_job(suffix=self.suffix)),((11123,1735689600),[1,2]))
        self.assertEqual(self.lookup(self.pages(),lambda:guard.job_clock(11123)),(1735689600,[1,2]))

    def test_exact_multiple_finishes_without_an_empty_tail_page(self):
        page=self.pages()[0]
        page["total_count"]=100
        page["jobs"][-1].update(name=self.suffix,status="in_progress")
        self.assertEqual(self.lookup([page],lambda:guard.job_clock(11100)),(1735689600,[1]))

    def test_reject_duplicate_count_changes_foreign_ids_and_ambiguous_display_name(self):
        for fault in ("duplicate","growing","short","too-many","name","sha","attempt","run","other-url","false-suffix","wrong-check"):
            with self.subTest(fault=fault):
                pages=self.pages()
                late=pages[1]["jobs"][-1]
                target=11123
                if fault=="duplicate":
                    pages[1]["jobs"][0]["id"]=pages[0]["jobs"][0]["id"]
                if fault=="growing":
                    pages[1]["total_count"]=124
                if fault=="short":
                    pages[0]["jobs"].pop()
                if fault=="too-many":
                    pages[0]["total_count"]=1001
                if fault=="name":
                    pages[0]["jobs"][0].update(name=self.suffix,status="in_progress")
                if fault=="sha":
                    late["head_sha"]="a"*40
                if fault=="run":
                    late["run_id"]=346
                if fault=="attempt":
                    late["run_attempt"]=1
                if fault=="false-suffix":
                    late["name"]="misleading"+self.suffix
                if fault=="wrong-check":
                    target=11005
                if fault=="other-url":
                    late["check_run_url"]=late["check_run_url"].replace(guard.REPO,"other/repo")
                with self.assertRaises(ValueError):
                    self.lookup(pages,lambda:guard.job_clock(target))

    def test_all_ordinary_workflow_fallbacks_bind_name_and_server_clock(self):
        root=Path(__file__).resolve().parents[2]
        workflow=(root/".github/workflows/bare-arm64-probe.yml").read_text()
        self.assertEqual(workflow.count('job-check --job-suffix "$CLOCK_SUFFIX"'),3)
        self.assertNotIn('jobs?per_page=100" | jq -er --arg suffix "$CLOCK_SUFFIX"',workflow)
        self.assertIn('job-clock --check-run "$MY_CHECK"',workflow)
        self.assertIn('job-clock --check-run "$CHECK_RUN"',workflow)


if __name__=="__main__":
    unittest.main()
