from pathlib import Path
import tempfile
import unittest
import yaml

import chain


def loc(n):
    return f"draft:{n}:{n:064x}"


def good(run=11, count=3, finish=None):
    jobs = {}
    parent = chain.SEED
    stopped = False
    for i in range(1, count + 2):
        job = "last_receipt" if i > count else chain.slot(i)
        if stopped:
            jobs[job] = {"result": "skipped"}
            continue
        state = "apk" if i == finish else "verified" if i > count else "candidate"
        child = parent if state == "verified" else loc(i)
        jobs[job] = {"result": "success", "outputs": {"owner_run": str(run), "owner_attempt": "1",
                     "ordinal": str(i), "status": state, "receipt": child, "accepted_parent": parent}}
        parent = child
        stopped = state == "apk"
    return jobs


class FiniteChainTests(unittest.TestCase):
    def test_early_terminal_at_any_slot(self):
        for i in (1, 2, 3):
            state, receipt = chain.summarize(good(finish=i), 11, 3)
            self.assertEqual((state, receipt), ("apk-available-for-private-receipt", loc(i)))

    def test_limit_requires_independent_final_receipt(self):
        self.assertEqual(chain.summarize(good(), 11, 3), ("limit-with-verified-parent", loc(3)))
        bad = good()
        bad["last_receipt"]["result"] = "skipped"
        with self.assertRaises(ValueError):
            chain.summarize(bad, 11, 3)

    def test_stale_parents_attempts_unknown_receipts_stopped(self):
        for field, bad_value in (("accepted_parent", chain.SEED), ("owner_run", "10"),
                                 ("owner_attempt", "2"), ("ordinal", "1"), ("receipt", "unknown"),
                                 ("receipt", loc(1))):
            with self.subTest(field=field, value=bad_value):
                bad = good()
                bad["slot03"]["outputs"][field] = bad_value
                with self.assertRaises(ValueError):
                    chain.summarize(bad, 11, 3)

    def test_no_advance_after_terminal(self):
        late = good(finish=1)
        late["slot02"] = good()["slot02"]
        with self.assertRaises(ValueError):
            chain.summarize(late, 11, 3)
        none = good(finish=2)
        none["slot02"]["outputs"].update(status="no-progress", receipt=loc(1))
        self.assertEqual(chain.summarize(none, 11, 3), ("no-progress", loc(1)))

    def test_generated_dag_all_twelve(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp, "worker.yml")
            f.write_text(yaml.safe_dump({"on": {"workflow_call": {
                "inputs": {k: {"type": "number" if k == "ordinal" else "string"}
                           for k in ("mode", "ordinal", "parent")},
                "outputs": {k: {"value": "${{ jobs.trial.outputs." + k + " }}"}
                            for k in chain.OUTPUTS}}},
                "jobs": {"trial": {"outputs": {k: "${{ steps.real.outputs." + k + " }}"
                                                for k in chain.OUTPUTS}}}}))
            caller = chain.render(f)
        self.assertEqual(set(caller["on"]), {"workflow_call"})
        jobs = caller["jobs"]
        all_slots = [chain.slot(n) for n in range(1, 13)]
        self.assertEqual(jobs["first_attempt_result"]["needs"], all_slots + ["last_receipt"])
        self.assertEqual(jobs["recover_saved"]["with"]["mode"], "recover-only")
        self.assertIn("github.run_attempt != '1'", jobs["recover_saved"]["if"])
        for i, name in enumerate(all_slots + ["last_receipt"]):
            self.assertIn("github.run_attempt == '1'", jobs[name]["if"])
            if i:
                self.assertIn(all_slots[i - 1], jobs[name]["needs"])
                self.assertIn("accepted_parent", jobs[name]["if"])
        self.assertEqual(jobs["last_receipt"]["with"]["mode"], "verify-only")


if __name__ == "__main__":
    unittest.main()
