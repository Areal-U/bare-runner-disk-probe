import gzip
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "signing"))
from label_baseline import (LABEL, manifest_entry, ORIGINAL_CONTENT, PERSONAL_SHA, S1_SHA, S1_PROOF_SHA, UPSTREAM_SHA, activate,
                            certificate, job_identity, match_lineage, record_successor, restore_source)
from segment_graph import load, write_record


class LabelLineageTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "checkpoint").mkdir()
        self.out = self.root / "out/Bare"
        self.out.mkdir(parents=True)
        self.cert = {"trial_run_id": 10, "raw_sha256": "1" * 64, "optimized_sha256": "2" * 64}
        evidence = dict(parent_sha256=S1_SHA, old_pending=1911, remaining=1911, resource_sha256="1" * 64,
                        optimized_sha256="2" * 64, retained={"files": 3, "sha256": "3" * 64})
        self.lineage = dict(version=1, run=20, head="c" * 40, original=S1_SHA, certificate_sha256="4" * 64,
                            trial=10, old_content=ORIGINAL_CONTENT, new_content=evidence["retained"],
                            original_baseline_sha256="5" * 64, new_baseline_sha256="6" * 64, evidence=evidence,
                            evidence_sha256=hashlib.sha256(json.dumps(evidence, sort_keys=True,
                            separators=(",", ":")).encode("ascii")).hexdigest())

    def test_unaccepted_cert_and_consumed_runs_refused(self):
        write_record(self.root / "label_trial_certificate.json", {"status": "awaiting-independent-resource-trial"})
        with self.assertRaisesRegex(ValueError, "no reviewed acceptance"):
            certificate(self.root)
        for run in (45771045621, 45841492691):
            with self.assertRaisesRegex(ValueError, "Unexpected production"):
                job_identity({"GITHUB_RUN_ID": str(run), "SEGMENT_ORDINAL": "2", "GITHUB_SHA": "c" * 40})

    def test_successor_carries_actual_transition_and_restores_corrected_input(self):
        data = self.root / "checkpoint"
        write_record(data / "label-lineage.json", self.lineage)
        write_record(data / "provenance-check.json", {"matched": True})
        record_successor(self.root, self.cert, "4" * 64, 20, 2, "c" * 40)
        receipt = load(data / "provenance-check.json")
        self.assertTrue(receipt["matched"])
        self.assertEqual(receipt["personal_label"]["lineage"]["evidence"], self.lineage["evidence"])
        write_record(self.out / "checkpoint-source-verification.json", receipt)
        (data / "label-lineage.json").unlink()
        with patch("label_baseline.check_material"), patch("label_baseline.manifest_entry"), patch("label_baseline.prepare",
                return_value={"before": UPSTREAM_SHA, "after": PERSONAL_SHA}) as apply:
            restore_source(self.out, self.root, self.cert, "4" * 64, 20, 3, "c" * 40)
            apply.assert_called_once()
        self.assertEqual(load(data / "label-lineage.json"), self.lineage)

    def test_lost_evidence_wrong_run_and_wrong_slot_refused_before_source_change(self):
        write_record(self.out / "checkpoint-source-verification.json",
                     {"personal_label": {"producer_slot": 2, "lineage": self.lineage}})
        with patch("label_baseline.prepare") as apply:
            for run, slot in [(20, 4), (21, 3)]:
                with self.assertRaises(ValueError):
                    restore_source(self.out, self.root, self.cert, "4" * 64, run, slot, "c" * 40)
            apply.assert_not_called()
        del self.lineage["evidence"]
        with self.assertRaises(ValueError):
            match_lineage(self.lineage, self.cert, "4" * 64, 20, "c" * 40)

    def test_unapproved_final_resource_digest_is_rejected(self):
        self.lineage["evidence"]["optimized_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "Wrong or absent migration"):
            match_lineage(self.lineage, self.cert, "4" * 64, 20, "c" * 40)

    def test_stale_or_duplicate_record_refused_even_if_other_restoration_steps_skip_it(self):
        rows = self.out / "checkpoint-inputs.jsonl.gz"
        def write(*digests):
            header = {"roots": {"src": "/work/chromium/src"}}
            with gzip.open(rows, "wt") as output:
                output.write(json.dumps(header) + "\n")
                for digest in digests:
                    output.write(json.dumps(dict(root="src", path=str(LABEL), mtime_ns=123,
                                                 type="file", sha256=digest)) + "\n")
        write(PERSONAL_SHA)
        self.assertEqual(manifest_entry(self.out, PERSONAL_SHA)["mtime_ns"], 123)
        for wrong in [(UPSTREAM_SHA,), (UPSTREAM_SHA, PERSONAL_SHA), (PERSONAL_SHA, PERSONAL_SHA), ()]:
            write(*wrong)
            with self.assertRaisesRegex(ValueError, "does not attest"):
                manifest_entry(self.out, PERSONAL_SHA)

    def test_baseline_swap_preserves_old_file_and_rejects_mismatched_new_plan(self):
        # Exercise the on-disk transition itself. Material verification is covered
        # by the independent resource run. Commitments below stand in for 324262 files.
        from graph import sha as real_sha
        plan = {f"{i:064x}": [f"{i}.o"] for i in range(1911)}
        data = self.root / "checkpoint"
        live = data / "segment-before.json"
        proposal = data / "segment-after-label.json"
        proof = self.out / "checkpoint-segment-frontier.json"
        write_record(proof, {"after": list(plan), "child_content": ORIGINAL_CONTENT})
        old = dict(parent_sha256=S1_SHA, format="test", graph="graph", target="chrome_public_apk",
                   planned_groups=plan, files={"old": 1})
        newer = dict(old, files={"new": 2})
        changed_content = self.lineage["new_content"]
        result = dict(self.lineage["evidence"], mode="prepare",
                      source={"before": UPSTREAM_SHA, "after": PERSONAL_SHA}, additional_pending=[])
        write_record(data / "label-resource-migration.json", result)
        write_record(live, old)
        before = real_sha(live)
        def digest(path):
            return S1_PROOF_SHA if path == proof else real_sha(path)
        def inventory_digest(files):
            return {("old",): ORIGINAL_CONTENT, ("new",): changed_content}[tuple(files)]
        with patch("label_baseline.check_material"), patch("label_baseline.sha", digest), \
             patch("label_baseline.commitment", inventory_digest):
            write_record(proposal, dict(newer, planned_groups={}))
            with self.assertRaisesRegex(ValueError, "Unverified migration"):
                activate(self.out, self.root, self.cert, "4" * 64, 20, "c" * 40)
            self.assertEqual(real_sha(live), before)
            write_record(proposal, newer)
            activate(self.out, self.root, self.cert, "4" * 64, 20, "c" * 40)
            self.assertEqual(load(live), newer)
            self.assertEqual(real_sha(data / "segment-before-original-s1.json"), before)
            self.assertEqual(load(data / "label-lineage.json")["evidence"], result)
