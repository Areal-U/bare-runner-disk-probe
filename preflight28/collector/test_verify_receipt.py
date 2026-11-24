import copy
import hashlib
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from verify_receipt import ReceiptError, verify_owner, verify_source


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.data = Path(temp.name) / "cipher"
        self.data.write_bytes(b"test encrypted payload")
        self.sha = hashlib.sha256(self.data.read_bytes()).hexdigest()
        self.repo = {"full_name": "example/test"}
        self.head = "a" * 40
        self.ticket = {"operation": "trial", "expected": {
            "repository": "example/test", "pull_request": 9, "source_branch": "trial-branch",
            "workflow": "test.yml", "run_name": "trial", "initial_attempt": 1,
            "head_sha": self.head, "artifact_name": "receipt-<run_id>-<attempt>"}}
        self.run = {"id": 55, "run_attempt": 1, "display_title": "trial", "event": "pull_request",
                    "repository": self.repo, "head_repository": self.repo, "head_sha": self.head,
                    "head_branch": "trial-branch", "pull_requests": [{"number": 9}],
                    "path": ".github/workflows/test.yml", "status": "completed", "conclusion": "success"}
        self.job = {"run_attempt": 1, "run_id": 55, "id": 123, "conclusion": "success"}
        self.asset = {"id": 66, "name": "receipt-55-1", "expired": False,
                      "expires_at": "2026-11-25T05:00:00Z",
                      "workflow_run": {"id": 55, "head_sha": self.head}}
        self.reported = {"operation": "trial", "run_id": 55, "attempt": 1, "head_sha": self.head,
                         "artifact_id": 66, "cipher_sha256": self.sha, "clear_sha256": "b" * 64,
                         "cipher_bytes": self.data.stat().st_size}
        self.now = datetime(2026, 11, 25, 1, 0, tzinfo=timezone.utc)

    def source(self):
        return verify_source(self.ticket, self.run, self.job, self.asset, self.reported,
                             self.data, self.now)

    def test_registered_only(self):
        self.assertEqual(self.source()["job_id"], 123)
        self.assertFalse(self.source()["backup_urgent"])

    def test_near_expiry_is_urgent(self):
        self.now = self.now.replace(hour=3)
        self.assertTrue(self.source()["backup_urgent"])

    def test_conflicting_records_fail(self):
        for record, field, bad in [
            (self.reported, "artifact_id", 18), (self.run, "pull_requests", []),
            (self.run, "head_repository", {"full_name": "other/fork"}),
            (self.run, "run_attempt", 2), (self.run, "head_sha", "b"*40),
            (self.job, "run_id", 56), (self.asset, "expired", True),
            (self.reported, "cipher_sha256", "0"*64), (self.reported, "attempt", 2),
            (self.asset, "expires_at", "2026-11-25T01:00:00Z")]:
            with self.subTest(field=field):
                before = record[field]
                record[field] = bad
                with self.assertRaises(ReceiptError):
                    self.source()
                record[field] = before

    def test_controller_only_file_is_not_owner_receipt(self):
        self.ticket["destination"] = {
            "allocated_file_id": "fixed", "owned_folder": "/個人用ソフト", "account_id": "personal",
            "completed_filename": "TEST-ONLY.apk", "expected_pending_version": 0}
        item = {"library_file_id": "fixed", "file_id": "backing", "kind": "file", "surface": "library",
                "path": "/個人用ソフト/TEST-ONLY.apk", "size_bytes": self.data.stat().st_size,
                "version_id": 1, "is_shared": False}
        publication = {"version": 1, "library_file_id": "fixed", "file_id": "backing",
                       "signed_sha256": self.sha, "certificate_sha256": "d"*64}
        for change in ({"is_shared": True}, {"version_id": 0}, {"file_id": "wrong"},
                       {"path": "/agent-only/TEST-ONLY.apk"}, {"library_file_id": "other"}):
            with self.subTest(change=change):
                candidate = dict(copy.copy(item), **change)
                with self.assertRaises(ReceiptError):
                    verify_owner(self.ticket, {"surface": "library", "items": [candidate]},
                                 publication, self.data, Path("/unused-for-negative-test.jar"))


if __name__ == "__main__":
    unittest.main()
