import importlib.util
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock


class ExactExpatSnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        recipe = Path(__file__).with_name("recipes") / "install_six.sh"
        subprocess.run(["bash", str(recipe)], check=True, env=dict(os.environ, RUNNER_TEMP=str(folder)))
        spec = importlib.util.spec_from_file_location("pinned", folder / "round26-pool-install.py")
        self.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.p)
        self.dst = folder / "download.deb"

    def test_signed_two_records_may_use_same_snapshot_after_public_pool_failure(self):
        for path, record in self.p.EXPAT_SNAPSHOT.items():
            with self.subTest(path=path):
                with patch.object(self.p, "download", side_effect=["HTTP 404", "HTTP 404", "verified"]) as fetch:
                    self.assertIsNone(self.p.acquire((path, record, self.dst)))
                self.assertEqual([c.args[0] for c in fetch.call_args_list],
                                 ["archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com"])

    def test_other_package_stays_on_original_two_pools_and_mismatched_record_is_rejected(self):
        path, record = next(iter(self.p.EXPAT_SNAPSHOT.items()))
        with patch.object(self.p, "download", side_effect=["HTTP 404", "HTTP 404"]) as fetch:
            self.assertIsNotNone(self.p.acquire(("pool/main/o/other/other.deb", record, self.dst)))
            self.assertEqual(fetch.call_count, 2)
        with patch.object(self.p, "download") as fetch:
            with self.assertRaisesRegex(ValueError, "differs from signed APT index"):
                self.p.acquire((path, (*record[:4], "0" * 64), self.dst))
            fetch.assert_not_called()

    def test_wrong_bytes_at_the_allowed_url_cannot_pass(self):
        path, record = next(iter(self.p.EXPAT_SNAPSHOT.items()))
        conn = MagicMock()
        response = conn.getresponse.return_value
        response.status = 200
        response.read.side_effect = [b"x" * record[3], b""]
        with patch.object(self.p.http.client, "HTTPSConnection", return_value=conn):
            with self.assertRaisesRegex(ValueError, "Size/SHA256 mismatch"):
                self.p.download("snapshot.ubuntu.com", path, record, self.dst)
        self.assertEqual(conn.request.call_args.args[:2], ("GET", "/ubuntu/20261112T093000Z/" + path))
