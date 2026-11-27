import importlib.util
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock


class SignedSnapshotTest(unittest.TestCase):
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

    def test_unlisted_signed_package_falls_back_only_to_the_fixed_snapshot(self):
        path = "pool/main/e/elfutils/libelf1_0.186-1ubuntu0.1_i386.deb"
        record = ("libelf1", "0.186-1ubuntu0.1", "i386", 55424,
                  "d2afb45a01c2d7cfa7e956741cc0e2502bf5a0b823422d63d1b65b47ad714259")
        for results in (["verified"], ["HTTP 404", "verified"], ["HTTP 404", "HTTP 404", "verified"],
                        ["HTTP 404", "HTTP 404", "HTTP 302"]):
            with self.subTest(results=results), patch.object(self.p, "download", side_effect=results) as fetch:
                result = self.p.acquire((path, record, self.dst))
                self.assertEqual(result is None, results[-1] == "verified")
                self.assertEqual([c.args for c in fetch.call_args_list],
                                 [(host, path, record, self.dst) for host in
                                  ("archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com")[:len(results)]])

    def test_mismatched_receipted_expat_is_rejected_before_transport(self):
        path, record = next(iter(self.p.EXPAT_SNAPSHOT.items()))
        with patch.object(self.p, "download") as fetch:
            with self.assertRaisesRegex(ValueError, "differs from signed APT index"):
                self.p.acquire((path, (*record[:4], "0" * 64), self.dst))
            fetch.assert_not_called()

    def test_missing_or_changed_staged_receipt_cannot_move_to_the_fallback(self):
        recipe = Path(__file__).with_name("recipes") / "fetch_six.sh"
        section = recipe.read_text().split("<<'SIX_VERIFIED_RECEIPTS'\n", 1)[1]
        data = section.split("\nSIX_VERIFIED_RECEIPTS", 1)[0] + "\n"
        path = self.dst.parent / "receipts.json"
        path.write_text(data)
        records = self.p.fixed_receipts(path.parent)
        self.assertEqual(len(records), 6)
        for changed in ({k:v for k,v in list(records.items())[1:]},
                        {k:dict(v,bytes=v["bytes"]+1) for k,v in records.items()}):
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "Different fixed six package receipts"):
                self.p.fixed_receipts(path.parent)

    def test_untrusted_or_different_snapshot_index_cannot_supply_any_fallback(self):
        for trusted, prefix in (("no", self.p.SNAP), ("yes", self.p.SNAP.replace("20261112","20261113"))):
            target = (f"Identifier: Packages\nTrusted: {trusted}\nURI: {prefix}dists/jammy/main/binary-i386/Packages"
                      "\nFilename: /var/lib/apt/lists/packages")
            with self.subTest(trusted=trusted,prefix=prefix), patch.object(self.p, "checked", return_value=target):
                with self.assertRaisesRegex(ValueError, "outside the exact trusted snapshot"):
                    self.p.records_for({})

    def test_alternate_snapshot_url_or_path_cannot_enter_transaction(self):
        path = "pool/main/e/elfutils/libelf1_0.186-1ubuntu0.1_i386.deb"
        def transaction(base, name):
            return f"'{base}{name}' libelf1.deb 55424 SHA256:unused"
        self.assertEqual(self.p.requested(transaction(self.p.SNAP, path)), {path: ("libelf1.deb", 55424)})
        for base, rel in [(self.p.SNAP, "../"+path), (self.p.SNAP, path+"?date=now"),
                          (self.p.SNAP.replace("20261112", "20261113"), path),
                          ("https://other.invalid/ubuntu/", path)]:
            with self.subTest(base=base, rel=rel), self.assertRaisesRegex(ValueError, "Unrecognized package URI"):
                self.p.requested(transaction(base, rel))

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
