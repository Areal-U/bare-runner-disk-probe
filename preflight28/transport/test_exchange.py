"""Exercise the live send/receive code without GitHub, keys or real checkpoints."""
import hashlib
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch


def digest(data):
    return hashlib.sha256(data).hexdigest()

class TransportTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        e = patch.dict(os.environ, RUNNER_TEMP=temp.name, GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
                       TRIAL_SHA="9"*40, GITHUB_OUTPUT=temp.name+"/outputs", MANIFEST_ID="", MANIFEST_SHA="")
        e.start()
        self.addCleanup(e.stop)
        self.rows = []
        self.payload = {}
        self.dropped = True
        helper = types.SimpleNamespace(RELEASE_ID=452114666, BASE="/repos/repo", UPLOAD="uploads", http=__import__("http"))
        self.modules = patch.dict(sys.modules, transfer=helper)
        self.modules.start()
        self.addCleanup(self.modules.stop)
        spec = importlib.util.spec_from_file_location("r28_exchange_tested", Path(__file__).with_name("exchange.py"))
        self.job = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.job)
        self.job.PART = 7
        self.job.source = lambda: None
        self.job.anonymous = lambda row: None
        helper.draft = lambda release_id: {"assets": self.rows}
        helper.asset_info = self.asset_info
        helper.request = self.request
        helper.download = self.download
        helper.sha256_file = lambda path: digest(path.read_bytes())
        self.raw = b"some checkpoint"
        self.file = self.root/"r28-child.tar.zst"
        self.file.write_bytes(self.raw)
        f = self.root/"bare-official/exchange/checkpoint"
        f.mkdir(parents=True)
        (f/"graph-sha.txt").write_text("a"*64)
        (f/"child-provenance.json").write_text(json.dumps({"identity_sha256":"b"*64}))

    def request(self, domain, method, path, **kw):
        name = path.split("name=")[-1]
        data = b"".join(iter(lambda: kw["body"].read(4), b""))
        self.assertEqual(len(data), kw["length"])
        row = {"id": 30 + len(self.rows), "name":name, "size":len(data), "digest":"sha256:"+digest(data), "state":"uploaded"}
        self.rows.append(row)
        self.payload[row["id"]] = data
        if self.dropped:
            self.dropped = False
            raise ConnectionResetError("lost POST acknowledgement")
        return io.BytesIO(), types.SimpleNamespace(status=201, read=lambda n:b"")

    def asset_info(self, release, name, size, sha, id_=None):
        matches = [r for r in release["assets"] if r["name"]==name]
        if len(matches)!=1:
            raise ValueError("ambiguous")
        row=matches[0]
        if not (row["state"]=="uploaded" and row["size"]==size and row["digest"]=="sha256:"+sha and id_ in (None,row["id"])):
            raise ValueError("conflicting receipt")
        return row

    def download(self, id_, size, sha, sink):
        raw = self.payload[id_]
        if len(raw)!=size or digest(raw)!=sha:
            raise ValueError("download mismatch")
        sink.write(raw)

    def test_multipart_lost_ack_then_replayed_send_and_independent_receive(self):
        self.job.send()
        self.assertEqual(len(self.rows),4)
        self.job.send()
        self.assertEqual(len(self.rows),4)
        self.file.unlink()
        self.job.receive()
        self.assertEqual(self.file.read_bytes(),self.raw)
        self.assertEqual(json.loads((self.root/"r28-child.json").read_text())["producer_attempt"],1)

    def test_starter_untouched(self):
        self.rows.append(dict(name=self.job.prefix()+"p00",id=1,state="starter",size=0,digest=None))
        self.job.send()
        self.assertEqual(self.rows[0]["state"],"starter")
        self.assertEqual(self.rows[1]["name"],self.job.prefix()+"p00-retry1")

    def test_corrupt_received_object_rejected(self):
        self.job.send()
        self.payload[self.rows[0]["id"]]=b"x"
        self.file.unlink()
        with self.assertRaisesRegex(ValueError,"download mismatch"):
            self.job.receive()
        self.assertFalse((self.root/"r28-child.json").exists())

    def test_reject_retry_writer(self):
        os.environ["GITHUB_RUN_ATTEMPT"]="2"
        with self.assertRaisesRegex(ValueError,"initial attempt"):
            self.job.send()
        self.assertEqual(self.rows,[])

if __name__=="__main__":
    unittest.main()
