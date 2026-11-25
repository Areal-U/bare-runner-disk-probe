"""Immutable exact-ID ZIP route, including the transient split visibility regression."""
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

os.environ.setdefault("RUNNER_TEMP", tempfile.gettempdir())
import trial
from trial import rest_zip


def make_zip(files):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_STORED) as z:
        for name, contents in files:
            z.writestr(name, contents)
    return out.getvalue()


class Response:
    def __init__(self, status, body=b"", **headers):
        self.status = status
        self.headers = headers
        self.io = io.BytesIO(body)

    def getheader(self, name):
        return self.headers.get(name)

    def read1(self, n):
        return self.io.read(n)


class ExactArchive(unittest.TestCase):
    def setUp(self):
        self.data = make_zip([("ticket.json", b'{"test":true}')])
        self.row = dict(id=15008017363, size_in_bytes=len(self.data),
                        name="bare-next-rx-10-a1-delayed-ticket", expires_at="2099-11-26T09:21:39Z",
                        expired=False, digest="sha256:" + hashlib.sha256(self.data).hexdigest())
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        env = patch.dict(os.environ, {"GH_TOKEN":"fixture-token","GITHUB_RUN_ID":"10"})
        env.start()
        self.addCleanup(env.stop)
        b = patch.object(trial,"binding",return_value={"run":10,"head":"a"*40})
        b.start()
        self.addCleanup(b.stop)
        p = patch.object(trial,"ROOT",Path(self.root.name))
        p.start()
        self.addCleanup(p.stop)
        self.requests = []

    def clients(self, responses):
        parent = self
        class Client:
            def __init__(self, host, timeout):
                self.host = host
                self.sock = None
            def request(self, method, path, headers):
                parent.requests.append((self.host,path,dict(headers)))
            def getresponse(self):
                return responses.pop(0)
            def close(self):
                pass
        return patch.object(rest_zip.http.client,"HTTPSConnection",Client)

    @staticmethod
    def redirect():
        return Response(302, Location="https://productionresultssa1.blob.core.windows.net/test/path?sig=test")

    def fetch(self, getrow=None, **kw):
        trial.lookup("delayed", "ticket", wait=.4, pause=.001, lookup_artifact=getrow or
                     (lambda *a, **k: self.row), **kw)

    def test_delayed_publication_and_rest_get_exact_id(self):
        rows = iter([None,self.row,self.row,self.row])
        with self.clients([Response(404),self.redirect(),Response(503),self.redirect(),Response(200,self.data)]):
            self.fetch(lambda *a,**k: next(rows), expected_id=self.row["id"])
        self.assertEqual((trial.ROOT / "ticket/ticket.json").read_bytes(), b'{"test":true}')
        for host, path, headers in self.requests:
            if host == "api.github.com":
                self.assertEqual(path,f"/repos/{trial.bridge.REPO}/actions/artifacts/{self.row['id']}/zip")
                self.assertEqual(headers["Authorization"],"Bearer fixture-token")
            else:
                self.assertEqual(host,"productionresultssa1.blob.core.windows.net")
                self.assertNotIn("Authorization",headers)

    def test_payload_mismatch_or_wrong_member_is_never_installed(self):
        with self.clients([self.redirect(),Response(200,b"X"+self.data[1:])]):
            with self.assertRaisesRegex(ValueError,"digest mismatch"):
                self.fetch()
        with self.assertRaisesRegex(ValueError,"members"):
            rest_zip.unpack(make_zip([("../malicious",b"x")]),trial.ROOT/"ticket",{"ticket.json"},1024)
        self.assertFalse((trial.ROOT/"ticket").exists())
        with self.assertRaisesRegex(ValueError,"members"):
            rest_zip.unpack(self.data,trial.ROOT/"ticket",{"ticket.json"},4)

    def test_cross_host_and_mutated_or_foreign_id_rejected(self):
        with self.clients([Response(302,Location="https://productionresultssa.blob.core.windows.net.evil.example/?sig=t")]):
            with self.assertRaisesRegex(ValueError,"redirect"): self.fetch()
        with self.assertRaisesRegex(ValueError,"identity changed"):
            self.fetch(expected_id=1234)
        with self.clients([Response(404)]):
            rows = iter([self.row,{**self.row,"id":self.row["id"]+1}])
            with self.assertRaisesRegex(ValueError,"identity changed"):
                self.fetch(lambda *a,**kw: next(rows))
        self.assertFalse((trial.ROOT/"ticket").exists())

    def test_permanently_missing_zip_stops_at_deadline(self):
        attempts = []
        def missing(row, deadline):
            attempts.append(row["id"])
            raise trial.bridge.TransientReadError("404")
        with self.assertRaises(TimeoutError):
            trial.lookup("delayed", "ticket", wait=.03, pause=.002, lookup_artifact=lambda *a,**k:self.row, read_zip=missing)
        self.assertTrue(len(attempts)>1)
        self.assertEqual(set(attempts),{self.row["id"]})
        self.assertFalse((trial.ROOT/"ticket").exists())

if __name__=="__main__":
    unittest.main()
