"""Real CMS plus controlled in-memory object transport for the split-job contract."""
import contextlib
import hashlib
import http.client
import io
import os
from pathlib import Path
import subprocess
import tempfile
import time
from unittest.mock import patch
import unittest

os.environ.setdefault("RUNNER_TEMP","/tmp")
import bridge
import compiler_fixture


class Response(io.BytesIO):
    def __init__(self,payload=b"",status=200):
        super().__init__(payload)
        self.status=status

    def getheader(self,name,default=""):
        return "https://release-assets.githubusercontent.com/example/one?trial=sample"


class SplitTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name)
        self.ordinary=root/"ordinary";self.writer=root/"limited"
        self.ordinary.mkdir();self.writer.mkdir()
        self.at=self.ordinary
        env=patch.dict(os.environ,GITHUB_JOB="ordinary",GITHUB_RUN_ID="42",SOURCE_MANIFEST_ID="7",SOURCE_MANIFEST_SHA="1"*64)
        env.start();self.addCleanup(env.stop)
        self.payload=os.urandom(1500000)
        digest=hashlib.sha256(self.payload).hexdigest()
        self.manifest={"bytes":len(self.payload),"sha256":digest,"parts":[{"id":11,"bytes":len(self.payload),"sha256":digest}]}

    def move(self,which):
        bridge.ROOT=which
        os.environ["GITHUB_JOB"]="ordinary" if which==self.ordinary else "limited"
        (which/"incoming").mkdir(exist_ok=True)

    def test_complete_and_corrupt(self):
        with patch.object(bridge,"get_source",return_value=self.manifest), patch.object(bridge,"disk"), patch.object(bridge,"inventory"):
            self.move(self.ordinary);bridge.keygen()
            self.move(self.writer);bridge.keygen()
            (self.writer/"incoming/public.pem").write_bytes((self.ordinary/"public.pem").read_bytes())
            class Private:
                API="api.github.com";BASE="/repos/Areal-U/bare-runner-disk-probe"
                def request(o,host,meth,path,auth=False,accept=""):
                    self.assertTrue(auth);self.assertEqual(host,o.API)
                    return io.BytesIO(), Response(status=302)
                def download(o,id_,size,digest,sink):
                    self.assertEqual(id_,11);sink.write(self.payload)
            with patch.object(bridge,"auth_api",return_value=Private()):
                bridge.issue()
                self.move(self.ordinary)
                sealed=(self.writer/"input.cms").read_bytes()
                self.assertNotIn(b"release-assets.githubusercontent",sealed)
                (self.ordinary/"incoming/input.cms").write_bytes(sealed)
                class Public:
                    def __init__(o,host,timeout):
                        self.assertEqual(host,"release-assets.githubusercontent.com")
                    def request(o,m,p,headers):
                        self.assertNotIn("Authorization",headers)
                    def getresponse(o):return Response(self.payload)
                    def close(o):pass
                with patch.object(http.client,"HTTPSConnection",Public):
                    bridge.acquire()
                bridge.seal(self.ordinary/"checkpoint.tar.zst")
                compiler_fixture.produce()
                self.move(self.writer)
                for n in ["checkpoint.cms","fixture.cms","cipher-receipt.json"]:
                    (self.writer/"incoming"/n).write_bytes((self.ordinary/n).read_bytes())
                compiler_fixture.receive()
                self.assertEqual((self.writer/"received.o").read_bytes(),(self.ordinary/"worker.o").read_bytes())
                bridge.accepted()
                self.assertEqual((self.writer/"restored.tar.zst").read_bytes(),self.payload)
                self.assertNotEqual((self.writer/"public.pem").read_bytes(),(self.ordinary/"public.pem").read_bytes())
                # Tampered ciphertext and different recipient both fail real CMS authentication.
                e=self.writer/"incoming/checkpoint.cms"
                data=e.read_bytes();middle=len(data)//2
                e.write_bytes(data[:middle]+bytes([data[middle]^1])+data[middle+1:])
                with self.assertRaises((subprocess.CalledProcessError,ValueError)):
                    bridge.decrypt(e,self.writer/"tampered")
                self.move(self.ordinary)
                with self.assertRaises(subprocess.CalledProcessError):
                    bridge.decrypt(self.ordinary/"checkpoint.cms",self.ordinary/"wrong-key")
            
if __name__=="__main__":
    unittest.main()
