"""Run the original pinned GitHub HTTP classification against controlled wire responses."""
from contextlib import ExitStack
import http.client
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import normal as n

ROOT=Path(__file__).resolve().parents[2]


class VisibilityTests(unittest.TestCase):
    def setUp(self):
        stack=ExitStack();self.addCleanup(stack.close)
        root=ROOT if (ROOT/".github/workflows/bare-round26-transport-check.yml").exists() else ROOT/"candidate28"
        temp=Path(stack.enter_context(tempfile.TemporaryDirectory()))
        stack.enter_context(patch.dict(os.environ,GITHUB_WORKSPACE=str(root),RUNNER_TEMP=str(temp)))
        subprocess.run([sys.executable,str(root/"preflight28/transport/prepare.py"),"tools"],check=True,capture_output=True)
        stack.enter_context(patch.object(sys,"path",[str(temp),*sys.path]))
        spec=importlib.util.spec_from_file_location("r28_pinned_anon",temp/"transfer.py")
        self.api=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.api)
        self.epoch=1_795_000_000
        self.mono=100.0
        self.sleeps=[];self.calls=[];self.throttle=[]
        stack.enter_context(patch.object(n.time,"time",side_effect=lambda:self.epoch))
        stack.enter_context(patch.object(n.time,"monotonic",side_effect=lambda:self.mono))
        stack.enter_context(patch.object(n.time,"sleep",side_effect=self.sleep))
        stack.enter_context(patch.object(self.api,"request",side_effect=self.request))
        self.rows=[{"id":i,"size":18,"digest":"sha256:"+str(i)*64,
                    "browser_download_url":f"https://github.com/{n.b.REPO}/releases/download/tag/a{i}"}
                   for i in (1,2)]

    def sleep(self,nsec):
        self.sleeps.append(nsec);self.epoch+=nsec;self.mono+=nsec

    def request(self,host,method,path,**kwargs):
        self.assertEqual(method,"GET");self.assertFalse(kwargs.get("auth"))
        self.calls.append((host,path))
        answer=self.throttle.pop(0) if host==self.api.API and self.throttle else (404,{},None)
        status,headers,body=answer
        payload=json.dumps(body).encode() if body is not None else b""
        packet=(f"HTTP/1.1 {status} Mock\r\nContent-Length: {len(payload)}\r\n"+
                "".join(f"{k}: {v}\r\n" for k,v in headers.items())+"\r\n").encode()+payload
        # A real stdlib HTTP response processes the status, headers and rate JSON.
        class Input:
            def makefile(self,mode):return io.BytesIO(packet)
            def close(self):pass
        conn=Input();r=http.client.HTTPResponse(conn);r.begin()
        return conn,r

    def test_two_distinct_provider_resets_then_private(self):
        start=self.epoch
        self.throttle.extend([(403,{"X-RateLimit-Remaining":"0","X-RateLimit-Reset":str(start+320)},
                               {"message":"API rate limit exceeded for fixture"}),
                              (429,{"Retry-After":"66"},{"message":"You have exceeded a secondary rate limit"})])
        ok,evidence=n.visibility(self.api,self.rows,start+900)
        self.assertTrue(ok);self.assertEqual(self.sleeps,[325,71])
        self.assertEqual([e["direct"] for e in evidence.values()],["404","404"])
        self.assertEqual([e["api"] for e in evidence.values()],["404","404"])
        self.assertEqual(len(self.calls),6)

    def test_deadline_prior_to_reset_and_request_budget(self):
        self.throttle.append((403,{"X-RateLimit-Remaining":"0","X-RateLimit-Reset":str(self.epoch+1798)},
                              {"message":"API rate limit exceeded for fixture"}))
        ok,state=n.visibility(self.api,self.rows,self.epoch+330)
        self.assertFalse(ok);self.assertFalse(self.sleeps)
        self.assertEqual(state[1]["api"],"rate_limited")
        self.assertEqual(state[1]["retry_at"],self.epoch+1803)
        self.assertEqual(state[2]["api"],"not_probed")
        self.assertEqual(state[2]["direct"],"404")
        self.calls.clear()
        ok,state=n.visibility(self.api,self.rows,self.epoch+15)
        self.assertFalse(ok);self.assertFalse(self.calls)
        self.assertEqual(state[1]["direct"],"not_probed")

    def test_forbidden_redirect_or_public_response_never_confirms_private(self):
        for status,headers,body in ((403,{},{"message":"Resource not accessible by integration"}),
                                   (404,{"Location":"https://github.com/anything"},None),(200,{},None)):
            with self.subTest(status=status):
                self.throttle.append((status,headers,body))
                with self.assertRaisesRegex(Exception,"nonredirecting 404"):
                    n.visibility(self.api,self.rows,self.epoch+900)


if __name__=="__main__":unittest.main()
