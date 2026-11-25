"""Real CMS descriptor and a resumed full-body delivery through independent local roles."""
import base64
from contextlib import ExitStack
from datetime import datetime,timezone
import hashlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import tempfile
from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import thaw_read as r


class Draft:
    API="api.github.com"
    BASE="/repos/"+r.b.REPO
    def __init__(self,raw,url):
        self.url=url
        self.deny=[]
        self.rows={}
        self.rows[11]=self.row(11,"p00",raw)
        self.raw=r.thaw.manifest(self.receipt(self.rows[11]))
        self.rows[12]=self.row(12,"manifest.json",self.raw)
    def row(self,aid,suffix,data):
        name=r.thaw.PREFIX+suffix
        return {"id":aid,"name":name,"state":"uploaded","size":len(data),"digest":"sha256:"+hashlib.sha256(data).hexdigest(),
                "browser_download_url":"https://github.com/"+r.b.REPO+"/releases/download/draft-test/"+name}
    def receipt(self,row):
        return dict(id=row["id"],name=row["name"],bytes=row["size"],sha256=row["digest"][7:])
    def draft(self,aid):
        assert aid==r.b.RELEASE
        return {"assets":list(self.rows.values())}
    def asset_info(self,rel,name,size,sha,aid):
        row=self.rows[aid]
        assert row in rel["assets"] and (row["name"],row["size"],row["digest"])==(name,size,"sha256:"+sha)
        return row
    def download(self,aid,size,sha,target):
        assert aid==12 and len(self.raw)==size and hashlib.sha256(self.raw).hexdigest()==sha
        target.write(self.raw)
    def anonymous_status(self,host,path,label):
        self.deny.append((host,path,label))
        return None
    def request(self,host,method,path,*,auth,accept):
        assert (host,method,path,auth,accept)==(self.API,"GET",self.BASE+"/releases/assets/11",True,"application/octet-stream")
        return SimpleNamespace(close=lambda:None), SimpleNamespace(status=302,getheader=lambda *_:self.url)


class ThawReadTests(unittest.TestCase):
    def test_complete_other_host_download_and_rerun(self):
        self.full_delivery(False)

    def test_published_only_full_read(self):
        self.full_delivery(True)

    def full_delivery(self,replay):
        with tempfile.TemporaryDirectory() as td, ExitStack() as stack:
            top=Path(td)
            data=random.Random(39).randbytes(3*r.CHUNK+44)
            sha=hashlib.sha256(data).hexdigest()
            stamp=datetime.fromtimestamp(int(time.time())+1800,timezone.utc).isoformat().replace('+00:00','Z')
            address="https://release-assets.githubusercontent.com/part?se="+stamp
            head="5"*40; run=99999999999
            event=top/"event"
            event.write_text(json.dumps({"number":9,"pull_request":{"number":9,"head":{"repo":{"id":1450926240},
                "ref":"work-bare-27-storage-check","sha":head},"base":{"repo":{"id":1450926240},"ref":"bare-coexist-v2.0.4",
                "sha":"bf70ddbf474f3390a62220a076b8c43347fecc64"}},"action":"synchronize","after":head,
                "repository":{"id":1450926240},"sender":{"id":292261483}}))
            env={"GITHUB_ACTOR":"Areal-U","GITHUB_TRIGGERING_ACTOR":"Areal-U","GITHUB_EVENT_PATH":str(event),"TRIAL_SHA":head,
                 "GITHUB_RUN_ID":str(run),"GITHUB_RUN_ATTEMPT":"1","GITHUB_REPOSITORY":r.b.REPO,
                 "GITHUB_OUTPUT":str(top/"out"),"GITHUB_TOKEN":"","GH_TOKEN":"test-read-only"}
            stack.enter_context(patch.dict(os.environ,env))
            stack.enter_context(patch.object(r.thaw,"SIZE",len(data)))
            stack.enter_context(patch.object(r.thaw,"SHA",sha))
            stack.enter_context(patch.dict(r.thaw.HISTORY,bytes=len(data),sha256=sha))
            api=Draft(data,address)
            stack.enter_context(patch.object(r.thaw,"private",return_value=api))
            gates=[]
            if replay:
                import anon_peer
                os.environ["R28_RESUME_PUBLISHED"]="45522666298"
                stack.enter_context(patch.object(anon_peer,"sample",return_value={"ids":[]}))
                stack.enter_context(patch.object(r,"published_gate",side_effect=lambda:gates.append("published-only")))
            stack.enter_context(patch.object(r.thaw,"gate",side_effect=gates.append))
            reverse=top/"ordinary";issuer=top/"issuer";reverse.mkdir();issuer.mkdir()
            def role(name):
                os.environ["GITHUB_JOB"]=name
                r.thaw.TEMP=reverse if name=="receive" else issuer
                r.ROOT=r.thaw.TEMP/"r28-thaw"
            self.addCleanup(setattr,r.thaw,"TEMP",r.thaw.TEMP)
            self.addCleanup(setattr,r,"ROOT",r.ROOT)
            def service(path,expected=200):
                if expected=="denied":
                    self.assertEqual(os.environ["GITHUB_JOB"],"receive")
                    self.assertTrue(path.endswith(f"/releases/{r.b.RELEASE}"))
                    return {}
                c=r.scope()
                if "/jobs?" in path:
                    return {"total_count":1,"jobs":[{"name":r.READER,"status":"in_progress","conclusion":None,
                        "run_id":run,"run_attempt":c["attempt"],"head_sha":head,
                        "steps":[{"name":"Deposit receiver-key for this exact recovery","status":"completed","conclusion":"success"}]}]}
                row={"name":r.label(c,"key"),"id":33,"size_in_bytes":1800,
                     "workflow_run":{"id":run,"head_sha":head},"expired":False,"expires_at":"test","digest":"sha256:"+"f"*64}
                if "/artifacts?" in path:
                    return {"total_count":1,"artifacts":[row]}
                if path.endswith("/artifacts/33"):
                    return row
                return {"id":run,"run_attempt":int(os.environ["GITHUB_RUN_ATTEMPT"]),"head_sha":head,"path":r.WORKFLOW,
                        "status":"in_progress","repository":{"id":1450926240},"actor":{"id":292261483}}
            stack.enter_context(patch.object(r.b,"api_json",side_effect=service))
            os.environ["MANIFEST_ID"]="12"; os.environ["MANIFEST_SHA"]=hashlib.sha256(api.raw).hexdigest()
            role("receive");r.key()
            role("issue");r.wait("key")
            (r.ROOT/"incoming").mkdir(parents=True,mode=0o700)
            for f in ("public.pem","holder.json"):shutil.copyfile(reverse/"r28-thaw"/f,r.ROOT/"incoming"/f)
            r.issue()
            self.assertEqual(gates,["published-only"] if replay else ["verify"]);self.assertEqual(len(api.deny),4)
            encrypted=(r.ROOT/"descriptor.cms").read_bytes()
            self.assertNotIn(b"release-assets.github",encrypted)
            self.assertNotIn(b"se=",encrypted)
            role("receive")
            (r.ROOT/"incoming").mkdir()
            (r.ROOT/"incoming/descriptor.cms").write_bytes(encrypted)
            with self.assertRaisesRegex(r.Rejected,"Credential"):r.read()
            os.environ["GH_TOKEN"]=""
            with patch.dict(os.environ,MANIFEST_ID="9"),self.assertRaisesRegex(r.Rejected,"Different issued"):r.read()
            with patch.dict(os.environ,GITHUB_RUN_ATTEMPT="2"),self.assertRaisesRegex(r.Rejected,"different receiver"):r.read()
            transfers=[]
            class CDN:
                def __init__(self,host,timeout):
                    assert host=="release-assets.githubusercontent.com" and timeout==60
                def request(self,method,path,headers):
                    assert method=="GET" and set(headers)=={"User-Agent","Range","Accept-Encoding"} and "se=" in path
                    assert headers["Accept-Encoding"]=="identity"
                    self.start=int(headers["Range"].split("=")[1].split("-")[0]);transfers.append(self.start)
                def getresponse(self):
                    class Reply(io.BytesIO):
                        status=206
                        def getheader(this,name,default=None):
                            return {"Content-Range":f"bytes {self.start}-{len(data)-1}/{len(data)}",
                                    "Content-Length":str(len(data)-self.start)}.get(name,default)
                    return Reply(data[self.start:self.start+r.CHUNK] if len(transfers)==1 else data[self.start:])
                def close(self):pass
            stack.enter_context(patch.object(r.http.client,"HTTPSConnection",CDN))
            stack.enter_context(patch.object(r.os,"statvfs",return_value=SimpleNamespace(f_bavail=30*1024**3,
                                                                                       f_frsize=1,f_favail=2_000_000)))
            r.read()
            self.assertEqual(transfers,[0,r.CHUNK]);self.assertEqual((reverse/"r28-child.tar.zst").read_bytes(),data)
            self.assertEqual((reverse/"r28-child.json").read_bytes(),api.raw)
            with patch.dict(os.environ,GITHUB_RUN_ATTEMPT="2",MANIFEST_ID="",MANIFEST_SHA=""):
                r.manifest_inputs(api.receipt(api.rows[12]),2)
                with self.assertRaisesRegex(r.Rejected,"Different issued"):
                    r.manifest_inputs(api.receipt(api.rows[12]),1)

    def test_short_expiry_and_incorrect_host(self):
        past="https://release-assets.githubusercontent.com/p?se=2000-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError,"Expired"):
            r.expires(past)
        with self.assertRaisesRegex(ValueError,"endpoint"):
            r.expires("https://example.org/p?se=2030-01-01T00:00:00Z")
        with self.assertRaisesRegex(ValueError,"lifetime"):
            r.expires("https://objects.githubusercontent.com/p?bad=query")


if __name__=="__main__":
    unittest.main(verbosity=2)
