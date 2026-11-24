"""Two real CMS keypairs, immutable test generation, simulated authenticated Draft I/O."""
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs,urlsplit

os.environ.setdefault("RUNNER_TEMP","/tmp")
import normal as n
import bridge as b


class LocalDraft:
    API="api.github.com";UPLOAD="uploads.github.com";BASE="/repos/Areal-U/bare-runner-disk-probe"
    def __init__(self):self.assets=[];self.data={};self.lost=True
    def draft(self,rid):
        assert rid==b.RELEASE
        return {"assets":self.assets}
    def request(self,host,method,path,**kwargs):
        if method=="POST":
            name=parse_qs(urlsplit(path).query)["name"][0]
            data=b"".join(iter(lambda:kwargs["body"].read(65536),b""))
            assert len(data)==kwargs["length"] and kwargs["auth"] and host==self.UPLOAD
            row={"name":name,"state":"uploaded","id":len(self.assets)+81,"size":len(data),
                 "digest":"sha256:"+hashlib.sha256(data).hexdigest(),
                 "browser_download_url":"https://github.com/"+b.REPO+"/releases/download/test/"+name}
            self.assets.append(row);self.data[row["id"]]=data
            if self.lost:self.lost=False;raise ConnectionResetError("ack dropped")
            class Created(io.BytesIO):status=201
            return io.BytesIO(),Created()
        assert method=="GET" and host==self.API and kwargs["auth"]
        class Redirect:
            status=302
            def getheader(self,k,default=""):
                return f"https://release-assets.githubusercontent.com/object/{path.rsplit('/',1)[-1]}?fixture=1"
        return io.BytesIO(),Redirect()
    def asset_info(self,r,name,length,digest,id_):
        matches=[a for a in r["assets"] if a["name"]==name and a["id"]==id_ and a["size"]==length and a["digest"]=="sha256:"+digest]
        assert len(matches)==1
        return matches[0]
    def anonymous_status(self,host,path,label):
        assert host in ("api.github.com","github.com")
    def download(self,id_,n,sha,dest):
        raw=self.data[id_];assert len(raw)==n and hashlib.sha256(raw).hexdigest()==sha
        dest.write(raw)


class TestTransport(unittest.TestCase):
    def test_generation_and_recovery(self):
        with tempfile.TemporaryDirectory() as tmp,patch.dict(os.environ,
             GITHUB_REPOSITORY=b.REPO,GITHUB_RUN_ID="1234",GITHUB_RUN_ATTEMPT="1",R28_SLOT="1",
             R28_PARENT_SHA=n.PARENT["sha"],R28_PARENT_IDENTITY=n.PARENT["identity"],R28_HEAD_SHA="5"*40,
             GITHUB_OUTPUT=str(Path(tmp)/"outputs")),patch.object(b,"disk"):
            work=Path(tmp)
            api=LocalDraft()
            with patch.object(b,"auth_api",return_value=api),patch.object(n,"PART",1_000_000):
                def role(name,num):
                    os.environ["GITHUB_JOB"]=name
                    n.ROOT=b.ROOT=work/(name+str(num))
                def newkeys(num):
                    for i,key in enumerate(("ordinary","limited")):
                        role(key,num);n.keygen(key,11+i)
                        (n.ROOT/"incoming").mkdir()
                def copy_peer(num,key,to,files):
                    for file in files:
                        (work/(to+str(num))/"incoming"/file).write_bytes((work/(key+str(num))/file).read_bytes())
                def issue_slot(num):
                    newkeys(num);copy_peer(num,"ordinary","limited",["public.pem","holder.json"])
                    role("limited",num);n.issue()
                    copy_peer(num,"limited","ordinary",["input.cms"])
                issue_slot(1)
                role("ordinary",1);n.acquire()
                sys.path.insert(0,str(Path(n.__file__).resolve().parents[2]))
                import checkpoint
                src=work/"fixture";out=src/"out/Bare";out.mkdir(parents=True)
                (out/"apks").mkdir()
                (out/"apks/Trichrome.ssargs").write_text("--test\n")
                (out/"build.ninja.d").write_text("build.ninja.stamp: apks/Trichrome.ssargs ../../DEPS\n")
                obj=out/"kernel.o";obj.write_bytes(os.urandom(1_250_000))
                identity={"ci_revision":os.environ["R28_HEAD_SHA"]}
                ih=checkpoint.canonical_hash(identity)
                (out/"checkpoint-provenance.json").write_text(json.dumps({"format":checkpoint.PROVENANCE_FORMAT,
                           "version":checkpoint.CHECKPOINT_VERSION,"identity":identity,"identity_sha256":ih}))
                proof={"format":"bare-apk-segment-frontier-v2","target":"chrome_public_apk","parent_sha256":n.PARENT["sha"],
                       "before":["b"*64,"a"*64],"after":["b"*64],"witnesses":[{"kernel.o":os.urandom(16).hex()}]}
                pf=out/"checkpoint-segment-frontier.json";pf.write_text(json.dumps(proof))
                psha=hashlib.sha256(pf.read_bytes()).hexdigest()
                tar=subprocess.run(["tar","-C",str(src),"-cf","-","out/Bare"],capture_output=True,check=True).stdout
                candidate=n.ROOT/"new.tar.zst"
                candidate.write_bytes(subprocess.run(["zstd","-qc","-9"],input=tar,capture_output=True,check=True).stdout)
                n.seal(candidate,ih,psha)
                with patch.object(b,"inventory",return_value=[]),patch.dict(os.environ,R28_RELAY_BYTE_CEILING="1"):
                    with self.assertRaisesRegex(ValueError,"storage ceiling"):n.capacity()
                with self.assertRaisesRegex(ValueError,"changed actual graph proof"):
                    n.verify_payload(candidate,{"proof_sha":"f"*64})
                copy_peer(1,"ordinary","limited",["outcome.json","checkpoint.cms"])
                role("limited",1)
                with patch.object(n,"verify_outputs",side_effect=ValueError("response lost after immutable manifest")):
                    with self.assertRaisesRegex(ValueError,"response lost"):n.publish()
                self.assertEqual(len(api.assets),4)
                os.environ["GITHUB_RUN_ATTEMPT"]="2"
                manifest_row=api.assets.pop()
                n.recover()
                self.assertIn("recovery_status=all_private_bytes_verified_manifest_absent",(work/"outputs").read_text())
                second=api.assets.pop()
                n.recover()
                self.assertIn("recovery_status=partial_private_parts",(work/"outputs").read_text())
                api.assets.extend([second,manifest_row])
                n.recover()
                self.assertEqual(len(api.assets),4)
                with self.assertRaisesRegex(ValueError,"Rerun"):n.publish()
                rec=dict(line.split("=",1) for line in (work/"outputs").read_text().splitlines())
                self.assertEqual(rec["checkpoint_key"],"bare-coexist-204-1234-1-checkpoint-production-s1")
                self.assertEqual(rec["private_readback_verified"],"true")
                self.assertEqual(int(rec["checkpoint_bytes"]),candidate.stat().st_size)
                os.environ.update(R28_SLOT="2",R28_PARENT_SHA=rec["checkpoint_sha"],R28_PARENT_IDENTITY=rec["checkpoint_identity"],
                    R28_PARENT_MANIFEST=rec["checkpoint_manifest_id"],R28_PARENT_MANIFEST_SHA=rec["checkpoint_manifest_sha"],GITHUB_RUN_ATTEMPT="1")
                issue_slot(2)
                role("ordinary",2)
                class CDN:
                    def __init__(self,host,timeout):assert host in b.CDN
                    def request(self,method,path,headers):
                        assert "Authorization" not in headers
                        self.object=int(urlsplit(path).path.rsplit("/",1)[-1])
                    def getresponse(self):
                        class Reply(io.BytesIO):status=200
                        return Reply(api.data[self.object])
                    def close(self):pass
                with patch.object(http.client,"HTTPSConnection",CDN):n.acquire()
                self.assertEqual((n.ROOT/"checkpoint.tar.zst").read_bytes(),candidate.read_bytes())
                n.stop("verify-only");copy_peer(2,"ordinary","limited",["outcome.json"])
                role("limited",2);n.publish();self.assertEqual(len(api.assets),4)
                # Ciphertext-only or missing generation never publishes/restarts other work.
                with self.assertRaisesRegex(ValueError,"No unique committed"):n.recover()

if __name__=="__main__":unittest.main()
