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
import time
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
            owner_key=work/"test-owner.agekey"
            subprocess.run(["age-keygen","-o",str(owner_key)],check=True,stderr=subprocess.DEVNULL)
            recipient=subprocess.check_output(["age-keygen","-y",str(owner_key)],text=True).strip()
            os.environ.update(R28_OWNER_RECIPIENT=recipient,R28_COLLECTION_CLAIM="123")
            accepted_owner=patch.object(n.owner_recovery,"RECIPIENT",recipient)
            accepted_owner.start()
            self.addCleanup(accepted_owner.stop)
            api=LocalDraft()
            with patch.object(b,"auth_api",return_value=api),patch.object(n,"PART",1_000_000):
                def role(name,num):
                    os.environ["GITHUB_JOB"]=name
                    n.ROOT=b.ROOT=work/(name+str(num))
                def newkeys(num):
                    for i,key in enumerate(("ordinary","limited")):
                        role(key,num)
                        n.keygen(key,11+i,int(n.time.time()) if key=="limited" else None)
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
                self.assertIn("sender_outcome_deadline="+str(n.sender_deadline(n.info())),(work/"outputs").read_text())
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
                # A provider throttle never acknowledges private visibility. The
                # part/manifest were committed only once; all reconciliation is GET.
                deadline=time.time()+210
                timeline=[]
                def throttled(host,path,label):
                    timeline.append((host,path,label))
                    return int(deadline+3600) if label=="api" else None
                with patch.object(api,"anonymous_status",side_effect=throttled):
                    n.recover(deadline=deadline)
                pending=dict(line.split("=",1) for line in (work/"outputs").read_text().splitlines())
                self.assertEqual(pending["recovery_status"],"manifest_present_visibility_pending")
                self.assertEqual(pending["private_readback_verified"],"false")
                self.assertEqual(pending["checkpoint_advanced"],"false")
                self.assertEqual(int(pending["checkpoint_manifest_id"]),manifest_row["id"])
                self.assertEqual(pending["checkpoint_manifest_sha"],manifest_row["digest"].removeprefix("sha256:"))
                self.assertEqual(pending["checkpoint_sha"],b.digest(candidate))
                self.assertEqual([event[2] for event in timeline],["direct","direct","direct","api"])
                explicit={"R28_EXPECTED_RECOVERY_MANIFEST":str(manifest_row["id"]),
                          "R28_EXPECTED_RECOVERY_MANIFEST_SHA":pending["checkpoint_manifest_sha"]}
                with patch.dict(os.environ,explicit):
                    with patch.dict(os.environ,R28_EXPECTED_RECOVERY_MANIFEST="999999"):
                        with self.assertRaisesRegex(ValueError,"observed private manifest changed"):
                            n.recover(deadline=time.time()+900)
                    n.recover(deadline=time.time()+900)
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
                role("ordinary",2);(n.ROOT/"outcome.json").unlink()
                n.stop("size-exceeded");copy_peer(2,"ordinary","limited",["outcome.json"])
                role("limited",2);n.publish();self.assertEqual(len(api.assets),4)
                # Ciphertext-only or missing generation never publishes/restarts other work.
                with self.assertRaisesRegex(ValueError,"No unique committed"):n.recover()
                # The limited VM was lost before an intent or manifest. On a read-only
                # retry the signed-in service can identify the original owner artifact.
                c=n.context()
                claim={"schema":1,"campaign":"bare-personal-204-r28","repository_id":1450926240,
                       "workflow":".github/workflows/bare-checkpoint-transfer.yml","branch":"bare-coexist-v2.0.4",
                       "head":c["producer_sha"],"initial_parent":b.PARENT_SHA,"release_id":b.RELEASE,
                       "recipient":recipient,"run_id":c["run"],"producer_attempt":1}
                raw=json.dumps(claim).encode()
                row={"id":123,"name":"bare-personal-204-r28-production-run-claim.json","size":len(raw),
                     "digest":"sha256:"+hashlib.sha256(raw).hexdigest(),"state":"uploaded"}
                api.assets.append(row);api.data[123]=raw
                artifact={"id":321,"name":"r28-1234-a1-s02-outcome","digest":"sha256:"+"7"*64,
                          "size_in_bytes":2048,"expired":False,"expires_at":"2099-12-01T00:00:00Z",
                          "workflow_run":{"id":1234,"head_sha":c["producer_sha"]}}
                with patch.object(b,"api_json",side_effect=lambda path: artifact if path.endswith("/artifacts/321") else {"artifacts":[artifact],"total_count":1}):
                    n.recover()
                    self.assertIn("recovery_status=owner_outcome_artifact_available",(work/"outputs").read_text())
                    self.assertIn("owner_outcome_artifact_id=321",(work/"outputs").read_text())
                    artifact["workflow_run"]["head_sha"]="8"*40
                    with self.assertRaisesRegex(ValueError,"Foreign run or revision"):n.recover()


if __name__=="__main__":unittest.main()
