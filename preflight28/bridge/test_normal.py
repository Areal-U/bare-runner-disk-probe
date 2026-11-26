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
from test_storage_admission import Provider, ENV


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
    def test_recovery_reads_only_the_new_campaign_claim(self):
        api = LocalDraft()
        ctx = {"producer_sha": "d" * 40, "run": 81}
        original = dict(schema=1, campaign="bare-personal-204-r29", repository_id=1450926240,
                        workflow=".github/workflows/bare-checkpoint-transfer.yml", branch="bare-coexist-v2.0.4",
                        head=ctx["producer_sha"], release_id=b.RELEASE, recipient=n.owner_recovery.RECIPIENT,
                        producer_attempt=1, initial_parent=b.PARENT_SHA, run_id=ctx["run"], registration_id="Automation_fixture")

        def add(asset_id, name, claim):
            raw = json.dumps(claim).encode()
            api.assets.append(dict(id=asset_id, name=name, size=len(raw),
                                   digest="sha256:" + hashlib.sha256(raw).hexdigest()))
            api.data[asset_id] = raw

        add(101, "bare-personal-204-r29-production-run-claim.json", original)
        self.assertIsNone(n.owner_recovery.collection_claim(api, api.draft(b.RELEASE), ctx))
        add(102, "bare-personal-204-r30-production-run-claim.json", original)
        with self.assertRaisesRegex(ValueError, "Wrong original collection claim"):
            n.owner_recovery.collection_claim(api, api.draft(b.RELEASE), ctx)
        api.assets.pop()
        add(103, "bare-personal-204-r30-production-run-claim.json", dict(original, campaign="bare-personal-204-r30"))
        self.assertEqual(n.owner_recovery.collection_claim(api, api.draft(b.RELEASE), ctx), 103)
        replacement = dict(ctx, run=82, ordinal=2, parent_sha="e" * 64, parent_identity="a" * 64)
        claim = dict(original, campaign="bare-personal-204-r30", run_id=82, original_claim_id=103,
                     origin_run=81, ordinal=2, initial_parent=replacement["parent_sha"],
                     parent_sha=replacement["parent_sha"], parent_identity=replacement["parent_identity"])
        event = dict(inputs={"mode": "recover-lost-slot", "loss_origin_run": "81"},
                     sender={"id": 292261483}, repository={"id": 1450926240})
        with tempfile.TemporaryDirectory() as work:
            event_path = Path(work) / "event.json"
            event_path.write_text(json.dumps(event))
            with patch.dict(os.environ, GITHUB_EVENT_PATH=str(event_path)):
                add(104, "bare-personal-204-r29-loss-replacement-claim.json", claim)
                with self.assertRaisesRegex(ValueError, "No immutable replacement collection claim"):
                    n.owner_recovery.collection_claim(api, api.draft(b.RELEASE), replacement)
                add(105, "bare-personal-204-r30-loss-replacement-claim.json", claim)
                self.assertEqual(n.owner_recovery.collection_claim(api, api.draft(b.RELEASE), replacement), 105)


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
                complete=b"# ninja log v5\n1\t2\t3000000\tkernel.o\t123\n"
                (out/".ninja_log").write_bytes(complete)
                proof={"format":"bare-apk-segment-frontier-v4", "ninja_log":[len(complete),hashlib.sha256(complete).hexdigest()],"target":"chrome_public_apk","parent_sha256":n.PARENT["sha"],
                       "before":["b"*64,checkpoint.canonical_hash(["kernel.o"])],"after":["b"*64],"closed_groups":[["kernel.o"]],"witnesses":[{"kernel.o":os.urandom(16).hex()}]}
                pf=out/"checkpoint-segment-frontier.json";pf.write_text(json.dumps(proof))
                psha=hashlib.sha256(pf.read_bytes()).hexdigest()
                tar=subprocess.run(["tar","-C",str(src),"-cf","-","out/Bare"],capture_output=True,check=True).stdout
                candidate=n.ROOT/"new.tar.zst"
                # Exercise the ordinary packer before sealing and independently acquiring the generation.
                packer = Path(__file__).resolve().parents[1] / "transport/pack_draft.py"
                subprocess.run([sys.executable, str(packer), str(candidate), "auto", str(len(tar)), "--",
                                "tar", "-C", str(src), "-cf", "-", "out/Bare"], check=True)
                n.seal(candidate,ih,psha)
                with patch.object(b,"api_json",side_effect=Provider().get),patch.dict(os.environ,
                      R28_STORAGE_CEILING=ENV["R28_STORAGE_CEILING"],R28_STORAGE_UNTIL=ENV["R28_STORAGE_UNTIL"],
                      RUNNER_ENVIRONMENT="github-hosted",R28_RELAY_BYTE_CEILING="1"):
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
                claim={"schema":1,"campaign":"bare-personal-204-r30","repository_id":1450926240,
                       "workflow":".github/workflows/bare-checkpoint-transfer.yml","branch":"bare-coexist-v2.0.4",
                       "head":c["producer_sha"],"initial_parent":b.PARENT_SHA,"registration_id":"Automation_fixture","release_id":b.RELEASE,
                       "recipient":recipient,"run_id":c["run"],"producer_attempt":1}
                raw=json.dumps(claim).encode()
                row={"id":123,"name":"bare-personal-204-r30-production-run-claim.json","size":len(raw),
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

                # A new physical run may replace exactly a lost segment. The
                # preceding manifest is origin-scoped; every publication is new.
                dispatch = work/"replacement-dispatch.json"
                event = {"repository":{"id":1450926240}, "sender":{"id":292261483},
                         "inputs":{"mode":"recover-lost-slot","loss_origin_run":"1234"}}
                dispatch.write_text(json.dumps(event))
                with patch.dict(os.environ,GITHUB_RUN_ID="2345",GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_REF="refs/heads/bare-coexist-v2.0.4",GITHUB_ACTOR="Areal-U",GITHUB_SHA="5"*40,
                        GITHUB_EVENT_PATH=str(dispatch),R28_PARENT_BACKEND="draft",R28_PARENT_READBACK_ONLY="false",
                        R28_PARENT_RUN="1234",R28_EXPECTED_PARENT_KEY=rec["checkpoint_key"]):
                    for override in ({"GITHUB_RUN_ATTEMPT":"2"}, {"R28_PARENT_BACKEND":"cache"},
                                     {"R28_PARENT_READBACK_ONLY":"true"}, {"GITHUB_SHA":"4"*40},
                                     {"R28_EXPECTED_PARENT_KEY":n.logical(1)}, {"R28_SLOT":"1"},
                                     {"R28_SLOT":"3"}, {"R28_SLOT":"13"}, {"R28_PARENT_RUN":"2345"}):
                        with self.subTest(override=override),patch.dict(os.environ,override):
                            with self.assertRaisesRegex(ValueError,"Unbound replacement"):n.parent_read_run()
                    for override in ({"mode":"build-apk"},{"loss_origin_run":"999"}):
                        dispatch.write_text(json.dumps({**event,"inputs":{**event["inputs"],**override}}))
                        with self.subTest(override=override),self.assertRaisesRegex(ValueError,"Cross-run parent"):
                            n.parent_read_run()
                    dispatch.write_text(json.dumps(event))
                    with self.assertRaisesRegex(ValueError,"Unrecognized private manifest"):
                        n.get_manifest(int(rec["checkpoint_manifest_id"]),rec["checkpoint_manifest_sha"],1)
                    os.environ["R28_COLLECTION_CLAIM"]="124"
                    issue_slot(22)
                    role("ordinary",22)
                    with patch.object(http.client,"HTTPSConnection",CDN):n.acquire()
                    self.assertEqual((n.ROOT/"checkpoint.tar.zst").read_bytes(),candidate.read_bytes())
                    self.assertEqual(n.info()["source"]["run"],1234)
                    self.assertEqual(n.info()["run"],2345)
                    group = ["second.o"]
                    (out/group[0]).write_text("successor output")
                    proof.update(parent_sha256=rec["checkpoint_sha"],before=[checkpoint.canonical_hash(group)],
                                 after=[],closed_groups=[group],witnesses=[{group[0]:"fixture"}])
                    pf.write_text(json.dumps(proof))
                    new_candidate=n.ROOT/"replacement.tar.zst"
                    tar=subprocess.check_output(["tar","-C",str(src),"-cf","-","out/Bare"])
                    new_candidate.write_bytes(subprocess.check_output(["zstd","-qc","-9"],input=tar))
                    # A manual reader may recover the exact new sealed relay
                    # after both jobs are gone, using the new claim for this slot.
                    replacement_claim = dict(claim,run_id=2345,original_claim_id=123,origin_run=1234,ordinal=2,
                                             initial_parent=rec["checkpoint_sha"],parent_sha=rec["checkpoint_sha"],
                                             parent_identity=rec["checkpoint_identity"])
                    raw=json.dumps(replacement_claim).encode()
                    api.assets.append(dict(row,id=124,name="bare-personal-204-r30-loss-replacement-claim.json",
                                           size=len(raw),digest="sha256:"+hashlib.sha256(raw).hexdigest()))
                    api.data[124]=raw
                    # The new input wrapper is also bound to the replacement claim.
                    role("limited",22)
                    self.assertEqual(n.owner_recovery.collection_claim(api,api.draft(b.RELEASE),n.context()),124)
                    with self.assertRaisesRegex(ValueError,"Unbound replacement"):
                        n.owner_recovery.collection_claim(api,api.draft(b.RELEASE),dict(n.context(),ordinal=3))
                    replacement_artifact = dict(artifact,id=322,name="r28-2345-a1-s02-outcome",
                                                workflow_run={"id":2345,"head_sha":n.context()["producer_sha"]})
                    def read_artifact(path):
                        if path.endswith("/artifacts/322"):
                            return replacement_artifact
                        return {"artifacts":[replacement_artifact],"total_count":1}
                    with patch.dict(os.environ,GITHUB_RUN_ATTEMPT="2"),patch.object(b,"api_json",side_effect=read_artifact):
                        n.recover()
                        self.assertIn("owner_outcome_artifact_id=322",(work/"outputs").read_text())
                    role("ordinary",22)
                    n.seal(new_candidate,ih,b.digest(pf))
                    copy_peer(22,"ordinary","limited",["outcome.json","checkpoint.cms"])
                    start_count=len(api.assets)
                    role("limited",22);n.publish()
                    second_receipt=dict(line.split("=",1) for line in (work/"outputs").read_text().splitlines())
                    self.assertEqual(second_receipt["checkpoint_key"],"bare-coexist-204-2345-1-checkpoint-production-s2")
                    self.assertEqual(second_receipt["private_readback_verified"],"true")
                    self.assertEqual(len(api.assets)-start_count,4)
                    self.assertTrue(all(row["name"].startswith("r28-2345-a1-s02-") for row in api.assets[start_count:]))
                    os.environ.update(R28_SLOT="3",R28_PARENT_RUN="",R28_PARENT_READBACK_ONLY="true",
                            R28_EXPECTED_PARENT_KEY=second_receipt["checkpoint_key"],
                            R28_PARENT_SHA=second_receipt["checkpoint_sha"],R28_PARENT_IDENTITY=second_receipt["checkpoint_identity"],
                            R28_PARENT_MANIFEST=second_receipt["checkpoint_manifest_id"],
                            R28_PARENT_MANIFEST_SHA=second_receipt["checkpoint_manifest_sha"])
                    issue_slot(23)
                    role("ordinary",23)
                    with patch.object(http.client,"HTTPSConnection",CDN):n.acquire()
                    self.assertEqual(n.info()["source"]["run"],2345)
                    self.assertEqual((n.ROOT/"checkpoint.tar.zst").read_bytes(),new_candidate.read_bytes())
                    n.stop("verify-only")
                    copy_peer(23,"ordinary","limited",["outcome.json"])
                    role("limited",23);n.publish()
                    self.assertEqual(len(api.assets)-start_count,4)


if __name__=="__main__":unittest.main()
