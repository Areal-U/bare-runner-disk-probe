"""Exercise both complete collection paths with GUI redaction, exact API captures and ZIP bytes."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import importlib.util
import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import production as p
import owner_snapshot as o
from test_handoff_sample import sample


def hashed(b):
    return sha256(b).hexdigest()


def raw(x):
    return json.dumps(x,sort_keys=True,separators=(",",":")).encode()


class SnapshotTest(unittest.TestCase):
    def setUp(self):
        self.temp=TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for name in ("private","artifacts"):
            (self.root/name).mkdir()
        self.now=datetime.now(timezone.utc)
        self.utc=lambda offset:(self.now+timedelta(seconds=offset)).isoformat().replace("+00:00","Z")
        self.run=77
        self.head="a"*40
        self.tag="synthetic-owner-capture"
        self.probe=b"offline local receipt fixture"
        real=os.environ.get("R28_ORIGINAL_OWNER_PROBE")
        if real:
            self.probe=Path(real).read_bytes()
            self.assertEqual((len(self.probe),hashed(self.probe)),(49,"6d3adfcb254e849273bf1acb809da3e670b55706abda9e791798b2f4002a9055"))
        self.helper=SimpleNamespace(DRAFT_TITLE="Private checkpoint transport probe (25-s2)",OWNER="Areal-U",
                        DRAFT_TARGETS={"main"},DRAFT_TAG_SHA256=hashed(self.tag.encode()),
                        SAMPLE="owner-storage-probe.txt",PROBE_BYTES=len(self.probe),PROBE_SHA=hashed(self.probe))
        spec=importlib.util.spec_from_file_location("r28_verified_draft",Path(__file__).resolve().parents[1]/"transport/draft_anchor.py")
        mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
        anchor=patch.dict("sys.modules",r28_verified_draft=mod);anchor.start();self.addCleanup(anchor.stop)
        self.jobs=[];self.rows=[];self.artifacts=[];self.metadata={}
        self.gui=dict(form_id="edit_release_452114666",release_url=o.WEB+"tag/"+self.tag,label="Draft",title=self.helper.DRAFT_TITLE,
                      author="Areal-U",viewer="Areal-U",target="main",tag=self.tag,assets=self.rows)
        self.add_private("owner-storage-probe.txt",self.probe)
        old=self.add_private("checkpoint-25-s2.tar.gz",None)
        old["sha256"]="dd2177a80c72db7d0d6b558bec1fbd2c0acf448b28144d02dd26796104315413"
        self.cipher=b"age-encryption.org/v1\nsynthetic-bytes"
        if os.environ.get("R28_C1_OWNER_CIPHER"):
            self.cipher=Path(os.environ["R28_C1_OWNER_CIPHER"]).read_bytes()
            self.assertEqual(hashed(self.cipher),os.environ["R28_C1_OWNER_CIPHER_SHA"])
        self.seal=dict(schema=p.apk_seal.SCHEMA,run=self.run,attempt=1,ordinal=1,producer_sha=self.head,accepted_parent=p.S2_SHA,
                       recipient=p.apk_seal.RECIPIENT,sha=hashed(self.cipher),bytes=len(self.cipher))
        common=dict(schema=1,campaign=p.CAMPAIGN,repository_id=p.REPO_ID,workflow=p.WORKFLOW,branch=p.BASE_REF,head=self.head,
                    release_id=p.RELEASE_ID,recipient=p.apk_seal.RECIPIENT,initial_parent=p.S2_SHA)
        service="Automation_"+"a"*32
        name=p.TICKET_NAME
        ticket = dict(common,collector_registration_id=service,owner_destination_id="owner-private-file-id")
        earlier, refs = sample(self, ticket)
        for source_name, _, data, _ in earlier:
            self.add_private(source_name,data)
        t=raw(ticket)
        self.add_private(name,t)
        self.locator=dict(ticket_asset_id=200,ticket_sha=hashed(t),head=self.head,registration_id=service,owner_destination_id="owner-private-file-id")
        c=raw(dict(common,run_id=self.run,producer_attempt=1,registration_id=service,ticket_asset_id=200,ticket_sha=hashed(t),**refs))
        self.add_private(p.CLAIM,c)
        self.claim_witness=self.witness("claim",[(name,200,t,True),(p.CLAIM,201,c,False)])
        self.job(o.CLAIM_JOB,[o.CLAIM_STEP])
        self.metadata[f"actions/runs/{self.run}/attempts/1"]=dict(id=self.run,run_attempt=1,path=p.WORKFLOW,head_sha=self.head,
                     event="workflow_dispatch",head_branch=p.BASE_REF,head_repository={"id":p.REPO_ID},repository={"id":p.REPO_ID},actor=p.OWNER)

    def add_private(self,name,data):
        row=dict(name=name,state="uploaded",created_at=self.utc(-3),sha256=hashed(data or b""),
                 href=o.WEB+"download/"+self.tag+"/"+name)
        self.rows.append(row)
        if data is not None:(self.root/"private"/name).write_bytes(data)
        return row

    def artifact(self,name,files):
        buffer=io.BytesIO()
        with ZipFile(buffer,"w") as archive:
            for filename,data in files:archive.writestr(filename,data)
        data=buffer.getvalue();aid=len(self.artifacts)+1
        (self.root/"artifacts"/f"{aid}.zip").write_bytes(data)
        row=dict(id=aid,name=name,workflow_run=dict(id=self.run,head_sha=self.head),size_in_bytes=len(data),
                 digest="sha256:"+hashed(data),created_at=self.utc(-3),expired=False,expires_at=self.utc(3000))
        self.artifacts.append(row);self.metadata[f"actions/artifacts/{aid}"]=dict(row)
        return row

    def witness(self,kind,records):
        rows=[dict(name=n,id=i,sha256=hashed(b),bytes=len(b),owner_issued=issuer) for n,i,b,issuer in records]
        note=dict(schema="bare-r28-owner-witness-v1",run=self.run,attempt=1,head=self.head,release_id=p.RELEASE_ID,kind=kind,rows=rows)
        name="owner-claim" if kind=="claim" else "s01-owner-terminal"
        return self.artifact(f"r28-{self.run}-a1-"+name,[("witness.json",raw(note))])

    def job(self,name,steps):
        job=dict(id=len(self.jobs)+1,name=name,run_id=self.run,run_attempt=1,head_sha=self.head,status="completed",
                 conclusion="success",completed_at=self.utc(-1),steps=[dict(name=s,started_at=self.utc(-10),completed_at=self.utc(-1),
                                                                          conclusion="success") for s in steps])
        self.jobs.append(job);return job

    def delivery(self,private=False):
        if not private:
            self.cipher_asset=self.artifact(f"bare-personal-204-encrypted-{self.run}-1-s1",
                                           [("seal.json",raw(self.seal)),(p.apk_seal.CIPHER_FILE,self.cipher)])
            self.job("Bounded build segment 1 / Compute / Compile or verify authenticated APK slot 1",["Upload the encrypted APK bundle"])
            return
        tag=f"r28-{self.run}-a1-s01"
        cipher,receipt=tag+p.CIPHER_SUFFIX,tag+p.RECEIPT_SUFFIX
        part=dict(id=310,name=cipher,bytes=len(self.cipher),sha256=hashed(self.cipher))
        record=raw(dict(schema="bare-r28-private-apk-v1",seal=self.seal,collection_claim_id=201,
                        source_cache_key=f"bare-coexist-204-apk-v1-{self.run}-1-s1",cipher=part,depositor_run=self.run))
        self.add_private(cipher,self.cipher);self.add_private(receipt,record)
        self.witness("terminal",[(receipt,311,record,False),(cipher,310,self.cipher,False)])
        self.job("Bounded build segment 1 / "+p.DRAFT_JOB,[p.DRAFT_STEP,o.TERMINAL_STEP])

    def write(self):
        self.gui["asset_count"]=len(self.rows)
        self.metadata[f"actions/runs/{self.run}/attempts/1/jobs?per_page=100&page=1"]=dict(total_count=len(self.jobs),jobs=self.jobs)
        self.metadata[f"actions/runs/{self.run}/artifacts?per_page=100&page=1"]=dict(total_count=len(self.artifacts),artifacts=self.artifacts)
        for side in ("before","after"):
            (self.root/f"draft-{side}.json").write_bytes(raw(self.gui))
            (self.root/f"actions-{side}.json").write_bytes(raw({o.BASE+k:v for k,v in self.metadata.items()}))

    def collect(self):
        snapshot=o.OwnerSnapshot(self.root,self.helper)
        with patch.object(p.subprocess,"run",side_effect=AssertionError("unexpected CLI")),patch.object(p.recover,"get",side_effect=AssertionError("unexpected network")):
            return p.collect(self.locator,self.root/"accepted",snapshot,actions=snapshot,draft_rows=snapshot.draft_rows)

    def test_collect_artifact_without_token_or_private_api(self):
        self.delivery();self.write()
        receipt=self.collect();self.assertEqual(receipt["artifact_id"],self.cipher_asset["id"])
        self.assertEqual(self.collect(),receipt)
        self.assertEqual((self.root/"accepted"/p.apk_seal.CIPHER_FILE).read_bytes(),self.cipher)

    def test_owner_capture_for_r30_rotation_uses_both_original_receipt_files(self):
        import r28_verified_draft as anchor
        self.delivery()
        current = "untagged-" + "a" * 20
        for row in self.rows:
            row["href"] = row["href"].replace("/" + self.tag + "/", "/" + current + "/")
        self.tag = current
        self.gui.update(tag=current, release_url=o.WEB + "tag/" + current)
        fixtures = Path(__file__).resolve().parents[1] / "transport" / "fixtures"
        for name, aid, _, _ in anchor.CLAIMS:
            self.add_private(name, (fixtures / f"claim-{aid}.json").read_bytes())
        self.write()
        with patch.object(anchor, "R30_TAG_SHA", hashed(current.encode())):
            self.assertEqual(self.collect()["artifact_id"], self.cipher_asset["id"])
            for name, _, _, _ in anchor.CLAIMS:
                file = self.root / "private" / name
                original = file.read_bytes()
                file.write_bytes(b"wrong")
                with self.assertRaises(ValueError):
                    self.collect()
                file.write_bytes(original)
        with self.assertRaises(ValueError):
            self.collect()

    def test_owner_intent_recovers_ticket_id_only_from_original_job(self):
        self.delivery(); self.write()
        intent = {k:v for k,v in self.locator.items() if k!="ticket_asset_id"}
        capture = o.OwnerSnapshot(self.root,self.helper)
        resolved = capture.resolve_original_ticket(intent)
        self.assertEqual(resolved,self.locator)
        receipt = p.collect(resolved,self.root/"accepted",capture,actions=capture,draft_rows=capture.draft_rows)
        self.assertEqual(receipt["artifact_id"],self.cipher_asset["id"])
        self.assertNotIn("ticket_asset_id",intent)
        for extra in ({"ticket_sha":"f"*64}, {"ticket_asset_id":201}, {"owner_destination_id":"operator-only"},
                      {"registration_id":"Automation_"+"f"*32}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                capture.resolve_original_ticket(dict(intent,**extra))
        with patch.dict(self.jobs[0], run_attempt=2):
            self.write()
            with self.assertRaises(ValueError):
                o.OwnerSnapshot(self.root,self.helper).resolve_original_ticket(intent)

    def test_collect_private_terminal_without_actions_cipher_or_private_api(self):
        self.delivery(private=True);self.write()
        receipt=self.collect()
        self.assertEqual((receipt["draft_receipt_id"],receipt["draft_asset_id"],receipt["seal"]["sha"]),(311,310,hashed(self.cipher)))
        self.assertEqual(self.collect(),receipt)

    def test_find_later_depositor_witness_without_its_run_id_or_an_original_witness(self):
        self.delivery(private=True)
        source=self.run
        original=self.artifacts.pop()
        self.metadata.pop(f"actions/artifacts/{original['id']}")
        original_bytes=(self.root/"artifacts"/f"{original['id']}.zip").read_bytes()
        with ZipFile(io.BytesIO(original_bytes)) as z:
            note=json.loads(z.read("witness.json"))
        self.run=98
        note["run"]=self.run
        saved_artifacts,saved_jobs=self.artifacts,self.jobs
        self.artifacts=[{},{}];self.jobs=[]
        later=self.artifact("r28-98-a1-s01-owner-terminal",[("witness.json",raw(note))])
        self.job(o.RESCUE_JOB,[o.TERMINAL_STEP])
        self.metadata["actions/runs/98/attempts/1/jobs?per_page=100&page=1"]=dict(total_count=1,jobs=self.jobs)
        self.metadata["actions/runs/98/artifacts?per_page=100&page=1"]=dict(total_count=1,artifacts=[later])
        self.artifacts,self.jobs=saved_artifacts,saved_jobs;self.run=source
        source_run=self.metadata[f"actions/runs/{source}/attempts/1"]
        source_run["created_at"]=self.utc(-90)
        self.metadata["actions/runs/98/attempts/1"]=dict(source_run,id=98,created_at=self.utc(-40))
        query=o.urlencode(dict(branch=p.BASE_REF,event="workflow_dispatch",head_sha=self.head,status="completed",
                             created=">="+source_run["created_at"]))
        path="actions/workflows/bare-checkpoint-transfer.yml/runs?"+query+"&per_page=100&page=1"
        self.metadata[path]=dict(total_count=1,workflow_runs=[dict(self.metadata["actions/runs/98/attempts/1"],status="completed")])
        self.write()
        self.assertEqual(self.collect()["draft_receipt_id"],311)
        self.metadata[path]["total_count"]=2;self.write()
        with self.assertRaises(ValueError):self.collect()

    def test_public_witness_remains_usable_with_only_a_private_starter(self):
        row=self.add_private(self.claim_witness["name"]+".json",None)
        row.update(state="starter",sha256="")
        self.delivery();self.write()
        self.assertEqual(self.collect()["claim_asset_id"],201)

    def test_valid_alternate_survives_failed_private_ack_or_missing_zip_and_true_conflict_stops(self):
        self.delivery()
        artifact=self.claim_witness
        name=artifact["name"]+".json"
        path=self.root/"artifacts"/f"{artifact['id']}.zip"
        saved_zip=path.read_bytes()
        with ZipFile(path) as z:
            note=json.loads(z.read("witness.json"))
        b=raw(note)+b"\n"
        gui=self.add_private(name,b)
        job=self.jobs[0]
        write=dict(name="Preserve the registered owner claim witness in the original Draft",started_at=self.utc(-10),
                   completed_at=self.utc(-2),conclusion="failure")
        ack=dict(name=f"Attest registered owner claim SHA256 {hashed(b)}",started_at=self.utc(-2),
                 completed_at=self.utc(-1),conclusion="success")
        job["steps"].extend([write,ack]);self.write()
        self.assertEqual(self.collect()["claim_asset_id"],201)
        write["conclusion"]="success";self.write();path.unlink()
        self.assertEqual(self.collect()["claim_asset_id"],201)
        path.write_bytes(saved_zip)
        note["rows"][1]["id"]=909
        altered=raw(note)+b"\n"
        (self.root/"private"/name).write_bytes(altered);gui["sha256"]=hashed(altered)
        ack["name"]=f"Attest registered owner claim SHA256 {hashed(altered)}";self.write()
        with self.assertRaisesRegex(ValueError,"witnesses disagree"):self.collect()

    def test_private_claim_and_terminal_witnesses_when_all_actions_artifacts_are_gone(self):
        self.delivery(private=True)
        for artifact,kind,job in ((self.artifacts[0],"claim",self.jobs[0]),(self.artifacts[1],"terminal",self.jobs[1])):
            with ZipFile(self.root/"artifacts"/f"{artifact['id']}.zip") as z:
                note=json.loads(z.read("witness.json"))
            b=raw(note)+b"\n"
            self.add_private(artifact["name"]+".json",b)
            write=dict(name=f"Preserve the registered owner {kind} witness in the original Draft",started_at=self.utc(-10),
                       completed_at=self.utc(-2),conclusion="success")
            ack=dict(name=f"Attest registered owner {kind} SHA256 {hashed(b)}",started_at=self.utc(-2),
                     completed_at=self.utc(-1),conclusion="success")
            job["steps"].extend([write,ack])
        self.write()
        both=self.collect()
        self.artifacts.clear();self.write()
        self.assertEqual(self.collect(),both)
        self.jobs[0]["steps"][-1]["name"]="Attest registered owner claim SHA256 "+"a"*64;self.write()
        with self.assertRaises(ValueError):self.collect()

    def test_original_job_attests_exact_claim_and_terminal_without_either_stored_witness(self):
        self.delivery(private=True)
        for artifact,kind,job in ((self.artifacts[0],"claim",self.jobs[0]),(self.artifacts[1],"terminal",self.jobs[1])):
            with ZipFile(self.root/"artifacts"/f"{artifact['id']}.zip") as z:
                note=json.loads(z.read("witness.json"))
            note["rows"].sort(key=lambda row:row["name"])
            digest=hashed(raw(note)+b"\n")
            vector=",".join(str(r["id"]) for r in note["rows"])
            job["steps"][-1]["conclusion"]="failure"
            for label,begin,end,state in (
                (f"Bind the allowlisted private {kind} identities for the registered owner",-12,-10,"success"),
                (f"Preserve the registered owner {kind} witness in the original Draft",-10,-9,"failure"),
                (f"Attest registered owner {kind} SHA256 {digest}",-9,-8,"success"),
                (f"Attest registered owner {kind} IDs {vector}",-2,-1,"success")):
                job["steps"].append(dict(name=label,started_at=self.utc(begin),completed_at=self.utc(end),conclusion=state))
            (self.root/"artifacts"/f"{artifact['id']}.zip").unlink()
        self.artifacts.clear();self.write()
        result=self.collect()
        self.assertEqual((result["claim_asset_id"],result["draft_receipt_id"],result["draft_asset_id"]),(201,311,310))
        self.assertEqual(result["seal"]["sha"],hashed(self.cipher))
        # A different vector or an attestation preceding the verified issuer
        # cannot claim the same private files.
        mark=self.jobs[0]["steps"][-1]
        wrong_order = ",".join(reversed(mark["name"].split()[-1].split(",")))
        for field,value in (("name","Attest registered owner claim IDs "+wrong_order),("started_at",self.utc(-11)),
                            ("conclusion","failure")):
            with patch.dict(mark,{field:value}):
                self.write()
                with self.assertRaises(ValueError):self.collect()

    def test_changed_gui_or_pagination_or_missing_witness_rejected(self):
        self.delivery();self.write()
        for name,value in (("label","Published"),("author","other"),("viewer","other"),("target","other"),("form_id","edit_release_1")):
            with patch.dict(self.gui,{name:value}):
                self.write()
                with self.assertRaises(ValueError):self.collect()
        self.write();(self.root/"draft-after.json").write_bytes(b"{}")
        with self.assertRaises(ValueError):self.collect()
        self.write()
        (self.root/"artifacts"/"1.zip").write_bytes(b"broken")
        with self.assertRaises(ValueError):self.collect()

    def test_wrong_origin_truncated_inventory_or_corrupt_private_download_rejected(self):
        self.delivery(private=True);self.write()
        self.jobs[0]["head_sha"]="f"*40;self.write()
        with self.assertRaises(ValueError):self.collect()
        self.jobs[0]["head_sha"]=self.head;self.write()
        for side in ("before","after"):
            path=self.root/f"actions-{side}.json"
            payload=json.loads(path.read_bytes())
            payload[o.BASE+f"actions/runs/{self.run}/artifacts?per_page=100&page=1"]["total_count"]+=1
            path.write_bytes(raw(payload))
        with self.assertRaises(ValueError):self.collect()
        self.write()
        (self.root/"private"/(f"r28-{self.run}-a1-s01"+p.CIPHER_SUFFIX)).write_bytes(b"another")
        with self.assertRaises(ValueError):self.collect()


if __name__=="__main__":
    unittest.main()
