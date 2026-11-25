import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

import apk_seal
import owner_witness as w


class Docs:
    def __init__(self):
        self.rows=[]
        self.data={}

    def add(self,name,obj,owner=False):
        raw=json.dumps(obj,sort_keys=True).encode() if isinstance(obj,dict) else obj
        i=len(self.rows)+1
        self.data[i]=raw
        row=dict(id=i,name=name,size=len(raw),state="uploaded",digest="sha256:"+hashlib.sha256(raw).hexdigest(),
                 uploader=w.OWNER if owner else {"login":"github-actions[bot]"})
        self.rows.append(row)
        return row

    def draft(self,release_id):
        assert release_id==w.RELEASE_ID
        return {"assets":self.rows}

    def download(self,i,size,sha,output):
        data=self.data[i]
        assert len(data)==size and hashlib.sha256(data).hexdigest()==sha
        output.write(data)


class Witness(unittest.TestCase):
    def setUp(self):
        self.tmp=TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.env=dict(GITHUB_RUN_ID="77",GITHUB_JOB="bind-private-receiver",GITHUB_SHA="a"*40,
                      GITHUB_REPOSITORY=w.REPO,GITHUB_REF="refs/heads/"+w.BASE_REF,GITHUB_RUN_ATTEMPT="1",
                      GITHUB_ACTOR="Areal-U",GITHUB_EVENT_NAME="workflow_dispatch",RUNNER_TEMP=self.tmp.name)
        self.docs=Docs()
        self.common=dict(schema=1,campaign=w.CAMPAIGN,repository_id=w.owner.REPO_ID,workflow=w.owner.WORKFLOW,
                         branch=w.BASE_REF,head=self.env["GITHUB_SHA"],recipient=apk_seal.RECIPIENT,release_id=w.RELEASE_ID)
        self.service="Automation_"+"1"*32
        self.dest="private-owner-destination-no-public"
        self.ticket=self.docs.add(w.CAMPAIGN+"-collection-registration.json",dict(**self.common,
                                  initial_parent=w.owner.S2_SHA,collector_registration_id=self.service,
                                  owner_destination_id=self.dest),owner=True)
        self.claim=self.docs.add(w.CLAIM,dict(**self.common,initial_parent=w.owner.S2_SHA,registration_id=self.service,
                                 ticket_asset_id=self.ticket["id"],ticket_sha=self.ticket["digest"][7:],producer_attempt=1,run_id=77))

    def get_note(self):
        raw=(Path(self.tmp.name)/"witness.json").read_bytes()
        for secret in (self.dest,self.service,"GH_TOKEN","irrelevant-private-name"):
            self.assertNotIn(secret.encode(),raw)
        return raw,json.loads(raw)

    def test_claim_is_canonical_small_and_bound_to_this_issuer_then_persisted_once(self):
        self.docs.add("irrelevant-private-name.json",b"not allowed")
        self.env["WITNESS_CLAIM_ID"]=str(self.claim["id"])
        with patch.object(w,"PagedOwnerDraft",lambda x:x):
            name,sha=w.write_witness(self.docs,self.env,"claim")
            raw,record=self.get_note()
            self.assertEqual((name,sha),("r28-77-a1-owner-claim",hashlib.sha256(raw).hexdigest()))
            self.assertEqual({(r["id"],r["owner_issued"]) for r in record["rows"]},{(self.ticket["id"],True),(self.claim["id"],False)})
            self.assertEqual(set(record),{"schema","head","kind","rows","run","attempt","release_id"})
            ids,computed=w.local_attestation(self.env,"claim")
            self.assertEqual((ids,computed),(",".join(str(r["id"]) for r in record["rows"]),sha))
            command=[sys.executable,w.__file__,"attest","claim"]
            dated=dict(os.environ,**self.env,WITNESS_SHA=sha,WITNESS_IDS=ids)
            dated.pop("GH_TOKEN",None)
            self.assertEqual(subprocess.run(command,env=dated,capture_output=True).returncode,0)
            dated["WITNESS_IDS"]="99999,99998"
            self.assertNotEqual(subprocess.run(command,env=dated,capture_output=True).returncode,0)
            env=dict(self.env,WITNESS_NAME=name,WITNESS_SHA=sha)
            with patch("admission.admit",return_value=81) as save:
                self.assertEqual(w.preserve(self.docs,env,"claim"),81)
                self.assertEqual(save.call_args.kwargs["name"],"r28-77-a1-owner-claim.json")
                with self.assertRaises(ValueError): w.preserve(self.docs,dict(env,WITNESS_NAME="arbitrary.json"),"claim")
                (Path(self.tmp.name)/"witness.json").write_bytes(raw+b" ")
                with self.assertRaises(ValueError): w.preserve(self.docs,env,"claim")
                self.assertEqual(save.call_count,1)

    def test_terminal_outputs_only_the_two_correlated_physical_rows(self):
        payload=b"age-encryption.org/v1\nonly sealed data"
        part=self.docs.add("r28-77-a1-s01-apk.age",payload)
        seal=dict(schema=apk_seal.SCHEMA,run=77,attempt=1,ordinal=1,producer_sha=self.env["GITHUB_SHA"],
                  accepted_parent=w.owner.S2_SHA,recipient=apk_seal.RECIPIENT,sha=part["digest"][7:],bytes=part["size"])
        actual=dict(schema="bare-r28-private-apk-v1",seal=seal,collection_claim_id=self.claim["id"],depositor_run=77,
                    source_cache_key="bare-coexist-204-apk-v1-77-1-s1",
                    cipher=dict(id=part["id"],name=part["name"],bytes=part["size"],sha256=seal["sha"]))
        receipt=self.docs.add("r28-77-a1-s01-apk-owner-receipt.json",actual)
        env=dict(self.env,GITHUB_JOB="deliver-recovered-cached-apk",GITHUB_RUN_ID="88",R28_SOURCE_RUN="77",R28_SLOT="1",
                 R28_PARENT_SHA=w.owner.S2_SHA,R28_COLLECTION_CLAIM=str(self.claim["id"]),WITNESS_RECEIPT_ID=str(receipt["id"]),
                 WITNESS_RECEIPT_SHA=receipt["digest"][7:])
        with patch.object(w,"PagedOwnerDraft",lambda x:x):
            name,sha=w.write_witness(self.docs,env,"terminal")
            _,record=self.get_note()
            self.assertEqual(name,"r28-88-a1-s01-owner-terminal")
            self.assertEqual(record["run"],88)
            self.assertEqual({r["id"] for r in record["rows"]},{part["id"],receipt["id"]})
            with self.assertRaises(ValueError): w.terminal_items(self.docs,self.docs.rows,dict(env,R28_PARENT_SHA="b"*64),88,self.env["GITHUB_SHA"])
            with self.assertRaises(ValueError): w.terminal_items(self.docs,self.docs.rows,dict(env,R28_COLLECTION_CLAIM="999"),88,self.env["GITHUB_SHA"])

    def test_read_only_retry_once_and_no_retry_for_conflicting_records(self):
        read=Mock(side_effect=[w.NotYetVisible("settling"),"ready"])
        self.assertEqual(w.verified_rows(read,pause=lambda _:None),"ready")
        self.assertEqual(read.call_count,2)
        conflict=Mock(side_effect=ValueError("Conflicting owner"))
        with self.assertRaises(ValueError): w.verified_rows(conflict,pause=lambda _:None)
        self.assertEqual(conflict.call_count,1)
        outage=Mock(side_effect=OSError("no service"))
        with self.assertRaises(OSError): w.verified_rows(outage,pause=lambda _:None)
        self.assertEqual(outage.call_count,2)


if __name__=="__main__":
    unittest.main()
