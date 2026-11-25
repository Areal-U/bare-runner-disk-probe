"""Exercise ordinary recovery with real ZIP bytes and an API that cannot supply job logs."""
import copy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile
import yaml

import apk_seal
import receipt_journal as journal
import recover

ROOT = Path(__file__).resolve().parents[2]
HEAD = "a"*40
RUN = 77
PARENT = recover.S2_SHA
NOW = datetime.now(timezone.utc).replace(microsecond=0)
stamp = lambda n: (NOW + timedelta(seconds=n)).isoformat()
CIPHER = b"age-encryption.org/v1\nopaque-test-cipher"
DIGEST = sha256(CIPHER).hexdigest()


def candidate(n):
    return dict(status="candidate",ordinal=n,producer_sha=HEAD,accepted_parent=PARENT if n==1 else f"{n-1:064x}",
                sha=f"{n:064x}",identity="f"*64,key=f"bare-coexist-204-77-1-checkpoint-production-s{n}",
                manifest_id=str(234+n),manifest_sha="d"*64,archive_bytes="800")


def seal(n):
    return dict(schema=apk_seal.SCHEMA,run=RUN,attempt=1,ordinal=n,producer_sha=HEAD,
                accepted_parent=PARENT if n==1 else f"{n-1:064x}",sha=DIGEST,bytes=len(CIPHER),recipient=apk_seal.RECIPIENT)


class SimulatedActions:
    def __init__(self):
        self.jobs=[]
        self.assets=[]
        self.objects={}
        self.raw={}
        self.caches=[]
        self.requests=[]
    def job(self,n,suffix,steps,result="success"):
        j=dict(id=100+len(self.jobs),name=f"Bounded build segment {n} / "+suffix,run_id=RUN,run_attempt=1,head_sha=HEAD,
               started_at=stamp(-20),completed_at=stamp(-5),status="completed",conclusion=result,
               steps=[dict(name=key,conclusion=value,started_at=stamp(-15),completed_at=stamp(-5)) for key,value in steps])
        self.jobs.append(j)
        return j
    def asset(self,name,filename,contents,after=False):
        current=len(self.assets)+1
        f=BytesIO()
        with ZipFile(f,"w") as zip_file:
            zip_file.writestr(filename,contents)
        raw=f.getvalue()
        row=dict(id=current,name=name,workflow_run={"id":RUN,"head_sha":HEAD},size_in_bytes=len(raw),
                 digest="sha256:"+sha256(raw).hexdigest(),expired=False,expires_at=stamp(3000),
                 created_at=stamp(0 if after else -6))
        self.assets.append(row);self.objects[current]=dict(row);self.raw[current]=raw
        return row
    def slot(self,n,body=None,conclusion="success"):
        self.job(n,journal.RESULT_JOB,[(journal.SLOT_STEP,conclusion)],result=conclusion)
        note=dict(schema=journal.SCHEMA,run=RUN,attempt=1,head=HEAD,result=body or candidate(n))
        return self.asset(f"r28-77-a1-s{n:02}-receipt","receipt.json",json.dumps(note))
    def terminal(self,n,*,separate=True,artifact=True,cache=False,sealbody=None):
        cipher_upload=("Upload the encrypted APK bundle","success" if artifact else "failure")
        steps=[cipher_upload,(journal.SEAL_STEP,"success" if separate else "failure")]
        if cache:
            steps.append(("Save only the encrypted APK for retrieval retry","failure"))
            self.caches.append(dict(key=f"bare-coexist-204-apk-v1-77-1-s{n}",ref="refs/heads/bare-coexist-v2.0.4",
                                    size_in_bytes=550,id=51,created_at=stamp(-6)))
        self.job(n,f"Authenticate parent / Compile or verify authenticated APK slot {n}",steps,"failure")
        if separate:
            self.asset(f"r28-77-a1-s{n:02}-apk-seal","seal.json",json.dumps(sealbody or seal(n)))
        if artifact:
            return self.asset(f"bare-personal-204-encrypted-77-1-s{n}","unused","reserved")
    def read(self,path):
        self.requests.append(path)
        if "logs" in path:
            raise AssertionError("job logs unavailable")
        if path=="actions/runs/77/attempts/1":
            return json.dumps(dict(id=RUN,head_sha=HEAD,path=recover.WORKFLOW,event="workflow_dispatch",run_attempt=1,
                                   status="completed",head_branch=recover.BASE_REF,repository={"id":recover.REPO_ID},
                                   head_repository={"id":recover.REPO_ID}))
        if path.endswith("/jobs?per_page=100&page=1"):
            return json.dumps({"jobs":self.jobs,"total_count":len(self.jobs)})
        if path.endswith("/artifacts?per_page=100&page=1"):
            return json.dumps({"artifacts":self.assets,"total_count":len(self.assets)})
        if path.startswith("actions/artifacts/"):
            return json.dumps(self.objects[int(path.rsplit("/",1)[1])])
        if path.startswith("actions/caches?"):
            return json.dumps({"actions_caches":self.caches,"total_count":len(self.caches)})
        raise AssertionError("Unexpected API: "+path)
    def main(self):
        with tempfile.TemporaryDirectory() as t:
            dest=Path(t)/"out"
            with patch.dict(os.environ,{"GITHUB_RUN_ID":str(RUN),"GITHUB_RUN_ATTEMPT":"2","GITHUB_SHA":HEAD,"GITHUB_OUTPUT":str(dest)}), \
                 patch.object(recover,"get",self.read),patch.object(recover,"download_note",self.raw.__getitem__):
                recover.main()
            return dict(l.split("=",1) for l in dest.read_text().splitlines())


class JournalTests(unittest.TestCase):
    def test_receipts_include_uploaded_unacknowledged_slot_and_never_use_logs(self):
        s=SimulatedActions();s.slot(1);s.slot(2,conclusion="failure")
        self.assertEqual(s.main()["accepted_parent"],candidate(1)["sha"])
        self.assertFalse(any("logs" in p for p in s.requests))
    def test_no_rollback_on_missing_expired_duplicate_foreign_or_changed_original(self):
        for scenario in ("gap","absent-last","expired","duplicate","wrong-parent","wrong-scope","late","different-id","bad-zip","done-later"):
            with self.subTest(scenario=scenario):
                s=SimulatedActions();s.slot(1)
                r=s.slot(2,dict(candidate(2),accepted_parent=PARENT) if scenario=="wrong-parent" else None)
                if scenario=="gap":s.assets.pop(0)
                if scenario=="absent-last":s.assets.pop()
                if scenario=="expired":r["expired"]=True;s.objects[r["id"]]["expired"]=True
                if scenario=="duplicate":s.assets.append(dict(r,id=55))
                if scenario=="wrong-scope":r["workflow_run"]={"id":15,"head_sha":HEAD}
                if scenario=="late":r["created_at"]=stamp(5);s.objects[r["id"]]["created_at"]=r["created_at"]
                if scenario=="different-id":s.objects[r["id"]]["id"]=333
                if scenario=="bad-zip":s.raw[r["id"]]+=b"x"
                if scenario=="done-later":s.job(4,"Compile or verify authenticated APK slot 4",[("compute","success")])
                with self.assertRaises(ValueError):s.main()
    def test_early_terminal_prevents_subsequent_work_or_seal(self):
        stop=dict(ordinal=1,producer_sha=HEAD,accepted_parent=PARENT,status="no-progress")
        s=SimulatedActions();s.slot(1,stop);self.assertEqual(s.main()["status"],"no-progress")
        s.terminal(1)
        with self.assertRaises(ValueError):s.main()
        s=SimulatedActions();s.slot(1,stop);s.slot(2)
        with self.assertRaises(ValueError):s.main()
    def test_seal_and_latest_slot_match_and_terminal_id_cannot_change(self):
        s=SimulatedActions();s.slot(1);r=s.terminal(2)
        success=dict(status="apk",ordinal=2,producer_sha=HEAD,accepted_parent=candidate(1)["sha"],
                     cipher_id=str(r["id"]),cipher_cache="",cipher_sha=DIGEST,cipher_bytes=str(len(CIPHER)))
        s.slot(2,success);out=s.main()
        self.assertEqual((out["status"],out["cipher_id"],out["cipher_sha"]),("inspect-terminal",str(r["id"]),DIGEST))
        for bad in (dict(success,cipher_sha="0"*64),dict(success,cipher_id="898")):
            ss=SimulatedActions();ss.slot(1);ss.terminal(2);ss.slot(2,bad)
            with self.assertRaises(ValueError):ss.main()
    def test_fallback_and_embedded_only_terminal_can_be_salvaged_without_log(self):
        s=SimulatedActions();s.slot(1);s.terminal(2,artifact=False,separate=False,cache=True)
        out=s.main()
        self.assertEqual((out["status"],out["ordinal"],out["cipher_sha"],out["cipher_cache"]),
                         ("inspect-terminal","2","","bare-coexist-204-apk-v1-77-1-s2"))
        s.caches[0]["created_at"]=stamp(2)
        with self.assertRaises(ValueError):s.main()
        s.caches.clear()
        with self.assertRaisesRegex(ValueError,"durable copy"):s.main()
    def test_only_read_only_terminal_salvage_may_recover_after_loss_of_a_committed_note(self):
        for expired in (True, False):
            s=SimulatedActions();s.slot(1);r=s.terminal(2)
            note=s.slot(2,dict(status="apk",ordinal=2,producer_sha=HEAD,accepted_parent=candidate(1)["sha"],
                               cipher_id=str(r["id"]),cipher_cache="",cipher_sha=DIGEST,cipher_bytes=str(len(CIPHER))))
            if expired:
                note["expired"]=True;s.objects[note["id"]]["expired"]=True
            else:
                s.assets.remove(note)
            out=s.main()
            self.assertEqual((out["status"],out["ordinal"],out["accepted_parent"]),
                             ("inspect-terminal","2",candidate(1)["sha"]))
            with self.assertRaises(ValueError):
                recover.slot_chain(s.jobs,s.assets,RUN,HEAD,s.objects.__getitem__,s.raw.__getitem__)
            s.slot(3)
            with self.assertRaises(ValueError):s.main()

    def test_fallback_survives_loss_of_artifact_with_accepted_receipt(self):
        s=SimulatedActions();s.terminal(1,artifact=False,cache=True)
        s.slot(1,dict(status="apk",ordinal=1,producer_sha=HEAD,accepted_parent=PARENT,cipher_id="716",
                      cipher_cache="bare-coexist-204-apk-v1-77-1-s1",cipher_sha=DIGEST,cipher_bytes=str(len(CIPHER))))
        self.assertEqual(s.main()["cipher_id"],"")
    def test_seal_conflict_and_extra_origin_are_rejected(self):
        s=SimulatedActions();s.terminal(1,sealbody=dict(seal(1),accepted_parent="4"*64))
        with self.assertRaises(ValueError):s.main()
        s=SimulatedActions();s.terminal(1);s.terminal(2)
        with self.assertRaises(ValueError):s.main()
    def test_authenticated_zip_is_required_even_with_only_an_embedded_seal(self):
        for variant in ("valid","wrong-digest","wrong-size","extra-file","large-seal"):
            with self.subTest(variant=variant),tempfile.TemporaryDirectory() as tmp:
                encoded=BytesIO()
                with ZipFile(encoded,"w") as z:
                    z.writestr("seal.json",json.dumps(seal(1)) if variant!="large-seal" else "x"*4097)
                    z.writestr(apk_seal.CIPHER_FILE,CIPHER)
                    if variant=="extra-file":z.writestr("../extra","data")
                raw=encoded.getvalue()
                actual="sha256:"+sha256(raw).hexdigest()
                dest=Path(tmp)/"bundle"
                size=len(raw)-int(variant=="wrong-size")
                expected=actual if variant!="wrong-digest" else "sha256:"+"0"*64
                if variant=="valid":
                    recover.receive_terminal_zip(BytesIO(raw),dest,size,expected)
                    self.assertEqual((dest/apk_seal.CIPHER_FILE).read_bytes(),CIPHER)
                else:
                    with self.assertRaises(ValueError):
                        recover.receive_terminal_zip(BytesIO(raw),dest,size,expected)

    def test_verified_terminal_requires_complete_bytes_and_matching_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            env=dict(RUNNER_TEMP=tmp,GITHUB_RUN_ID="77",ORDINAL="1",GITHUB_SHA=HEAD,ACCEPTED_PARENT=PARENT,
                     ARTIFACT_ID="41",ARTIFACT_OK="success",EXPECTED_CACHE="cache1",CACHE_MATCH="cache1",CACHE_HIT="true",CACHE_ID="81")
            def current_cache(key, ref):
                return [dict(id=81,key=key,ref=ref)]
            dirs=[Path(tmp)/name for name in ("bare-apk-artifact","bare-apk-delivery")]
            for d in dirs:
                d.mkdir();(d/"seal.json").write_text(json.dumps(seal(1)));(d/apk_seal.CIPHER_FILE).write_bytes(CIPHER)
            self.assertEqual(recover.verify_terminal(env,current_cache)["sha"],DIGEST)
            for changes in ({"EXPECTED_SHA":"d"*64,"EXPECTED_BYTES":str(len(CIPHER))},{"GITHUB_RUN_ID":"87"},
                            {"ACCEPTED_PARENT":"4"*64},{"CACHE_ID":"91"},{"CACHE_MATCH":"","ARTIFACT_OK":"failure"}):
                with self.assertRaises(ValueError):recover.verify_terminal(dict(env,**changes),current_cache)
            (dirs[0]/apk_seal.CIPHER_FILE).write_bytes(CIPHER[:-1]+b"B")
            with self.assertRaises(ValueError):recover.verify_terminal(env,current_cache)
    def test_replacement_rerun_is_bound_to_admitted_parent_and_one_compute(self):
        for start in (1,4,12):
            parent=PARENT if start==1 else f"{start-1:064x}"
            ident=recover.S2_IDENTITY if start==1 else "4"*64
            env=dict(R28_REPLAY_MODE="recover-lost-slot",R28_REPLAY_ORDINAL=str(start),
                     R28_REPLAY_PARENT=parent,R28_REPLAY_IDENTITY=ident)
            s=SimulatedActions();s.slot(start)
            s.slot(start+1,dict(status="limit-verified",ordinal=start+1,producer_sha=HEAD,
                                accepted_parent=candidate(start)["sha"],sha=candidate(start)["sha"]))
            if start==12:
                s.jobs[-1]["name"]="Independently receive checkpoint at the 12-segment limit / "+journal.RESULT_JOB
            with patch.dict(os.environ,env):
                self.assertEqual(s.main()["status"],"limit-verified")
                with patch.dict(os.environ,{"R28_REPLAY_PARENT":"5"*64}),self.assertRaises(ValueError):s.main()
            with patch.dict(os.environ,env):
                s=SimulatedActions();s.slot(start);s.slot(start+1)
                with self.assertRaises(ValueError):s.main()
            with patch.dict(os.environ,env):
                s=SimulatedActions();s.slot(start,dict(candidate(start),ordinal=start-1))
                with self.assertRaises(ValueError):s.main()

    def test_no_unexpected_output_field_can_override_latest_parent(self):
        s=SimulatedActions();s.slot(1,dict(candidate(1),private_ordinal=9))
        with self.assertRaises(ValueError):s.main()

    def test_wired_journal_is_immutable_and_blocks_forward_on_failure(self):
        worker=yaml.safe_load((ROOT/".github/workflows/bare-r28-native-slot.yml").read_text())
        journal_step=next(s for s in worker["jobs"]["result"]["steps"] if s.get("name")==journal.SLOT_STEP)
        self.assertFalse(journal_step["with"]["overwrite"]);self.assertEqual(journal_step["with"]["retention-days"],30)
        self.assertFalse(journal_step.get("continue-on-error",False))
        caller=yaml.safe_load((ROOT/".github/workflows/bare-checkpoint-transfer.yml").read_text())
        recovery=caller["jobs"]["recover-first-attempt"]
        self.assertIn("receipt_journal.py",recovery["steps"][0]["run"])
        self.assertEqual(recovery["permissions"],{"actions":"read"})
        self.assertIn("verify-terminal",recovery["steps"][-1]["run"])
        self.assertIn("needs.slot01.result == 'success'",caller["jobs"]["slot02"]["if"])


if __name__=="__main__":
    unittest.main()
