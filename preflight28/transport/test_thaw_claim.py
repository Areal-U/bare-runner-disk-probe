"""No network, GitHub mutations or real key material: exercise actual admission methods."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit
import thaw_claim as t
from test_recovery_claim import GitHub, OWNER, REPO, context, run as base_run

RID=t.ROTATED_RUN+100
WHEAD="6"*40
WHEN=datetime(2026,11,25,0,35,tzinfo=timezone.utc)


def original_manifest():
    return {"campaign":t.v2.CAMPAIGN,"source_sha":t.HEAD,"producer_run":t.SOURCE,"producer_attempt":1,"segment":1,
            "parent_sha":t.a.S2_SHA,"parent_identity":t.PARENT_IDENTITY,"parent_cache_id":t.v2.CACHE_ID,
            "parent_key":t.v2.CACHE_KEY,"format":"tar.zst","bytes":t.SIZE,"sha256":t.CHILD,
            "identity":t.IDENTITY,"graph_sha":t.GRAPH,"trial_provenance_sha":t.PROVENANCE,
            "parts":[{"name":t.STEM+"p00","id":992,"bytes":t.SIZE,"sha256":t.CHILD}]}


def source_jobs():
    def job(jid, conclusion, stages):
        return {"id":jid,"status":"completed","run_id":t.SOURCE,"conclusion":conclusion,
                "steps":[dict(name=k,conclusion=v,status="completed") for k,v in stages.items()]}
    return [job(t.RESERVE,"success",{}),job(t.PRODUCE,"failure",{
        "Prepare fixed builder and progress one genuine APK dependency, then pack new full zstd":"success",
        "Seal full newly built candidate to the independent restricted writer":"success","Upload the scoped cipher Artifact":"success",
        t.AUDIT_FAIL:"failure","Reconfirm original read-only cache after transfer":"skipped"}),
        job(t.SEND,"failure",{"Upload the scoped key Artifact":"success","Locate exact same-run cipher Artifact by service ID":"failure",
                              t.PRIVATE_SEND:"skipped"}),job(t.RECEIVE,"skipped",{})]


def accepted_history():
    labels=[
        ("Confirm failed prior acceptance, exact surviving artifacts and new single recovery claim","success"),
        ("Create recipient for the existing test owner and bind the current recovery job","success"),
        ("Deposit request for this exact recovery","success"),
        ("Read verified original original-key Artifact by immutable ID","success"),
        ("Read verified original original-cipher Artifact by immutable ID","success"),
        ("Read original S2 for exact archive comparison","success"),
        ("Locate the owner-encrypted response in the existing private Draft","failure"),
        ("Open disposable owner authorisation on this one recovery host","skipped"),
        ("Open original authenticated frames and verify the original producer evidence","skipped"),
        ("Recover already committed identical private bytes without any new key exchange","skipped"),
        ("Compare every original S2 payload and audit the GN diagnostic in the actual graphs","skipped"),
        ("Authorize only the fixed original archive using the complete accepted audit","skipped"),
        ("Reconcile original data and publish the original immutable generation","skipped")]
    names={t.ROTATED_RECOVER:"Recover original sealed candidate and audit before immutable private publication",
           t.ROTATED_RECEIVE:"Ordinary runner reads and verifies the private generation from the original recipe",
           t.ROTATED_ISSUE:"Grant only a short-lived read of original private checkpoint parts"}
    return [dict(id=key,name=name,status="completed",run_id=t.ROTATED_RUN,
            conclusion="failure" if key==t.ROTATED_RECOVER else "skipped",
            steps=[dict(number=i+1,name=n,status="completed",conclusion=v) for i,(n,v) in enumerate(labels)]
                  if key==t.ROTATED_RECOVER else []) for key,name in names.items()]


class Service(GitHub):
    def __init__(self):
        super().__init__()
        self.add(t.v2.CLAIM,t.a.encode(t.v2_holder()),t.CLAIM_ID)
        self.add(t.PREVIOUS_CLAIM,t.a.encode(t.previous_holder()),t.ROTATED_CLAIM_ID)
        self.rotated=accepted_history()
        self.challenges=[dict(id=t.ROTATED_CHALLENGE,name=f"r28-thaw-{t.ROTATED_RUN}-request",size_in_bytes=t.CHALLENGE_SIZE,
             digest="sha256:"+t.CHALLENGE_SHA,workflow_run=dict(id=t.ROTATED_RUN,head_sha=t.ROTATED_HEAD,head_branch=t.a.BRANCH,
             repository_id=t.a.REPO_ID,head_repository_id=t.a.REPO_ID))]
        self.rotated_attempt=1
        self.history=source_jobs()
        outcomes={"Confirm failed prior acceptance, exact surviving artifacts and new single recovery claim":"failure",
                  "Deposit request for this exact recovery":"skipped",
                  "Open original authenticated frames and verify the original producer evidence":"skipped",
                  "Reconcile original data and publish the original immutable generation":"skipped"}
        self.previous=[dict(id=j,status="completed",run_id=t.FAILED_GATE,conclusion=concl,
                            steps=[dict(name=k,conclusion=v) for k,v in outcomes.items()] if i==0 else [])
                       for i,(j,concl) in enumerate(zip(t.FAILED_JOBS,["failure","skipped","skipped"]))]
        self.arts=[dict(id=aid,size_in_bytes=size,digest="sha256:"+digest,expires_at=expires,expired=False,
                    name=f"r28-fresh-{t.SOURCE}-{key}",workflow_run=dict(id=t.SOURCE,head_sha=t.HEAD,head_branch=t.a.BRANCH,
                    repository_id=t.a.REPO_ID,head_repository_id=t.a.REPO_ID)) for key,(aid,size,digest,expires) in t.ARTIFACTS.items()]
    def metadata(self, url, **kwargs):
        route=urlsplit(url).path.removeprefix(self.BASE)
        if route.startswith("/actions/runs/"):
            rid=int(route.split("/")[3])
            if rid==t.ROTATED_RUN:
                if route.endswith("/jobs"): return dict(total_count=len(self.rotated),jobs=self.rotated)
                if route.endswith("/artifacts"): return dict(total_count=len(self.challenges),artifacts=self.challenges)
                return {**base_run(rid),"run_attempt":self.rotated_attempt,"head_sha":t.ROTATED_HEAD,"path":t.WORKFLOW,
                        "status":"completed","conclusion":"failure"}
            if rid==t.FAILED_GATE:
                if route.endswith("/jobs"): return dict(total_count=3,jobs=self.previous)
                if route.endswith("/artifacts"): return dict(total_count=0,artifacts=[])
                return {**base_run(rid),"head_sha":t.FAILED_HEAD,"path":t.WORKFLOW,"status":"completed","conclusion":"failure"}
            if rid==t.SOURCE:
                if route.endswith("/jobs"):return dict(total_count=len(self.history),jobs=self.history)
                if route.endswith("/artifacts"):return dict(total_count=len(self.arts),artifacts=self.arts)
            result=base_run(rid)
            result.update(head_sha=t.HEAD if rid==t.SOURCE else WHEAD,
                          path=t.v2.WORKFLOW if rid==t.SOURCE else t.WORKFLOW)
            if rid==t.SOURCE:result.update(conclusion="failure",status="completed")
            if "/attempts/" in route:result["run_attempt"]=int(route.rsplit("/",1)[1])
            return result
        return super().metadata(url,**kwargs)
    def part(self):
        self.rows[t.STEM+"p00"]=dict(name=t.STEM+"p00",id=992,state="uploaded",size=t.SIZE,digest="sha256:"+t.CHILD)
    def manifest(self):
        self.part();self.add(t.STEM+"manifest.json",json.dumps(original_manifest(),sort_keys=True,separators=(",",":")).encode(),993)


def apply(h,mode="reserve",rid=RID,attempt=1,role=None,audit=None,now=WHEN):
    env,event=context(rid)
    env.update(GITHUB_JOB=role or ("issue" if mode=="verify" else "recover"),TRIAL_SHA=WHEAD,PRIOR_SHA=t.HEAD,
               GITHUB_RUN_ATTEMPT=str(attempt))
    event.update(after=WHEAD,before=t.HEAD)
    event["pull_request"]["head"]["sha"]=WHEAD
    def log(job,reason):
        assert (job==t.PRODUCE and reason.endswith("gn_logs.txt")) or (job==t.SEND and "peer" in reason)
    return t.run(mode,h,env,event,WHEAD,audit=audit,clock=now,read_log=log)


def report():
    e={"chromium":"800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6","build_gn_sha256":"31f8205fe64264c5b4f9638eb6552e558ccf78a4839413a7c1a194116f26e72e",
       "target":"chrome_public_apk","diagnostic_query":"unknown target","graph_references":0,"aliases":0,
       "manifest_content":{"files":101,"sha256":"f"*64},"sections":{"<header>":{}}}
    return {"schema":"bare-r28-archive-continuity-v3","status":"passed","parent_sha":t.a.S2_SHA,"child_sha":t.CHILD,
            "parent_content":{"files":195432,"sha256":"a"*64},"child_content":{"files":195433,"sha256":"b"*64},
            "counts":{"added":1,"removed":0,"unclassified":0,"gn_diagnostic":1},
            "diagnostics":[dict(path="gn_logs.txt",producer="//BUILD.gn:1662-1672",parent="f:0:50:aaa",
                                child="f:0:51:bbb",evidence={"parent":dict(e),
                                "child":dict(e),"changed_sections":["timing"]})],"differences":[]}


class Tests(unittest.TestCase):
    def test_reserve_authorize_then_read_only_recover(self):
        with tempfile.TemporaryDirectory() as tmp:
            audit=Path(tmp)/"audit.json";audit.write_text(json.dumps(report()))
            h=Service()
            self.assertEqual(apply(h),(810,0));self.assertEqual(apply(h),(810,0));self.assertEqual(h.posts,1)
            h.part()
            self.assertEqual(apply(h,"authorize",audit=audit),(810,0))
            with self.assertRaises(ValueError):apply(h,"verify")
            h.manifest();h.arts=[]
            self.assertEqual(apply(h,"verify",attempt=2),(810,993))
            self.assertEqual(apply(h),(810,993))
            self.assertEqual(h.posts,1)
            with self.assertRaises(ValueError):apply(h,"authorize",attempt=2,audit=audit)
            with self.assertRaises(ValueError):apply(h,"verify",role="receive")
            with self.assertRaises(ValueError):apply(h,"authorize",rid=RID+1,audit=audit)
            self.assertEqual(h.posts,1)

    def test_old_logs_need_no_token_and_prior_gate_cannot_progress(self):
        for job,(size,digest,line) in t.TRANSCRIPTS.items():
            t.log_witness(job,line.split("Z ",1)[1])
            with self.assertRaises(ValueError): t.log_witness(job,"different failure")
        fake=Service();fake.previous[0]["steps"][-1]["conclusion"]="success"
        with self.assertRaisesRegex(ValueError,"first admission"):apply(fake)
        self.assertEqual(fake.posts,0)

    def test_wrong_service_evidence_never_reserves(self):
        for change in ("wrong-claim","expired","cipher-sha","wrong-size","handoff-name","original-writer-ran","other-transfer",
                       "existing-data","existing-manifest","unexpected-log","near-expiry"):
            with self.subTest(change=change):
                h=Service();now=WHEN
                if change=="wrong-claim":h.files[t.CLAIM_ID]=b"changed"
                if change=="expired":h.arts[0]["expired"]=True
                if change=="cipher-sha":h.arts[0]["digest"]="sha256:"+"f"*64
                if change=="wrong-size":h.arts[0]["size_in_bytes"]+=1
                if change=="handoff-name":h.arts[1]["name"]+="alt"
                if change=="original-writer-ran":h.history[2]["steps"][-1]["conclusion"]="success"
                if change=="other-transfer":h.add(t.STEM+"p01",b"other",888)
                if change=="existing-data":h.part();h.rows[t.STEM+"p00"]["digest"]="sha256:"+"a"*64
                if change=="existing-manifest":h.manifest();r=original_manifest();r["sha256"]="0"*64;h.add(t.STEM+"manifest.json",json.dumps(r).encode(),993)
                if change=="unexpected-log":h.history[1]["steps"].append({"name":"Other failure","status":"completed","conclusion":"failure"})
                if change=="near-expiry":now=datetime(2026,11,25,23,57,24,tzinfo=timezone.utc)
                with self.assertRaises(ValueError):apply(h,now=now)
                self.assertEqual(h.posts,0)

    def test_accepted_previous_stopped_and_immutable(self):
        frozen=t.a.encode(t.previous_holder())
        self.assertEqual(len(frozen),1125)
        self.assertEqual(hashlib.sha256(frozen).hexdigest(),"fc68bc4b80b30dfe115e6bbe2dc205c177416bb5188e5cb44e0056aa88a83eb9")
        for flaw in ("restarted","scope","unsealed","published","challenge","more","foreign-data","old-name","substituted-authority"):
            h=Service()
            if flaw=="restarted":h.rotated_attempt=2
            if flaw=="scope":h.rotated[1]["name"],h.rotated[2]["name"]=h.rotated[2]["name"],h.rotated[1]["name"]
            if flaw=="unsealed":h.rotated[0]["steps"][8]["conclusion"]="success"
            if flaw=="published":h.rotated[0]["steps"][-1]["conclusion"]="success"
            if flaw=="challenge":h.challenges[0]["digest"]="sha256:"+"0"*64
            if flaw=="more":h.challenges.append(dict(h.challenges[0],id=11))
            if flaw=="foreign-data":h.files[t.ROTATED_CLAIM_ID]=b"not original"
            if flaw=="old-name":h.rows.pop(t.PREVIOUS_CLAIM)
            if flaw=="substituted-authority":h.rows[t.PREVIOUS_CLAIM]["id"]=32;h.files[32]=frozen
            with self.subTest(flaw=flaw),self.assertRaises((ValueError,KeyError)):apply(h)
            self.assertEqual(h.posts,0)
        h=Service();cid,_=apply(h)
        self.assertEqual(h.files[t.ROTATED_CLAIM_ID],frozen)
        self.assertEqual(h.rows[t.PREVIOUS_CLAIM]["id"],t.ROTATED_CLAIM_ID)
        self.assertNotEqual(cid,t.ROTATED_CLAIM_ID)
        self.assertEqual(h.posts,1)

    def test_bad_audit_cannot_authorize(self):
        h=Service();apply(h)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"result"
            for kind in ("missing","failed","another-child","loss","wrong-diagnostic"):
                r=report()
                if kind=="failed":r["status"]="rejected"
                if kind=="another-child":r["child_sha"]="f"*64
                if kind=="loss":r["counts"]["unclassified"]=1
                if kind=="wrong-diagnostic":r["diagnostics"][0]["path"]="subdir/gn_logs.txt"
                if kind!="missing":path.write_text(json.dumps(r))
                with self.subTest(kind=kind),self.assertRaises((ValueError,FileNotFoundError)):
                    apply(h,"authorize",audit=path)
            self.assertEqual(h.posts,1)

if __name__=="__main__":
    unittest.main()
