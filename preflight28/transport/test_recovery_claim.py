"""Service-bound recovery claim regression cases using the observed v1 producer/receiver outcomes."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
from pathlib import Path
from threading import Barrier, Lock, local
import unittest
from urllib.parse import parse_qs, unquote, urlsplit
import sys

CONTROL=Path(__file__).resolve().parents[1]/"control"
sys.path.insert(0,str(CONTROL))
import admission as gate
import recovery_claim as retry


OLD=45508307819
OLD_JOB=138849157324
OLD_RCV=138862098593
NEW=OLD+99
OLD_HEAD="77eba2168e05302346583bba0ba01082738f5742"
OLD_BEFORE="b9553267cbb4f1645db9d2d40c4d85eb68c26d5d"
HEAD="e"*40
PRIOR=OLD_HEAD
CAMPAIGN="r28-preflight-s2-20261125-v2"
WF=".github/workflows/bare-r28-s2-recovery.yml"
REPO={"id":gate.REPO_ID,"full_name":gate.REPO}
OWNER={"id":292261483,"login":"Areal-U"}
VER="0264306e8c9c344d72477fc809ba4e6806bdcb35f30b425cf16709453c4e9acd"
SOURCE_KEY="bare-coexist-204-45285202990-1-checkpoint-production-s2"
STEPS={"Check canonical generation and reserve the single producer":"success",
       "Read the actual service job start and preflight source receipt":"success",
       "Restore the exact S2 parent at its original path":"success",
       "Validate parent and advance one required APK edge, then pack bounded zstd":"failure",
       "Send only the verified generation to the existing owner Draft":"skipped",
       "Record retained parent and receiver manifest":"skipped"}


def context(rid=OLD+99):
    env=dict(GITHUB_RUN_ID=str(rid),GITHUB_RUN_ATTEMPT="1",GITHUB_REPOSITORY=gate.REPO,GITHUB_JOB="reserve",
             GITHUB_EVENT_NAME="pull_request",GITHUB_REF="refs/pull/9/merge",GITHUB_ACTOR="Areal-U",
             GITHUB_TRIGGERING_ACTOR="Areal-U",TRIAL_SHA=HEAD,PRIOR_SHA=PRIOR,GITHUB_SHA=HEAD)
    pr=dict(number=9,state="open",head=dict(repo=REPO,ref=gate.BRANCH,sha=HEAD),
            base=dict(repo=REPO,ref=gate.BASE_REF,sha=gate.BASE_SHA))
    event=dict(action="synchronize",number=9,before=PRIOR,after=HEAD,repository=REPO,pull_request=pr,sender=OWNER)
    return env,event


def run(rid):
    old=rid==OLD
    return dict(id=rid,run_attempt=1,path=gate.WORKFLOW if old else WF,
                head_sha=OLD_HEAD if old else HEAD,head_branch=gate.BRANCH,head_repository=REPO,repository=REPO,
                actor=OWNER,triggering_actor=OWNER,status="completed" if old else "in_progress",
                conclusion="failure" if old else None,event="pull_request",pull_requests=[{"number":9}],
                name="r28-preflight-s2-20261125-v1 / S2 transport" if old else CAMPAIGN,
                workflow_id=429664031 if old else 123456)


def service_job(job_id,name,conclusion):
    return dict(id=job_id,run_id=OLD,run_attempt=1,head_sha=OLD_HEAD,status="completed",name=name,
                conclusion=conclusion,steps=[dict(name=k,number=i,status="completed",conclusion=v)
                       for i,(k,v) in enumerate(STEPS.items(),11)] if job_id==OLD_JOB else [])


class GitHub:
    BASE="/repos/"+gate.REPO
    UPLOAD="uploads.github.com"
    RELEASE_ID=gate.RELEASE_ID
    def __init__(self):
        self.old=run(OLD);self.live=None
        self.pages={}
        self.current=local()
        self.jobs=[service_job(OLD_JOB,"Create one S2 successor and transfer to fixed private Draft","failure"),
                   service_job(OLD_RCV,"Recover and verify required edge on an independent runner","skipped")]
        self.s2=dict(id=11016400308,ref="refs/heads/"+gate.BASE_REF,key=SOURCE_KEY,size_in_bytes=2742685925,version=VER)
        self.artifacts=[]
        self.pr=context()[1]["pull_request"]
        self.rows={};self.files={};self.posts=0;self.mx=Lock();self.lost=True;self.barrier=None
        holder=dict(schema=1,campaign=gate.CAMPAIGN,workflow=gate.WORKFLOW,repository_id=gate.REPO_ID,pr=9,
                    run_id=OLD,producer_attempt=1,producer_job="produce",head=OLD_HEAD,before=OLD_BEFORE,
                    parent_s2_sha256=gate.S2_SHA)
        self.add(gate.CLAIM,gate.encode(holder),789237341)
    def add(self,name,data,aid):
        self.files[aid]=data
        self.rows[name]=dict(id=aid,name=name,state="uploaded",size=len(data),digest="sha256:"+hashlib.sha256(data).hexdigest())
        return self.rows[name]
    def draft(self,release):
        assert release==self.RELEASE_ID
        with self.mx: return dict(id=release,assets=list(self.rows.values()),draft=True)
    def metadata(self,url,**kwargs):
        route=urlsplit(url);p=unquote(route.path.removeprefix(self.BASE));q=parse_qs(route.query)
        if p==f"/releases/{self.RELEASE_ID}/assets":
            return self.pages.get(int(q.get("page",["1"])[0]), self.draft(self.RELEASE_ID)["assets"] if q.get("page",["1"])[0]=="1" else [])
        if p=="/pulls/9":return self.pr
        if p in ("/git/ref/heads/"+gate.BRANCH,"/git/refs/heads/"+gate.BRANCH):
            return {"object":{"sha":self.pr["head"]["sha"]}}
        if p=="/actions/caches":return dict(total_count=1,actions_caches=[self.s2])
        if p.endswith("/runs") and (p=="/actions/runs" or "/actions/workflows/" in p):
            rows=[run(getattr(self.current,"rid",NEW))] + ([self.live] if self.live else [])
            return dict(total_count=len(rows),workflow_runs=rows)
        if p.startswith("/actions/jobs/"):
            return next(j for j in self.jobs if j["id"]==int(p.split("/")[3]))
        if p.startswith("/actions/runs/"):
            bits=p.split("/");rid=int(bits[3])
            if bits[-1]=="jobs":return dict(total_count=len(self.jobs),jobs=self.jobs)
            if bits[-1]=="artifacts":return dict(total_count=len(self.artifacts),artifacts=self.artifacts)
            if rid!=OLD: self.current.rid=rid
            return self.old if rid==OLD else run(rid)
        raise AssertionError("Uncovered service route "+p)
    def asset_info(self,release,name,size,sha,asset_id=None):
        row=self.rows[name]
        if row["digest"]!="sha256:"+sha or row["size"]!=size or (asset_id and row["id"]!=asset_id):
            raise ValueError("Immutable service object differs from expected")
        return row
    def download(self,aid,size,sha,destination):
        data=self.files[aid]
        if len(data)!=size or hashlib.sha256(data).hexdigest()!=sha: raise ValueError("Wrong bytes")
        destination.write(data)
    def request(self,host,method,url,**kw):
        assert host==self.UPLOAD and method=="POST" and kw["auth"] and kw["length"]==len(kw["body"])
        name=parse_qs(urlsplit(url).query)["name"][0]
        if self.barrier is not None:self.barrier.wait(timeout=3)
        with self.mx:
            if name in self.rows:
                class Conflict:
                    status=422
                return io.BytesIO(),Conflict()
            self.posts+=1
            self.add(name,kw["body"],810)
        if self.lost:raise ConnectionResetError("reply lost after successful upload")
        class OK:
            status=201
        return io.BytesIO(),OK()


def reserve(h,rid=OLD+99,edit=None):
    env,event=context(rid)
    if edit:edit(env,event)
    return retry.reserve(h,env,event,HEAD)


class SupersedingTests(unittest.TestCase):
    def test_recovery_after_confirmed_presend_failure(self):
        h=GitHub()
        reserve(h)
        self.assertEqual(h.posts,1)
        reserve(h)
        self.assertEqual(h.posts,1)

    def test_duplicate_physical_dispatch_race(self):
        h=GitHub();h.barrier=Barrier(2)
        def enter(rid):
            try:reserve(h,rid);return True
            except ValueError:return False
        with ThreadPoolExecutor(max_workers=2) as workers:
            self.assertCountEqual(workers.map(enter,[OLD+99,OLD+100]),[False,True])
        self.assertEqual(h.posts,1)

    def test_recovery_denied_if_old_run_restarted_or_transferred(self):
        for change in ("later-attempt","not-complete","receiver-ran","transfer-not-skipped","prior-artifact","prior-part",
                       "same-revision-live","new-native-uncommitted","source-changed","foreign-head","old-claim-bytes"):
            h=GitHub()
            if change=="later-attempt":h.old["run_attempt"]=2
            if change=="not-complete":h.old["status"]="in_progress"
            if change=="receiver-ran":h.jobs[1]["conclusion"]="success"
            if change=="transfer-not-skipped":h.jobs[0]["steps"][-2]["conclusion"]="success"
            if change=="prior-artifact":h.artifacts=[dict(id=42,name=f"r28-{OLD}-a1-s01-outcome",expired=False)]
            if change=="prior-part":h.add(f"{gate.CAMPAIGN}-run{OLD}-a1-seg01-p00",b"partial",51)
            if change=="same-revision-live":h.live=run(OLD+551)
            if change=="new-native-uncommitted":h.add(f"r28-{NEW}-a1-s01-intent.json",b"partial",52)
            if change=="source-changed":h.s2["version"]="a"*64
            if change=="foreign-head":h.old["head_sha"]=HEAD
            if change=="old-claim-bytes":h.files[789237341]=b"replaced"
            with self.subTest(change=change),self.assertRaises(ValueError):reserve(h)
            self.assertEqual(h.posts,0)

    def test_conflicting_prior_final_receipt_on_another_draft_asset_page(self):
        h=GitHub();hidden=dict(id=930,state="uploaded",name=f"{gate.CAMPAIGN}-run{OLD}-a1-seg01-manifest.json")
        h.pages[1]=list(h.draft(h.RELEASE_ID)["assets"])+[dict(id=i,name="unrelated-"+str(i)) for i in range(1000,1099)]
        h.pages[2]=[hidden]
        with self.assertRaises(ValueError):reserve(h)
        self.assertEqual(h.posts,0)

    def test_rerun_wrong_pr_and_before_never_reserve(self):
        for edit in [lambda env,event:env.update(GITHUB_RUN_ATTEMPT="2"),
                     lambda env,event:event.update(before="9"*40),
                     lambda env,event:event["pull_request"].update(number=10)]:
            h=GitHub()
            with self.assertRaises(ValueError):reserve(h,edit=edit)
            self.assertEqual(h.posts,0)
