"""Drive a physically different, one-interval replacement through the dispatch entry and the same GET-only lease."""
import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest import TestCase, main
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import loss_resume as loss
from test_receipt_journal import SimulatedActions, HEAD, RUN, candidate
from test_registration import OwnerDraft


def iso(dt):
    return dt.isoformat().replace("+00:00","Z")


class Service(OwnerDraft):
    UPLOAD = "test"
    BASE = "/repos/"+loss.REPO

    def __init__(self, start):
        super().__init__()
        self.now = start
        self.other = RUN + 100
        self.posts = 0
        self.written = {}
        self.caches = []
        self.s = SimulatedActions()
        self.times = {name:iso(start+timedelta(seconds=n)) for name,n in
                      (("prior",-1000),("observed",-400),("ticket",-300),("start",-200),("claim",-5))}
        self.ticket.update(head=HEAD,issued_at=self.times["prior"],expires_at=iso(start+timedelta(days=3)),
                           storage_valid_until=iso(start+timedelta(days=50)))
        self.ack.update(head=HEAD,valid_until=iso(start+timedelta(days=3)),storage_valid_until=self.ticket["storage_valid_until"],
                        observed_at=self.times["prior"])
        aid, sha = self.add(loss.reg.CAMPAIGN+"-collector-ack-"+self.ack["registration_nonce"]+".json",
                            self.ack,812,"prior")
        self.ticket.update(collector_ack_asset_id=aid,collector_ack_sha=sha)
        aid, sha = self.add(loss.reg.TICKET_NAME,self.ticket,901,"prior")
        common = {key:self.ticket[key] for key in
                  ("schema","campaign","repository_id","workflow","branch","head","release_id","recipient")}
        self.add(loss.reg.CLAIM,dict(common,run_id=RUN,producer_attempt=1,initial_parent=loss.S2_SHA,
                 ticket_asset_id=aid,ticket_sha=sha,registration_id=self.ticket["collector_registration_id"],
                 source_run_id=loss.handoff.SOURCE_RUN,source_claim_id=loss.handoff.SOURCE_CLAIM_ID,
                 source_claim_sha=loss.handoff.SOURCE_CLAIM_SHA),902,"prior")
        previous = candidate(1)
        previous.update(manifest_id="991",manifest_sha="e"*64,archive_bytes="80")
        self.parent = previous
        self.s.slot(1,previous)
        self.written[991] = (dict(id=991,name=f"r28-{RUN}-a1-s01-manifest.json-retry1",state="uploaded",
                                  size=80,digest="sha256:"+"e"*64),b"")
        steps = [(x,"success") for x in (loss.FRONTIER,loss.COMPILE,loss.PACK,"Certify an advanced checkpoint exists before transfer")]
        steps.extend((x,"skipped") for x in (*loss.RELAY,loss.CIPHER,loss.CACHE,loss.APK))
        self.job = self.s.job(2,"Compile or verify authenticated APK slot 2",steps)
        self.job["completed_at"] = self.times["prior"]
        self.job["conclusion"]="failure"
        self.s.jobs[-1] = self.job
        common.update(origin_run=RUN,original_claim_id=902,ordinal=2,
                      collector_registration_id=self.ticket["collector_registration_id"],
                      owner_destination_id=self.ticket["owner_destination_id"])
        self.evidence=dict(common,observed_at=self.times["observed"],parent_sha=previous["sha"],
                       pending_writes=0,producer_job_id=self.job["id"],state="ledger-closed-no-durable-output",
                       owner_copy="confirmed-absent",ledger_version=2,ledger_receipt_id="original-operation-reconciled",
                       lost_product="checkpoint")
        eid,esha=self.add(f"{loss.reg.CAMPAIGN}-loss-evidence-{RUN}.json",self.evidence,903,"observed")
        ticket=dict(self.ticket,**common,evidence_asset_id=eid,evidence_sha=esha,producer_attempt=1,
                    state="original-operation-closed-no-durable-output",issued_at=self.times["ticket"])
        self.add(f"{loss.reg.CAMPAIGN}-loss-{RUN}.json",ticket,904,"ticket")

    def add(self,name,obj,aid,when):
        data=json.dumps(obj).encode() if not isinstance(obj,bytes) else obj
        digest=hashlib.sha256(data).hexdigest()
        self.written[aid]=(dict(id=aid,name=name,state="uploaded",size=len(data),digest="sha256:"+digest,
                                uploader=loss.reg.OWNER,created_at=self.times[when]),data)
        return aid,digest

    def run_row(self,run,attempt):
        return dict(self.origin,id=run,head_sha=HEAD,run_attempt=attempt,
                    status="completed" if run==RUN else "in_progress",
                    updated_at=self.times["prior"] if run==RUN else self.times["start"],created_at=self.times["start"])

    def metadata(self,path):
        suffix=urlsplit(path).path.removeprefix(self.BASE)
        if suffix==f"/actions/runs/{RUN}/attempts/1/jobs": rows,key=self.s.jobs,"jobs"
        elif suffix.endswith("/attempts/1/jobs"):
            rows, key = [dict(id=644,run_id=self.other,run_attempt=1,head_sha=HEAD,status="completed",
                              name="Reserve one confirmed lost physical interval",conclusion="success",
                              steps=[dict(name="Claim one certified loss",conclusion="success",
                                          started_at=self.times["start"],completed_at=iso(self.now))])],"jobs"
        elif suffix==f"/actions/runs/{RUN}/artifacts": rows,key=self.s.assets,"artifacts"
        elif suffix=="/actions/caches": rows,key=self.caches,"actions_caches"
        elif suffix.startswith("/actions/artifacts/"): return self.s.objects[int(suffix.split("/")[-1])]
        elif suffix.startswith("/actions/runs/"):
            parts=suffix.split("/")
            return self.run_row(int(parts[3]),int(parts[5]) if len(parts)>4 else 1)
        elif suffix.startswith("/releases/"): return self.draft(loss.RELEASE_ID)["assets"]
        else: return super().metadata(path)
        return {key:rows,"total_count":len(rows)}

    def draft(self,rid): return {"assets":[row for row,_ in self.written.values()]}
    def asset_info(self,release,name,size,sha,aid=None):
        rows=[a for a in release["assets"] if a["name"]==name]
        loss.require(len(rows)==1 and (not aid or rows[0]["id"]==aid) and rows[0]["size"]==size
                     and rows[0]["digest"]=="sha256:"+sha,"Different private claim")
        return rows[0]

    def download(self,aid,size,sha,target): target.write(self.written[aid][1])
    def request(self,host,method,path,**kwargs):
        assert method=="POST" and parse_qs(urlsplit(path).query)["name"]==[loss.LOSS_CLAIM]
        self.posts+=1
        self.add(loss.LOSS_CLAIM,kwargs["body"],950,"claim")
        raise ConnectionResetError("Stored claim, lost response")


class PhysicalReplacement(TestCase):
    def setUp(self):
        self.enterContext(patch.object(loss.handoff,"validate_source", autospec=True))
        self.now=datetime.now(timezone.utc)
        self.api=Service(self.now)
        self.env=dict(GITHUB_JOB="loss-admission",GITHUB_RUN_ID=str(self.api.other),GITHUB_RUN_ATTEMPT="1",
                      GITHUB_REPOSITORY=loss.REPO,GITHUB_SHA=HEAD,GITHUB_REF="refs/heads/"+loss.BASE_REF,
                      RUNNER_ENVIRONMENT="github-hosted",GITHUB_EVENT_NAME="workflow_dispatch")
        self.event=dict(repository=dict(id=loss.REPO_ID),sender=loss.reg.OWNER,
                        inputs=dict(mode="recover-lost-slot",loss_origin_run=str(RUN)))

    def enter(self,op="claim"):
        with patch.object(loss.recover,"download_note",self.api.s.raw.__getitem__):
            return loss.operation(self.api,self.env,self.event,op,self.now)

    def test_original_to_replacement_readback_conflict_and_read_only_rerun(self):
        result=self.enter()
        self.assertEqual((result["ordinal"],result["next_ordinal"],result["parent_sha"],result["parent_run"],
                         result["parent_manifest_id"]),(2,3,self.api.parent["sha"],str(RUN),"991"))
        with patch.dict(self.env,GITHUB_JOB="collection-lease"): self.assertEqual(self.enter("lease")["claim_asset_id"],950)
        with patch.dict(self.env,GITHUB_JOB="reread-loss-admission",GITHUB_RUN_ATTEMPT="2"):
            self.assertEqual(self.enter("reread")["parent_sha"],result["parent_sha"])
            with self.assertRaises(ValueError): self.enter()
        with patch.dict(self.env,GITHUB_RUN_ID=str(self.api.other+1)),self.assertRaises(ValueError): self.enter()
        self.assertEqual(self.api.posts,1)

    def test_vm_terminated_mid_compile_without_any_durable_write(self):
        job=self.api.job
        job["conclusion"]="timed_out"
        for step in job["steps"]:
            if step["name"] == loss.COMPILE:
                step["conclusion"]="cancelled"
            elif step["name"] in (loss.PACK, "Certify an advanced checkpoint exists before transfer"):
                step["conclusion"]="skipped"
        ledger=dict(self.api.evidence,lost_product="interrupted-build")
        args=(ledger,self.api.s.jobs,self.api.s.assets,[],[],[self.api.parent],RUN,HEAD,2,self.now,
              self.api.s.objects.__getitem__)
        self.assertEqual(loss.loss_proof(*args)["parent_run"],str(RUN))
        job["conclusion"]="failure"
        with self.assertRaises(ValueError):
            loss.loss_proof(*args)

    def test_known_expired_relay_contrasts_with_missing_or_live_upload(self):
        svc=self.api
        upload=next(s for s in svc.job["steps"] if s["name"]==loss.RELAY[0])
        upload.update(conclusion="success",started_at=svc.times["prior"],completed_at=svc.times["prior"])
        row=svc.s.asset(f"r28-{RUN}-a1-s02-outcome","checkpoint.cms","expired")
        row.update(created_at=svc.times["prior"],expired=True,expires_at=svc.times["observed"])
        svc.s.objects[row["id"]]=dict(row)
        self.assertEqual(self.enter()["ordinal"],2)
        row["expired"]=False
        svc.s.objects[row["id"]]=dict(row)
        with self.assertRaises(ValueError): self.enter()
        svc.s.assets.remove(row)
        with self.assertRaises(ValueError): self.enter()

    def test_uncertain_or_retained_source_is_never_a_new_interval(self):
        for scenario in ("missing-journal","foreign-origin","private-part","cached","upload-response-lost","no-progress","already-received"):
            with self.subTest(scenario=scenario):
                service=Service(self.now)
                if scenario=="missing-journal": service.s.assets.clear()
                elif scenario=="foreign-origin": service.job["head_sha"]="d"*40
                elif scenario=="private-part": service.add(f"r28-{RUN}-a1-s02-p00",b"still here",990,"prior")
                elif scenario=="cached": service.caches=[dict(key=f"bare-coexist-204-apk-v1-{RUN}-1-s2",id=874)]
                elif scenario=="upload-response-lost": next(s for s in service.job["steps"] if s["name"]==loss.RELAY[0])["conclusion"]="failure"
                elif scenario=="no-progress": next(s for s in service.job["steps"] if s["name"].startswith("Certify"))["conclusion"]="skipped"
                else:
                    child=candidate(2)
                    service.s.slot(2,child)
                with patch.object(self,"api",service),self.assertRaises(ValueError): self.enter()
                self.assertEqual(service.posts,0)


if __name__=="__main__":
    main()
