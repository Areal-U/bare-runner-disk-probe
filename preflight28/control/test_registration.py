import hashlib
import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from registration import BASE_REF, CAMPAIGN, CLAIM, OWNER, RECIPIENT, RELEASE_ID, REPO, REPO_ID, S2_SHA, WORKFLOW, bind


class OwnerDraft:
    BASE = "test"
    def __init__(self):
        self.ticket = dict(schema=1,campaign=CAMPAIGN,repository_id=REPO_ID,workflow=WORKFLOW,branch=BASE_REF,
                           head="a"*40,initial_parent=S2_SHA,release_id=RELEASE_ID,recipient=RECIPIENT,
                           collector_registration_id="Automation_"+"f"*32, issued_at="2026-11-25T01:00:00Z",
                           expires_at="2026-11-28T01:00:00Z")
        self.asset = dict(name=CAMPAIGN+"-collection-registration.json",id=901,uploader=OWNER,created_at="2026-11-25T01:00:00Z")
        self.origin = dict(id=81,run_attempt=1,head_sha="a"*40,path=WORKFLOW,event="workflow_dispatch",
                           head_branch=BASE_REF,actor=OWNER,repository={"id":REPO_ID},head_repository={"id":REPO_ID},
                           created_at="2026-11-25T01:03:00Z")
    def data(self): return json.dumps(self.ticket).encode()
    def draft(self, rid):
        assert rid == RELEASE_ID
        return {"assets":[dict(self.asset,size=len(self.data()),digest="sha256:"+hashlib.sha256(self.data()).hexdigest())]}
    def asset_info(self, release, name, size, sha, aid):
        assert len(self.data()) == size and aid == 901
    def metadata(self, path): return self.origin
    def download(self, aid, size, digest, target): target.write(self.data())


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.d = OwnerDraft()
        self.env = dict(REGISTRATION_ASSET_ID="901",GITHUB_SHA="a"*40,GITHUB_JOB="bind-private-receiver",
                        GITHUB_RUN_ID="81",GITHUB_RUN_ATTEMPT="1",GITHUB_REPOSITORY=REPO,GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_REF="refs/heads/"+BASE_REF)
        self.event = dict(repository={"id":REPO_ID},sender=OWNER,inputs={"mode":"build-apk","build_segments":"12","apk_recipient":RECIPIENT})
        self.now = datetime(2026,11,26,tzinfo=timezone.utc)
    def enter(self):
        self.env["REGISTRATION_SHA"]=hashlib.sha256(self.d.data()).hexdigest()
        return bind(self.d,self.env,self.event,self.now)
    @patch("registration.admit",return_value=123)
    def test_prior_registration_and_binding(self, claim):
        self.assertEqual(self.enter()[0],123)
        holder=claim.call_args.args[1]
        self.assertEqual((holder["run_id"],holder["producer_attempt"],holder["ticket_asset_id"]),(81,1,901))
        self.assertEqual(claim.call_args.kwargs["name"],CLAIM)
    @patch("registration.admit",return_value=92)
    def test_dispatch_with_defaults_discovers_exact_owner_ticket(self, claim):
        self.env.update(REGISTRATION_ASSET_ID="",REGISTRATION_SHA="")
        self.assertEqual(bind(self.d,self.env,self.event,self.now)[0],92)
        self.assertEqual(claim.call_args.args[1]["ticket_asset_id"],901)
        asset=self.d.draft(RELEASE_ID)["assets"][0]
        with patch.object(self.d,"draft",return_value={"assets":[asset,asset]}), self.assertRaises(ValueError):
            bind(self.d,self.env,self.event,self.now)
    @patch("registration.admit")
    def test_ticket_not_prepared_earlier_or_wrong_actor_or_expired(self, claim):
        for target, key, bad in [(self.d.asset,"created_at","2026-11-25T01:04:00Z"),
                                (self.d.ticket,"expires_at","2026-11-25T01:04:00Z"),
                                (self.d.ticket,"head","f"*40),(self.d.ticket,"collector_registration_id",""),
                                (self.d.asset,"uploader",{}),(self.env,"GITHUB_RUN_ATTEMPT","2"),(self.env,"REGISTRATION_ASSET_ID","")]:
            with self.subTest(key=key), patch.dict(target,{key:bad}), self.assertRaises(ValueError):
                self.enter()
        claim.assert_not_called()
