import hashlib
import json
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit
from registration import BASE_REF, CAMPAIGN, CLAIM, FIRST_HEAD, FIRST_JOBS, FIRST_RUN, TICKET_NAME, OWNER, RECIPIENT, RELEASE_ID, REPO, REPO_ID, S2_SHA, WORKFLOW, bind


class OwnerDraft:
    BASE = "test"
    def __init__(self):
        self.ticket = dict(schema=1,campaign=CAMPAIGN,repository_id=REPO_ID,workflow=WORKFLOW,branch=BASE_REF,
                           head="a"*40,initial_parent=S2_SHA,release_id=RELEASE_ID,recipient=RECIPIENT,
                           collector_registration_id="Automation_"+"f"*32, issued_at="2026-11-25T01:00:00Z",
                           expires_at="2026-11-28T01:00:00Z")
        self.ack=dict(schema=1, campaign=CAMPAIGN, branch=BASE_REF,head="a"*40,collector_registration_id="Automation_"+"f"*32,
                      owner_destination_id="libfile_private_owner",registration_nonce="b"*32,recipient=RECIPIENT,
                      observed_at="2026-11-25T00:58:00Z",valid_until="2026-11-29T00:00:00Z",state="collector-read-back-owner-reservation",
                      poll_seconds=3600,pickup_retry_seconds=900)
        storage = dict(storage_policy="github-public-standard-r28-v1",artifact_ceiling_bytes=10*1024**3,
                       storage_valid_until="2027-01-01T00:00:00Z")
        self.ack.update(storage)
        self.ticket.update(storage)
        self.ticket.update(registration_nonce=self.ack["registration_nonce"],owner_destination_id=self.ack["owner_destination_id"],
                           collector_ack_asset_id=812,collector_ack_sha=hashlib.sha256(self.data(812)).hexdigest())
        self.ack_asset = dict(name=CAMPAIGN+"-collector-ack-"+self.ticket["registration_nonce"]+".json",id=812,
                              created_at="2026-11-25T00:59:00Z")
        self.asset = dict(name=TICKET_NAME,id=901,uploader=OWNER,created_at="2026-11-25T01:00:00Z")
        from registration import PREVIOUS_CAMPAIGN, PREVIOUS_HEAD
        self.prior = dict(self.ticket, campaign=PREVIOUS_CAMPAIGN, head=PREVIOUS_HEAD,
            collector_registration_id="Automation_"+"2"*32, registration_nonce="3"*32)
        self.first = dict(self.ticket,head=FIRST_HEAD,registration_nonce="6"*32,collector_ack_sha="7"*64)
        self.first_jobs = [dict(id=i, run_id=FIRST_RUN, run_attempt=1, head_sha=FIRST_HEAD, status="completed", conclusion=c)
                           for i,c in {**FIRST_JOBS,40:"skipped"}.items()]
        self.origin = dict(id=81,run_attempt=1,head_sha="a"*40,path=WORKFLOW,event="workflow_dispatch",
                           head_branch=BASE_REF,actor=OWNER,repository={"id":REPO_ID},head_repository={"id":REPO_ID},
                           created_at="2026-11-25T01:03:00Z")
    def data(self,n=901): return json.dumps(self.prior if n==700 else self.first if n==701 else self.ticket if n==901 else self.ack).encode()
    def draft(self, rid):
        assert rid == RELEASE_ID
        return {"assets":[dict(self.asset,size=len(self.data()),digest="sha256:"+hashlib.sha256(self.data()).hexdigest()),dict(self.ack_asset,size=len(self.data(812))), dict(name=CAMPAIGN+"-collection-registration.json",id=701,state="uploaded",uploader=OWNER,size=len(self.data(701)),digest="sha256:"+hashlib.sha256(self.data(701)).hexdigest()), dict(name=self.prior["campaign"]+"-collection-registration.json",id=700,state="uploaded",uploader=OWNER,size=len(self.data(700)),digest="sha256:"+hashlib.sha256(self.data(700)).hexdigest())]}
    def asset_info(self, release, name, size, sha, aid):
        assert len(self.data(aid)) == size and aid in (901,812,700,701)
    def metadata(self, path):
        first = f"{self.BASE}/actions/runs/{FIRST_RUN}/attempts/1"
        if path == first:
            return dict(self.origin,id=FIRST_RUN,head_sha=FIRST_HEAD,conclusion="failure",status="completed")
        if path == first+"/jobs?per_page=100":
            return dict(total_count=len(self.first_jobs),jobs=self.first_jobs)
        if path == "/repos/"+REPO:
            return dict(id=REPO_ID,full_name=REPO,private=False,fork=False,visibility="public")
        if "/actions/runs?status=" in path:
            return dict(total_count=0,workflow_runs=[])
        if "/actions/artifacts?" in path:
            return dict(total_count=0,artifacts=[])
        if "/releases/" in path:
            return self.draft(RELEASE_ID)["assets"]
        return self.origin
    def download(self, aid, size, digest, target): target.write(self.data(aid))


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.d = OwnerDraft()
        first = patch("registration.FIRST_TICKET_SHA", hashlib.sha256(self.d.data(701)).hexdigest())
        first.start()
        self.addCleanup(first.stop)
        prior = patch("registration.PREVIOUS_TICKET_SHA", hashlib.sha256(self.d.data(700)).hexdigest())
        prior.start()
        self.addCleanup(prior.stop)
        self.env = dict(RUNNER_ENVIRONMENT="github-hosted",REGISTRATION_ASSET_ID="901",GITHUB_SHA="a"*40,GITHUB_JOB="bind-private-receiver",
                        GITHUB_RUN_ID="81",GITHUB_RUN_ATTEMPT="1",GITHUB_REPOSITORY=REPO,GITHUB_EVENT_NAME="workflow_dispatch",
                        GITHUB_REF="refs/heads/"+BASE_REF)
        self.event = dict(repository={"id":REPO_ID},sender=OWNER,inputs={"mode":"build-apk","build_segments":"12","apk_recipient":RECIPIENT})
        self.now = datetime(2026,11,26,tzinfo=timezone.utc)
    def enter(self):
        self.env["REGISTRATION_SHA"]=hashlib.sha256(self.d.data()).hexdigest()
        return bind(self.d,self.env,self.event,self.now)

    def test_late_page_registration_ack_and_lost_claim_response(self):
        class Release(OwnerDraft):
            UPLOAD = "uploads.github.com"

            def __init__(self):
                super().__init__()
                ticket, ack, first, prior = super().draft(RELEASE_ID)["assets"]
                self.assets = [dict(id=i, name="old-"+str(i)) for i in range(1,101)] + [ticket, ack, first, prior]
                self.assets.extend(dict(id=i, name="old-"+str(i)) for i in range(101,199))
                self.posts = 0
                self.pages = []

            def draft(self, ident):
                self.assert_release(ident)
                return {"assets": self.assets[:30]}

            def assert_release(self, ident):
                assert ident == RELEASE_ID

            def metadata(self, path):
                if "/releases/" not in path:
                    return super().metadata(path)
                uri = urlsplit(path)
                assert uri.path.endswith(f"/releases/{RELEASE_ID}/assets")
                query = parse_qs(uri.query)
                assert query["per_page"] == ["100"]
                page = int(query["page"][0])
                self.pages.append(page)
                return self.assets[(page-1)*100:page*100]

            def request(self, host, method, path, **args):
                assert host == self.UPLOAD and method == "POST" and args["auth"]
                assert parse_qs(urlsplit(path).query)["name"] == [CLAIM]
                self.posts += 1
                self.claim = args["body"]
                self.assets.append(dict(id=940, name=CLAIM, size=len(self.claim),
                                        digest="sha256:"+hashlib.sha256(self.claim).hexdigest()))
                raise ConnectionResetError("response lost after creation")

            def asset_info(self, release, name, size, digest, aid=None):
                matches = [a for a in release["assets"] if a["name"] == name]
                assert len(matches) == 1
                record = matches[0]
                assert record["size"] == size and (aid is None or record["id"] == aid)
                if aid is None and record["digest"] != "sha256:" + digest:
                    raise ValueError("Immutable claim digest differs")
                return record

            def download(self, aid, size, digest, target):
                data = self.claim if aid == 940 else self.data(aid)
                assert len(data) == size and hashlib.sha256(data).hexdigest() == digest
                target.write(data)

        self.d=Release()
        self.env.update(REGISTRATION_ASSET_ID="",REGISTRATION_SHA="")
        self.assertEqual(bind(self.d,self.env,self.event,self.now)[0],940)
        self.env["GITHUB_JOB"]="collection-lease"
        self.assertEqual(bind(self.d,self.env,self.event,self.now,verify_only=True)[0],940)
        # A later run using the same approved ticket cannot replace the claim.
        self.env.update(GITHUB_RUN_ID="82", GITHUB_JOB="bind-private-receiver")
        self.d.origin["id"] = 82
        with self.assertRaisesRegex(ValueError, "Immutable claim digest differs"):
            bind(self.d, self.env, self.event, self.now)
        self.assertEqual(self.d.posts,1)
        self.assertGreaterEqual(self.d.pages.count(3),3)
    @patch("registration.admit")
    def test_nominal_ticket_cannot_reserve_a_legacy_or_alternate_build(self, claim):
        fixed = dict(checkpoint_key="bare-coexist-204-45285202990-1-checkpoint-production-s2",
                     checkpoint_sha=S2_SHA, checkpoint_identity="a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc")
        for override in ({"checkpoint_backend":"cache"}, {"checkpoint_compression":"unknown"}, dict(fixed,build_segments="1"), dict(fixed,build_segments="2"),
                         dict(fixed,checkpoint_key="foreign"), {"checkpoint_sha":S2_SHA}, {"compile_minutes":"25"},
                         {"loss_origin_run":"42"}, {"retain_existing_caches":"true"}, {"jobs":"1"}, {"output_gib":"19"},
                         {"encrypted_apk_bytes":"859"}, {"apk_recipient":"other"}):
            with self.subTest(override=override), patch.dict(self.event["inputs"],override), \
                 patch.object(self.d,"metadata",side_effect=AssertionError("Unexpected provider I/O")), \
                 self.assertRaises(ValueError):
                self.enter()
        claim.assert_not_called()
        with patch.dict(self.event["inputs"],dict(fixed,compile_minutes="180")):
            self.enter()
        claim.assert_called_once()

    @patch("registration.admit")
    def test_unconfirmed_storage_never_writes_origin_claim(self, claim):
        del self.d.ticket["artifact_ceiling_bytes"]
        with self.assertRaisesRegex(ValueError, "storage policy"):
            self.enter()
        claim.assert_not_called()

    @patch("registration.admit",return_value=123)
    def test_prior_registration_and_binding(self, claim):
        self.assertEqual(self.enter()[0],123)
        holder=claim.call_args.args[1]
        self.assertEqual((holder["run_id"],holder["producer_attempt"],holder["ticket_asset_id"]),(81,1,901))
        self.assertEqual(claim.call_args.kwargs["name"],CLAIM)
    @patch("registration.admit",return_value=92)
    def test_dispatch_with_defaults_discovers_exact_owner_ticket(self, claim):
        self.env.update(REGISTRATION_ASSET_ID="",REGISTRATION_SHA="")
        self.event["inputs"]={}
        self.assertEqual(bind(self.d,self.env,self.event,self.now)[0],92)
        self.assertEqual(claim.call_args.args[1]["ticket_asset_id"],901)
        asset=self.d.draft(RELEASE_ID)["assets"][0]
        with patch.object(self.d,"draft",return_value={"assets":[asset,asset]}), self.assertRaises(ValueError):
            bind(self.d,self.env,self.event,self.now)
    @patch("registration.admit",return_value=123)
    def test_once_ack_reused_only_while_lease_covers_remaining_local_segment(self, claim):
        self.env.update(REGISTRATION_ASSET_ID="",REGISTRATION_SHA="",GITHUB_JOB="collection-lease")
        bind(self.d,self.env,self.event,self.now,verify_only=True)
        self.assertEqual(claim.call_args.args[0],"recover")
        self.d.ack["valid_until"]="2026-11-26T04:00:00Z"
        self.d.ticket["collector_ack_sha"]=hashlib.sha256(self.d.data(812)).hexdigest()
        with self.assertRaisesRegex(ValueError,"lease"):
            bind(self.d,self.env,self.event,self.now,verify_only=True)
        self.d.ack["valid_until"]="2026-11-28T04:00:00Z"
        with self.assertRaisesRegex(ValueError,"ACK bytes"):
            bind(self.d,self.env,self.event,self.now,verify_only=True)

    @patch("registration.admit")
    def test_previous_ticket_and_previous_ack_cannot_activate_this_campaign(self, claim):
        from registration import PREVIOUS_CAMPAIGN
        with patch.dict(self.d.ticket, campaign=PREVIOUS_CAMPAIGN), self.assertRaisesRegex(
                ValueError, "another campaign"):
            self.enter()
        with patch.dict(self.d.ack, campaign=PREVIOUS_CAMPAIGN):
            pinned = hashlib.sha256(self.d.data(812)).hexdigest()
            with patch.dict(self.d.ticket, collector_ack_sha=pinned), self.assertRaisesRegex(
                    ValueError, "ACK disagrees with owner ticket: campaign"):
                self.enter()
        claim.assert_not_called()

    @patch("registration.admit")
    def test_conflicting_predecessor_reservation_cannot_claim(self, claim):
        for change in (dict(owner_destination_id="different_owner_destination"),
                       dict(registration_nonce=self.d.prior["registration_nonce"]),
                       dict(collector_registration_id=self.d.prior["collector_registration_id"])):
            with self.subTest(change=change), patch.dict(self.d.ticket,change), self.assertRaises(ValueError):
                self.enter()
        with patch.dict(self.d.prior,campaign="foreign"), self.assertRaises(ValueError):
            self.enter()
        claim.assert_not_called()

    @patch("registration.admit")
    def test_reissue_keeps_original_collector_and_consumption_limits(self, claim):
        for change in [dict(collector_registration_id="Automation_"+"8"*32), dict(registration_nonce="6"*32),
                       dict(collector_ack_sha="7"*64), dict(artifact_ceiling_bytes=11*1024**3),
                       dict(storage_valid_until="2028-01-01T00:00:00Z"), dict(expires_at="2028-01-01T00:00:00Z")]:
            with self.subTest(change=change), patch.dict(self.d.ticket,change), self.assertRaises(ValueError):
                self.enter()
        claim.assert_not_called()

    @patch("registration.admit")
    def test_reissue_refuses_another_runnable_job_or_missing_failed_binder(self, claim):
        with patch.dict(self.d.first_jobs[-1],conclusion="success"), self.assertRaisesRegex(ValueError, "closure"):
            self.enter()
        with patch.dict(self.d.first_jobs[1],conclusion="skipped"), self.assertRaisesRegex(ValueError, "closure"):
            self.enter()
        claim.assert_not_called()

    def test_lease_includes_receiver_private_deposit_and_receipt(self):
        from registration import checked_ack, instant
        created = instant(self.d.origin["created_at"])
        expiry = instant(self.d.ticket["expires_at"])
        latest, _ = checked_ack(self.d,self.d.draft(RELEASE_ID),self.d.ticket,created,created)
        self.assertEqual(int(expiry.timestamp())-latest,(350+25+45+7)*60+2*3600+900)

    @patch("registration.admit", return_value=123)
    def test_owner_ack_discovery_pins_immutable_id_and_bytes(self, claim):
        del self.d.ticket["collector_ack_asset_id"]
        self.d.ack_asset.update(state="uploaded", uploader=OWNER, digest="sha256:"+self.d.ticket["collector_ack_sha"])
        self.assertEqual(self.enter()[0],123)
        self.assertEqual(claim.call_args.args[1]["collector_ack_asset_id"],812)
        claim.reset_mock()
        for key, bad in (("name", "foreign.json"), ("id", True), ("uploader", {"login":"other","id":292261483}),
                         ("digest","sha256:"+"9"*64),("state","starter"), ("created_at","2026-11-25T02:00:00Z")):
            with self.subTest(key=key), patch.dict(self.d.ack_asset,{key:bad}), self.assertRaises(ValueError):
                self.enter()
        for bad in (None, False, "812", 999):
            with self.subTest(pinned=bad), patch.dict(self.d.ticket,collector_ack_asset_id=bad), self.assertRaises(ValueError):
                self.enter()
        rows = self.d.draft(RELEASE_ID)["assets"]
        with patch.object(self.d,"draft",return_value={"assets":[*rows,dict(rows[1],id=814)]}), self.assertRaises(ValueError):
            self.enter()
        with patch.dict(self.d.ack,head="f"*40), self.assertRaises(ValueError):
            self.enter()
        claim.assert_not_called()

    @patch("registration.admit")
    def test_ticket_not_prepared_earlier_or_wrong_actor_or_expired(self, claim):
        for target, key, bad in [(self.d.asset,"created_at","2026-11-25T01:04:00Z"),
                                (self.d.ticket,"expires_at","2026-11-25T01:04:00Z"),
                                (self.d.ticket,"head","f"*40),(self.d.ticket,"collector_registration_id",""),
                                (self.d.asset,"uploader",{}),(self.env,"GITHUB_RUN_ATTEMPT","2"),(self.env,"REGISTRATION_ASSET_ID","")]:
            with self.subTest(key=key), patch.dict(target,{key:bad}), self.assertRaises(ValueError):
                self.enter()
        claim.assert_not_called()
