"""One fresh run may continue the accepted R30 slot-1 bytes at logical slot 2."""
import re

from admission import BASE_REF, REPO_ID, RELEASE_ID, S2_SHA, require
import slot1_handoff as old

CAMPAIGN = old.CAMPAIGN
SOURCE_RUN = 45771045621
SOURCE_HEAD = "9869f9af1ba14eeb943e6ef38af7dc77456f4ec3"
SOURCE_CLAIM_ID = 794665611
SOURCE_CLAIM_SHA = "6d33d3c3c0fec79b98b7628e26c6a920bb17413be6db6c20e4ff6a6fe956b70d"
SOURCE_TICKET_ID = 794655609
SOURCE_TICKET_SHA = "1b5e39349364e348652ce7b23e8f9838f810c3965d8502b617e6126bb4d44068"
PARENT_SHA = "fa44728d39b61c25d4116579e6da2c63ca7898cec24ada0e7ae453548bbd73bf"
PARENT_IDENTITY = "8f6e0fc60ac76d6558ff3f7f593a8db5a3a5c2da523b251b3847fb594fa2e3be"
MANIFEST_ID = 795559195
MANIFEST_SHA = "f48700364b590b28188715d565d564b1afba5d5d90df1e4b98efa5cef04971c8"
SOURCE_CLAIM_NAME = old.CLAIM
SOURCE_TICKET_NAME = old.TICKET_NAME
TICKET_NAME = CAMPAIGN + "-s02-resume-collection-registration.json"
CLAIM = CAMPAIGN + "-s02-resume-795559195.json"
TRIAL_BRANCH = "bare-r30-s1-restore-20261126"
TRIAL_WORKFLOW = ".github/workflows/bare-disk-probe.yml"
SOURCE_SUCCESS = {139743505816,139743534349,139743721608,139743808787,139743809962,
                  139875979725,139876103607,139876268785}
SOURCE_FAILED = {139876269687,139894938365,139895004680}
NEGATIVE = "Reject changed inputs on the restored candidate"
FRONTIER = "Verify the received APK frontier and establish the segment baseline"
COMPILE = "Run the real APK target within its time and output budgets"
CERTIFICATION = "Certify the fixed S1 restore"
TRIAL_LAUNCHER_BLOB = "9df05ba086ea2c45e3200378e21967636df22a94"


def source_rows():
    return ((SOURCE_CLAIM_NAME,SOURCE_CLAIM_ID,791,SOURCE_CLAIM_SHA,False),
            (SOURCE_TICKET_NAME,SOURCE_TICKET_ID,941,SOURCE_TICKET_SHA,True))


def fields(row, expected, why):
    require(all(type(row.get(k)) is type(v) and row[k] == v for k,v in expected.items()),why)


def route(ticket):
    expected = dict(source_run_id=SOURCE_RUN, manifest_id=MANIFEST_ID, manifest_sha=MANIFEST_SHA,
                    initial_parent=PARENT_SHA)
    fields(ticket,expected,"Different candidate or source run in the registration")
    trial,head=ticket.get("trial_run_id"),ticket.get("trial_head")
    require(type(trial) is int and trial > 0 and trial != SOURCE_RUN and
            isinstance(head,str) and re.fullmatch("[0-9a-f]{40}",head) and head != SOURCE_HEAD,
            "Unidentified independent candidate trial")
    return dict(expected,trial_run_id=trial,trial_head=head)


def check_binding(source, prior, ticket):
    from registration import RECIPIENT, WORKFLOW
    common = dict(schema=1,campaign=CAMPAIGN,repository_id=REPO_ID,release_id=RELEASE_ID,
                  recipient=RECIPIENT,workflow=WORKFLOW,branch=BASE_REF)
    fields(source,dict(common,head=SOURCE_HEAD,run_id=SOURCE_RUN,producer_attempt=1,
                       initial_parent=S2_SHA,ticket_asset_id=SOURCE_TICKET_ID,ticket_sha=SOURCE_TICKET_SHA,
                       collector_ack_asset_id=794652106),"Different physical slot-1 grant")
    old.check_reference(source)
    fields(prior,dict(common,head=SOURCE_HEAD,initial_parent=S2_SHA,
                      collector_ack_sha="c153213cbc5de78f41b6f55b8639346ba616cd74cffd68d3326b465ce2a734c0",
                      collector_registration_id=source["registration_id"]),"Different previous receiver")
    fields(ticket,common,"Changed repository, owner recipient, workflow or branch")
    route(ticket)
    for key in ("collector_registration_id","owner_destination_id","artifact_ceiling_bytes",
                "storage_policy","expires_at","storage_valid_until"):
        fields(ticket,{key:prior[key]},"Changed owner service, destination or storage policy")
    require(all(ticket[k] != prior[k] for k in ("head","registration_nonce","collector_ack_sha")),
            "Reused closed owner reservation")


def checked_run(helper,rid,head,branch,workflow,conclusion):
    from registration import OWNER
    path = f"{helper.BASE}/actions/runs/{rid}"
    run = helper.metadata(path)
    fields(run,dict(id=rid,run_attempt=1,head_sha=head,head_branch=branch,path=workflow,event="workflow_dispatch",
                    status="completed",conclusion=conclusion),"Foreign, unfinished or rerun admission evidence")
    require(run["repository"]["id"] == run["head_repository"]["id"] == REPO_ID and
            all(run["actor"].get(k) == v for k,v in OWNER.items()),"Foreign actor or repository")
    page=helper.metadata(path+"/attempts/1/jobs?per_page=100")
    jobs=page["jobs"]
    require(0<len(jobs)==len({j["id"] for j in jobs})==page["total_count"]<=100 and
            all(j["run_id"]==rid and j["run_attempt"]==1 and j["head_sha"]==head and
                j["status"]=="completed" for j in jobs),"Incomplete trial or source job inventory")
    return {j["id"]:j for j in jobs}


def proof_source(helper, head, *, trial=False):
    tree = helper.metadata(f"{helper.BASE}/git/trees/{head}?recursive=1")
    require(tree.get("truncated") is False, "Incomplete source tree")
    if trial:
        launcher = [row["sha"] for row in tree["tree"] if row["path"] == TRIAL_WORKFLOW and row["type"] == "blob"]
        require(launcher == [TRIAL_LAUNCHER_BLOB], "Unreviewed trial entry or certification")
    paths = (".github/workflows/bare-arm64-probe.yml", "preflight28/graph", "preflight28/transport",
             "preflight28/bridge/bridge.py", "preflight28/bridge/artifact_poll.py", "preflight28/bridge/frames.py",
             "preflight28/bridge/normal.py",
             "preflight28/bridge/r30_parent.py", "preflight28/bridge/check_archive.py",
             "preflight28/bridge/verify_payload.py", "checkpoint.py", "build_trial.py", "coexist_inputs.py")
    found = {row["path"]:row["sha"] for row in tree["tree"] if row["path"] in paths}
    require(len(found)==len(paths) and all(re.fullmatch("[a-f0-9]{40}",sha) for sha in found.values()),
            "Trial implementation is missing")
    return found


def validate_trial(helper,ticket):
    fixed=route(ticket)
    require(proof_source(helper,fixed["trial_head"],trial=True) == proof_source(helper,ticket["head"]),
            "Production frontier or checkpoint verifier differs from the certified trial")
    jobs=checked_run(helper,fixed["trial_run_id"],fixed["trial_head"],TRIAL_BRANCH,TRIAL_WORKFLOW,"success")
    cert=[j for j in jobs.values() if j["name"]==CERTIFICATION]
    require(len(cert)==1 and cert[0]["conclusion"]=="success","Missing fixed candidate certification")
    compute=[j for j in jobs.values() if any(s["name"]==NEGATIVE for s in j.get("steps",[]))]
    require(len(compute)==1 and compute[0]["conclusion"]=="success","Missing independent restore job")
    checks={s["name"]:s["conclusion"] for s in compute[0]["steps"]}
    fields(checks,{NEGATIVE:"success",FRONTIER:"success",COMPILE:"skipped"},
           "Negative control, complete frontier or compile prohibition unverified")


def validate_source(helper, release, ticket, *, initial):
    inputs=[old.read_fixed(helper,release,name,aid,n,sha,owner=owner)
            for name,aid,n,sha,owner in source_rows()]
    check_binding(*inputs,ticket)
    if initial:
        require(not any(r["name"]==CAMPAIGN+"-loss-replacement-claim.json" for r in release["assets"]),
                "An exceptional producer already owns this campaign")
        jobs=checked_run(helper,SOURCE_RUN,SOURCE_HEAD,BASE_REF,".github/workflows/bare-checkpoint-transfer.yml","failure")
        require(len(jobs)==45 and {i for i,r in jobs.items() if r["conclusion"]=="success"}==SOURCE_SUCCESS
                and {i for i,r in jobs.items() if r["conclusion"]=="failure"}==SOURCE_FAILED
                and all(r["conclusion"]=="skipped" for i,r in jobs.items() if i not in SOURCE_SUCCESS|SOURCE_FAILED),
                "Original campaign state changed")
        steps={s["name"]:s["conclusion"] for s in jobs[139876269687]["steps"]}
        fields(steps,{FRONTIER:"failure",COMPILE:"skipped"},"Original slot 2 already computed")
        rows=[a for a in release["assets"] if a.get("id")==MANIFEST_ID]
        require(len(rows)==1 and rows[0]["name"] in
                (f"r28-{SOURCE_RUN}-a1-s01-manifest.json",f"r28-{SOURCE_RUN}-a1-s01-manifest.json-retry1"),
                "Missing fixed candidate manifest")
        old.read_fixed(helper,release,rows[0]["name"],MANIFEST_ID,948,MANIFEST_SHA)
        validate_trial(helper,ticket)


def check_reference(claim,ticket):
    fields(claim,dict(route(ticket),source_claim_id=SOURCE_CLAIM_ID,source_claim_sha=SOURCE_CLAIM_SHA),
           "Unbound slot-2 claim or different independent trial")
    require(type(claim.get("run_id")) is int and claim["run_id"]>0 and
            claim["run_id"] not in (SOURCE_RUN,ticket["trial_run_id"]),"Circular slot-2 claim")
