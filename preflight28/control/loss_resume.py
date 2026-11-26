"""One replacement interval following positively certified loss of the original VM and durable output."""
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlencode

import admission
from admission import BASE_REF, BASE_SHA, RELEASE_ID, REPO, REPO_ID, S2_SHA, PagedOwnerDraft, require
import loss_marker
import receipt_journal as journal
import recover
import registration as reg

LOSS_CLAIM = reg.CAMPAIGN + "-loss-replacement-claim.json"
S2_KEY = "bare-coexist-204-45285202990-1-checkpoint-production-s2"
FRONTIER = "Verify the received APK frontier and establish the segment baseline"
COMPILE = "Run the real APK target within its time and output budgets"
PACK = "Pack the completed intermediate outputs"
APK = "Verify the completed APK and encrypt it for private recovery"
RELAY = ("Deposit outcome in this run", "Retry the same sealed files at the same immutable name once")
CIPHER = "Upload the encrypted APK bundle"
CACHE = "Save only the encrypted APK for retrieval retry"
PRIVATE_WRITES = ("Receive bounded ciphertext and independently verify fixed private publication",
                  "Deposit and read back the owner-encrypted bytes and immutable receiver record")
TRANSFER_STOPS = {"relay-quota-denied","relay-capacity-exceeded","relay-deadline","relay-missing","relay-ambiguous"}


def fields(row, expected):
    require(all(k in row and type(row[k]) is type(v) and row[k] == v for k,v in expected.items()),
            "Record does not match its physical operation")


def named(api, release, name, *, owner=False):
    matches = [a for a in release["assets"] if a["name"] == name]
    require(len(matches) == 1, "Missing or ambiguous " + name)
    asset, = matches
    digest = (asset.get("digest") or "").removeprefix("sha256:")
    require(asset["state"] == "uploaded" and type(asset["id"]) is int and asset["id"] > 0 and
            0 < asset["size"] <= 8192 and re.fullmatch(r"[0-9a-f]{64}",digest) and
            asset["digest"] == "sha256:" + digest, "Unconfirmed immutable private record")
    if owner:
        fields(asset["uploader"],reg.OWNER)
    api.asset_info(release,name,asset["size"],digest,asset["id"])
    raw = io.BytesIO()
    api.download(asset["id"],asset["size"],digest,raw)
    require(hashlib.sha256(raw.getvalue()).hexdigest() == digest,"Private record failed readback")
    return json.loads(raw.getvalue()), asset["id"], digest, reg.instant(asset["created_at"])


def pages(api, path, key):
    result = []
    total = None
    sep = "&" if "?" in path else "?"
    for index in range(1,101):
        row = api.metadata(f"{api.BASE}/{path}{sep}per_page=100&page={index}")
        batch = row[key]
        require(type(batch) is list and len(batch) <= 100 and
                type(row["total_count"]) is int and (total is None or total == row["total_count"]),
                "Provider inventory changed")
        total = row["total_count"]
        result.extend(batch)
        if len(batch) < 100:
            require(len(result) == total == len({x["id"] for x in result}),"Incomplete provider inventory")
            return result
    raise ValueError("Unbounded provider inventory")


def identity(api, run, head, attempt=None):
    suffix = "" if attempt is None else f"/attempts/{attempt}"
    row = api.metadata(f"{api.BASE}/actions/runs/{run}{suffix}")
    fields(row,dict(id=run,head_sha=head,head_branch=BASE_REF,path=reg.WORKFLOW,event="workflow_dispatch"))
    if attempt is not None:
        fields(row,dict(run_attempt=attempt))
    fields(row["actor"],reg.OWNER)
    require(row["repository"]["id"] == row["head_repository"]["id"] == REPO_ID,"Wrong repository")
    return row


def state(job, step):
    entries = [s for s in job["steps"] if s["name"] == step]
    require(len(entries) == 1 and entries[0].get("conclusion") in
            ("skipped","success","failure","cancelled","timed_out"), "Original step has no definitive provider state: " + step)
    return entries[0]["conclusion"]


def parent_at(records, k, run, head):
    require(1 <= k <= 12 and len(records) in (k-1,k),"Missing original receipt or later work exists")
    if len(records) == k:
        require(records[-1]["ordinal"] == k and records[-1]["status"] in TRANSFER_STOPS,
                "The lost slot was already received or stopped for a different reason")
    if k == 1:
        return dict(parent_key=S2_KEY,parent_sha=S2_SHA,parent_identity=recover.S2_IDENTITY,
                    parent_manifest_id="",parent_manifest_sha="",parent_producer=BASE_SHA,parent_run="")
    last = records[k-2]
    fields(last,dict(ordinal=k-1,status="candidate",producer_sha=head,
                     key=f"bare-coexist-204-{run}-1-checkpoint-production-s{k-1}"))
    require(re.fullmatch("[1-9][0-9]*",last["manifest_id"]) and
            all(re.fullmatch("[a-f0-9]{64}",last[key]) for key in ("sha","identity","manifest_sha")),
            "Previous interval lacks an authenticated private manifest")
    return dict(parent_key=last["key"],parent_sha=last["sha"],parent_identity=last["identity"],
                parent_manifest_id=last["manifest_id"],parent_manifest_sha=last["manifest_sha"],
                parent_producer=head,parent_run=str(run))


def loss_proof(ledger, jobs, artifacts, caches, assets, records, run, head, k, now, metadata, download=None):
    parent = parent_at(records,k,run,head)
    job = journal.original_job(jobs,run,head,k,f"Compile or verify authenticated APK slot {k}")
    require(job is not None and state(job,FRONTIER) == "success" and
            state(job,COMPILE) in ("success","failure","cancelled","timed_out"),
            "No authenticated original interval advanced from this parent")
    fields(ledger,dict(producer_job_id=job["id"], parent_sha=parent["parent_sha"], pending_writes=0,
                       owner_copy="confirmed-absent",state="ledger-closed-no-durable-output"))
    require(reg.instant(ledger["observed_at"]).timestamp() >= journal.timestamp(job["completed_at"]),
            "Owner observation precedes original VM termination")
    require(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}",ledger["ledger_receipt_id"]) and
            type(ledger["ledger_version"]) is int and ledger["ledger_version"] > 0,"Unidentified owner ledger")
    # The collector identifies which actual product was lost. Packing may cleanly
    # skip a no-progress interval, so also bind its provider-observed advance path.
    product = ledger["lost_product"]
    if product == "checkpoint":
        require(state(job,COMPILE) == "success" and state(job,PACK) == "success" and
                state(job,"Certify an advanced checkpoint exists before transfer") == "success",
                "No completed advanced checkpoint")
    elif product == "interrupted-build":
        step = next(s for s in job["steps"] if s["name"] == COMPILE)
        require(job["conclusion"] in ("cancelled","timed_out") and step["started_at"] and
                state(job,COMPILE) in ("cancelled","failure","timed_out") and
                state(job,PACK) == state(job,APK) == "skipped",
                "No provider-confirmed interruption of an active build")
    else:
        require(product == "apk" and state(job,COMPILE) == state(job,APK) == "success","No original sealed APK")
        note = journal.read_note(artifacts,run,head,k,job,"seal",metadata,download or recover.download_note)
        require(note is not None,"Unconfirmed original APK seal")
        recover.apk_seal.validate(note,run=run,ordinal=k,head=head,parent=parent["parent_sha"])
    marker = product == "apk" and loss_marker.verified(artifacts,job,run,head,k,parent,now,metadata,
                                                     download or recover.download_note)
    prefix = f"r28-{run}-a1-s{k:02}-"
    require(not any(a["name"].startswith(prefix) for a in assets),"A partial or complete private deposit exists")
    key = f"bare-coexist-204-apk-v1-{run}-1-s{k}"
    require(not any(c["key"] == key for c in caches) and state(job,CACHE) == "skipped",
            "Fallback cache exists or its prior write lacks a provider loss record")
    for other in jobs:
        if other["name"].startswith(f"Bounded build segment {k} / ") and other.get("conclusion") != "skipped":
            require(other["status"] == "completed","Original job still active")
            for step in other.get("steps",[]):
                if marker and step["name"] == PRIVATE_WRITES[0]:
                    continue
                if step["name"] in PRIVATE_WRITES:
                    require(step.get("conclusion") == "skipped","Prior private publication needs transfer-only reconciliation")
    for name, uploads in ((prefix+"outcome",RELAY),(f"bare-personal-204-encrypted-{run}-1-s{k}",(CIPHER,))):
        if marker and name == prefix+"outcome":
            continue
        existing = journal.one_artifact(artifacts,name)
        attempted = [s for s in uploads if state(job,s) != "skipped"]
        if existing is None:
            require(not attempted,"Attempted upload without conclusive provider tombstone")
            continue
        require(attempted and existing["expired"] is True and reg.instant(existing["expires_at"]) <= now,
                "Original artifact may still be recoverable")
        created = journal.timestamp(existing["created_at"])
        source = [step["name"] for step in job["steps"] if step["name"] in attempted and
                  int(journal.timestamp(step["started_at"])) <= created <
                  int(journal.timestamp(step.get("completed_at") or job["completed_at"]))+1]
        require(len(source) == 1,"Expired object is not bound to one original upload")
        journal.checked_artifact(existing,run,head,job,source[0],metadata)
    return parent


def original_parent(api, release, origin, head, ticket, evidence, now):
    original = identity(api,origin,head,1)
    latest = identity(api,origin,head)
    require(original["status"] == latest["status"] == "completed" and
            max(reg.instant(x["updated_at"]) for x in (original,latest)) <= reg.instant(evidence["observed_at"]) <= now,
            "Original operation is active or postdates the owner loss evidence")
    jobs = pages(api,f"actions/runs/{origin}/attempts/1/jobs","jobs")
    require(all(row["status"] == "completed" for row in jobs),"Original VM lifecycle is unsettled")
    k = ticket["ordinal"]
    def inspect():
        artifacts = pages(api,f"actions/runs/{origin}/artifacts","artifacts")
        metadata = lambda aid: api.metadata(f"{api.BASE}/actions/artifacts/{aid}")
        records = recover.slot_chain(jobs,artifacts,origin,head,metadata,recover.download_note)
        cachekey = f"bare-coexist-204-apk-v1-{origin}-1-s{k}"
        query = urlencode(dict(key=cachekey,ref="refs/heads/"+BASE_REF))
        caches = pages(api,"actions/caches?"+query,"actions_caches")
        live = api.draft(RELEASE_ID)
        result = loss_proof(evidence,jobs,artifacts,caches,live["assets"],records,origin,head,k,now,metadata)
        if k > 1:
            matches = [x for x in live["assets"] if str(x["id"]) == result["parent_manifest_id"]]
            manifest = f"r28-{origin}-a1-s{k-1:02}-manifest.json"
            require(len(matches) == 1 and matches[0]["name"] in (manifest, manifest+"-retry1"),
                    "Accepted predecessor manifest is unavailable")
            row, = matches
            api.asset_info(live,row["name"],row["size"],result["parent_manifest_sha"],row["id"])
        return result
    first = inspect()
    require(first == inspect() and identity(api,origin,head) == latest,"Original recovery state changed")
    return first


def original_grant(api, run, head, issued):
    rows = pages(api,f"actions/runs/{run}/attempts/1/jobs","jobs")
    grants = [j for j in rows if j["name"] == "Reserve one confirmed lost physical interval" and
              j["run_attempt"] == 1 and j["run_id"] == run and j["head_sha"] == head]
    require(len(grants) == 1 and grants[0]["status"] == "completed" and grants[0]["conclusion"] == "success",
            "Original replacement admission did not complete")
    steps = [s for s in grants[0]["steps"] if s["name"] == "Claim one certified loss" and s["conclusion"] == "success"]
    require(len(steps) == 1 and int(journal.timestamp(steps[0]["started_at"])) <= issued.timestamp() <
            int(journal.timestamp(steps[0]["completed_at"]))+1,"Claim predates or postdates admission")


def operation(helper, env, event, mode, now):
    require(mode in ("claim","lease","reread"),"Unknown loss operation")
    run, head, attempt = int(env["GITHUB_RUN_ID"]), env["GITHUB_SHA"], int(env["GITHUB_RUN_ATTEMPT"])
    expected_job = {"claim":"loss-admission","lease":"collection-lease","reread":"reread-loss-admission"}[mode]
    require(env["GITHUB_JOB"] == expected_job and env["GITHUB_EVENT_NAME"] == "workflow_dispatch" and
            env["GITHUB_REF"] == "refs/heads/"+BASE_REF and env["GITHUB_REPOSITORY"] == REPO and
            re.fullmatch("[a-f0-9]{40}",head) and ((attempt>1) if mode=="reread" else (attempt==1)),
            "Unexpected loss-recovery execution")
    inputs = event["inputs"]
    fields(event["sender"],reg.OWNER)
    fields(event["repository"],dict(id=REPO_ID))
    require(inputs["mode"] == "recover-lost-slot" and inputs.get("checkpoint_backend","draft") == "draft" and
            inputs.get("build_segments","12") == "12" and inputs.get("compile_minutes","0") == "0" and
            inputs.get("output_gib","18") == "18" and inputs.get("jobs","2") == "2" and
            inputs.get("retain_existing_caches","false") in (False,"false") and
            inputs.get("apk_recipient",reg.RECIPIENT) == reg.RECIPIENT and
            not any(inputs.get(x) for x in ("checkpoint_key","checkpoint_sha","checkpoint_identity","encrypted_apk_bytes")) and
            re.fullmatch("[1-9][0-9]{0,18}",inputs["loss_origin_run"]),
            "Recovery requires the existing default draft route, a single original run and no caller-selected parent")
    origin = int(inputs["loss_origin_run"])
    require(origin != run and run > 0,"Original and replacement must be different runs")
    api = PagedOwnerDraft(helper)
    replacement = identity(api,run,head,attempt)
    created = reg.instant(identity(api,run,head,1)["created_at"])
    release = api.draft(RELEASE_ID)
    expected = dict(schema=1,campaign=reg.CAMPAIGN,repository_id=REPO_ID,workflow=reg.WORKFLOW,
                    branch=BASE_REF,head=head,release_id=RELEASE_ID,recipient=reg.RECIPIENT)
    genesis, source_claim, _, _ = named(api,release,reg.CLAIM)
    fields(genesis,dict(**expected,run_id=origin,producer_attempt=1,initial_parent=S2_SHA))
    initial, tid, tsha, _ = named(api,release,reg.TICKET_NAME,owner=True)
    fields(genesis,dict(ticket_asset_id=tid,ticket_sha=tsha,registration_id=initial["collector_registration_id"]))
    fields(initial,dict(**expected,initial_parent=S2_SHA))
    ticket, aid, digest, issued = named(api,release,f"{reg.CAMPAIGN}-loss-{origin}.json",owner=True)
    require((inputs.get("registration_asset_id",""),inputs.get("registration_sha","")) in
            (("",""),(str(aid),digest)), "Different replacement collection ticket")
    fields(ticket,dict(**expected,origin_run=origin,original_claim_id=source_claim,producer_attempt=1,
                       state="original-operation-closed-no-durable-output",
                       collector_registration_id=initial["collector_registration_id"],
                       owner_destination_id=initial["owner_destination_id"]))
    k = ticket["ordinal"]
    require(type(k) is int and 1 <= k <= 12 and reg.instant(ticket["issued_at"]) <= issued <= created,
            "Wrong replacement scope or ticket issued after replacement start")
    ledger, eid, esha, observed = named(api,release,f"{reg.CAMPAIGN}-loss-evidence-{origin}.json",owner=True)
    fields(ticket,dict(evidence_asset_id=eid,evidence_sha=esha))
    fields(ledger,dict(**expected,origin_run=origin,ordinal=k,original_claim_id=source_claim,
                       collector_registration_id=initial["collector_registration_id"],
                       owner_destination_id=initial["owner_destination_id"]))
    require(reg.instant(ledger["observed_at"]) <= observed <= issued, "Unordered loss evidence")
    bound = dict(**expected,origin_run=origin,original_claim_id=source_claim,ordinal=k,run_id=run,producer_attempt=1,
                 registration_id=ticket["collector_registration_id"],owner_destination_id=ticket["owner_destination_id"],
                 ticket_asset_id=aid,ticket_sha=digest,evidence_asset_id=eid,evidence_sha=esha)
    if mode == "reread":
        holder, cid, _, grant_time = named(api,release,LOSS_CLAIM)
        original_grant(api,run,head,grant_time)
        fields(holder,bound)
        require(holder["initial_parent"] == ledger["parent_sha"] == holder["parent_sha"],"Different recovery parent")
        return dict(holder,claim_asset_id=cid)
    require(replacement["status"] == "in_progress","Replacement is no longer active")
    latest, ack = reg.checked_ack(api,release,ticket,created,now)
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"bridge"))
    import storage_admission as storage
    ceiling, until = storage.policy(ticket,ack)
    settings = dict(env,R28_STORAGE_CEILING=str(ceiling),R28_STORAGE_UNTIL=str(until))
    storage.draft_room(release,settings,claim=(mode == "claim"))
    storage.admit(api.metadata,settings,storage.lease_size(settings),1,stage="lease",now=now.timestamp(),lead=350*60)
    if mode == "claim":
        parent = original_parent(api,release,origin,head,ticket,ledger,now)
        holder = dict(bound,**parent,initial_parent=parent["parent_sha"])
        cid = admission.admit("compute",holder,api,name=LOSS_CLAIM)
    else:
        holder, cid, _, grant_time = named(api,release,LOSS_CLAIM)
        original_grant(api,run,head,grant_time)
        fields(holder,bound)
        require(holder["initial_parent"] == ledger["parent_sha"] == holder["parent_sha"],"Different recovery parent")
    return dict(holder,claim_asset_id=cid,next_ordinal=k+1,latest_start=latest,storage_ceiling=ceiling,storage_until=until)


def main():
    sys.path.insert(0,os.environ["RUNNER_TEMP"])
    import transfer
    mode, = sys.argv[1:]
    if mode != "claim":
        from recover_private import read_only
        transfer.request = read_only(transfer.request)
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    out = operation(transfer,os.environ,event,mode,datetime.now(timezone.utc))
    keys = ("ordinal","next_ordinal","parent_sha","parent_identity","parent_run","parent_key","parent_manifest_id",
            "parent_manifest_sha","parent_producer","claim_asset_id","latest_start","storage_ceiling","storage_until")
    with open(os.environ["GITHUB_OUTPUT"],"a") as f:
        for key in keys:
            print(f"{key}={out.get(key,'')}",file=f)


if __name__ == "__main__":
    main()
