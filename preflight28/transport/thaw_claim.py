"""Authorize one private transfer of the original already-computed Run 28 S2 child."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import recovery_claim as v2

a = v2.old
require = a.require
SOURCE = 45513782890
HEAD = "81105d5f7b9ba994034753ce4fbd65d9b981dde3"
BEFORE = "828c31d7c948970027b747618d6aee3df5377845"
CLAIM_ID = 789343072
RESERVE, PRODUCE, SEND, RECEIVE = 138867879857, 138867986638, 138867986660, 138883657205
CAMPAIGN = "r28-preflight-s2-20261125-v3"
WORKFLOW = ".github/workflows/bare-r28-s2-thaw.yml"
CLAIM = CAMPAIGN + "-frozen-s2-claim.json"
STEM = f"{v2.CAMPAIGN}-run{SOURCE}-a1-seg01-"
CHILD = "532ca75915583a89e2830d062076e3d7130f1edabbe5c03159ce6b1e3c76c1ba"
SIZE = 1745316602
IDENTITY = "c98323daf2070e10aec251a63cef34058a4bac2568762b036c2e4ddd60448dda"
GRAPH = "1c00445b7ea5bc2dfbf493fab9a8f7fae0edb9eb13494d85bcbc9806717b47f5"
PROVENANCE = "82f1c55fde8d6b1a58518161ae40f26de22dcf777206ec12f369a1fdee6f53a8"
PARENT_IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
ARTIFACTS = {
    "cipher": (14978478511,1747040746,"b7d84d5399d6bce27424370573375a965fabe568a97e0b8a16b1faa421daaa21","2026-11-26T00:27:01Z"),
    "writer": (14976353454,4443,"0cf210a57eb60e904189e1259ff55d077f6159c09d872c9e0545dcf2aa411c79","2026-11-25T23:57:23Z"),
}
AUDIT_FAIL = "Compare all retained APK payloads from original S2 against the securely deposited child"
PRIVATE_SEND = "Verify full ciphertext, authenticated private payload, and put new bounded draft parts"


def v2_holder():
    previous = v2.old_holder()
    return {**previous, "schema":2, "campaign":v2.CAMPAIGN, "workflow":v2.WORKFLOW, "run_id":SOURCE,
            "head":HEAD, "before":BEFORE, "producer_job":"produce", "claim_job":"reserve",
            "parent_s2_cache_id":v2.CACHE_ID, "supersedes_run":v2.OLD_RUN, "supersedes_claim":v2.OLD_CLAIM_ID,
            "supersedes_job":v2.OLD_JOB, "supersedes_claim_sha256":hashlib.sha256(a.encode(previous)).hexdigest()}


def check_event(api, env, event, checkout, mode):
    attempt, rid = int(env["GITHUB_RUN_ATTEMPT"]), int(env["GITHUB_RUN_ID"])
    head, before, pr = env["TRIAL_SHA"], env["PRIOR_SHA"], event["pull_request"]
    require(rid>SOURCE and attempt>=1 and env["GITHUB_JOB"] == ("issue" if mode=="verify" else "recover") and
            (mode=="verify" or attempt==1) and env["GITHUB_ACTOR"]==env["GITHUB_TRIGGERING_ACTOR"]==v2.OWNER and
            env["GITHUB_REPOSITORY"]==a.REPO and env["GITHUB_EVENT_NAME"]=="pull_request" and
            env["GITHUB_REF"]=="refs/pull/9/merge", "Forbidden transfer attempt, role, or actor")
    require(re.fullmatch("[0-9a-f]{40}",head) and re.fullmatch("[0-9a-f]{40}",before) and
            head!=before and checkout==head==event["after"]==pr["head"]["sha"] and event["before"]==before and
            event["action"]=="synchronize" and event["number"]==pr["number"]==9 and pr["head"]["ref"]==a.BRANCH and
            pr["base"]["ref"]==a.BASE_REF and pr["base"]["sha"]==a.BASE_SHA and
            all(r["id"]==a.REPO_ID and r["full_name"]==a.REPO for r in (event["repository"],pr["head"]["repo"],pr["base"]["repo"])) and
            event["sender"]["id"]==v2.OWNER_ID and event["sender"]["login"]==v2.OWNER, "Wrong transfer PR or head")
    original=api.metadata(f"{api.BASE}/actions/runs/{rid}/attempts/1")
    v2.pinned_run(original,rid,head,WORKFLOW)
    current=original if attempt==1 else api.metadata(f"{api.BASE}/actions/runs/{rid}/attempts/{attempt}")
    v2.pinned_run(current,rid,head,WORKFLOW,attempt)
    require(current["status"]=="in_progress" and current["conclusion"] is None,"Inactive transfer attempt")
    return {"schema":3,"campaign":CAMPAIGN,"workflow":WORKFLOW,"repository_id":a.REPO_ID,"pr":9,
            "run_id":rid,"initial_attempt":1,"head":head,"before":before,"source_run":SOURCE,"source_head":HEAD,
            "source_attempt":1,"source_claim":CLAIM_ID,"source_claim_sha256":hashlib.sha256(a.encode(v2_holder())).hexdigest(),
            "source_job":PRODUCE,"source_parent_sha":a.S2_SHA,"original_draft_stem":STEM,
            "source_sha256":CHILD,"source_bytes":SIZE,
            "artifacts":{k:dict(id=v[0],bytes=v[1],sha256=v[2],expires_at=v[3]) for k,v in ARTIFACTS.items()}}


# Immutable provider transcripts read independently with the existing owner
# connector. SHA is over the exact UTF-8 decoded transcript re-encoded as UTF-8.
# The job-scoped workflow token can read job metadata but returned an error
# fetching historical logs in run 45519361611; the live checks below remain.
TRANSCRIPTS = {
    PRODUCE: (440582, "725b17f56b83b4a46e5cb6efb1ee5a6e13893ee3a9361036795768962ae0679e",
              "2026-11-25T00:28:39.2724305Z ValueError: Unaccounted retained output replacement: gn_logs.txt"),
    SEND: (14139, "f9f2af3ac7a4cf7c01a6198d17157fd792a7c2c7f984274a3393192d552e6c7c",
           "2026-11-25T00:28:41.7256633Z ValueError: Original peer ended without proof of success"),
}
FAILED_GATE = 45519361611
FAILED_HEAD = "82d6fe3a24c4aa7a6d4280419d4121c95e884c0b"
FAILED_JOBS = (138886992719, 138887106729, 138887107201)


def log_witness(job, expected):
    size, digest, line = TRANSCRIPTS[job]
    require(line.split("Z ",1)[1]==expected and size>0 and re.fullmatch("[0-9a-f]{64}",digest),
            "Historical owner-verified witness does not match the selected failure")
    print(f"transcript_source=prior_independent_owner_read job={job} utf8_bytes={size} sha256={digest}")


def previous_gate(api):
    root=f"{api.BASE}/actions/runs/{FAILED_GATE}"
    run=api.metadata(root+"/attempts/1")
    v2.pinned_run(run,FAILED_GATE,FAILED_HEAD,WORKFLOW)
    require(run["status"]=="completed" and run["conclusion"]=="failure","Prior thaw could still be running")
    page=api.metadata(root+"/attempts/1/jobs?per_page=100")
    jobs={j["id"]:j for j in page["jobs"]}
    require(page["total_count"]==3 and set(jobs)==set(FAILED_JOBS) and
            [jobs[k]["conclusion"] for k in FAILED_JOBS]==["failure","skipped","skipped"] and
            all(j["status"]=="completed" and j["run_id"]==FAILED_GATE for j in jobs.values()),
            "Prior thaw might have accepted original bytes")
    results={s["name"]:s["conclusion"] for s in jobs[FAILED_JOBS[0]]["steps"]}
    failure="Confirm failed prior acceptance, exact surviving artifacts and new single recovery claim"
    require({k for k,v in results.items() if v=="failure"}=={failure} and
            all(results.get(k)=="skipped" for k in ("Deposit request for this exact recovery",
                "Open original authenticated frames and verify the original producer evidence",
                "Reconcile original data and publish the original immutable generation")),
            "Prior thaw did not stop at its first admission check")
    arts=api.metadata(root+"/artifacts?per_page=100")
    require(arts["total_count"]==0 and not arts["artifacts"],"Prior thaw already created a transfer")
    print(f"prior_unclaimed_gate={FAILED_GATE} prior_publication=skipped prior_artifacts=0")


def source_failed(api, read_log):
    root=f"{api.BASE}/actions/runs/{SOURCE}"
    r=api.metadata(root)
    v2.pinned_run(r,SOURCE,HEAD,v2.WORKFLOW)
    require(r["status"]=="completed" and r["conclusion"]=="failure","Source run has a different outcome")
    page=api.metadata(root+"/attempts/1/jobs?per_page=100")
    jobs={j["id"]:j for j in page["jobs"]}
    require(set(jobs)=={RESERVE,PRODUCE,SEND,RECEIVE} and page["total_count"]==len(page["jobs"])==4 and
            all(j["status"]=="completed" and j["run_id"]==SOURCE for j in jobs.values()) and
            [jobs[k]["conclusion"] for k in (RESERVE,PRODUCE,SEND,RECEIVE)]==["success","failure","failure","skipped"],
            "Source job history changed")
    def steps(key, failed, expected):
        entries=jobs[key]["steps"]
        statuses={s["name"]:s["conclusion"] for s in entries if s["status"]=="completed"}
        require(len(statuses)==len(entries) and {s for s,v in statuses.items() if v=="failure"}=={failed} and
                all(statuses.get(name)==value for name,value in expected.items()),"Source stage chronology changed")
    steps(PRODUCE,AUDIT_FAIL,{"Prepare fixed builder and progress one genuine APK dependency, then pack new full zstd":"success",
                              "Seal full newly built candidate to the independent restricted writer":"success",
                              "Upload the scoped cipher Artifact":"success","Reconfirm original read-only cache after transfer":"skipped"})
    steps(SEND,"Locate exact same-run cipher Artifact by service ID",{"Upload the scoped key Artifact":"success",PRIVATE_SEND:"skipped"})
    read_log(PRODUCE,"ValueError: Unaccounted retained output replacement: gn_logs.txt")
    read_log(SEND,"ValueError: Original peer ended without proof of success")


def valid_artifacts(api, now):
    root=f"{api.BASE}/actions/runs/{SOURCE}/artifacts?per_page=100"
    page=api.metadata(root)
    rows={r["id"]:r for r in page["artifacts"]}
    require(page["total_count"]==len(page["artifacts"])==2 and set(rows)=={x[0] for x in ARTIFACTS.values()},
            "Original transfer inputs missing or ambiguous")
    for kind,(aid,size,digest,expires) in ARTIFACTS.items():
        r=rows[aid]; w=r["workflow_run"]
        require(r["name"]==f"r28-fresh-{SOURCE}-{kind}" and r["digest"]=="sha256:"+digest and r["size_in_bytes"]==size
                and not r["expired"] and r["expires_at"]==expires and datetime.fromisoformat(expires.replace("Z","+00:00"))>now and
                w["id"]==SOURCE and w["repository_id"]==w["head_repository_id"]==a.REPO_ID and
                w["head_sha"]==HEAD and w["head_branch"]==a.BRANCH, "Frozen artifact ID, bytes, SHA, run, or expiry mismatch")


def check_original_draft(api):
    release=api.draft(a.RELEASE_ID)
    assets=release["assets"]
    require(a.claim_info(api,a.encode(v2_holder()),v2.CLAIM)==CLAIM_ID,"Wrong original v2 claim bytes or ID")
    rows=[r for r in assets if r["name"].startswith(STEM)]
    require(all(r["name"] in {STEM+x+y for x in ("p00","manifest.json") for y in ("","-retry1")} for r in rows) and
            not any((r["name"].startswith(CAMPAIGN+"-") and r["name"]!=CLAIM) or
                    (r["name"].startswith(v2.CAMPAIGN+"-") and r["name"]!=v2.CLAIM and not r["name"].startswith(STEM)) or
                    r["name"].startswith(f"r28-{SOURCE}-a1-s01-") for r in assets),
            "Unexpected alternate source or destination asset")
    def original(suffix):
        matches=[r for r in rows if r["name"] in (STEM+suffix,STEM+suffix+"-retry1")]
        require(all(r["state"]=="uploaded" or (r["state"]=="starter" and r["size"]==0) for r in matches),
                "Mismatched incomplete source asset")
        uploaded=[r for r in matches if r["state"]=="uploaded"]
        require(len(uploaded)<=1,"Duplicate original asset receipts")
        return uploaded[0] if uploaded else None
    part=original("p00")
    if part:
        api.asset_info(release,part["name"],SIZE,CHILD,part["id"])
    manifest=original("manifest.json")
    if not manifest:
        return 0
    require(part is not None and 0<manifest["size"]<=16384 and re.fullmatch("sha256:[0-9a-f]{64}",manifest["digest"]),
            "Source manifest has no verified matching part")
    sha=manifest["digest"].split(":")[1]
    buf=io.BytesIO()
    api.download(manifest["id"],manifest["size"],sha,buf)
    data=json.loads(buf.getvalue())
    fields={"campaign":v2.CAMPAIGN,"source_sha":HEAD,"producer_run":SOURCE,"producer_attempt":1,"segment":1,
            "parent_sha":a.S2_SHA,"parent_identity":PARENT_IDENTITY,"parent_cache_id":v2.CACHE_ID,
            "parent_key":v2.CACHE_KEY,"format":"tar.zst","bytes":SIZE,"sha256":CHILD,
            "identity":IDENTITY,"graph_sha":GRAPH,"trial_provenance_sha":PROVENANCE,"parts":[{"name":part["name"],"id":part["id"],"bytes":SIZE,"sha256":CHILD}]}
    require(data==fields and buf.getvalue()==json.dumps(fields,sort_keys=True,separators=(",",":")).encode(),
            "Existing manifest belongs to another generation")
    return manifest["id"]


def passed_audit(path):
    st=path.lstat()
    require(stat.S_ISREG(st.st_mode) and 0<st.st_size<=128*1024**2,"Missing or oversized frozen-pair audit")
    raw=path.read_bytes()
    report=json.loads(raw)
    require(report["schema"]=="bare-r28-archive-continuity-v3" and report["status"]=="passed" and
            report["parent_sha"]==a.S2_SHA and report["child_sha"]==CHILD, "No successful archive audit for the exact frozen pair")
    for name in ("parent_content","child_content"):
        c=report[name]
        require(type(c["files"]) is int and 0<c["files"]<=550000 and re.fullmatch("[0-9a-f]{64}",c["sha256"]),
                "Invalid actual payload commitment")
    counts=report["counts"]
    require(all(type(v) is int and v>=0 for v in counts.values()) and
            counts["removed"]==counts["unclassified"]==0 and counts["added"]>0 and counts["gn_diagnostic"]==1,
            "Unresolved retention loss or unverified diagnostics")
    d,=report["diagnostics"]
    require(d["path"]=="gn_logs.txt" and d["producer"]=="//BUILD.gn:1662-1672" and d.get("parent") and
            d.get("child") and d["parent"]!=d["child"] and d.get("evidence") and isinstance(report["differences"],list),
            "Missing scoped GN diagnostic evidence")
    for side in ("parent","child"):
        e=d["evidence"][side]
        require(e["chromium"]=="800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6" and
                e["build_gn_sha256"]=="31f8205fe64264c5b4f9638eb6552e558ccf78a4839413a7c1a194116f26e72e" and
                e["target"]=="chrome_public_apk" and e["diagnostic_query"]=="unknown target" and
                e["graph_references"]==e["aliases"]==0 and e["manifest_content"]["files"]>0 and
                re.fullmatch("[0-9a-f]{64}",e["manifest_content"]["sha256"]) and e["sections"],
                "Missing original graph or source-format proof for GN diagnostic")
    require(isinstance(d["evidence"]["changed_sections"],list), "Missing GN section comparison")
    return hashlib.sha256(raw).hexdigest()


def run(mode, helper, env, event, checkout, *, audit=None, clock=None, read_log=log_witness):
    require(mode in ("reserve","authorize","verify"),"Unsupported thaw operation")
    api=v2.CompleteDraft(helper)
    holder=check_event(api,env,event,checkout,mode)
    manifest=check_original_draft(api)
    if mode=="reserve":
        previous_gate(api)
        source_failed(api,read_log)
        if not manifest:
            valid_artifacts(api,clock or datetime.now(timezone.utc))
        claim=a.admit("compute",holder,api,name=CLAIM)
    else:
        claim=a.claim_info(api,a.encode(holder),CLAIM)
        require(claim is not None,"No accepted original thaw reservation")
        if mode=="authorize":
            require(audit is not None,"Audit required before promotion")
            print("frozen_audit_sha256="+passed_audit(audit),flush=True)
        else:
            require(manifest,"Original verified private manifest missing; receiver cannot publish or recompute")
    print(f"mode={mode} wrapper_run={holder['run_id']} source_run={SOURCE} original_claim={CLAIM_ID} "
          f"thaw_claim={claim} original_manifest_id={manifest} source_bytes={SIZE} source_sha256={CHILD}",flush=True)
    return claim,manifest


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("reserve","authorize","verify"))
    p.add_argument("--audit",type=Path)
    args=p.parse_args()
    sys.path.insert(0,os.environ["RUNNER_TEMP"])
    import transfer
    event=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    checkout=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip()
    claim, manifest=run(args.mode,transfer,os.environ,event,checkout,audit=args.audit)
    with open(os.environ["GITHUB_OUTPUT"],"a") as f:
        print(f"claim_id={claim}\nsource_run={SOURCE}\noriginal_manifest_id={manifest}",file=f)


if __name__=="__main__":
    main()
