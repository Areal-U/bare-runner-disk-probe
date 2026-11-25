"""Admit only a metadata-only trial job from a short-lived authenticated operator capture."""
import base64
import hashlib
import os
import re
import time

import storage_admission as budget


WORKFLOW_ID = 411691930


def initial(capture, mode, head, *, branch, workflow, cost, total_cap, now=None):
    now = int(time.time()) if now is None else now
    start, end = capture.get("started_at"), capture.get("finished_at")
    budget.require(capture.get("schema") == "bare-next-preflight-reads-v1" and
                   (capture.get("head"), capture.get("mode"), capture.get("workflow_id")) == (head, mode, WORKFLOW_ID)
                   and re.fullmatch(r"[0-9a-f]{40}", head) and type(start) is int and type(end) is int
                   and now-120 <= start <= end <= now, "Wrong, incomplete or stale pre-dispatch capture")
    base = budget.BASE
    responses = capture["responses"]
    repo = responses[base]
    budget.public_host(repo, "github-hosted")
    budget.require(repo.get("default_branch") == "main", "Default branch differs from the registered diagnostic entry")
    ref = responses[f"{base}/git/ref/heads/{branch}"]
    budget.require(ref.get("ref") == "refs/heads/" + branch and
                   ref.get("object", {}).get("type") == "commit" and ref["object"]["sha"] == head,
                   "Capture belongs to a different test branch or SHA")
    name = ".github/workflows/" + workflow
    file = responses[f"{base}/contents/{name}?ref=main"]
    budget.require(file.get("type") == "file" and file.get("path") == name and file.get("encoding") == "base64" and
                   isinstance(file.get("content"), str) and 0 < len(file["content"]) < 128*1024,
                   "Missing default-branch workflow contents")
    raw = base64.b64decode("".join(file["content"].splitlines()), validate=True)
    oid = hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
    budget.require(oid == file.get("sha") and re.search(rb"^\s*workflow_dispatch:\s*$", raw, re.M),
                   "Default-branch workflow blob or manual event mismatch")
    # One full, clear sweep. A single contaminated snapshot cannot advance by replaying it twice.
    budget.diagnostic_active_runs(responses.__getitem__, {"GITHUB_RUN_ID":"0"}, delays=(0,))
    rows = responses[f"{base}/actions/runs?head_sha={head}&event=workflow_dispatch&per_page=100"]
    runs = rows.get("workflow_runs")
    budget.require(isinstance(runs, list) and type(rows.get("total_count")) is int
                   and rows["total_count"] == len(runs) <= 100, "Incomplete diagnostic history in capture")
    ids = set()
    for item in runs:
        ident = item.get("id")
        budget.require(type(ident) is int and ident > 0 and ident not in ids and
                       type(item.get("workflow_id")) is int and item["workflow_id"] > 0 and
                       item.get("event") == "workflow_dispatch" and item.get("head_sha") == head and
                       isinstance(item.get("display_title"),str), "Unbound run in supplied test history")
        ids.add(ident)
        if item["workflow_id"] == WORKFLOW_ID and item["display_title"] == f"Bare next-build trial {mode} {head}":
            raise ValueError(f"Diagnostic already issued as run {ident}")
    ceiling = total_cap
    if os.environ.get("R28_RELAY_BYTE_CEILING"):
        ceiling = min(ceiling,budget.integer(int(os.environ["R28_RELAY_BYTE_CEILING"]), "existing repository ceiling"))
    budget.require(cost <= ceiling, "The known ceiling cannot accommodate this diagnostic")
    # No Artifact request is admitted here. The job must verify the actual storage before granting any relay.
    return {"ceiling":str(ceiling), "until":str(now + 2*86400)}
