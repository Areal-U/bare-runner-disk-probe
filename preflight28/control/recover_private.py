"""Receive an existing owner-Draft checkpoint using only GET/HEAD from the original run."""
from datetime import datetime
import os
from pathlib import Path
import re
import sys
import time

from admission import BASE_REF, REPO, require

JOB_NAME = "Re-read the exact last private checkpoint without resuming compilation"
JOB_MINUTES = 85
STEP_MINUTES = 80
EXIT_MINUTES = 3


def job_label(env):
    attempt=int(env["GITHUB_RUN_ATTEMPT"])
    if env["GITHUB_JOB"]=="recover-draft-checkpoint":
        require(attempt>1,"Manual recovery only runs on subsequent attempts")
        return JOB_NAME
    slot=int(env["R28_SLOT"])
    require(env["GITHUB_JOB"]=="confirm-private" and attempt==1 and 1<=slot<=12 and env["GITHUB_ACTOR"]=="Areal-U" and
            re.fullmatch("[1-9][0-9]*",env["R28_EXPECTED_RECOVERY_MANIFEST"]) and
            re.fullmatch("[a-f0-9]{64}",env["R28_EXPECTED_RECOVERY_MANIFEST_SHA"]),
            "Automatic readback requires the exact pending manifest on an originating slot")
    return f"Confirm original private visibility for slot {slot}"


def recovery_deadline(api, env, now):
    """Use the actual hosted job start and this recovery step's start."""
    run, attempt = int(env["GITHUB_RUN_ID"]), int(env["GITHUB_RUN_ATTEMPT"])
    step_start = int(env["R28_STEP_START"])
    check = env.get("R28_CHECK_RUN","")
    label = job_label(env)
    require(run > 0 and (not check or re.fullmatch("[1-9][0-9]*",check)),
            "Invalid physical recovery run or check identity")
    rows = []
    for page in range(1,11):
        listing=api.metadata(f"{api.BASE}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100&page={page}")
        batch=listing["jobs"]
        require(isinstance(batch,list) and len(batch)<=100,"Invalid recovery job listing")
        rows.extend(batch)
        if len(batch)<100:
            require(len(rows)==listing["total_count"]==len({j["id"] for j in rows}),"Incomplete recovery job inventory")
            break
    else:
        raise ValueError("Recovery job inventory exceeds bounded query")
    eligible=[j for j in rows if j["run_id"]==run and j["run_attempt"]==attempt and j["head_sha"]==env["GITHUB_SHA"]
              and j["status"]=="in_progress" and (j["name"]==label or j["name"].endswith(" / "+label)) and
              re.fullmatch(r"https://api\.github\.com/repos/"+re.escape(REPO)+r"/check-runs/[1-9][0-9]*",j["check_run_url"]) and
              (not check or j["check_run_url"].endswith('/'+check))]
    require(len(eligible)==1,"No unique active recovery job on this attempt")
    started=datetime.fromisoformat(eligible[0]["started_at"].replace("Z","+00:00"))
    require(started.tzinfo is not None and 0 < started.timestamp() <= step_start <= now,
            "Invalid or inconsistent hosted recovery clock")
    deadline=min(int(started.timestamp())+JOB_MINUTES*60,step_start+STEP_MINUTES*60)-EXIT_MINUTES*60
    require(deadline>now,"Recovery clock expired before readback")
    return deadline


def read_only(request):
    def restricted(host, method, path, **kwargs):
        require(method in ("GET", "HEAD") and kwargs.get("body") is None and
                not any(k in kwargs for k in ("length", "content_type")), "Receipt verification permits reads only")
        return request(host, method, path, **kwargs)
    return restricted


def main():
    e=os.environ
    require(e["GITHUB_REPOSITORY"] == REPO and e["GITHUB_REF"] == "refs/heads/"+BASE_REF and
            e["GITHUB_EVENT_NAME"]=="workflow_dispatch","Unexpected recovery caller")
    sys.path[:0]=[str(Path(__file__).resolve().parents[1]/"bridge"),e["RUNNER_TEMP"]]
    import normal
    import transfer
    transfer.request=read_only(transfer.request)
    deadline = recovery_deadline(transfer,e,time.time())
    normal.recover(deadline=deadline)


if __name__=="__main__":
    main()
