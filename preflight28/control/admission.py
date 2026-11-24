"""Admit exactly one PR9 S2 trial run. Replayed GitHub attempts are readers only."""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

REPO = "Areal-U/bare-runner-disk-probe"
REPO_ID = 1450926240
BRANCH = "work-bare-27-storage-check"
BASE_REF = "bare-coexist-v2.0.4"
BASE_SHA = "bf70ddbf474f3390a62220a076b8c43347fecc64"
CAMPAIGN = "r28-preflight-s2-20261125-v1"
WORKFLOW = ".github/workflows/bare-r28-s2-preflight.yml"
CLAIM = CAMPAIGN + "-s2-run-claim.json"
S2_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
RELEASE_ID = 452114666


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checked_holder(mode, before, environment, event, api_run, checkout):
    """Validate immutable event data. A subsequent push must not invalidate retrieval."""
    rid = int(environment["GITHUB_RUN_ID"])
    attempt = int(environment["GITHUB_RUN_ATTEMPT"])
    require(rid > 0 and attempt > 0, "Invalid physical run identity")
    require(re.fullmatch("[0-9a-f]{40}", before), "Invalid expected prior commit")
    pr = event["pull_request"]
    head = pr["head"]["sha"]
    require(re.fullmatch("[0-9a-f]{40}", head) and head != before and checkout == head,
            "Checkout does not match the triggering head")
    require(environment["GITHUB_REPOSITORY"] == REPO and
            environment["GITHUB_EVENT_NAME"] == "pull_request" and
            environment["GITHUB_REF"] == "refs/pull/9/merge" and
            event["number"] == 9 and pr["number"] == 9 and event["action"] == "synchronize" and
            event["before"] == before and event["after"] == head and
            pr["head"]["ref"] == BRANCH and pr["base"]["ref"] == BASE_REF and
            pr["base"]["sha"] == BASE_SHA, "Not the approved PR9 transition")
    for repo in (pr["head"]["repo"], pr["base"]["repo"], event["repository"]):
        require(repo["id"] == REPO_ID and repo["full_name"] == REPO,
                "Unexpected repository identity")
    require(event["sender"]["id"] == 292261483 and event["sender"]["login"] == "Areal-U"
            and api_run["actor"]["id"] == 292261483, "Unexpected event actor")
    require(api_run["id"] == rid and api_run["run_attempt"] == attempt and
            api_run["path"] == WORKFLOW and api_run["event"] == "pull_request" and
            api_run["head_sha"] == head and api_run["head_branch"] == BRANCH and
            api_run["head_repository"]["id"] == REPO_ID and
            api_run["repository"]["id"] == REPO_ID and
            any(p["number"] == 9 for p in api_run["pull_requests"]),
            "GitHub did not confirm this physical trial")
    if mode == "compute":
        require(attempt == 1 and environment["GITHUB_JOB"] == "produce",
                "Only the first physical producer may compute")
    else:
        require(mode == "recover" and environment["GITHUB_JOB"] == "receive",
                "Recovery requires the read-only receiver job")
    return {"schema": 1, "campaign": CAMPAIGN, "workflow": WORKFLOW, "repository_id": REPO_ID,
            "pr": 9, "run_id": rid, "producer_attempt": 1, "producer_job": "produce",
            "head": head, "before": before, "parent_s2_sha256": S2_SHA}


def encode(holder):
    return (json.dumps(holder, sort_keys=True, separators=(",", ":")) + "\n").encode()


class PagedOwnerDraft:
    """Keep the pinned Draft checks and enumerate the full owner asset inventory for each read."""
    def __init__(self, helper):
        self.helper = helper

    def __getattr__(self, key):
        return getattr(self.helper, key)

    def draft(self, release_id):
        require(release_id == RELEASE_ID, "Unexpected private release")
        release = self.helper.draft(release_id)
        assets = []
        for page in range(1, 12):
            batch = self.helper.metadata(f"{self.BASE}/releases/{release_id}/assets?per_page=100&page={page}")
            require(isinstance(batch, list) and len(batch) <= 100, "Invalid private asset page")
            assets.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise ValueError("Private asset inventory exceeds the bounded listing")
        ids = {a["id"]: a["name"] for a in assets}
        require(len(ids) == len(assets) and all(ids.get(a["id"]) == a["name"] for a in release["assets"]),
                "Private asset inventory changed during pagination")
        return {**release, "assets": assets}


def claim_info(helper, payload, name=CLAIM):
    release = helper.draft(RELEASE_ID)
    names = [a for a in release["assets"] if a["name"] == name]
    if not names:
        return None
    digest = hashlib.sha256(payload).hexdigest()
    asset = helper.asset_info(release, name, len(payload), digest)
    retrieved = io.BytesIO()
    helper.download(asset["id"], len(payload), digest, retrieved)
    require(retrieved.getvalue() == payload, "Existing claim belongs to another producer")
    return asset["id"]


def admit(mode, holder, helper, pause=time.sleep, *, name=CLAIM):
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,125}\.json", name), "Invalid claim name")
    payload = encode(holder)
    found = claim_info(helper, payload, name)
    if found:
        return found
    require(mode == "compute", "No first-attempt receipt to recover")
    # The asset name is unique within this one fixed draft. No replace, cleanup or
    # alternate filename is allowed for a run claim, even on a lost response.
    path = f"{helper.BASE}/releases/{RELEASE_ID}/assets?name={name}"
    status = None
    try:
        connection, response = helper.request(helper.UPLOAD, "POST", path, auth=True, body=payload,
                                              length=len(payload), content_type="application/json")
        try:
            status = response.status
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        pass  # Read back, without assuming the POST failed or duplicating it.
    for delay in (0, 1, 3, 6):
        if delay:
            pause(delay)
        found = claim_info(helper, payload, name)
        if found:
            return found
    raise ValueError(f"Canonical claim not confirmed (POST {status}); no compute")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("compute", "recover"))
    parser.add_argument("--before", required=True)
    parser.add_argument("--helper-dir", type=Path, required=True)
    args = parser.parse_args()
    # prepare.py extracts this fixed reviewed implementation from the pinned trial.
    sys.path.insert(0, str(args.helper_dir.resolve(strict=True)))
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    rid = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    run = transfer.metadata(f"{transfer.BASE}/actions/runs/{rid}/attempts/{attempt}")
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    holder = checked_holder(args.mode, args.before, os.environ, event, run, revision)
    asset_id = admit(args.mode, holder, transfer)
    print(f"campaign={CAMPAIGN} canonical_run={rid} producer_attempt=1 "
          f"current_attempt={attempt} claim_asset={asset_id} mode={args.mode}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, http.client.HTTPException) as error:
        sys.exit(str(error))
