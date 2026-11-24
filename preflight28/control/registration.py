"""Bind one previously registered, owner-only collection ticket to one physical build."""
import hashlib
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

from admission import BASE_REF, REPO, REPO_ID, S2_SHA, RELEASE_ID, admit, require

CAMPAIGN = "bare-personal-204-r28"
CLAIM = CAMPAIGN + "-production-run-claim.json"
WORKFLOW = ".github/workflows/bare-checkpoint-transfer.yml"
OWNER = {"id": 292261483, "login": "Areal-U"}
RECIPIENT = "age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx"


def instant(value):
    require(isinstance(value, str) and value.endswith("Z"), "Expected UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def bind(helper, env, event, now):
    aid, digest = env["REGISTRATION_ASSET_ID"], env["REGISTRATION_SHA"]
    require(re.fullmatch(r"[1-9][0-9]{0,18}", aid) and re.fullmatch("[0-9a-f]{64}", digest),
            "Missing or invalid pre-registered private collection ticket")
    run, revision = int(env["GITHUB_RUN_ID"]), env["GITHUB_SHA"]
    require(env["GITHUB_RUN_ATTEMPT"] == "1" and run > 0 and re.fullmatch("[0-9a-f]{40}", revision)
            and env["GITHUB_JOB"] == "bind-private-receiver" and env["GITHUB_REPOSITORY"] == REPO
            and env["GITHUB_REF"] == "refs/heads/" + BASE_REF and env["GITHUB_EVENT_NAME"] == "workflow_dispatch",
            "Only the approved physical originating job can bind a registration")
    require(event["repository"]["id"] == REPO_ID and event["inputs"].get("mode") == "build-apk"
            and all(event["sender"].get(k) == v for k,v in OWNER.items()), "Unexpected dispatch")
    api = helper.metadata(f"{helper.BASE}/actions/runs/{run}/attempts/1")
    require(api["id"] == run and api["run_attempt"] == 1 and api["head_sha"] == revision
            and api["path"] == WORKFLOW and api["event"] == "workflow_dispatch" and api["head_branch"] == BASE_REF
            and all(api["actor"].get(k) == v for k,v in OWNER.items())
            and api["repository"]["id"] == api["head_repository"]["id"] == REPO_ID, "Unconfirmed physical run")
    release = helper.draft(RELEASE_ID)
    found = [x for x in release["assets"] if x.get("id") == int(aid)]
    require(len(found) == 1, "Registration ID does not exist in the private owner Draft")
    asset = found[0]
    require(asset["name"] == CAMPAIGN + "-collection-registration.json" and 0 < asset["size"] <= 4096
            and all((asset.get("uploader") or {}).get(k) == v for k,v in OWNER.items()),
            "Missing owner-issued collection registration")
    helper.asset_info(release, asset["name"], asset["size"], digest, int(aid))
    raw = io.BytesIO()
    helper.download(int(aid), asset["size"], digest, raw)
    require(hashlib.sha256(raw.getvalue()).hexdigest() == digest, "Wrong registration digest")
    ticket = json.loads(raw.getvalue())
    inputs = event["inputs"]
    parent = S2_SHA if inputs.get("build_segments") == "12" else (inputs.get("checkpoint_sha") or "cold")
    expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, workflow=WORKFLOW, branch=BASE_REF,
                    head=revision, initial_parent=parent, release_id=RELEASE_ID, recipient=RECIPIENT)
    require(all(ticket.get(k) == v for k,v in expected.items()) and inputs.get("apk_recipient") == RECIPIENT,
            "Registration belongs to another campaign, owner, revision or initial parent")
    service = ticket["collector_registration_id"]
    require(re.fullmatch(r"Automation_[0-9a-f]{32}", service), "A separately registered collection target is required")
    created, issued, expires = instant(api["created_at"]), instant(ticket["issued_at"]), instant(ticket["expires_at"])
    require(instant(asset["created_at"]) <= created and issued <= created <= now < expires,
            "Ticket expired or prepared after run creation")
    holder = dict(expected, registration_id=service, ticket_asset_id=int(aid), ticket_sha=digest,
                  run_id=run, producer_attempt=1)
    # Independent of ticket ID: two concurrent dispatches cannot bind this campaign twice.
    return admit("compute", holder, helper, name=CLAIM), service


def main():
    sys.path.insert(0, str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    claim, service = bind(transfer, os.environ, event, datetime.now(timezone.utc))
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        print(f"claim_asset_id={claim}\ncollector_registration_id={service}", file=out)
    print(f"Bound prior collection ticket to original run {os.environ['GITHUB_RUN_ID']} attempt 1; claim {claim}")


if __name__ == "__main__":
    main()
