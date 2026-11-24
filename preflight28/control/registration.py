"""Bind one previously registered, owner-only collection ticket to one physical build."""
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
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


def checked_ack(helper, release, ticket, created, now):
    """The owner ticket pins the separate collector self-read response by immutable ID/digest."""
    nonce = ticket.get("registration_nonce", "")
    destination = ticket.get("owner_destination_id", "")
    require(re.fullmatch("[0-9a-f]{32,64}", nonce) and re.fullmatch("[A-Za-z0-9_-]{12,200}", destination),
            "Missing registration nonce or owner destination")
    aid, sha = ticket.get("collector_ack_asset_id"), ticket.get("collector_ack_sha")
    require(type(aid) is int and aid > 0 and isinstance(sha,str) and re.fullmatch("[0-9a-f]{64}",sha),
            "The independently registered collector has not acknowledged readiness")
    found = [a for a in release["assets"] if a["id"] == aid]
    require(len(found) == 1, "The exact pinned collector acknowledgement is unavailable")
    ack_asset = found[0]
    name = CAMPAIGN + "-collector-ack-" + nonce + ".json"
    require(ack_asset["name"] == name and 0 < ack_asset["size"] <= 4096 and instant(ack_asset["created_at"]) <= created,
            "The collector acknowledgement was not deposited before the original run")
    helper.asset_info(release, name, ack_asset["size"], sha, aid)
    raw=io.BytesIO()
    helper.download(aid,ack_asset["size"],sha,raw)
    require(hashlib.sha256(raw.getvalue()).hexdigest()==sha,"The owner-approved collector ACK bytes changed")
    ack=json.loads(raw.getvalue())
    for key in ("campaign","branch","head","collector_registration_id","owner_destination_id","registration_nonce","recipient"):
        require(ack.get(key)==ticket[key],"Collector ACK disagrees with owner ticket: "+key)
    require(ack.get("state")=="collector-read-back-owner-reservation" and ack.get("schema")==1,
            "Expected the collector's independent receipt of the owner reservation")
    period, retry = ack.get("poll_seconds"), ack.get("pickup_retry_seconds")
    require(type(period) is int and period>0 and type(retry) is int and retry>0,
            "Pickup cadence and retry window must be measured and declared by the collector")
    latest = min(instant(ack["valid_until"]),instant(ticket["expires_at"])) - timedelta(seconds=350*60+2*period+retry)
    require(instant(ack["observed_at"]) <= created <= now <= latest,
            "Collector lease does not cover this segment and pickup")
    return int(latest.timestamp())


def bind(helper, env, event, now, *, verify_only=False):
    aid, digest = env["REGISTRATION_ASSET_ID"], env["REGISTRATION_SHA"]
    require((not aid and not digest) or
            (re.fullmatch(r"[1-9][0-9]{0,18}", aid) and re.fullmatch("[0-9a-f]{64}", digest)),
            "Supply both private ticket identifiers together or leave both empty")
    run, revision = int(env["GITHUB_RUN_ID"]), env["GITHUB_SHA"]
    require(env["GITHUB_RUN_ATTEMPT"] == "1" and run > 0 and re.fullmatch("[0-9a-f]{40}", revision)
            and env["GITHUB_JOB"] == ("collection-lease" if verify_only else "bind-private-receiver") and env["GITHUB_REPOSITORY"] == REPO
            and env["GITHUB_REF"] == "refs/heads/" + BASE_REF and env["GITHUB_EVENT_NAME"] == "workflow_dispatch",
            "Only the approved physical originating job can bind a registration")
    require(event["repository"]["id"] == REPO_ID and event["inputs"].get("mode","build-apk") == "build-apk"
            and all(event["sender"].get(k) == v for k,v in OWNER.items()), "Unexpected dispatch")
    api = helper.metadata(f"{helper.BASE}/actions/runs/{run}/attempts/1")
    require(api["id"] == run and api["run_attempt"] == 1 and api["head_sha"] == revision
            and api["path"] == WORKFLOW and api["event"] == "workflow_dispatch" and api["head_branch"] == BASE_REF
            and all(api["actor"].get(k) == v for k,v in OWNER.items())
            and api["repository"]["id"] == api["head_repository"]["id"] == REPO_ID, "Unconfirmed physical run")
    release = helper.draft(RELEASE_ID)
    expected_name = CAMPAIGN + "-collection-registration.json"
    found = [x for x in release["assets"] if x.get("name") == expected_name]
    require(len(found) == 1, "Expected one owner collection ticket for this campaign")
    asset = found[0]
    if not aid:
        aid = str(asset["id"])
        digest = (asset.get("digest") or "").removeprefix("sha256:")
        require(asset.get("digest") == "sha256:" + digest and re.fullmatch("[0-9a-f]{64}", digest),
                "Service did not attest the discovered ticket digest")
    require(asset.get("id") == int(aid) and int(aid) > 0 and 0 < asset["size"] <= 4096
            and all((asset.get("uploader") or {}).get(k) == v for k,v in OWNER.items()),
            "Missing owner-issued collection registration")
    helper.asset_info(release, asset["name"], asset["size"], digest, int(aid))
    raw = io.BytesIO()
    helper.download(int(aid), asset["size"], digest, raw)
    require(hashlib.sha256(raw.getvalue()).hexdigest() == digest, "Wrong registration digest")
    ticket = json.loads(raw.getvalue())
    inputs = event["inputs"]
    parent = S2_SHA if inputs.get("build_segments","12") == "12" else (inputs.get("checkpoint_sha") or "cold")
    expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, workflow=WORKFLOW, branch=BASE_REF,
                    head=revision, initial_parent=parent, release_id=RELEASE_ID, recipient=RECIPIENT)
    require(all(ticket.get(k) == v for k,v in expected.items()) and inputs.get("apk_recipient",RECIPIENT) == RECIPIENT,
            "Registration belongs to another campaign, owner, revision or initial parent")
    service = ticket["collector_registration_id"]
    require(re.fullmatch(r"Automation_[0-9a-f]{32}", service), "A separately registered collection target is required")
    created, issued, expires = instant(api["created_at"]), instant(ticket["issued_at"]), instant(ticket["expires_at"])
    require(instant(asset["created_at"]) <= created and issued <= created <= now < expires,
            "Ticket expired or prepared after run creation")
    latest = checked_ack(helper, release, ticket, created, now)
    holder = dict(expected, registration_id=service, ticket_asset_id=int(aid), ticket_sha=digest,
                  run_id=run, producer_attempt=1)
    # Independent of ticket ID: two concurrent dispatches cannot bind this campaign twice.
    return admit("recover" if verify_only else "compute", holder, helper, name=CLAIM), service, latest


def main():
    sys.path.insert(0, str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    verify_only = sys.argv[1:] == ["check-lease"]
    require(verify_only or not sys.argv[1:], "Unknown registration operation")
    if verify_only:
        from recover_private import read_only
        transfer.request = read_only(transfer.request)
    claim, service, latest = bind(transfer, os.environ, event, datetime.now(timezone.utc), verify_only=verify_only)
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        print(f"claim_asset_id={claim}\ncollector_registration_id={service}\nlatest_start={latest}", file=out)
    print(f"Bound prior collection ticket to original run {os.environ['GITHUB_RUN_ID']} attempt 1; claim {claim}")


if __name__ == "__main__":
    main()
