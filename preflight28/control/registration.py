"""Bind one previously registered, owner-only collection ticket to one physical build."""
import hashlib
import io
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import re
import sys

import slot1_handoff
import s1_resume
import s1_label_resume
from slot1_handoff import CAMPAIGN, CLAIM, TICKET_NAME
from admission import BASE_REF, REPO, REPO_ID, S2_SHA, RELEASE_ID, PagedOwnerDraft, admit, require

PREVIOUS_CAMPAIGN = "bare-personal-204-r29"
PREVIOUS_HEAD = "5737dcb88171dea54566bf4202d3d17092a1d176"
PREVIOUS_TICKET_SHA = "d6be078c59a3ab8c56ab928a8c0e183d76f39ddccba241586b676f2bfe49568a"
FIRST_TICKET_SHA = "c0a5b7fa88bc91bc616ac9c2f5fbf89054f5c34798206ed0ac744b6c0835d816"
FIRST_HEAD = "172a2b3e608632cf1e9155d866427456cdb4197c"
FIRST_RUN = 45763502309
FIRST_JOBS = {139718818153: "success", 139718863397: "failure", 139718917585: "failure"}
WORKFLOW = ".github/workflows/bare-checkpoint-transfer.yml"
OWNER = {"id": 292261483, "login": "Areal-U"}
RECIPIENT = "age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx"
SEGMENT_MINUTES = 350


def instant(value):
    require(isinstance(value, str) and value.endswith("Z"), "Expected UTC timestamp")
    return datetime.fromisoformat(value[:-1] + "+00:00")



def read_prior_ticket(helper, release, earlier_name, digest):
    found = [row for row in release["assets"] if row["name"] == earlier_name]
    require(len(found) == 1, "Prior owner ticket missing or ambiguous")
    row = found[0]
    require(type(row["id"]) is int and row["id"] > 0 and row["state"] == "uploaded" and
            0 < row["size"] <= 4096 and row["digest"] == "sha256:" + digest and
            all(row["uploader"].get(k) == v for k, v in OWNER.items()), "Unconfirmed prior owner ticket")
    helper.asset_info(release, earlier_name, row["size"], digest, row["id"])
    raw = io.BytesIO()
    helper.download(row["id"], row["size"], digest, raw)
    require(len(raw.getvalue()) == row["size"] and hashlib.sha256(raw.getvalue()).hexdigest() == digest,
            "Prior owner ticket changed")
    return json.loads(raw.getvalue())


def same_owner_as_previous(helper, release, ticket):
    """Keep the prior campaign's owner binding and the same R30 collector on reissue."""
    prior = read_prior_ticket(helper, release, PREVIOUS_CAMPAIGN + "-collection-registration.json", PREVIOUS_TICKET_SHA)
    fields = dict(schema=1, campaign=PREVIOUS_CAMPAIGN, head=PREVIOUS_HEAD,
                  initial_parent=S2_SHA, repository_id=REPO_ID, release_id=RELEASE_ID,
                  workflow=WORKFLOW, branch=BASE_REF, recipient=RECIPIENT)
    require(all(prior.get(k) == v for k,v in fields.items()) and
            prior["owner_destination_id"] == ticket["owner_destination_id"] and
            prior["registration_nonce"] != ticket["registration_nonce"] and
            prior["collector_registration_id"] != ticket["collector_registration_id"] and
            prior["head"] != ticket["head"], "Changed destination or reused prior owner registration")

    first = read_prior_ticket(helper, release, CAMPAIGN + "-collection-registration.json", FIRST_TICKET_SHA)
    expected = dict(fields, campaign=CAMPAIGN, head=FIRST_HEAD)
    same = ("collector_registration_id", "owner_destination_id", "storage_policy", "artifact_ceiling_bytes",
            "storage_valid_until", "expires_at")
    require(all(first.get(k) == v for k, v in expected.items()) and
            all(first[k] == ticket.get(k) for k in same) and first["head"] != ticket["head"] and
            first["registration_nonce"] != ticket["registration_nonce"] and
            first["collector_ack_sha"] != ticket["collector_ack_sha"], "Invalid R30 pre-claim reissue or changed storage policy")


def check_first_run(helper):
    """The single earlier physical attempt failed in admission and performed no build work."""
    base = f"{helper.BASE}/actions/runs/{FIRST_RUN}/attempts/1"
    run = helper.metadata(base)
    require(run["id"] == FIRST_RUN and run["run_attempt"] == 1 and run["head_sha"] == FIRST_HEAD and
            run["repository"]["id"] == run["head_repository"]["id"] == REPO_ID and
            run["event"] == "workflow_dispatch" and run["path"] == WORKFLOW and run["head_branch"] == BASE_REF and
            all(run["actor"].get(k) == v for k, v in OWNER.items()) and
            run["status"] == "completed" and run["conclusion"] == "failure", "Prior R30 attempt still open or foreign")
    page = helper.metadata(base + "/jobs?per_page=100")
    jobs = page["jobs"]
    require(0 < len(jobs) == page["total_count"] <= 100 and len({j["id"] for j in jobs}) == len(jobs) and
            all(j["run_id"] == FIRST_RUN and j["run_attempt"] == 1 and j["head_sha"] == FIRST_HEAD and
                j["status"] == "completed" for j in jobs) and
            {j["id"]: j["conclusion"] for j in jobs if j["conclusion"] != "skipped"} == FIRST_JOBS,
            "Unconfirmed pre-claim closure or prior compute job")


def checked_ack(helper, release, ticket, created, now):
    """The owner ticket pins the separate collector self-read response by immutable ID/digest."""
    nonce = ticket.get("registration_nonce", "")
    destination = ticket.get("owner_destination_id", "")
    require(re.fullmatch("[0-9a-f]{32,64}", nonce) and re.fullmatch("[A-Za-z0-9_-]{12,200}", destination),
            "Missing registration nonce or owner destination")
    sha = ticket.get("collector_ack_sha")
    require(isinstance(sha,str) and re.fullmatch("[0-9a-f]{64}",sha),
            "The independently registered collector has not acknowledged readiness")
    name = CAMPAIGN + "-collector-ack-" + nonce + ".json"
    found = [a for a in release["assets"] if a["name"] == name]
    require(len(found) == 1, "The exact pinned collector acknowledgement is unavailable")
    ack_asset = found[0]
    aid = ack_asset["id"]
    require(type(aid) is int and aid > 0, "Invalid immutable collector ACK ID")
    if "collector_ack_asset_id" in ticket:
        expected = ticket["collector_ack_asset_id"]
        require(type(expected) is int and expected == aid, "Different pinned collector ACK ID")
    else:
        require(all((ack_asset.get("uploader") or {}).get(k) == v for k,v in OWNER.items()) and
                ack_asset.get("state") == "uploaded" and ack_asset.get("digest") == "sha256:" + sha,
                "Discovered ACK does not match the owner, upload state or pinned digest")
    require(0 < ack_asset["size"] <= 4096 and instant(ack_asset["created_at"]) <= created,
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
    latest = min(instant(ack["valid_until"]),instant(ticket["expires_at"])) - timedelta(seconds=(SEGMENT_MINUTES+25+45+7)*60+2*period+retry)
    require(instant(ack["observed_at"]) <= created <= now <= latest,
            "Collector lease does not cover this segment and pickup")
    return int(latest.timestamp()), dict(ack, collector_ack_asset_id=aid)


def checked_build_route(inputs, *, resume=False):
    """This campaign's sole physical claim authorizes the approved numbered Draft pipeline."""
    required = {"mode": "build-apk", "build_segments": "12", "checkpoint_backend": "draft",
                "apk_recipient": RECIPIENT, "jobs": "2", "output_gib": "18"}
    require(all(inputs.get(k, v) == v for k, v in required.items()) and
            inputs.get("compile_minutes", "0") in ("0", "180") and
            inputs.get("checkpoint_compression", "auto") in ("auto", "compact") and
            inputs.get("retain_existing_caches", "false") in ("false", False) and
            not inputs.get("loss_origin_run") and not inputs.get("encrypted_apk_bytes"),
            "Dispatch differs from the R28 numbered Draft build")
    parent = tuple(inputs.get(k, "") for k in ("checkpoint_key", "checkpoint_sha", "checkpoint_identity"))
    if resume:
        pinned = (f"bare-coexist-204-{s1_resume.SOURCE_RUN}-1-checkpoint-production-s1",
                  s1_resume.PARENT_SHA, s1_resume.PARENT_IDENTITY)
    else:
        pinned = ("bare-coexist-204-45285202990-1-checkpoint-production-s2", S2_SHA,
                  "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc")
    require(parent in (("", "", ""), pinned), "Only the complete fixed parent may be supplied")


def bind(helper, env, event, now=None, *, verify_only=False):
    # Explicit reference times remain available to replay historical evidence.
    live_clock = now is None
    if live_clock:
        now = datetime.now(timezone.utc)
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
    resume = env.get("R30_RESUME_S1") == "1"
    checked_build_route(event["inputs"], resume=resume)
    gate = s1_label_resume if resume else slot1_handoff
    api = helper.metadata(f"{helper.BASE}/actions/runs/{run}/attempts/1")
    require(api["id"] == run and api["run_attempt"] == 1 and api["head_sha"] == revision
            and api["path"] == WORKFLOW and api["event"] == "workflow_dispatch" and api["head_branch"] == BASE_REF
            and all(api["actor"].get(k) == v for k,v in OWNER.items())
            and api["repository"]["id"] == api["head_repository"]["id"] == REPO_ID, "Unconfirmed physical run")
    helper = PagedOwnerDraft(helper)
    release = helper.draft(RELEASE_ID)
    expected_name = gate.TICKET_NAME
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
    expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, workflow=WORKFLOW, branch=BASE_REF,
                    head=revision, initial_parent=s1_resume.PARENT_SHA if resume else S2_SHA, release_id=RELEASE_ID, recipient=RECIPIENT)
    require(all(ticket.get(k) == v for k,v in expected.items()),
            "Registration belongs to another campaign, owner, revision or initial parent")
    if not resume:
        same_owner_as_previous(helper, release, ticket)
        if not verify_only:
            check_first_run(helper)
    gate.validate_source(helper, release, ticket, initial=not verify_only)
    service = ticket["collector_registration_id"]
    require(re.fullmatch(r"Automation_[0-9a-f]{32}", service), "A separately registered collection target is required")
    created, issued, expires = instant(api["created_at"]), instant(ticket["issued_at"]), instant(ticket["expires_at"])
    require(instant(asset["created_at"]) <= created and issued <= created <= now < expires,
            "Ticket expired or prepared after run creation")
    latest, ack = checked_ack(helper, release, ticket, created, now)
    if resume:
        s1_resume.fields(ack, gate.route(ticket), "Independent receiver did not accept this candidate and trial")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"bridge"))
    import storage_admission
    ceiling, until = storage_admission.policy(ticket, ack)
    settings = dict(env, R28_STORAGE_CEILING=str(ceiling), R28_STORAGE_UNTIL=str(until))
    # Before the immutable production claim and again on each collection lease.
    storage_admission.draft_room(release, settings, claim=not verify_only)
    storage_admission.admit(helper.metadata, settings, storage_admission.lease_size(settings), 1,
                            stage="lease", now=None if live_clock else now.timestamp(), lead=SEGMENT_MINUTES*60)
    holder = dict(expected, registration_id=service, ticket_asset_id=int(aid), ticket_sha=digest,
                  run_id=run, producer_attempt=1, source_run_id=gate.SOURCE_RUN,
                  source_claim_id=gate.SOURCE_CLAIM_ID, source_claim_sha=gate.SOURCE_CLAIM_SHA)
    if "collector_ack_asset_id" not in ticket:
        holder["collector_ack_asset_id"] = ack["collector_ack_asset_id"]
    if resume:
        holder.update(gate.route(ticket))
        gate.check_reference(holder, ticket)
    else:
        slot1_handoff.check_reference(holder)
    storage_latest = (until - SEGMENT_MINUTES*60 - storage_admission.JOURNAL_TAIL
                      - storage_admission.JOURNAL_DAYS*storage_admission.DAY)

    def check_window():
        decision = datetime.now(timezone.utc) if live_clock else now
        require(now <= decision and decision.timestamp() <= latest,
                "Collector lease no longer covers this segment and pickup after admission reads")
        require(decision.timestamp() <= storage_latest, "Storage policy expired during registration")

    # Check again at the real claim POST after the final private inventory, and
    # before handing the verified lease to the next job after claim readback.
    check_window()
    claim = admit("recover" if verify_only else "compute", holder, helper, name=gate.CLAIM, before_write=check_window)
    check_window()
    return claim, service, latest, ceiling, until


def main():
    sys.path.insert(0, str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    verify_only = sys.argv[1:] == ["check-lease"]
    require(verify_only or not sys.argv[1:], "Unknown registration operation")
    if verify_only:
        from recover_private import read_only
        transfer.request = read_only(transfer.request)
    claim, service, latest, ceiling, until = bind(transfer, os.environ, event, verify_only=verify_only)
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        print(f"claim_asset_id={claim}\ncollector_registration_id={service}\nlatest_start={latest}\nstorage_ceiling={ceiling}\nstorage_until={until}", file=out)
    print(f"Bound prior collection ticket to original run {os.environ['GITHUB_RUN_ID']} attempt 1; claim {claim}")


if __name__ == "__main__":
    main()
