"""Authorize one replacement for a particular failed, unsent S2 trial."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control"))
import admission as old

OLD_RUN = 45508307819
OLD_JOB = 138849157324
OLD_RECEIVER = 138862098593
OLD_HEAD = "77eba2168e05302346583bba0ba01082738f5742"
OLD_BEFORE = "b9553267cbb4f1645db9d2d40c4d85eb68c26d5d"
OLD_CLAIM_ID = 789237341
OWNER = "Areal-U"
OWNER_ID = 292261483
CAMPAIGN = "r28-preflight-s2-20261125-v2"
WORKFLOW = ".github/workflows/bare-r28-s2-recovery.yml"
CLAIM = CAMPAIGN + "-s2-run-claim.json"
CACHE_KEY = "bare-coexist-204-45285202990-1-checkpoint-production-s2"
CACHE_ID = 11016400308
CACHE_VERSION = "0264306e8c9c344d72477fc809ba4e6806bdcb35f30b425cf16709453c4e9acd"
OLD_RECEIPT = "Record retained parent and receiver manifest"
OLD_SEND = "Send only the verified generation to the existing owner Draft"
OLD_BUILD = "Validate parent and advance one required APK edge, then pack bounded zstd"
OLD_RESERVE = "Check canonical generation and reserve the single producer"


class CompleteDraft:
    """Keep the existing audited Draft checks and join all pages of its assets."""
    def __init__(self, helper):
        self.helper = helper

    def __getattr__(self, name):
        return getattr(self.helper, name)

    def draft(self, ident):
        old.require(ident == old.RELEASE_ID, "Unexpected release for recovery")
        release = self.helper.draft(ident)
        rows = []
        for page in range(1, 11):
            batch = self.helper.metadata(f"{self.BASE}/releases/{ident}/assets?per_page=100&page={page}")
            old.require(isinstance(batch, list) and len(batch) <= 100, "Invalid Draft inventory")
            rows.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise ValueError("Release inventory could not be completely reconciled")
        seen = {r["id"]: r["name"] for r in rows}
        old.require(len(seen) == len(rows) and
                    all(seen.get(a["id"]) == a["name"] for a in release["assets"]),
                    "Draft inventory changed during supersession")
        return {**release, "assets": rows}


def pinned_run(run, rid, head, workflow, attempt=1):
    old.require(run["id"] == rid and run["run_attempt"] == attempt and
                run["event"] == "pull_request" and run["path"] == workflow and
                run["head_sha"] == head and run["head_branch"] == old.BRANCH and
                all(run[k]["id"] == old.REPO_ID for k in ("repository", "head_repository")) and
                run["actor"]["id"] == OWNER_ID and run["actor"]["login"] == OWNER and
                any(p["number"] == 9 for p in run["pull_requests"]), "Unexpected physical run or attempt")


def failed_before_send(helper):
    run_path = f"{helper.BASE}/actions/runs/{OLD_RUN}"
    info = helper.metadata(run_path)
    pinned_run(info, OLD_RUN, OLD_HEAD, old.WORKFLOW)
    old.require(info["status"] == "completed" and info["conclusion"] == "failure",
                "Earlier trial is active, already accepted, or has an unreviewed result")
    jobs = helper.metadata(run_path + "/attempts/1/jobs?per_page=100")
    rows = {j["id"]: j for j in jobs["jobs"]}
    old.require(jobs["total_count"] == len(jobs["jobs"]) == len(rows) == 2 and set(rows) == {OLD_JOB, OLD_RECEIVER},
                "Earlier attempt's job list changed")
    producer, receiver = rows[OLD_JOB], rows[OLD_RECEIVER]
    old.require(all(j["status"] == "completed" and j["run_id"] == OLD_RUN and
                    j.get("run_attempt",1) == 1 and j.get("head_sha",OLD_HEAD) == OLD_HEAD for j in (producer, receiver)) and
                producer["name"] == "Create one S2 successor and transfer to fixed private Draft" and
                receiver["name"] == "Recover and verify required edge on an independent runner" and
                producer["conclusion"] == "failure" and receiver["conclusion"] == "skipped",
                "Earlier producer or receiver might have proceeded")
    steps = producer["steps"]
    by_name = {s["name"]: s for s in steps}
    old.require(len(by_name) == len(steps) and
                all(by_name[k]["status"] == "completed" for k in (OLD_RESERVE, OLD_BUILD, OLD_SEND, OLD_RECEIPT)) and
                by_name[OLD_RESERVE]["conclusion"] == "success" and by_name[OLD_BUILD]["conclusion"] == "failure" and
                by_name[OLD_SEND]["conclusion"] == by_name[OLD_RECEIPT]["conclusion"] == "skipped" and
                by_name[OLD_RESERVE]["number"] < by_name[OLD_BUILD]["number"] < by_name[OLD_SEND]["number"] < by_name[OLD_RECEIPT]["number"],
                "Earlier attempt may have sent the candidate")
    artifacts = helper.metadata(run_path + "/artifacts?per_page=100")
    old.require(artifacts["total_count"] == 0 and artifacts["artifacts"] == [],
                "Earlier trial retained an Artifact; recover it before another computation")


def old_holder():
    return {"schema": 1, "campaign": old.CAMPAIGN, "workflow": old.WORKFLOW, "repository_id": old.REPO_ID,
            "pr": 9, "run_id": OLD_RUN, "producer_attempt": 1, "producer_job": "produce",
            "head": OLD_HEAD, "before": OLD_BEFORE, "parent_s2_sha256": old.S2_SHA}


def listed_sources(helper, head, workflow_id):
    old.require(type(workflow_id) is int and workflow_id > 0, "Invalid physical workflow ID")
    prefix = (f"{helper.BASE}/actions/workflows/{workflow_id}/runs?"
              f"head_sha={head}&branch={old.BRANCH}&event=pull_request&per_page=100")
    found = {}
    for page in range(1,11):
        data = helper.metadata(f"{prefix}&page={page}")
        batch = data["workflow_runs"]
        old.require(isinstance(batch,list) and len(batch) <= 100, "Invalid matching workflow run list")
        for item in batch:
            old.require(item["id"] not in found and item["head_sha"] == head and
                        item["path"] == WORKFLOW and item["event"] == "pull_request" and
                        item["head_branch"] == old.BRANCH and item["repository"]["id"] == old.REPO_ID,
                        "Run listing is inconsistent with selected revision")
            found[item["id"]] = item
        if len(batch) < 100:
            old.require(data["total_count"] == len(found), "Partial run listing; cannot exclude another active worker")
            break
    else:
        raise ValueError("Too many matching workflow runs")
    return found


def physical_sources(helper, rid, head, workflow_id):
    for delay in (0,2,4):
        if delay:
            time.sleep(delay)
        found = listed_sources(helper, head, workflow_id)
        old.require(all(run_id == rid or item["status"] == "completed" for run_id,item in found.items()),
                    "Another run of this recovery at the same revision is active")
        if rid in found:
            return set(found)
    raise ValueError("GitHub has not yet indexed this physical run; no compute")


def intact_parent_and_no_candidate(helper, physical):
    query = f"{helper.BASE}/actions/caches?key={CACHE_KEY}&ref=refs%2Fheads%2F{old.BASE_REF}&per_page=100"
    record = helper.metadata(query)
    rows = record["actions_caches"]
    exact = [r for r in rows if r["key"] == CACHE_KEY]
    old.require(record["total_count"] == len(rows) and len(exact) == 1, "Ambiguous original S2 cache")
    item = exact[0]
    old.require(item["id"] == CACHE_ID and item["ref"] == "refs/heads/"+old.BASE_REF and
                item["size_in_bytes"] == 2742685925 and item["version"] == CACHE_VERSION,
                "Original S2 stored object changed")
    # The cache API has an opaque version, not the archive SHA. Only the ordinary
    # consumer may open it and verify the pinned inner SHA before any compilation.
    assets = helper.draft(old.RELEASE_ID)["assets"]
    conflicts = [a["id"] for a in assets if (a["name"].startswith(old.CAMPAIGN+"-") and a["name"] != old.CLAIM)
                 or (a["name"].startswith(CAMPAIGN+"-") and a["name"] != CLAIM)
                 or any(a["name"].startswith(f"r28-{rid}-a1-s01-") for rid in physical)]
    old.require(not conflicts, f"Existing S2 candidate or incomplete object needs recovery first: {conflicts}")
    old.require(old.claim_info(helper, old.encode(old_holder()), old.CLAIM) == OLD_CLAIM_ID,
                "Original canonical claim missing or replaced")


def checked_context(helper, env, event, checkout):
    rid = int(env["GITHUB_RUN_ID"])
    head, before = env["TRIAL_SHA"], env["PRIOR_SHA"]
    pr = event["pull_request"]
    old.require(rid > OLD_RUN and env["GITHUB_ACTOR"] == env["GITHUB_TRIGGERING_ACTOR"] == OWNER and
                env["GITHUB_REPOSITORY"] == old.REPO and env["GITHUB_EVENT_NAME"] == "pull_request" and
                env["GITHUB_REF"] == "refs/pull/9/merge", "Unexpected recovery revision, repo or actor")
    old.require(re.fullmatch("[0-9a-f]{40}", head) and re.fullmatch("[0-9a-f]{40}", before) and
                head != before and head == checkout == event["after"] == pr["head"]["sha"] and
                before == event["before"] and event["action"] == "synchronize" and event["number"] == pr["number"] == 9 and
                pr["head"]["ref"] == old.BRANCH and pr["base"]["ref"] == old.BASE_REF and
                pr["base"]["sha"] == old.BASE_SHA and event["sender"]["id"] == OWNER_ID and
                event["sender"]["login"] == OWNER and all(r["id"] == old.REPO_ID and r["full_name"] == old.REPO
                    for r in (event["repository"], pr["base"]["repo"], pr["head"]["repo"])), "Not the authorized PR9 revision")
    run = helper.metadata(f"{helper.BASE}/actions/runs/{rid}/attempts/1")
    pinned_run(run, rid, head, WORKFLOW)
    holder = {**old_holder(), "schema": 2, "campaign": CAMPAIGN, "workflow": WORKFLOW, "run_id": rid, "head": head,
              "before": before, "producer_job": "produce", "claim_job": "reserve", "parent_s2_cache_id": CACHE_ID,
              "supersedes_run": OLD_RUN, "supersedes_claim": OLD_CLAIM_ID, "supersedes_job": OLD_JOB,
              "supersedes_claim_sha256": hashlib.sha256(old.encode(old_holder())).hexdigest()}
    return run, holder


def reserve(helper, env, event, checkout):
    old.require(env["GITHUB_JOB"] == "reserve" and env["GITHUB_RUN_ATTEMPT"] == "1",
                "Only the first-attempt reserve job may supersede")
    run, holder = checked_context(helper, env, event, checkout)
    rid, head = holder["run_id"], holder["head"]
    old.require(run["status"] == "in_progress" and run["conclusion"] is None, "Replacement run is not active")
    helper = CompleteDraft(helper)
    failed_before_send(helper)
    physical = physical_sources(helper, rid, head, run["workflow_id"])
    intact_parent_and_no_candidate(helper, physical | {OLD_RUN})
    claim_id = old.admit("compute", holder, helper, name=CLAIM)
    print(f"campaign={CAMPAIGN} canonical_run={rid} claim_asset={claim_id} superseded_run={OLD_RUN} "
          f"superseded_job={OLD_JOB} superseded_claim={OLD_CLAIM_ID} remote_send=skipped original_cache_id={CACHE_ID} "
          f"inner_sha_required_before_build={old.S2_SHA}", flush=True)
    return claim_id


def verify(helper, env, event, checkout):
    attempt = int(env["GITHUB_RUN_ATTEMPT"])
    old.require(attempt >= 1 and env["GITHUB_JOB"] == "receive", "Only the restricted receiver may read recovery admission")
    first, holder = checked_context(helper, env, event, checkout)
    rid = holder["run_id"]
    if attempt > 1:
        current = helper.metadata(f"{helper.BASE}/actions/runs/{rid}/attempts/{attempt}")
        pinned_run(current, rid, holder["head"], WORKFLOW, attempt=attempt)
    else:
        current = first
    old.require(current["status"] == "in_progress" and current["conclusion"] is None,
                "Receiver is not running on the bound physical attempt")
    reader = CompleteDraft(helper)
    old.require(old.claim_info(reader, old.encode(old_holder()), old.CLAIM) == OLD_CLAIM_ID,
                "Original canonical claim missing or replaced")
    # The candidate is expected to exist here. Do not rerun the earlier uniqueness
    # check, require that the original cache still exists, or create a new claim.
    claim_id = old.claim_info(reader, old.encode(holder), CLAIM)
    old.require(claim_id is not None, "No original v2 claim; read-only receipt cannot start computation")
    print(f"campaign={CAMPAIGN} canonical_run={rid} producer_attempt=1 receiver_attempt={attempt} "
          f"claim_asset={claim_id} original_claim_asset={OLD_CLAIM_ID} mode=verify", flush=True)
    return claim_id


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("reserve","verify"))
    args = parser.parse_args()
    sys.path.insert(0, os.environ["RUNNER_TEMP"])
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    operation = reserve if args.mode == "reserve" else verify
    claim = operation(transfer, os.environ, event, checkout)
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        print(f"claim_id={claim}", file=out)
        print(f"source_run={os.environ['GITHUB_RUN_ID']}", file=out)


if __name__ == "__main__":
    main()
