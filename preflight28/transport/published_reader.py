"""Read the immutable original S2 publication after its ordinary read grant failed."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import thaw_claim as thaw

RUN = 45522666298
HEAD = "2c2ba5c9c04f691d20b6f67f7f21034c0cdc4534"
BEFORE = "8090a5a88ed3625bed1a5cfe57fafdb657721caf"
RECOVER, ISSUE, RECEIVE = 138898154898, 138903070166, 138903070096
CLAIM_ID, CLAIM_BYTES = 789516828, 1892
CLAIM_SHA = "846e2a749d626366d85c754c41bc88fb7a7842d5ac0a13bdfcc49b91c4dd0681"
PART_ID = 789540148
MANIFEST_ID, MANIFEST_BYTES = 789542812, 974
MANIFEST_SHA = "2bf4a5a4516e5c5609d151a26436a7e4a0f04f067079796880333cdb32329267"
AUDIT_SHA = "12ccf1d57ef4c0aa89de82c6a3a9d99e6ab1456f2508b0f198a31d0bc02eb6b7"
# Independent owner read of the exact UTF-8 issuer/publisher transcripts. The
# historical job log API denies the workflow token. Its metadata API returns
# the authoritative attempt, job and step status checked again at admission.
PUBLISH_LOG_SHA = "e9aefa7f3e5a0ab9e4901d84de28f94f133df0b8dfac708532b6de7641567966"
ISSUE_LOG_SHA = "652657894233148b24493899835028219762666617e12e2f71fc5d606081f6e6"
require = thaw.require

JOBS = {
    RECOVER: ("Recover original sealed candidate and audit before immutable private publication", "success"),
    ISSUE: ("Grant only a short-lived read of original private checkpoint parts", "failure"),
    RECEIVE: ("Ordinary runner reads and verifies the private generation from the original recipe", "failure"),
}
# Steps within each tuple are ordered by the provider's step number.
STEPS = {
    RECOVER: (
        ("Confirm failed prior acceptance, exact surviving artifacts and new single recovery claim", "success"),
        ("Read verified original original-key Artifact by immutable ID", "success"),
        ("Read verified original original-cipher Artifact by immutable ID", "success"),
        ("Read original S2 for exact archive comparison", "success"),
        ("Open original authenticated frames and verify the original producer evidence", "success"),
        ("Recover already committed identical private bytes without any new key exchange", "skipped"),
        ("Compare every original S2 payload and audit the GN diagnostic in the actual graphs", "success"),
        ("Preserve a bounded failed continuity report encrypted to the original disposable test recipient", "skipped"),
        ("Deposit failed-audit for this exact recovery", "skipped"),
        ("Authorize only the fixed original archive using the complete accepted audit", "success"),
        ("Reconcile original data and publish the original immutable generation", "success"),
    ),
    ISSUE: (
        ("Read the exact original successful recovery claim before granting asset access", "success"),
        ("Locate authenticated key Artifact", "success"),
        ("Read exact peer Artifact", "success"),
        ("Issue fresh part-scoped GET redirects encrypted to the separate runner", "failure"),
        ("Deposit descriptor for this exact recovery", "skipped"),
    ),
    RECEIVE: (
        ("Verify ordinary token denial and generate ephemeral receiver public key", "success"),
        ("Deposit receiver-key for this exact recovery", "success"),
        ("Locate authenticated descriptor Artifact", "failure"),
        ("Read exact peer Artifact", "skipped"),
        ("Download and hash every private checkpoint byte without repository credentials", "skipped"),
        ("Independently restore using the exact original code, provenance, and strictly dry APK plan", "skipped"),
    ),
}


@contextmanager
def read_only(transfer):
    original = transfer.request

    def get(host, method, path, **options):
        require(method == "GET" and not ({"body", "length", "content_type"} & options.keys()),
                "Only bodyless GET is permitted while checking the existing publication")
        return original(host, method, path, **options)

    transfer.request = get
    try:
        yield thaw.v2.CompleteDraft(transfer)
    finally:
        transfer.request = original


def historical_run(api):
    root = f"{api.BASE}/actions/runs/{RUN}"
    # Latest run_attempt must still be 1. A later attempt could have delivered
    # a grant after the frozen transcript was captured.
    for path in (root, root + "/attempts/1"):
        row = api.metadata(path)
        thaw.v2.pinned_run(row, RUN, HEAD, thaw.WORKFLOW)
        require(row["status"] == "completed" and row["conclusion"] == "failure",
                "Original reader is still active or has a different terminal outcome")
    page = api.metadata(root + "/attempts/1/jobs?per_page=100")
    jobs = {row["id"]: row for row in page["jobs"]}
    require(set(jobs) == set(JOBS) and len(page["jobs"]) == page["total_count"] == 3,
            "Original publication attempt is ambiguous")
    for jid, (name, conclusion) in JOBS.items():
        job = jobs[jid]
        require(job["name"] == name and job["status"] == "completed" and job["conclusion"] == conclusion and
                job["run_id"] == RUN and job.get("run_attempt", 1) == 1 and job.get("head_sha", HEAD) == HEAD,
                "Original publication job or terminal outcome differs")
        stages = {s["name"]: s for s in job["steps"]}
        require(len(stages) == len(job["steps"]) and all(s["status"] == "completed" for s in stages.values()),
                "Incomplete or ambiguous original job steps")
        expected = STEPS[jid]
        require(all(stages.get(label, {}).get("conclusion") == result for label, result in expected) and
                {label for label, s in stages.items() if s["conclusion"] == "failure"} ==
                {label for label, result in expected if result == "failure"},
                "Original read stopped at a different boundary")
        numbers = [stages[label]["number"] for label, _ in expected]
        require(numbers == sorted(set(numbers)), "Original publication step order differs")


def previous_reads(api, env):
    """Before a retry, ensure no earlier ordinary VM already completed this delivery."""
    attempt, rid = int(env["GITHUB_RUN_ATTEMPT"]), int(env["GITHUB_RUN_ID"])
    require(attempt <= 12, "Read retry history exceeds the review bound")
    fetch, restore = (label for label, _ in STEPS[RECEIVE][-2:])
    for n in range(1, attempt):
        root = f"{api.BASE}/actions/runs/{rid}/attempts/{n}"
        row = api.metadata(root)
        thaw.v2.pinned_run(row, rid, env["TRIAL_SHA"], thaw.WORKFLOW, n)
        require(row["status"] == "completed" and row["conclusion"] in
                {"failure", "cancelled", "timed_out", "success", "startup_failure"},
                "Earlier read attempt has not reached a known terminal state")
        page = api.metadata(root + "/jobs?per_page=100")
        jobs = page["jobs"]
        require(len(jobs) == page["total_count"] <= 2 and len({j["id"] for j in jobs}) == len(jobs) and
                all(j["run_id"] == rid and j.get("run_attempt", n) == n and
                    j.get("head_sha", env["TRIAL_SHA"]) == env["TRIAL_SHA"] and j["status"] == "completed" and
                    j["name"] in {JOBS[ISSUE][0], JOBS[RECEIVE][0]} for j in jobs),
                "Incomplete or foreign read retry history")
        readers = [j for j in jobs if j["name"] == JOBS[RECEIVE][0]]
        require(len(readers) <= 1, "Duplicate ordinary readers in prior attempt")
        if readers:
            steps = readers[0]["steps"]
            outcomes = {s["name"]: s["conclusion"] for s in steps}
            require(len(outcomes) == len(steps) and all(s["status"] == "completed" for s in steps),
                    "Incomplete prior ordinary read history")
            require(outcomes.get(restore) != "success" and readers[0]["conclusion"] != "success",
                    "The ordinary reader already finished this immutable delivery")
            require(outcomes.get(fetch) != "success" or outcomes.get(restore) in
                    {"failure", "cancelled", "timed_out", "skipped"},
                    "Earlier verified download has an unknown restore outcome")
        else:
            require(row["conclusion"] != "success", "Successful prior read has no ordinary job receipt")


def verify(transfer, env, event, checkout):
    require(env["R28_RESUME_PUBLISHED"] == str(RUN) and int(env["GITHUB_RUN_ID"]) > RUN and
            env["MANIFEST_ID"] == str(MANIFEST_ID) and env["MANIFEST_SHA"] == MANIFEST_SHA,
            "Wrong read-only publication binding")
    with read_only(transfer) as api:
        thaw.check_event(api, env, event, checkout, "verify")
        previous_reads(api, env)
        historical_run(api)
        holder = thaw.a.encode(thaw.next_holder(RUN, HEAD, BEFORE, thaw.HISTORY[-1], 5))
        require(len(holder) == CLAIM_BYTES and hashlib.sha256(holder).hexdigest() == CLAIM_SHA and
                thaw.a.claim_info(api, holder, thaw.CLAIM) == CLAIM_ID, "Accepted publication claim differs")
        release = api.draft(thaw.a.RELEASE_ID)
        api.asset_info(release, thaw.STEM + "p00", thaw.SIZE, thaw.CHILD, PART_ID)
        api.asset_info(release, thaw.STEM + "manifest.json", MANIFEST_BYTES, MANIFEST_SHA, MANIFEST_ID)
        # Re-fetch the entire manifest and bind every canonical field, original
        # data-part ID and historical receipt. The ordinary VM performs the full
        # independent 1,745,316,602-byte GET under the new part-scoped grant.
        require(thaw.check_original_draft(api) == MANIFEST_ID, "Original manifest failed authenticated readback")
    return {"source_run": thaw.SOURCE, "source_head": thaw.HEAD, "claim_id": CLAIM_ID, "part_id": PART_ID,
            "original_manifest_id": MANIFEST_ID, "manifest_id": MANIFEST_ID, "manifest_sha": MANIFEST_SHA,
            "source_sha": thaw.CHILD, "source_bytes": thaw.SIZE, "original_audit_sha": AUDIT_SHA}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify",))
    parser.parse_args()
    sys.path.insert(0, os.environ["RUNNER_TEMP"])
    import transfer
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    checkout = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    receipt = verify(transfer, os.environ, event, checkout)
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for key, value in receipt.items():
            print(f"{key}={value}", file=out)
    print("authenticated_original_publication=" + json.dumps(receipt, sort_keys=True), flush=True)
    print(f"original_publish_job={RECOVER} transcript_sha={PUBLISH_LOG_SHA} original_issue_job={ISSUE} "
          f"transcript_sha={ISSUE_LOG_SHA} original_grant=direct_404_anonymous_primary_rate_403", flush=True)


if __name__ == "__main__":
    main()
