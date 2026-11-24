"""Read only the original attempt's accepted receipts when a 12-slot run is rerun."""
import json
import os
from pathlib import Path
import re
import subprocess

from admission import REPO, S2_SHA

HEX = re.compile(r"[a-f0-9]{64}")
WORKFLOW = ".github/workflows/bare-checkpoint-transfer.yml"


def require(ok, why):
    if not ok:
        raise ValueError(why)


def get(path):
    return subprocess.check_output(["gh", "api", "--method", "GET", "repos/" + REPO + "/" + path],
                                   timeout=90).decode("utf-8-sig")


def prefix_matches(raw, prefix):
    pattern = re.compile(r"^\S+Z " + prefix + r" (\{.*\})$")
    return [json.loads(m[1]) for line in raw.splitlines() if (m := pattern.fullmatch(line))]


def follow(receipts, run, sha):
    current = S2_SHA
    confirmed = S2_SHA
    seen = {current}
    terminal = None
    for n, r in enumerate(sorted(receipts, key=lambda x: int(x["ordinal"])), 1):
        require(terminal is None and r["ordinal"] == n and n <= 13 and r["producer_sha"] == sha
                and r["accepted_parent"] == current, "Stale, duplicate or incomplete slot chain")
        state = r["status"]
        # Each non-initial segment must have passed the frontier gate before its
        # own success receipt. A final candidate without the next gate is pending.
        if n > 1:
            confirmed = current
        if state == "candidate":
            require(n <= 12 and r["key"] == f"bare-coexist-204-{run}-1-checkpoint-production-s{n}"
                    and HEX.fullmatch(r["sha"]) and HEX.fullmatch(r["identity"])
                    and r["sha"] not in seen, "Conflicting successor")
            current = r["sha"]
            seen.add(current)
        elif state == "apk":
            require(HEX.fullmatch(r["cipher_sha"]) and 0 < int(r["cipher_bytes"]) <= 451 * 1024**2,
                    "Invalid ciphertext receipt")
            aid, cache = r["cipher_id"], r["cipher_cache"]
            require((not aid or re.fullmatch(r"[1-9]\d*", aid)) and
                    (not cache or cache == f"bare-coexist-204-apk-v1-{run}-1-s{n}")
                    and (aid or cache), "Invalid archived APK location")
            terminal = r
        elif state in {"no-progress", "apk-size-exceeded", "cipher-size-exceeded"}:
            terminal = r
        elif state == "limit-verified":
            require(n == 13 and r["sha"] == current, "Unverified last parent")
            terminal = r
        else:
            raise ValueError("Unknown accepted state")
    return terminal or {"status":"recovery-no-terminal", "accepted_parent":confirmed, "pending":current}


def inventory(path, collection):
    rows = []
    for page in range(1, 101):
        response = json.loads(get(f"{path}?per_page=100&page={page}"))
        added = response[collection]
        rows.extend(added)
        if len(rows) == response["total_count"]:
            require(len({x["id"] for x in rows}) == len(rows), "Duplicate inventory records")
            return rows
        require(len(added) == 100 and len(rows) < response["total_count"], "Incomplete inventory")
    raise ValueError("Unbounded inventory")


S2_IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"


def last_private_slot(jobs, receipts, run, sha, artifacts):
    # A partial publication can only belong to a producer that actually started.
    # Slot 13 verifies a parent only and has no publishable next generation.
    pattern = re.compile(r"^Bounded build segment ([1-9]|1[0-2]) /")
    candidates = [int(m[1]) for j in jobs if (m := pattern.match(j["name"])) and j["run_id"] == run and
                  j["run_attempt"] == 1 and j.get("conclusion") != "skipped" and any(
                      s.get("name") == "Issue time-limited parent read descriptors bound to the peer" and
                      s.get("conclusion") == "success" for s in j.get("steps", []))]
    if not candidates:
        return {}
    n = max(candidates)
    if n == 1:
        parent, identity = S2_SHA, S2_IDENTITY
    else:
        previous = [r for r in receipts if r["ordinal"] == n-1 and r["status"]=="candidate" and r["producer_sha"]==sha]
        require(len(previous)==1, "Unconfirmed predecessor for private recovery")
        parent,identity=previous[0]["sha"],previous[0]["identity"]
    found = [a for a in artifacts if a["name"] == f"r28-{run}-a1-s{n:02}-outcome"]
    require(len(found)<=1, "Conflicting encrypted candidate artifacts")
    result = {"private_ordinal": n, "private_parent": parent, "private_identity": identity}
    if found:
        a,=found
        require(a["workflow_run"]["id"] == run and a["workflow_run"]["head_sha"] == sha and
                re.fullmatch(r"sha256:[a-f0-9]{64}", a.get("digest") or ""), "Unbound private trial envelope")
        result.update(private_outcome_asset_id=a["id"], private_outcome_expires_at=a["expires_at"],
                      private_outcome_expired=a["expired"], private_outcome_outer_digest=a["digest"])
    return result


def salvage(outcome, jobs, artifacts, run, head, read_log):
    pattern = re.compile(r"bare-personal-204-encrypted-" + str(run) + r"-1-s([1-9]|1[0-2])")
    matches = [(a, int(m[1])) for a in artifacts if (m := pattern.fullmatch(a["name"]))]
    require(len(matches) <= 1, "Multiple apparently terminal encrypted artifacts in this run")
    if not matches:
        return outcome
    asset, ordinal = matches[0]
    require(asset["workflow_run"]["id"] == run and asset["workflow_run"]["head_sha"] == head and
            int(asset["id"]) > 0 and re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""),
            "Encrypted artifact belongs to another operation")
    if outcome.get("status") == "apk":
        require(outcome["ordinal"] == ordinal and outcome.get("cipher_id", "") in ("", str(asset["id"])),
                "Artifact inventory conflicts with terminal receipt")
        return dict(outcome, cipher_id=str(asset["id"]), artifact_digest=asset["digest"])
    require(outcome["status"] == "recovery-no-terminal", "Artifact inventory conflicts with a stop")
    candidates = [j for j in jobs if j["run_id"] == run and j["run_attempt"] == 1 and
                  j["name"].startswith(f"Bounded build segment {ordinal} /") and any(
                      step.get("name") == "Upload the encrypted APK bundle" and step.get("conclusion") in
                      {"success", "failure", "cancelled"} for step in j.get("steps", []))]
    require(len(candidates) == 1, "No unique originating seal job")
    markers = prefix_matches(read_log(candidates[0]["id"]), "R28_SEALED_CIPHER")
    require(len(markers) == 1, "Original ciphertext seal record is missing")
    mark = markers[0]
    require(mark["run"] == run and mark["attempt"] == 1 and mark["ordinal"] == ordinal and
            HEX.fullmatch(mark["sha"]) and 0 < mark["bytes"] <= 451 * 1024**2, "Invalid original seal")
    return dict(outcome, status="apk", ordinal=ordinal, cipher_id=str(asset["id"]),
                cipher_sha=mark["sha"], cipher_bytes=str(mark["bytes"]), artifact_digest=asset["digest"],
                cipher_cache="", receipt_source="original-seal-and-artifact-id")


def main():
    run, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    sha = os.environ["GITHUB_SHA"]
    require(attempt > 1 and run > 0 and re.fullmatch("[0-9a-f]{40}", sha), "Expected a manual rerun")
    base = f"actions/runs/{run}/attempts/1"
    origin = json.loads(get(base))
    require(origin["id"] == run and origin["head_sha"] == sha and origin["path"] == WORKFLOW and
            origin["event"] == "workflow_dispatch" and origin["run_attempt"] == 1 and
            origin["head_branch"] == "bare-coexist-v2.0.4", "Incorrect producer run")
    jobs = inventory(base + "/jobs", "jobs")
    receipts = []
    for j in jobs:
        if not j["name"].endswith("Record the independently verified segment outcome") or j["conclusion"] != "success":
            continue
        require(j["run_id"] == run and j["run_attempt"] == 1, "Wrong producer attempt")
        results = prefix_matches(get(f"actions/jobs/{int(j['id'])}/logs"), "R28_SEGMENT_RECEIPT")
        require(len(results) == 1, "Expected one immutable result per slot")
        receipts.extend(results)
    outcome = follow(receipts, run, sha)
    artifacts = inventory(f"actions/runs/{run}/artifacts", "artifacts")
    outcome = salvage(outcome, jobs, artifacts, run, sha, lambda j: get(f"actions/jobs/{j}/logs"))
    if outcome["status"] == "recovery-no-terminal":
        outcome.update(last_private_slot(jobs, receipts, run, sha, artifacts))
    aid = outcome.get("cipher_id", "")
    if aid:
        artifact = json.loads(get("actions/artifacts/" + aid))
        require(artifact["id"] == int(aid) and artifact["workflow_run"]["id"] == run and
                artifact["workflow_run"]["head_sha"] == sha and
                artifact.get("digest") == outcome.get("artifact_digest") and
                artifact["name"] == f"bare-personal-204-encrypted-{run}-1-s{outcome['ordinal']}",
                "Different artifact than the original receipt")
        outcome["expires_at"] = artifact["expires_at"]
        if artifact["expired"]:
            outcome["cipher_id"] = ""
            require(outcome.get("cipher_cache"), "Artifact expired; check the private recipient's durable copy")
    print("R28_READ_ONLY_RECOVERY " + json.dumps(outcome, sort_keys=True))
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        for k in ("status", "cipher_id", "cipher_cache", "cipher_sha", "cipher_bytes",
                  "private_ordinal", "private_parent", "private_identity"):
            print(f"{k}={outcome.get(k,'')}",file=f)


if __name__ == "__main__":
    main()
