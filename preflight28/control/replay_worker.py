"""Read-only segment worker for the real S2 preflight.

It follows the original S2 receipt, the real producing runner, and the separate
receiving runner. It deliberately has no ability to dispatch builds, publish a
checkpoint or sign an APK. The 'compute' slot only verifies existing evidence.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from admission import BASE_SHA, BRANCH, REPO, REPO_ID, S2_SHA, WORKFLOW, require
from chain import SEED

RUN27 = 45285202990
S2_READER = 138267741671
S2_KEY = "bare-coexist-204-45285202990-1-checkpoint-production-s2"
PRODUCER = "Create one S2 successor and transfer to fixed private Draft"
RECEIVER = "Recover and verify required edge on an independent runner"
DIGEST = r"[0-9a-f]{64}"


class GitHubHistory:
    def get(self, path):
        return json.loads(self.raw(path))

    def raw(self, path):
        # The only permitted paths are built from fixed repository strings and
        # validated numeric IDs. gh follows GitHub's signed redirect for logs.
        data = subprocess.check_output(["gh", "api", "--method", "GET", f"repos/{REPO}/{path}"],
                                       timeout=120)
        if len(data) > 64 * 1024**2:
            raise ValueError("GitHub evidence exceeds replay size bound")
        return data.decode("utf-8-sig")


def job(h, run, attempt, name):
    matches = h.get(f"actions/runs/{run}/attempts/{attempt}/jobs?per_page=100")
    require(matches["total_count"] == len(matches["jobs"]), "Incomplete job inventory")
    selected = [j for j in matches["jobs"] if j["name"] == name and
                j["run_attempt"] == attempt and j["run_id"] == run]
    require(len(selected) == 1 and selected[0]["conclusion"] == "success",
            "Missing unique successful service job: " + name)
    return selected[0]


def historical_seed(h):
    record = h.get(f"actions/jobs/{S2_READER}")
    require(record["id"] == S2_READER and record["run_id"] == RUN27 and record["run_attempt"] == 1
            and record["head_sha"] == BASE_SHA and record["conclusion"] == "success",
            "Historic S2 job identity changed")
    log = h.raw(f"actions/jobs/{S2_READER}/logs")
    require(S2_SHA in log and f"Verified successor cache {S2_KEY}" in log
            and '"archive_bytes": 2753879385' in log and '"members": 291583' in log,
            "Original S2 successful independent verification is missing")
    return SEED


def payloads(lines):
    for line in lines.splitlines():
        # Ignore shell source echoed in step groups. Parse only emitted JSON lines.
        t = re.match(r"^\S+Z (?P<data>(?:manifest_receipt=)?\{.*\})$", line)
        if t:
            raw = t["data"]
            try:
                yield raw.startswith("manifest_receipt="), json.loads(raw.removeprefix("manifest_receipt="))
            except ValueError:
                continue


def one(rows, label):
    rows = list(rows)
    require(len(rows) == 1, "Missing or conflicting " + label)
    return rows[0]


def producer(h, run, sha):
    info = h.get(f"actions/runs/{run}/attempts/1")
    require(info["id"] == run and info["run_attempt"] == 1 and info["event"] == "pull_request"
            and info["path"] == WORKFLOW and info["head_sha"] == sha and info["head_branch"] == BRANCH
            and info["repository"]["id"] == REPO_ID and info["head_repository"]["id"] == REPO_ID
            and any(p["number"] == 9 for p in info["pull_requests"]), "Unexpected producing run")
    record = job(h, run, 1, PRODUCER)
    content = h.raw(f"actions/jobs/{int(record['id'])}/logs")
    phases = list(payloads(content))
    manifest = one((d for prefixed, d in phases if prefixed), "producer manifest receipt")
    graph = one((d for _, d in phases if "new_target" in d and "proof_sha256" in d), "producer graph proof")
    require(f"canonical_run={run} producer_attempt=1 current_attempt=1" in content and
            "protected_s2_id=11016400308 outer=2742685925" in content and
            manifest["name"].startswith(f"r28-preflight-s2-20261125-v1-run{run}-a1-seg01-manifest.json") and
            type(manifest["id"]) is int and manifest["id"] > 0 and
            bool(re.fullmatch(DIGEST, manifest["sha256"])) and 0 < manifest["bytes"] <= 12288 and
            graph["parent_dirty"] > graph["child_dirty"] >= 0 and bool(re.fullmatch(DIGEST, graph["proof_sha256"])),
            "Invalid published preflight evidence")
    return f"draft:{manifest['id']}:{manifest['sha256']}", manifest["id"], graph, record["id"]


def independent(h, run, attempt, manifest_id, graph, producer_id):
    record = job(h, run, attempt, RECEIVER)
    require(record["id"] != producer_id, "Receiver and producer job are identical")
    content = h.raw(f"actions/jobs/{int(record['id'])}/logs")
    require(re.search(rf"^\S+Z independent_draft_read_id={manifest_id} archive_bytes=[1-9][0-9]* sha256={DIGEST}$",
                      content, re.MULTILINE), "Independent read did not reacquire the publisher's manifest")
    read = one((d for _, d in payloads(content) if "restored_target" in d), "independent graph report")
    require(read["restored_target"] == graph["new_target"] and
            read["proof_sha256"] == graph["proof_sha256"] and
            read["parent_dirty"] == graph["parent_dirty"] and
            read["restored_dirty"] == graph["child_dirty"],
            "Independent receiver did not recover the same APK edge and frontier")


def replay(h, *, mode, ordinal, parent, source_run, source_sha, receiver_attempt, current_attempt):
    require(source_run > 0 and receiver_attempt > 0 and current_attempt > 0 and
            bool(re.fullmatch("[0-9a-f]{40}", source_sha)), "Invalid physical evidence selector")
    if mode == "recover-only":
        require(ordinal == 0 and parent == "" and current_attempt > 1, "Invalid recovery input")
    else:
        require(mode == "verify-and-compute" and ordinal in (1, 2) and current_attempt == 1,
                "This preflight worker handles one generation and its independent receipt only")
    historical_seed(h)
    child, manifest_id, graph, producer_id = producer(h, source_run, source_sha)
    if ordinal == 1:
        require(parent == SEED, "Unexpected predecessor of the S2 candidate")
        return "candidate", child, SEED
    if ordinal == 2:
        require(parent == child, "Delayed or foreign candidate cannot advance")
    independent(h, source_run, receiver_attempt, manifest_id, graph, producer_id)
    return "preflight-received", child, child


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--ordinal", type=int, required=True)
    parser.add_argument("--parent", required=True)
    args = parser.parse_args()
    rid = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    status, receipt, parent = replay(GitHubHistory(), mode=args.mode, ordinal=args.ordinal,
             parent=args.parent, source_run=int(os.environ["SOURCE_RUN_ID"]), source_sha=os.environ["SOURCE_HEAD_SHA"],
             receiver_attempt=int(os.environ["SOURCE_RECEIVER_ATTEMPT"]), current_attempt=attempt)
    require(rid > 0, "Invalid replay owner")
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        for key, val in dict(status=status, receipt=receipt, accepted_parent=parent, ordinal=args.ordinal,
                             owner_run=rid, owner_attempt=1).items():
            print(f"{key}={val}", file=out)
    print(f"preflight evidence run={os.environ['SOURCE_RUN_ID']} status={status} receipt={receipt}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        sys.exit(str(error))
