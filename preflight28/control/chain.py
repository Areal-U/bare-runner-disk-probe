"""Render a finite same-run DAG and check its result without starting any workflow.

The caller supplies a *reviewed*, local reusable worker with independent restore,
verification, produce, and final-recovery modes. The output is a workflow_call
template; it has no push/PR/dispatch trigger. The preflight itself uses one real
producer and one real receiver in bare-r28-s2-preflight.yml.
"""
import argparse
import json
import os
from pathlib import Path
import re

from admission import S2_SHA, require

LIMIT = 12
SEED = f"actions-cache:11016400308:{S2_SHA}"
LOCATOR = re.compile(r"(?:draft|artifact|actions-cache):[1-9][0-9]{0,18}:[0-9a-f]{64}")
CHECKOUT = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"
OUTPUTS = ("status", "receipt", "accepted_parent", "owner_run", "owner_attempt", "ordinal")


def slot(number):
    return f"slot{number:02}"


def worker_contract(workflow):
    """Reject a template with unconnected inputs/outputs before emitting a caller."""
    import yaml
    caller = yaml.safe_load(workflow.read_text())
    events = caller.get("on", caller.get(True))
    require(isinstance(events, dict) and "workflow_call" in events, "Missing workflow_call")
    contract = events["workflow_call"]
    for key, kind in {"mode": "string", "ordinal": "number", "parent": "string"}.items():
        require(contract["inputs"][key]["type"] == kind, f"Invalid worker input {key}")
    additional = {k: contract["inputs"][k] for k in
                  ("source_run_id", "source_head_sha", "source_receiver_attempt") if k in contract["inputs"]}
    for key in OUTPUTS:
        binding = contract["outputs"][key].get("value", "")
        match = re.fullmatch(r"\$\{\{\s*jobs\.([A-Za-z_][A-Za-z0-9_-]*)\.outputs\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}", binding)
        require(match and match[2] in caller.get("jobs", {}).get(match[1], {}).get("outputs", {}),
                f"Worker does not expose a job-backed {key} receipt")
    return additional


def render(workflow, count=LIMIT):
    require(1 <= count <= LIMIT, "Invalid slot limit")
    require(re.fullmatch(r"[A-Za-z0-9_-]+\.ya?ml", workflow.name), "Invalid worker filename")
    additional = worker_contract(workflow)
    forwards = {k: "${{ inputs." + k + " }}" for k in additional}
    worker = "./.github/workflows/" + workflow.name
    jobs = {}
    initial = "github.run_attempt == '1'"
    for n in range(1, count + 2):
        previous = slot(n - 1)
        last_receive = n == count + 1
        condition = f"!cancelled() && {initial}"
        parent = SEED
        if n > 1:
            condition += (f" && needs.{previous}.result == 'success'"
                          f" && needs.{previous}.outputs.status == 'candidate'"
                          f" && needs.{previous}.outputs.receipt != ''"
                          f" && needs.{previous}.outputs.receipt != needs.{previous}.outputs.accepted_parent"
                          f" && needs.{previous}.outputs.owner_run == github.run_id"
                          f" && needs.{previous}.outputs.owner_attempt == '1'"
                          f" && needs.{previous}.outputs.ordinal == '{n-1}'")
            expected_parent = f"'{SEED}'" if n == 2 else f"needs.{slot(n - 2)}.outputs.receipt"
            condition += f" && needs.{previous}.outputs.accepted_parent == {expected_parent}"
            parent = "${{ needs." + previous + ".outputs.receipt }}"
        job = {"if": "${{ " + condition + " }}", "uses": worker,
               "with": {"mode": "verify-only" if last_receive else "verify-and-compute",
                        "ordinal": n, "parent": parent, **forwards}}
        if n > 1:
            job["needs"] = [previous] if n == 2 else [slot(n - 2), previous]
        jobs["last_receipt" if last_receive else slot(n)] = job
    dependencies = list(jobs)
    jobs["first_attempt_result"] = {
        "if": "${{ !cancelled() && github.run_attempt == '1' }}",
        "needs": dependencies, "runs-on": "ubuntu-24.04",
        "timeout-minutes": 5, "permissions": {"contents": "read"},
        "outputs": {key: "${{ steps.result.outputs." + key + " }}" for key in ("status", "receipt")},
        "steps": [{"uses": CHECKOUT, "with": {"persist-credentials": False}},
                  {"id": "result", "env": {"CHAIN_NEEDS": "${{ toJSON(needs) }}"},
                   "run": f"python3 preflight28/control/chain.py result --limit {count}"}]}
    # Verifier's recovery mode must discover and re-read the immutable first-
    # attempt result by run ID. It receives no provisional parent or compute flag.
    jobs["recover_saved"] = {
        "if": "${{ !cancelled() && github.run_attempt != '1' }}", "uses": worker,
        "with": {"mode": "recover-only", "ordinal": 0, "parent": "", **forwards}}
    return {"name": "Finite checkpoint chain (explicit reusable caller only)",
            "permissions": {"actions": "read", "contents": "read"},
            "on": {"workflow_call": {"inputs": additional, "outputs": {
                k: {"value": "${{ jobs.first_attempt_result.outputs." + k +
                              " || jobs.recover_saved.outputs." + k + " }}"}
                for k in ("status", "receipt")}}},
            "jobs": jobs}


def summarize(jobs, run_id, count=LIMIT):
    require(1 <= count <= LIMIT, "Invalid slot limit")
    expected = [slot(n) for n in range(1, count + 1)] + ["last_receipt"]
    require(set(jobs) == set(expected), "Missing or unexpected DAG worker")
    current = SEED
    observed = {current}
    result = None
    for ordinal, name in enumerate(expected, 1):
        job = jobs[name]
        if result is not None:
            require(job["result"] == "skipped", "Unexpected work after terminal state")
            continue
        require(job["result"] == "success", f"Incomplete job {name}; reconcile existing receipts")
        out = job["outputs"]
        require(out["owner_run"] == str(run_id) and out["owner_attempt"] == "1"
                and out["ordinal"] == str(ordinal), "Stale producer or wrong slot")
        require(out["accepted_parent"] == current,
                "Worker did not independently accept the current parent")
        status, receipt = out["status"], out["receipt"]
        require(bool(LOCATOR.fullmatch(receipt)), "Missing immutable storage ID and SHA-256")
        if name == "last_receipt":
            require(status == "verified" and receipt == current,
                    "Final candidate was not independently received")
            result = ("limit-with-verified-parent", receipt)
        elif status == "candidate":
            require(receipt not in observed, "Repeated checkpoint in one generation chain")
            observed.add(receipt)
            current = receipt
        elif status == "preflight-received":
            require(receipt == current and current != SEED, "Preflight must receive a real successor")
            result = ("preflight-received", receipt)
        elif status == "apk":
            require(receipt not in observed, "APK receipt cannot name an earlier checkpoint")
            result = ("apk-available-for-private-receipt", receipt)
        elif status == "no-progress":
            require(receipt == current, "No-progress result must retain the same parent")
            result = ("no-progress", current)
        else:
            raise ValueError(f"Unknown state from {name}")
    require(result is not None, "No verified termination")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    render_cmd = actions.add_parser("render")
    render_cmd.add_argument("worker", type=Path)
    result_cmd = actions.add_parser("result")
    for sub in (render_cmd, result_cmd):
        sub.add_argument("--limit", type=int, default=LIMIT)
    args = parser.parse_args()
    if args.action == "render":
        import yaml
        print(yaml.safe_dump(render(args.worker, args.limit), sort_keys=False))
    else:
        run = int(os.environ["GITHUB_RUN_ID"])
        require(run > 0 and os.environ["GITHUB_RUN_ATTEMPT"] == "1", "Not first-run aggregation")
        state, receipt = summarize(json.loads(os.environ["CHAIN_NEEDS"]), run, args.limit)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            print(f"status={state}\nreceipt={receipt}", file=output)
        print(f"run={run} status={state} receipt={receipt}")


if __name__ == "__main__":
    main()
