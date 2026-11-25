"""Read-only admission from the checkout. --dispatch sends one manual test after admission."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "preflight28/bridge"))
import storage_admission as budget
import connector_gate

BRANCH = "bare-next-build-prep-20261125"
WORKFLOW = "bare-disk-probe.yml"
# Public standard runner pricing is the billing basis. This independent engineering
# ceiling covers the observed 1.75 GB inventory plus the optional 3.5 GiB source
# trial, and caps the test even if an earlier inventory grows unexpectedly.
DIAGNOSTIC_TOTAL_CAP = 6 * 1024**3
MODES = {"source-v8": 192 * budget.MIB, "source-chromium": 7 * 1024**3 // 2,
         "split": 8 * budget.MIB, "receiver": 6 * budget.MIB}

def get(path):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "bare-next-trials"}
    if os.environ.get("GH_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GH_TOKEN"]
    checking_runs = "/actions/runs?status=" in path
    if checking_runs:
        headers["Cache-Control"] = "no-cache, max-age=0"
    with urlopen(Request("https://api.github.com" + path, headers=headers), timeout=6 if checking_runs else 30) as response:
        return json.load(response)

def check(api, mode, head, run, snapshot_ceiling=None, snapshot_until=None, *, runner=None, now=None):
    if mode not in MODES or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ValueError("Unknown trial or unpinned revision")
    now = int(time.time()) if now is None else now
    repository = api(budget.BASE)
    budget.public_host(repository, runner if run else "github-hosted")
    # Check before creating the dispatch itself; even an idle test job can block the build.
    budget.diagnostic_active_runs(api, {"GITHUB_RUN_ID": str(run)})
    workflow = api(f"{budget.BASE}/actions/workflows/{WORKFLOW}")
    ref = api(f"{budget.BASE}/git/ref/heads/{BRANCH}")
    if workflow["state"] != "active" or workflow["path"] != ".github/workflows/" + WORKFLOW or ref["object"]["sha"] != head:
        raise ValueError("Registered manual test entry or isolated branch revision differs")
    # After a lost POST response, the previous run may already have completed.
    marker = f"Bare next-build trial {mode} {head}"
    prior = api(f"{budget.BASE}/actions/workflows/{WORKFLOW}/runs?head_sha={head}&event=workflow_dispatch&per_page=100")
    if prior["total_count"] != len(prior["workflow_runs"]):
        raise ValueError("Incomplete history for this test revision")
    for item in prior["workflow_runs"]:
        if item["display_title"] == marker and item["head_sha"] == head and item["id"] != run:
            raise ValueError(f"Review the already issued trial {item['id']} before a new trial revision")
    occupied = sum(row[0] for row in budget.receipt_rows(api).values())
    worst = MODES[mode] + budget.CONTROL_RESERVE
    # Public standard-hosted diagnostics use only short-lived public fixtures.
    # Limit the reservation to visible bytes plus the specific bounded experiment.
    if run:
        if not snapshot_ceiling or not snapshot_until:
            raise ValueError("Missing pre-dispatch envelope")
        ceiling = budget.integer(int(snapshot_ceiling), "pre-dispatch ceiling")
        until = budget.integer(int(snapshot_until), "pre-dispatch expiry")
        if not now + 86400 + 4*3600 <= until <= now + 2*86400 + 300:
            raise ValueError("Expired or unexpected diagnostic envelope")
    else:
        ceiling, until = occupied + worst, now + 2*86400
    ceiling = min(ceiling, DIAGNOSTIC_TOTAL_CAP)
    if os.environ.get("R28_RELAY_BYTE_CEILING"):
        ceiling = min(ceiling, budget.integer(int(os.environ["R28_RELAY_BYTE_CEILING"]), "existing repository ceiling"))
    if occupied + worst > ceiling:
        raise ValueError("Visible artifacts plus bounded test exceed today's ceiling")
    return {"ceiling": str(min(ceiling,occupied + worst)), "until": str(until)}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=MODES)
    parser.add_argument("--connector-capture", type=Path,
                        help="Fresh authenticated pre-dispatch-only JSON captured by the Bare operator")
    parser.add_argument("--recovery-clear", action="store_true",
                        help="Bare operator has checked that the prior independent recovery has no pending GitHub work")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dispatch", action="store_true")
    group.add_argument("--inside-run", action="store_true")
    args = parser.parse_args()
    env = os.environ
    if args.inside_run:
        if args.connector_capture:
            raise ValueError("A running diagnostic must use the live service, never an offline capture")
        head = env["GITHUB_SHA"]
        if (env.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or env.get("GITHUB_RUN_ATTEMPT") != "1"
            or env.get("GITHUB_REPOSITORY") != budget.REPO or env.get("GITHUB_REF_NAME") != BRANCH
            or env.get("NEXT_EXPECTED_SHA") != head or env.get("NEXT_RECOVERY_CLEAR") != "true"):
            raise ValueError("Unbound or repeated diagnostic call")
        event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
        if env.get("GITHUB_ACTOR") != "Areal-U" or event.get("sender",{}).get("id") != 292261483:
            raise ValueError("Unrecognized Bare operator")
        bounds = check(get, args.mode, head, int(env["GITHUB_RUN_ID"]),
                       env.get("NEXT_CEILING"), env.get("NEXT_UNTIL"), runner=env.get("RUNNER_ENVIRONMENT"))
        with open(env["GITHUB_OUTPUT"], "a") as out:
            for k,v in bounds.items():
                print(f"{k}={v}", file=out)
        return
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if args.connector_capture:
        if args.connector_capture.stat().st_size > 12*1024**2:
            raise ValueError("Unexpected pre-dispatch capture size")
        capture = json.loads(args.connector_capture.read_text())
        bounds = connector_gate.initial(capture, args.mode, head, branch=BRANCH, workflow=WORKFLOW,
                                        cost=MODES[args.mode] + budget.CONTROL_RESERVE, total_cap=DIAGNOSTIC_TOTAL_CAP)
    else:
        bounds = check(get, args.mode, head, 0)
    inputs = {"trial":args.mode, "expected_sha":head, "recovery_clear":str(args.recovery_clear).lower(),
              "storage_ceiling":bounds["ceiling"], "storage_until":bounds["until"]}
    payload = {"ref":BRANCH,"inputs":inputs}
    if args.dispatch:
        if not args.recovery_clear:
            raise ValueError("Bare operator must first verify that the preceding collector has no pending GitHub work")
        # One POST only. Following a lost response locate the run for this SHA/mode before another request.
        subprocess.run(["gh", "api", "--method", "POST", f"{budget.BASE}/actions/workflows/{WORKFLOW}/dispatches",
                        "--input", "-"], input=json.dumps(payload), text=True, check=True)
    else:
        print(json.dumps(payload, indent=2))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
