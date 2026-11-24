"""Render the single reviewed, PR9-only non-production entry point (including helper bytes)."""
import argparse
from pathlib import Path
import re
import yaml

ROOT = Path(__file__).resolve().parents[2]
PATH = ".github/workflows/bare-r28-s2-preflight.yml"
CAMPAIGN = "r28-preflight-s2-20261125-v1"
OLD = "bf70ddbf474f3390a62220a076b8c43347fecc64"
KEY = "bare-coexist-204-45285202990-1-checkpoint-production-s2"

class Readable(yaml.SafeDumper):
    pass

def readable(dumper, string):
    return dumper.represent_scalar("tag:yaml.org,2002:str", string, style="|" if "\n" in string else None)

Readable.add_representer(str, readable)


def build(before):
    if not re.fullmatch(r"[0-9a-f]{40}", before):
        raise ValueError("Need the exact repository head before this change")
    shared = []
    for path in ["graph/graph.py", "limits/guard.py", "control/admission.py", "transport/prepare.py",
                 "transport/build-tail.sh", "transport/stream.py", "transport/exchange.py"]:
        s = (ROOT / "preflight28" / path).read_text()
        label = "REVIEWED_R28_" + path.replace("/", "_").replace(".", "_").replace("-", "_").upper()
        if label in s.splitlines():
            raise ValueError("Embedded source marker collision")
        lines = ["set -euo pipefail", f"mkdir -p preflight28/{path.split('/')[0]}", f"cat > preflight28/{path} <<'{label}'", s.rstrip("\n"), label]
        shared.append({"name": "Stage " + path, "run": "\n".join(lines) + "\n"})
    shared.append({"name":"Load byte-verified existing owner-Draft helpers", "run":"python3 preflight28/transport/prepare.py tools"})
    checkout = {"name":"Check out the trusted PR head without persisting credentials",
                "uses":"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                "with":{"ref":"${{ github.event.pull_request.head.sha }}","persist-credentials":False}}
    guard = ("github.event_name == 'pull_request' && github.event.action == 'synchronize' && "
             "github.event.pull_request.number == 9 && github.actor == 'Areal-U' && "
             "github.triggering_actor == 'Areal-U' && github.event.repository.fork == false && "
             "github.repository == 'Areal-U/bare-runner-disk-probe' && "
             "github.event.pull_request.head.repo.full_name == github.repository && "
             "github.event.pull_request.base.repo.full_name == github.repository && "
             "github.head_ref == 'work-bare-27-storage-check' && github.base_ref == 'bare-coexist-v2.0.4' && "
             f"github.event.pull_request.base.sha == '{OLD}' && github.event.before == '{before}'")
    auth = {"GH_TOKEN":"${{ github.token }}"}
    def admit(mode):
        return {"name":"Check canonical generation and " + ("reserve the single producer" if mode=="compute" else "verify its existing claim"),
                "env":auth, "timeout-minutes":3, "run":f'python3 preflight28/control/admission.py {mode} --before "$EXPECTED_BEFORE" --helper-dir "$RUNNER_TEMP"'}
    clock = {"name":"Read the actual service job start and preflight source receipt",
             "env":dict(auth, JOB_READ_TOKEN="${{ github.token }}",CHECK_RUN="${{ job.check_run_id }}"),
             "timeout-minutes":3,"run":'''set -euo pipefail
if [[ ! $CHECK_RUN =~ ^[1-9][0-9]*$ ]]; then
  case "$GITHUB_JOB" in
    produce) name='Create one S2 successor and transfer to fixed private Draft';;
    receive) name='Recover and verify required edge on an independent runner';;
    *) exit 1;;
  esac
  CHECK_RUN=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" |
    jq -er --arg name "$name" '[.jobs[]|select(.name==$name and .status=="in_progress")|.check_run_url|split("/")|last]|select(length==1)|first')
fi
epoch=$(python3 preflight28/limits/guard.py job-clock --check-run "$CHECK_RUN")
echo "JOB_STARTED=$epoch" >> "$GITHUB_ENV"
python3 preflight28/transport/exchange.py parent
'''}
    common = {"runs-on":"ubuntu-24.04","permissions":{"actions":"read","contents":"write"},"timeout-minutes":215}
    producer = {**common,"name":"Create one S2 successor and transfer to fixed private Draft",
                "cache-mode":"read","if":"${{ "+guard+" && github.run_attempt == '1' }}",
                "outputs":{"manifest_id":"${{ steps.send.outputs.manifest_id }}","manifest_sha":"${{ steps.send.outputs.manifest_sha }}"},
                "steps":[checkout,*shared,admit("compute"),clock,
                  {"uses":"actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25","name":"Restore the exact S2 parent at its original path",
                   "id":"parent","timeout-minutes":15,"with":{"path":"${{ runner.temp }}/bare-official/exchange/checkpoint/checkpoint.tar.gz","key":KEY,"fail-on-cache-miss":True}},
                  {"name":"Validate parent and advance one required APK edge, then pack bounded zstd",
                   "timeout-minutes":195,"env":{"MATCH":"${{ steps.parent.outputs.cache-matched-key }}","HIT":"${{ steps.parent.outputs.cache-hit }}"},
                   "run":f'''set -euo pipefail
[[ $HIT == true && $MATCH == '{KEY}' ]]
python3 preflight28/transport/prepare.py produce
'''},
                  {"name":"Send only the verified generation to the existing owner Draft","id":"send","timeout-minutes":6,"env":auth,
                   "run":"python3 preflight28/transport/exchange.py send"},
                  {"name":"Record retained parent and receiver manifest","timeout-minutes":2,"env":auth,
                   "run":"python3 preflight28/transport/exchange.py parent"}]}
    receiver = {**common,"name":"Recover and verify required edge on an independent runner",
                "needs":"produce","cache-mode":"none","if":"${{ !cancelled() && "+guard+" && (needs.produce.result == 'success' || github.run_attempt != '1') }}",
                "steps":[checkout,*shared,admit("recover"),clock,
                  {"name":"Read and authenticate the exact private manifest and successor bytes","timeout-minutes":85,
                   "env":dict(auth, MANIFEST_ID="${{ needs.produce.outputs.manifest_id }}", MANIFEST_SHA="${{ needs.produce.outputs.manifest_sha }}"),
                   "run":'''set -euo pipefail
python3 preflight28/limits/guard.py space "$RUNNER_TEMP" --bytes 3758096384 --inodes 2
python3 preflight28/transport/exchange.py receive
'''},
                  {"name":"Rebuild fixed environment and prove full restored APK frontier without new compilation",
                   "timeout-minutes":195,"run":"python3 preflight28/transport/prepare.py receive"},
                  {"name":"Verify source cache remains intact after read-only acquisition","timeout-minutes":2,
                   "env":auth,"run":"python3 preflight28/transport/exchange.py parent"}]}
    for job in (producer, receiver):
        for step in job["steps"]:
            if len(step.get("run", "")) > 21000:
                raise ValueError("GitHub run step too long: " + step["name"])
    return {"name":"Bare R28 fixed S2 preflight","run-name":CAMPAIGN+" / S2 transport",
            "on":{"pull_request":{"types":["synchronize"],"branches":["bare-coexist-v2.0.4"],"paths":[PATH]}},
            "permissions":{},"cache-mode":"none","concurrency":{"group":CAMPAIGN+"-s2","cancel-in-progress":False},
            "env":{"EXPECTED_BEFORE":before,"TRIAL_SHA":"${{ github.event.pull_request.head.sha }}"},
            "defaults":{"run":{"shell":"bash"}},"jobs":{"produce":producer,"receive":receiver}}


if __name__ == "__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("before")
    ap.add_argument("output",type=Path)
    args=ap.parse_args()
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(yaml.dump(build(args.before),Dumper=Readable,sort_keys=False,width=140))
