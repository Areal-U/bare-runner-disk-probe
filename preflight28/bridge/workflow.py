"""Render a single guarded submission for bridging an existing independently accepted S2 successor."""
import argparse
import hashlib
from pathlib import Path
import re
import sys
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT / "preflight28/transport"))
from workflow import Readable, OLD
NAME = ".github/workflows/bare-r28-s2-split-bridge.yml"
LABEL = "r28-preflight-s2-20261125-v1 bridge"
AUTH = {"GH_TOKEN":"${{ github.token }}"}
UPLOAD="actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
DOWNLOAD="actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"

def embed(name):
    code=(ROOT / "preflight28" / name).read_text().rstrip()
    tag="SEALED_BRIDGE_EMBEDDED_"+name.replace("/","_").replace(".","_")
    run=f"mkdir -p preflight28/{name.split('/')[0]}\ncat > preflight28/{name} <<'{tag}'\n{code}\n{tag}"
    assert len(run)<21000 and tag not in code.splitlines()
    return {"name":"Install reviewed "+name, "run":run}

def call(name, mode, token=False):
    s={"name":name, "run":"python3 preflight28/bridge/bridge.py "+mode}
    if token:s["env"]=AUTH
    return s

def artifact(kind):
    return "r28-split-s2-${{ github.run_id }}-a1-"+kind

def upload(kind, files):
    return {"name":"Upload "+kind+" to scoped trial Artifact", "id":"upload_"+kind, "uses":UPLOAD,
            "with":{"name":artifact(kind),"path":"\n".join("${{ runner.temp }}/r28-split/"+f for f in files),
                    "if-no-files-found":"error","overwrite":False,"retention-days":1,"compression-level":0}}

def read(kind):
    wait=call("Locate authenticated "+kind+" Artifact","wait "+kind,True)
    wait["id"]="wait_"+kind
    get={"name":"Acquire exact "+kind+" by artifact ID", "uses":DOWNLOAD,"with":{
        "artifact-ids":"${{ steps.wait_"+kind+".outputs.id }}","path":"${{ runner.temp }}/r28-split/incoming","merge-multiple":True}}
    return [wait,get]

def setup():
    return {"name":"Release unused hosted-image SDKs and verify temporary-disk starting point","run":'''set -euo pipefail
[[ $RUNNER_ENVIRONMENT == github-hosted && $RUNNER_OS == Linux && $RUNNER_ARCH == X64 ]]
for dir in /usr/local/lib/android /usr/local/share/boost /usr/share/dotnet /usr/share/swift /usr/local/.ghcup /opt/ghc /usr/lib/google-cloud-sdk; do
  if [[ -d $dir && $(realpath -- "$dir") == "$dir" ]] && ! mountpoint -q -- "$dir"; then
    sudo -n rm -rf --one-file-system -- "$dir"
  fi
done
df -B1 "$RUNNER_TEMP"
df -Pi "$RUNNER_TEMP"
openssl version
'''}

def render(before, run, head, mid, msha):
    assert all(re.fullmatch("[0-9a-f]{40}",h) for h in (before,head)) and re.fullmatch("[0-9a-f]{64}",msha) and run>0 and mid>0
    guard=("github.event_name == 'pull_request' && github.event.action == 'synchronize' && "
        "github.event.pull_request.number == 9 && github.run_attempt == '1' && github.actor == 'Areal-U' && "
        "github.triggering_actor == 'Areal-U' && github.repository == 'Areal-U/bare-runner-disk-probe' && "
        "github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.base.repo.full_name == github.repository && "
        "github.head_ref == 'work-bare-27-storage-check' && github.base_ref == 'bare-coexist-v2.0.4' && "
        f"github.event.pull_request.base.sha == '{OLD}' && github.event.before == '{before}'")
    stage=embed("bridge/bridge.py")
    commons={"if":"${{ "+guard+" }}","runs-on":"ubuntu-24.04","timeout-minutes":50,"cache-mode":"none"}
    begin=setup()
    check=call("Verify already-accepted source and record current storage","guard",True)
    key=call("Generate a job-local test transport key","keygen")
    ordinary={**commons,"name":"Ordinary runner without Draft access","permissions":{"actions":"read"},"cache-mode":"read",
            "steps":[stage,embed("bridge/compiler_fixture.py"),embed("graph/retained.py"),begin,check,key,upload("key",["public.pem"]),*read("descriptor"),
                call("Acquire exact full successor with no repository token","acquire"),
                call("Seal the same complete checkpoint to the separate Draft writer",'seal "$RUNNER_TEMP/r28-split/checkpoint.tar.zst"'),
                {"name":"Compile and separately seal a native test object on the ordinary runner", "run":"python3 preflight28/bridge/compiler_fixture.py produce"},
                call("Measure repository peak before introducing one full encrypted relay","before_upload",True),
                upload("cipher",["checkpoint.cms","fixture.cms","cipher-receipt.json"]),
                call("Record ordinary runner storage after ciphertext upload","inventory",True),
                {"name":"Read fixed S2 only for payload continuity cross-check",
                 "id":"parent","uses":"actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25","timeout-minutes":10,
                 "with":{"path":"${{ runner.temp }}/bare-official/exchange/checkpoint/checkpoint.tar.gz",
                         "key":"bare-coexist-204-45285202990-1-checkpoint-production-s2","fail-on-cache-miss":True}},
                {"name":"Compare retained APK payloads of the accepted S2 and successor, without compiling",
                 "env":{"MATCH":"${{ steps.parent.outputs.cache-matched-key }}"},
                 "run":'set -euo pipefail\n[[ $MATCH == bare-coexist-204-45285202990-1-checkpoint-production-s2 ]]\n'
                       'child=$(jq -er .source_sha "$RUNNER_TEMP/r28-split/cipher-receipt.json")\n'
                       'python3 preflight28/graph/retained.py archives --parent "$RUNNER_TEMP/bare-official/exchange/checkpoint/checkpoint.tar.gz" '
                       '--child "$RUNNER_TEMP/r28-split/checkpoint.tar.zst" '
                       '--parent-sha 4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf --child-sha "$child"'}
                    ]}
    limited={**commons,"name":"Restricted existing owner-Draft worker","permissions":{"contents":"write","actions":"read"},
            "steps":[{"name":"Check out fixed owner PR head, persist no credentials","uses":"actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
                      "with":{"ref":"${{ github.event.pull_request.head.sha }}","persist-credentials":False}},
                     stage,embed("bridge/compiler_fixture.py"),embed("transport/prepare.py"),
                     {"name":"Stage fixed and hash-validated private archive client","run":"python3 preflight28/transport/prepare.py tools"},
                     begin,check,key,*read("key"),
                     call("Issue an encrypted time-limited part-scoped read descriptor","issue",True),
                     upload("descriptor",["input.cms"]),*read("cipher"),
                     {"name":"Independently receive and verify the compiled fixture from the ordinary runner", "run":"python3 preflight28/bridge/compiler_fixture.py receive"},
                     call("Decrypt full candidate, independently read and reconcile existing Draft bytes","accepted",True)]}
    return {"name":"Bare R28 ordinary-to-private split bridge","run-name":LABEL,
            "on":{"pull_request":{"types":["synchronize"],"branches":["bare-coexist-v2.0.4"],"paths":[NAME]}},
            "permissions":{},"cache-mode":"none","concurrency":{"group":"r28-split-existing-checkpoint-only","cancel-in-progress":False},
            "env":{"PRIOR_SHA":before,"TRIAL_SHA":"${{ github.event.pull_request.head.sha }}","SOURCE_RUN":str(run),
                   "SOURCE_HEAD":head,"SOURCE_MANIFEST_ID":str(mid),"SOURCE_MANIFEST_SHA":msha},
            "defaults":{"run":{"shell":"bash"}},"jobs":{"ordinary":ordinary,"limited":limited}}

if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("before");ap.add_argument("source_run",type=int);ap.add_argument("source_head")
    ap.add_argument("manifest_id",type=int);ap.add_argument("manifest_sha");ap.add_argument("out",type=Path)
    x=ap.parse_args()
    data=yaml.dump(render(x.before,x.source_run,x.source_head,x.manifest_id,x.manifest_sha),Dumper=Readable,sort_keys=False,width=140)
    x.out.parent.mkdir(parents=True,exist_ok=True)
    x.out.write_text(data)
    print("workflow_bytes",len(data.encode()),"sha256",hashlib.sha256(data.encode()).hexdigest())
