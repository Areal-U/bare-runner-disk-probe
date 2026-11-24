"""Render only the explicitly reviewed PR9 retry after a physically lost, unsent candidate."""
import argparse
import hashlib
from pathlib import Path
import re
import yaml
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from preflight28.transport.workflow import Readable, OLD, KEY

PATH=".github/workflows/bare-r28-s2-recovery.yml"
CAMPAIGN="r28-preflight-s2-20261125-v2"
TOKEN={"GH_TOKEN":"${{ github.token }}"}
UPLOAD="actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
DOWNLOAD="actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"
RESTORE="actions/cache/restore@caa296126883cff596d87d8935842f9db880ef25"
SOURCE="${{ github.event.pull_request.head.sha }}"
FRESH="python3 preflight28/transport/fresh.py"
EXCHANGE="python3 preflight28/transport/exchange.py"

def sh(name,cmd,minutes=5,auth=False,**options):
    return {"name":name,"timeout-minutes":minutes,**({"env":TOKEN} if auth else {}),"run":cmd,**options}

def today():
    # No stored repository credentials, including on the contents:write VM. The
    # restricted token exists only on explicit fixed-scope REST operations.
    return sh("Read fixed public source at the exact synchronized head",'''set -euo pipefail
test "$GITHUB_REPOSITORY" = Areal-U/bare-runner-disk-probe
[[ $TRIAL_SHA =~ ^[0-9a-f]{40}$ ]]
git init --quiet .
git sparse-checkout set --no-cone '/preflight28/' '/.github/workflows/'
GIT_TERMINAL_PROMPT=0 git -c credential.helper= -c http.extraHeader= fetch --no-tags --depth=1 "https://github.com/$GITHUB_REPOSITORY.git" "$TRIAL_SHA"
git checkout --quiet --detach FETCH_HEAD
test "$(git rev-parse HEAD)" = "$TRIAL_SHA"
printf 'run=%s attempt=%s role=%s hosted_runner=%s version=%s\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$GITHUB_JOB" "$RUNNER_NAME" "${ImageVersion:-unknown}"''',6)

def tools():
    return sh("Load fixed R26 environment and validated owner-Draft client", "python3 preflight28/transport/prepare.py tools")

def clock(name):
    return sh("Use authenticated service job start and confirm original cache identity",'''set -euo pipefail
if [[ ! ${CHECK_RUN:-} =~ ^[1-9][0-9]*$ ]]; then
 CHECK_RUN=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" |
   jq -er --arg name "$CLOCK_NAME" '[.jobs[]|select(.name==$name and .status=="in_progress")|.check_run_url|split("/")|last]|select(length==1)|first')
fi
epoch=$(python3 preflight28/limits/guard.py job-clock --check-run "$CHECK_RUN")
echo "JOB_STARTED=$epoch" >> "$GITHUB_ENV"
if [[ $GITHUB_JOB != receive || $GITHUB_RUN_ATTEMPT == 1 ]]; then python3 preflight28/transport/exchange.py parent; fi''',3,env={**TOKEN,"JOB_READ_TOKEN":"${{ github.token }}","CHECK_RUN":"${{ job.check_run_id }}","CLOCK_NAME":name})

def artifact(kind):
    return "r28-fresh-${{ github.run_id }}-"+{"key":"writer","cipher":"cipher","delta":"delta"}[kind]

def upload(kind,files,**extra):
    return {"name":"Upload the scoped "+kind+" Artifact", "id":"put_"+kind,"uses":UPLOAD,
            "timeout-minutes":18 if kind=="cipher" else 6,**extra,"with":{"name":artifact(kind),
            "path":"\n".join("${{ runner.temp }}/r28-split/"+f for f in files),
            "retention-days":1,"compression-level":0,"if-no-files-found":"error","overwrite":False}}

def download(kind):
    wait=sh("Locate exact same-run "+kind+" Artifact by service ID",FRESH+" wait "+kind,
            225 if kind=="cipher" else 10,True,id="wait_"+kind)
    wait["env"]={**TOKEN,"FRESH_PEER_NAME":"Ordinary read-only runner builds and seals new APK dependency" if kind=="cipher" else "Limited sender receives new complete bytes and publishes one private checkpoint"}
    read={"name":"Download exact "+kind+" by immutable ID","uses":DOWNLOAD,"timeout-minutes":18,
          "with":{"artifact-ids":"${{ steps.wait_"+kind+".outputs.id }}","merge-multiple":True,
                  "path":"${{ runner.temp }}/r28-split/incoming"}}
    return [wait,read]

def render(before):
    assert re.fullmatch("[a-f0-9]{40}",before)
    cond=("github.event_name == 'pull_request' && github.event.action == 'synchronize' && github.event.pull_request.number == 9 && "
          "github.actor == 'Areal-U' && github.triggering_actor == 'Areal-U' && github.repository == 'Areal-U/bare-runner-disk-probe' && "
          "github.event.pull_request.base.repo.full_name == github.repository && github.event.pull_request.head.repo.full_name == github.repository && "
          "github.head_ref == 'work-bare-27-storage-check' && github.base_ref == 'bare-coexist-v2.0.4' && "
          f"github.event.pull_request.base.sha == '{OLD}' && github.event.before == '{before}'")
    com={"runs-on":"ubuntu-24.04","cache-mode":"none"}
    private={"actions":"read","contents":"write"}
    ok="${{ "+cond+" && github.run_attempt == '1' }}"
    approved="${{ "+cond+" && github.run_attempt == '1' && needs.reserve.result == 'success' && needs.reserve.outputs.claim_id != '' }}"
    namep="Ordinary read-only runner builds and seals new APK dependency"
    namer="Fresh runner restores new private generation without production build"
    reserve={**com,"name":"Restricted verification of lost run and one superseding claim","if":ok,
             "permissions":private,"timeout-minutes":13,"outputs":{"claim_id":"${{ steps.claim.outputs.claim_id }}"},
             "steps":[today(),tools(),sh("Bind one superseding physical run only after complete prior reconciliation",
                                        "python3 preflight28/transport/recovery_claim.py reserve",8,True,id="claim")]}
    producer={**com,"name":namep,"if":approved,"permissions":{"actions":"read"},"needs":"reserve","cache-mode":"read",
              "timeout-minutes":215,"steps":[today(),tools(),clock(namep),
                  sh("Confirm ordinary token cannot read the owner Draft",
                     '''PYTHONPATH=preflight28/bridge python3 -c 'import bridge as b; b.api_json(f"/repos/{b.REPO}/releases/{b.RELEASE}",expected="denied")' ''',2,True),
                  {"name":"Restore the exact S2 parent at its original read-only cache key","uses":RESTORE,"id":"parent",
                   "timeout-minutes":15,"with":{"path":"${{ runner.temp }}/bare-official/exchange/checkpoint/checkpoint.tar.gz",
                                                "key":KEY,"fail-on-cache-miss":True}},
                  sh("Prepare fixed builder and progress one genuine APK dependency, then pack new full zstd",
                     f'''set -euo pipefail
[[ $HIT == true && $MATCH == '{KEY}' ]]
python3 preflight28/transport/prepare.py produce''',178,
                     env={"MATCH":"${{ steps.parent.outputs.cache-matched-key }}","HIT":"${{ steps.parent.outputs.cache-hit }}"}),
                  *download("key"),
                  sh("Seal full newly built candidate to the independent restricted writer",FRESH+" seal",19),
                  sh("Record simultaneous Action Artifact use immediately before full upload",FRESH+" capacity",3,True),
                  upload("cipher",["checkpoint.cms","cipher-receipt.json"],**{"continue-on-error":True,
                         "env":{"NODE_OPTIONS":"--require=${{ github.workspace }}/preflight28/transport/quota-marker.cjs"}}),
                  sh("Reconcile an ambiguous full-upload response before permitting a small sealed delta",
                     """set -euo pipefail
name=r28-fresh-$GITHUB_RUN_ID-cipher
for n in 1 2 3 4 5; do
  state=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/artifacts?name=$name" |
    jq -er --arg name "$name" --arg rid "$GITHUB_RUN_ID" --arg head "$TRIAL_SHA" '
      select(.total_count==(.artifacts|length))|[.artifacts[]|select(.name==$name and .expired==false and
      (.workflow_run.id|tostring)==$rid and .workflow_run.head_sha==$head and .size_in_bytes>0)]|
      if length==0 then "absent" elif length==1 then "present" else error("ambiguous") end')
  if [[ $state == present ]]; then echo 'delta=false' >> "$GITHUB_OUTPUT"; exit 0; fi
  if (( n<5 )); then sleep 15; fi
done
if ! grep -Fxq 'create-rejected-storage-quota' "$RUNNER_TEMP/r28-split/full-quota-evidence"; then
  echo 'Provider acceptance remains ambiguous after bounded read-only reconciliation. Alternate deposit and publication stopped.' >&2
  exit 1
fi
echo 'delta=true' >> "$GITHUB_OUTPUT"
echo 'Provider explicitly rejected creation for storage quota, and no full Artifact is present.' 
""",2,True,id="fallback",**{"if":"${{ !cancelled() && steps.put_cipher.outcome == 'failure' }}"}),
                  sh("Generate a bounded sealed S2-relative delta from this same complete candidate",
                     """set -euo pipefail
if ! command -v rdiff >/dev/null; then
  sudo -n apt-get -qq -o Acquire::Retries=2 update
  sudo -n apt-get -qq -o Acquire::Retries=2 --no-install-recommends install rdiff
fi
python3 preflight28/transport/delta.py seal "$RUNNER_TEMP/bare-official/exchange/checkpoint/checkpoint.tar.gz" "$RUNNER_TEMP/r28-child.tar.zst" "$RUNNER_TEMP/r28-split/incoming/public.pem" "$RUNNER_TEMP/r28-split-delta"
install -m 600 "$RUNNER_TEMP/r28-split/cipher-receipt.json" "$RUNNER_TEMP/r28-split-delta/cipher-receipt.json"
(( $(du -b -c "$RUNNER_TEMP/r28-split-delta/"{delta.cms,delta.json,cipher-receipt.json} | tail -1 | cut -f1) + 1048576 <= 268435456 ))
""",16,**{"if":"${{ !cancelled() && steps.fallback.outputs.delta == 'true' }}"}),
                  {"name":"Upload one small sealed fallback Artifact after missing full receipt","id":"put_delta","uses":UPLOAD,"timeout-minutes":10,
                   "if":"${{ !cancelled() && steps.fallback.outputs.delta == 'true' && success() }}",
                   "with":{"name":artifact("delta"),"retention-days":1,"compression-level":0,"overwrite":False,"if-no-files-found":"error",
                           "path":"\n".join("${{ runner.temp }}/r28-split-delta/"+name for name in ("delta.cms","delta.json","cipher-receipt.json"))}},
                  sh("Compare all retained APK payloads from original S2 against the securely deposited child",
                     """set -euo pipefail
sha=$(jq -er .sha256 "$RUNNER_TEMP/r28-split/cipher-receipt.json")
python3 -I preflight28/graph/retained.py archives --parent "$RUNNER_TEMP/bare-official/exchange/checkpoint/checkpoint.tar.gz" \
  --child "$RUNNER_TEMP/r28-child.tar.zst" --parent-sha 4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf --child-sha "$sha"
""",20),
                  sh("Reconfirm original read-only cache after transfer",EXCHANGE+" parent",3,True)
              ]}
    sender={**com,"name":"Limited sender receives new complete bytes and publishes one private checkpoint",
            "needs":"reserve","if":approved,"permissions":private,"timeout-minutes":350,"cache-mode":"read",
            "outputs":{"manifest_id":"${{ steps.send.outputs.manifest_id }}","manifest_sha":"${{ steps.send.outputs.manifest_sha }}"},
            "steps":[today(),tools(),sh("Reserve full ciphertext and decoded checkpoint staging on disposable runner",
                                            "bash preflight28/bridge/host_space.sh",6),
                     sh("Generate a local recipient and seal its recovery copy to the prior test-only recipient",'''set -euo pipefail
umask 077
if ! command -v age >/dev/null; then
  sudo -n apt-get -qq -o Acquire::Retries=2 update
  sudo -n apt-get -qq -o Acquire::Retries=2 --no-install-recommends install age
fi
mkdir -m 700 -p "$RUNNER_TEMP/r28-split"
python3 preflight28/bridge/bridge.py keygen
public_test=age1ndr7f7txhcjqfxdjzrlf7m7za0sfa7yhzm4gg9404pfl5jtq4geqgcu466
grep -Fq "pub=$public_test" .github/workflows/bare-r28-delivery-preflight.yml
age -r "$public_test" -o "$RUNNER_TEMP/r28-split/writer-key.age" "$RUNNER_TEMP/r28-split/key.pem"
[[ -s $RUNNER_TEMP/r28-split/writer-key.age ]]
sha256sum "$RUNNER_TEMP/r28-split/writer-key.age"''',7),
                     upload("key",["public.pem","writer-key.age"]),*download("cipher"),
                     {"name":"Collect a concurrently visible small alternate relay by ID for receipt reconciliation",
                      "if":"${{ steps.wait_cipher.outputs.other_id != '' }}","uses":DOWNLOAD,"timeout-minutes":10,
                      "with":{"artifact-ids":"${{ steps.wait_cipher.outputs.other_id }}","merge-multiple":True,
                             "path":"${{ runner.temp }}/r28-split/alternate"}},
                     sh("Check exact original declaration across both transfer forms",
                        'cmp -- "$RUNNER_TEMP/r28-split/incoming/cipher-receipt.json" "$RUNNER_TEMP/r28-split/alternate/cipher-receipt.json"',
                        2,**{"if":"${{ steps.wait_cipher.outputs.other_id != '' }}" }),
                     sh("Reserve both fixed S2 cache layers before fallback patching",
                        'python3 preflight28/limits/guard.py space "$RUNNER_TEMP" --bytes 5563674174 --inodes 5',2,
                        **{"if":"${{ steps.wait_cipher.outputs.mode == 'delta' }}"}),
                     {"name":"Acquire read-only original S2 only for a sealed delta","if":"${{ steps.wait_cipher.outputs.mode == 'delta' }}",
                      "id":"delta_parent","uses":RESTORE,"timeout-minutes":15,"with":{"path":"${{ runner.temp }}/bare-official/exchange/checkpoint/checkpoint.tar.gz",
                                                "key":KEY,"fail-on-cache-miss":True}},
                     sh("Restore and authenticate the exact original full zstd bytes from the smaller encrypted relay",
                        f"""set -euo pipefail
[[ $MATCH == '{KEY}' ]]
if ! command -v rdiff >/dev/null; then
  sudo -n apt-get -qq -o Acquire::Retries=2 update
  sudo -n apt-get -qq -o Acquire::Retries=2 --no-install-recommends install rdiff
fi
incoming="$RUNNER_TEMP/r28-split/incoming"
packet="$RUNNER_TEMP/r28-split/delta-packet"
mkdir -m 700 "$packet"
ln -- "$incoming/delta.cms" "$incoming/delta.json" "$packet/"
sha=$(jq -er .sha256 "$incoming/cipher-receipt.json")
bytes=$(jq -er .bytes "$incoming/cipher-receipt.json")
python3 preflight28/transport/delta.py restore "$RUNNER_TEMP/bare-official/exchange/checkpoint/checkpoint.tar.gz" "$packet" "$RUNNER_TEMP/r28-child.tar.zst" --key-dir "$RUNNER_TEMP/r28-split" --expected-sha "$sha" --expected-bytes "$bytes"
""",20,**{"if":"${{ steps.wait_cipher.outputs.mode == 'delta' }}","env":{"MATCH":"${{ steps.delta_parent.outputs.cache-matched-key }}"}}),
                     sh("Verify full ciphertext, authenticated private payload, and put new bounded draft parts",
                        FRESH+" send",26,id="send",env={**TOKEN,"FRESH_MODE":"${{ steps.wait_cipher.outputs.mode }}","FRESH_ARTIFACT_ID":"${{ steps.wait_cipher.outputs.id }}","FRESH_OTHER_ID":"${{ steps.wait_cipher.outputs.other_id }}","FRESH_PEER_NAME":namep})
                    ]}
    receive={**com,"name":namer,"if":"${{ !cancelled() && "+cond+" && (github.run_attempt != '1' || (needs.produce.result == 'success' && needs.send.result == 'success')) }}",
             "needs":["produce","send"],"permissions":private,"timeout-minutes":215,"steps":[today(),tools(),sh("Verify original accepted supersession without changing it","python3 preflight28/transport/recovery_claim.py verify",4,True),clock(namer),
                sh("Restore exact manifest and all bytes from owner Draft",'''set -euo pipefail
python3 preflight28/limits/guard.py space "$RUNNER_TEMP" --bytes 3758096384 --inodes 2
python3 preflight28/transport/exchange.py receive''',75,
                   env={**TOKEN,"MANIFEST_ID":"${{ needs.send.outputs.manifest_id }}","MANIFEST_SHA":"${{ needs.send.outputs.manifest_sha }}"}),
                sh("Independently restore complete fixed APK graph and retained contents without new compilation",
                   "python3 preflight28/transport/prepare.py receive",177),
                sh("Reconfirm original S2 remains available after receipt",EXCHANGE+" parent",3,True,**{"if":"${{ github.run_attempt == '1' }}"})]}
    jobs={"reserve":reserve,"produce":producer,"send":sender,"receive":receive}
    for j in jobs.values():
        assert all(len(step.get("run",""))<21000 for step in j["steps"])
    return {"name":"Bare R28 S2 recoverable fresh checkpoint trial","run-name":CAMPAIGN+" / restricted fresh handoff",
            "on":{"pull_request":{"types":["synchronize"],"branches":["bare-coexist-v2.0.4"],"paths":[PATH]}},
            "permissions":{},"cache-mode":"none","concurrency":{"group":CAMPAIGN+"-fresh-only","cancel-in-progress":False},
            "env":{"PRIOR_SHA":before,"TRIAL_SHA":SOURCE,"R28_CAMPAIGN":CAMPAIGN},
            "defaults":{"run":{"shell":"bash"}},"jobs":jobs}

if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("before");p.add_argument("output",type=Path)
    a=p.parse_args();data=yaml.dump(render(a.before),Dumper=Readable,sort_keys=False,width=120)
    a.output.parent.mkdir(parents=True,exist_ok=True); a.output.write_text(data)
    print("workflow_bytes",len(data.encode()),"sha256",hashlib.sha256(data.encode()).hexdigest())
