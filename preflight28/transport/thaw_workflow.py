"""Render the PR9-only recovery of existing encrypted bytes. No compiler entry exists."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import yaml

spec=importlib.util.spec_from_file_location("r28_fresh_workflow",Path(__file__).with_name("recovery_workflow.py"))
orig=importlib.util.module_from_spec(spec)
spec.loader.exec_module(orig)
OLD=orig.OLD
PATH=".github/workflows/bare-r28-s2-thaw.yml"
HEAD="81105d5f7b9ba994034753ce4fbd65d9b981dde3"
SID=45513782890
KEY_ART=14976353454
CIPHER_ART=14978478511
OWNER_TOKEN={"GH_TOKEN":"${{ github.token }}"}
SOURCE_KEY=orig.KEY
THAW="python3 preflight28/transport/thaw.py"
CLAIM="python3 preflight28/transport/thaw_claim.py"
HAND="python3 preflight28/transport/handback.py"
REVERSE="python3 preflight28/transport/thaw_read.py"


def paths():
    return orig.sh("Pin original source separately from this recovery ticket",f'''set -euo pipefail
source_tree="$RUNNER_TEMP/r28-frozen-{HEAD[:10]}"
git -c credential.helper= -c http.extraHeader= fetch --no-tags --depth=1 "https://github.com/$GITHUB_REPOSITORY.git" {HEAD}
git -c advice.detachedHead=false worktree add --detach "$source_tree" {HEAD}
test "$(git -C "$source_tree" rev-parse HEAD)" = {HEAD}
test "$(git rev-parse HEAD)" = "$TRIAL_SHA"
test -f "$source_tree/.github/workflows/bare-r28-s2-recovery.yml"
{{
 echo "THAW_SOURCE_TREE=$source_tree"
 echo "THAW_CIPHER_DIR=$RUNNER_TEMP/r28-thaw/original-cipher"
 echo "THAW_KEY_ARTIFACT_DIR=$RUNNER_TEMP/r28-thaw/original-key"
 echo "THAW_KEY_PEM=$RUNNER_TEMP/r28-thaw/original-private.pem"
 echo "THAW_PARENT=$RUNNER_TEMP/bare-official/exchange/checkpoint/checkpoint.tar.gz"
}} >> "$GITHUB_ENV"
''',5)


def historical(aid,folder):
    return {"name":"Read verified original "+folder+" Artifact by immutable ID","uses":orig.DOWNLOAD,
            "timeout-minutes":20,"with":{"github-token":"${{ github.token }}","repository":"Areal-U/bare-runner-disk-probe",
                "run-id":str(SID),"artifact-ids":str(aid),"merge-multiple":True,"digest-mismatch":"error",
                "path":"${{ runner.temp }}/r28-thaw/"+folder}}


def receipt_name(kind):
    return "r28-thaw-${{ github.run_id }}-"+("request" if kind=="request" else "a${{ github.run_attempt }}-"+kind)


def upload(kind,files):
    return {"name":"Deposit "+kind+" for this exact recovery","id":"put_"+kind.replace("-","_"),"uses":orig.UPLOAD,"timeout-minutes":5,
        "with":{"name":receipt_name(kind),"if-no-files-found":"error","overwrite":False,"retention-days":1,"compression-level":0,
                "path":"\n".join("${{ runner.temp }}/r28-thaw/"+name for name in files)}}


def wait_peer(kind):
    return [orig.sh("Locate authenticated "+kind+" Artifact",REVERSE+" wait "+kind,15,True,id="find"),
            {"name":"Read exact peer Artifact","uses":orig.DOWNLOAD,"timeout-minutes":5,
             "with":{"artifact-ids":"${{ steps.find.outputs.id }}","path":"${{ runner.temp }}/r28-thaw/incoming","digest-mismatch":"error","merge-multiple":True}}]


def render(before):
    assert re.fullmatch("[0-9a-f]{40}",before)
    cond=("github.event_name == 'pull_request' && github.event.action == 'synchronize' && github.event.pull_request.number == 9 && "
          "github.actor == 'Areal-U' && github.triggering_actor == 'Areal-U' && github.repository == 'Areal-U/bare-runner-disk-probe' && "
          "github.event.pull_request.base.repo.full_name == github.repository && github.event.pull_request.head.repo.full_name == github.repository && "
          "github.head_ref == 'work-bare-27-storage-check' && github.base_ref == 'bare-coexist-v2.0.4' && "
          f"github.event.pull_request.base.sha == '{OLD}' && github.event.before == '{before}'")
    common={"runs-on":"ubuntu-24.04","cache-mode":"none"}
    limited={"actions":"read","contents":"write"}
    first="${{ "+cond+" && github.run_attempt == '1' }}"
    allowed="${{ !cancelled() && "+cond+" && (needs.recover.result == 'success' || github.run_attempt != '1') }}"
    recover_name="Recover original sealed candidate and audit before immutable private publication"
    recover={**common,"permissions":limited,"cache-mode":"read",
             "if":first,"name":recover_name,"timeout-minutes":155,
             "outputs":{"manifest_id":"${{ steps.publish.outputs.manifest_id }}","manifest_sha":"${{ steps.publish.outputs.manifest_sha }}"},
             "steps":[orig.today(),paths(),orig.tools(),
                orig.sh("Confirm failed prior acceptance, exact surviving artifacts and new single recovery claim",CLAIM+" reserve",8,True,id="claim"),
                orig.sh("Create recipient for the existing test owner and bind the current recovery job",
                        """set -euo pipefail
if [[ ! ${R28_CHECK_RUN:-} =~ ^[1-9][0-9]*$ ]]; then
  R28_CHECK_RUN=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$GITHUB_RUN_ID/attempts/$GITHUB_RUN_ATTEMPT/jobs?per_page=100" |
    jq -er --arg name "$CLOCK_DISPLAY" '[.jobs[]|select(.name==$name and .status=="in_progress")|.check_run_url|split("/")|last]|select(length==1)|first')
fi
export R28_CHECK_RUN
python3 preflight28/transport/handback.py request""",4,env={**OWNER_TOKEN,"R28_CHECK_RUN":"${{ job.check_run_id }}","CLOCK_DISPLAY":recover_name}),
                upload("request",["public.pem","request.json"]),
                orig.sh("Reserve actual temporary disk before acquiring either full object","bash preflight28/bridge/host_space.sh\ncommand -v ninja",6),
                historical(KEY_ART,"original-key"),historical(CIPHER_ART,"original-cipher"),
                orig.sh("Reserve both outer cache bytes and restored S2 gzip","python3 preflight28/limits/guard.py space \"$RUNNER_TEMP\" --bytes 5563674174 --inodes 10",2),
                {"name":"Read original S2 for exact archive comparison","id":"parent","uses":orig.RESTORE,"timeout-minutes":15,
                 "with":{"key":SOURCE_KEY,"path":"${{ runner.temp }}/bare-official/exchange/checkpoint/checkpoint.tar.gz","fail-on-cache-miss":True}},
                orig.sh("Locate the owner-encrypted response in the existing private Draft",
                        f'''set -euo pipefail
[[ $MATCH == '{SOURCE_KEY}' ]]
{HAND} wait''',32,env={**OWNER_TOKEN,"MATCH":"${{ steps.parent.outputs.cache-matched-key }}"}),
                orig.sh("Open disposable owner authorisation on this one recovery host",HAND+' consume "$RUNNER_TEMP/r28-thaw/response.json"',3),
                orig.sh("Open original authenticated frames and verify the original producer evidence",THAW+" open",24),
                orig.sh("Recover already committed identical private bytes without any new key exchange",THAW+" existing",24,
                        **{"if":"${{ steps.claim.outputs.original_manifest_id != '0' }}","env":{**OWNER_TOKEN,"THAW_ORIGINAL_MANIFEST_ID":"${{ steps.claim.outputs.original_manifest_id }}","THAW_CLAIM_ID":"${{ steps.claim.outputs.claim_id }}"}}),
                orig.sh("Compare every original S2 payload and audit the GN diagnostic in the actual graphs",THAW+" audit",30),
                orig.sh("Preserve a bounded failed continuity report encrypted to the original disposable test recipient",
                        """set -euo pipefail
umask 077
report="$RUNNER_TEMP/r28-thaw-audit.json"
cert="$RUNNER_TEMP/r28-thaw/original-key/public.pem"
if [[ -f $report && -s $cert ]]; then
  (( $(stat -c%s "$report") <= 134217728 ))
  openssl cms -encrypt -binary -stream -outform DER -aes-256-gcm -in "$report" -out "$RUNNER_TEMP/r28-thaw/failed-audit.cms" -recip "$cert" -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256
  sha256sum "$report" "$RUNNER_TEMP/r28-thaw/failed-audit.cms"
  echo 'available=true' >> "$GITHUB_OUTPUT"
fi""",3,id="audit_report",**{"if":"${{ failure() }}"}),
                {**upload("failed-audit",["failed-audit.cms"]),"if":"${{ failure() && steps.audit_report.outputs.available == 'true' }}"},
                orig.sh("Authorize only the fixed original archive using the complete accepted audit",CLAIM+' authorize --audit "$RUNNER_TEMP/r28-thaw-audit.json"',4,True),
                orig.sh("Reconcile original data and publish the original immutable generation",THAW+" publish",35,True,id="publish")]}
    challenge_only={
        "Create recipient for the existing test owner and bind the current recovery job",
        "Deposit request for this exact recovery","Read verified original original-key Artifact by immutable ID",
        "Read verified original original-cipher Artifact by immutable ID","Locate the owner-encrypted response in the existing private Draft",
        "Open disposable owner authorisation on this one recovery host","Open original authenticated frames and verify the original producer evidence"}
    marked=0
    for step in recover["steps"]:
        if step["name"] in challenge_only:
            step["if"]="${{ steps.claim.outputs.original_manifest_id == '0' }}"
            marked+=1
    assert marked==len(challenge_only)
    manifest={"MANIFEST_ID":"${{ needs.recover.outputs.manifest_id }}","MANIFEST_SHA":"${{ needs.recover.outputs.manifest_sha }}"}
    issue={**common,"if":allowed,"permissions":limited,"name":"Grant only a short-lived read of original private checkpoint parts",
           "needs":"recover","timeout-minutes":85,"env":manifest,"steps":[orig.today(),orig.tools(),
                orig.sh("Read the exact original successful recovery claim before granting asset access",CLAIM+" verify",6,True),
                *wait_peer("key"),orig.sh("Issue fresh part-scoped GET redirects encrypted to the separate runner",REVERSE+" issue",68,True),
                upload("descriptor",["descriptor.cms"])]}
    rn="Ordinary runner reads and verifies the private generation from the original recipe"
    clock=orig.clock(rn)
    # The recover job already verified S2. The independent receiver must not
    # depend on the cache: its origin is the previously committed private copy.
    clk=clock["run"].split("if [[ $GITHUB_JOB != receive",1)[0]
    clock["run"]=clk
    recv={**common,"if":allowed,"permissions":{"actions":"read"},"name":rn,"needs":"recover","timeout-minutes":215,
          "env":manifest,"steps":[orig.today(),paths(),clock,
            orig.sh("Reserve the receiving disk before requesting expiring private redirects","bash preflight28/bridge/host_space.sh",6),
            orig.sh("Verify ordinary token denial and generate ephemeral receiver public key",REVERSE+" key",4,True),
            upload("receiver-key",["public.pem","holder.json"]),*wait_peer("descriptor"),
            orig.sh("Download and hash every private checkpoint byte without repository credentials",REVERSE+" read",20),
            orig.sh("Independently restore using the exact original code, provenance, and strictly dry APK plan",
                   f'''set -euo pipefail
observer="$GITHUB_WORKSPACE/preflight28/transport/thaw_observe.py"
cd "$THAW_SOURCE_TREE"
test "$(git rev-parse HEAD)" = {HEAD}
env GITHUB_WORKSPACE="$THAW_SOURCE_TREE" TRIAL_SHA={HEAD} R28_CAMPAIGN=r28-preflight-s2-20261125-v2 python3 -I "$observer"''',178)]}
    jobs={"recover":recover,"issue":issue,"receive":recv}
    for j in jobs.values():
        assert all(len(s.get("run",""))<21000 for s in j["steps"])
    return {"name":"Bare R28 recover original sealed bytes","run-name":"r28-preflight-s2-20261125-v3 / recover original bytes",
            "on":{"pull_request":{"types":["synchronize"],"branches":["bare-coexist-v2.0.4"],"paths":[PATH]}},
            "permissions":{},"cache-mode":"none","concurrency":{"group":"r28-thaw-original-45513782890","cancel-in-progress":False},
            "env":{"PRIOR_SHA":before,"TRIAL_SHA":"${{ github.event.pull_request.head.sha }}","R28_CAMPAIGN":"r28-preflight-s2-20261125-v3"},
            "defaults":{"run":{"shell":"bash"}},"jobs":jobs}


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("before");p.add_argument("output",type=Path)
    a=p.parse_args();out=yaml.dump(render(a.before),Dumper=orig.Readable,sort_keys=False,width=120)
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(out)
    print("workflow_bytes",len(out.encode()),"sha256",hashlib.sha256(out.encode()).hexdigest())
