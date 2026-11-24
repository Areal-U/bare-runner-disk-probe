"""Run the result-producing Python from the real candidate workflows on regression cases."""
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

from admission import S2_SHA
from recover import follow, salvage, last_private_slot, recover_fallback
from recover_private import read_only

HERE = Path(__file__).resolve().parents[2]
if not (HERE/".github/workflows/bare-r28-native-slot.yml").exists():
    HERE = HERE/"candidate28"
WF = HERE/".github/workflows"
CALLER = yaml.safe_load((WF/"bare-checkpoint-transfer.yml").read_text())
WORKER = yaml.safe_load((WF/"bare-r28-native-slot.yml").read_text())
ARM = yaml.safe_load((WF/"bare-arm64-probe.yml").read_text())
REV = "a"*40


def dispatch(script, env):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp)/"output"
        out.touch()
        env = {**os.environ, **env, "GITHUB_SHA":REV, "GITHUB_RUN_ID":"77", "GITHUB_OUTPUT":str(out)}
        process = subprocess.run([sys.executable,"-c",script],env=env,capture_output=True,text=True)
        return process, dict(l.split("=",1) for l in out.read_text().splitlines())


def inputs(n=1):
    key=f"bare-coexist-204-77-1-checkpoint-production-s{n}"
    out=dict(checkpoint_key=key, checkpoint_sha=f"{n:064x}",checkpoint_identity="3"*64,
             producer_sha=REV, checkpoint_ordinal=str(n),checkpoint_advanced="true",
             checkpoint_saved="true", parent_frontier_verified="true",frontier_status="candidate")
    r = {k:out[k] for k in ("checkpoint_key","checkpoint_sha","checkpoint_identity")}
    return dict(arm={"result":"success","outputs":out}, read={"result":"success","outputs":r},
                apk={"result":"skipped","outputs":{}})


def record(needs,n=1,verify=False,backend="cache"):
    parent = S2_SHA if n == 1 else f"{n-1:064x}"
    return dispatch(WORKER["jobs"]["result"]["steps"][0]["run"], dict(SLOT_NEEDS=json.dumps(needs),
                    BACKEND=backend,PARENT_SHA=parent,ORDINAL=str(n), VERIFY_ONLY=str(verify).lower()))


class NativeTests(unittest.TestCase):
    def test_normal_action_entry_and_guard(self):
        self.assertEqual(CALLER["on"]["workflow_dispatch"]["inputs"]["build_segments"]["default"],"12")
        self.assertEqual(CALLER["on"]["workflow_dispatch"]["inputs"]["compile_minutes"]["default"],"0")
        for n in range(1,14):
            call=CALLER["jobs"][f"slot{n:02}"]
            self.assertEqual(call["with"]["ordinal"],n)
            self.assertEqual(call["with"]["verify_only"],n==13)
            self.assertIn("github.run_attempt == '1'",call["if"])
            self.assertEqual(call["permissions"],{"actions":"read","contents":"write"})
            self.assertEqual(ARM["jobs"]["compile-probe"]["permissions"],{"actions":"read"})
            self.assertEqual(call["uses"],"./.github/workflows/bare-r28-native-slot.yml")
        self.assertEqual(WORKER["jobs"]["arm"]["uses"],"./.github/workflows/bare-arm64-probe.yml")
        self.assertIn("github.run_attempt == '1'",ARM["jobs"]["compile-probe"]["if"])
        for k in ("segment_ordinal","expected_parent_producer","verify_frontier_only"):
            self.assertIn(k,ARM["on"]["workflow_call"]["inputs"])
        lookup=CALLER["jobs"]["recover-first-attempt"]
        self.assertIn("github.run_attempt != '1'",lookup["if"])
        self.assertEqual(lookup["needs"],"terminal-12")
        self.assertFalse(any("upload-artifact" in x.get("uses","") for x in lookup["steps"]))

    def test_received_candidate_and_nonmatching_parent(self):
        n=inputs(2)
        p,o=record(n,2)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(o["status"],"candidate")
        n["arm"]["outputs"]["parent_frontier_verified"]="false"
        self.assertNotEqual(record(n,2)[0].returncode,0)

    def test_no_progress_size_and_independent_verification(self):
        n=inputs(2);n["read"]["result"]="skipped"
        n["arm"]["outputs"]["frontier_status"]="no-progress"
        self.assertEqual(record(n,2)[1]["status"],"no-progress")
        n["arm"]["outputs"]["apk_delivery_status"]="apk-size-exceeded"
        self.assertEqual(record(n,2)[1]["status"],"apk-size-exceeded")
        n["arm"]["result"]="failure"
        self.assertNotEqual(record(n,2)[0].returncode,0)
        n=inputs(13);n["read"]["result"]="skipped"
        self.assertEqual(record(n,13,True)[1]["status"],"limit-verified")

    def test_exact_workflow_graph_and_embedded_scripts(self):
        workflows=("bare-checkpoint-transfer.yml","bare-r28-native-slot.yml","bare-arm64-probe.yml",
                   "bare-r28-replay-chain.yml","bare-r28-replay-worker.yml")
        parsed={name:yaml.safe_load((WF/name).read_text()) for name in workflows}
        for name,wf in parsed.items():
            for job_name,job in wf["jobs"].items():
                deps=job.get("needs",[])
                self.assertTrue(set([deps] if isinstance(deps,str) else deps)<=wf["jobs"].keys(),(name,job_name))
                path=job.get("uses","")
                if path.startswith("./"):
                    schema=parsed[Path(path).name]["on"]["workflow_call"]["inputs"]
                    supplied=job.get("with",{}).keys()
                    self.assertTrue(supplied<=schema.keys(),(name,job_name))
                    self.assertTrue(all(not v.get("required") or k in supplied for k,v in schema.items()),(name,job_name))
                for step in job.get("steps",[]):
                    if "run" not in step: continue
                    body=step["run"]
                    self.assertLessEqual(len(body),21000)
                    body=re.sub(r"\$\{\{.*?\}\}", "placeholder",body,flags=re.DOTALL)
                    if step.get("shell")=="python": compile(body,name,"exec")
                    elif step.get("shell","bash")=="bash":
                        process=subprocess.run(["bash","-n"],input=body,text=True,capture_output=True)
                        self.assertEqual(process.returncode,0,(name,job_name,step.get("name"),process.stderr))

    def test_inner_python_and_root_gate(self):
        for wf in (ARM,WORKER,CALLER):
            for job in wf["jobs"].values():
                for step in job.get("steps", []):
                    if step.get("shell") == "python":
                        compile(step["run"], step.get("name", "workflow step"), "exec")
        for job in CALLER["jobs"].values():
            if job.get("uses") in ("./.github/workflows/bare-arm64-probe.yml","./.github/workflows/bare-r28-native-slot.yml"):
                self.assertEqual(job["permissions"], {"actions":"read","contents":"write"})
        self.assertEqual(ARM["jobs"]["compile-probe"]["permissions"], {"actions":"read"})
        self.assertEqual(ARM["jobs"]["draft-publisher"]["permissions"], {"actions":"read","contents":"write"})
        for name in ("slot01", "production"):
            self.assertIn("bind-private-receiver",CALLER["jobs"][name]["needs"])
            self.assertIn("claim_asset_id",CALLER["jobs"][name]["if"])

    def test_private_readback(self):
        n=inputs(2); n["read"]["result"]="skipped"
        o=n["arm"]["outputs"]
        o.update(private_readback_verified="true",checkpoint_manifest_id="409",checkpoint_manifest_sha="6"*64,checkpoint_bytes="104")
        self.assertEqual(record(n,2,backend="draft")[1]["manifest_id"],"409")
        o["private_readback_verified"]="false"
        self.assertNotEqual(record(n,2,backend="draft")[0].returncode,0)

    def test_partial_private_publication_is_recovered_with_only_gets(self):
        job=dict(id=18,run_id=77,run_attempt=1,name="Bounded build segment 2 / Private checkpoint receipt for slot 2",
                 conclusion="failure",steps=[dict(name="Issue time-limited parent read descriptors bound to the peer",conclusion="success")])
        receipt=dict(ordinal=1,status="candidate",producer_sha=REV,sha="c"*64,identity="d"*64)
        out=last_private_slot([job],[receipt],77,REV,[])
        self.assertEqual((out["private_ordinal"],out["private_parent"],out["private_identity"]),(2,"c"*64,"d"*64))
        with self.assertRaises(ValueError): last_private_slot([job],[],77,REV,[])
        calls=[]
        client=read_only(lambda *args,**kwargs: calls.append(args[1]))
        client("api","GET","/test",auth=True)
        with self.assertRaises(ValueError): client("api","POST","/test",body=b"")
        self.assertEqual(calls,["GET"])
        recovery=CALLER["jobs"]["recover-draft-checkpoint"]
        self.assertIn("github.run_attempt != '1'",recovery["if"])
        self.assertFalse(any("publish" in step.get("run","") or "upload" in step.get("uses","") for step in recovery["steps"]))

    def test_incomplete_manifest_reports_observed_partial_state(self):
        step=CALLER["jobs"]["recover-draft-checkpoint"]["steps"][-1]["run"]
        def status(verified, partial, aid="", digest=""):
            return subprocess.run(["bash","-euo","pipefail","-c",step],env={**os.environ,
                       "R28_SLOT":"4","PARTIAL":partial,"PRIVATE_VERIFIED":verified,"MANIFEST_ID":aid,"DIGEST":digest},
                       text=True,capture_output=True)
        for name in ("all_private_bytes_verified_manifest_absent","partial_private_parts"):
            result=status("false",name)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(name,result.stdout)
        self.assertNotEqual(status("true","").returncode,0)
        self.assertEqual(status("true","","701","e"*64).returncode,0)

    def test_original_seal_can_be_salvaged_after_verifier_failed(self):
        initial=dict(status="recovery-no-terminal",accepted_parent=S2_SHA)
        art=dict(name="bare-personal-204-encrypted-77-1-s2",id=31,workflow_run={"id":77,"head_sha":REV},digest="sha256:"+"f"*64)
        job=dict(id=19,run_id=77,run_attempt=1,name="Bounded build segment 2 / Authenticate parent / compile-probe",
                 steps=[{"name":"Upload the encrypted APK bundle","conclusion":"success"}])
        mark=dict(run=77,attempt=1,ordinal=2,bytes=123,sha="d"*64)
        log=lambda _: "2026-11-25T09:50:00Z R28_SEALED_CIPHER "+json.dumps(mark)
        self.assertEqual(salvage(initial,[job],[art],77,REV,log)["cipher_sha"],"d"*64)
        with self.assertRaises(ValueError): salvage(initial,[job],[art,art],77,REV,log)
        mark["ordinal"]=1
        with self.assertRaises(ValueError): salvage(initial,[job],[art],77,REV,log)

    def test_fallback_cache_without_artifact_or_completed_result_job(self):
        outcome=dict(status="recovery-no-terminal");sha="a"*64; key="bare-coexist-204-apk-v1-77-1-s1"
        job=dict(id=700,name="Bounded build segment 1 / nested",run_id=77,run_attempt=1,
                 steps=[dict(name="Record the encrypted APK fallback receipt",conclusion="success")])
        mark=json.dumps(dict(run=77,attempt=1,ordinal=1,sha=sha,bytes=100))
        log=lambda x: ("2026-11-25T12:00:00Z R28_SEALED_CIPHER "+mark+"\n2026-11-25T12:03:00Z APK artifact upload failed; temporary ciphertext cache ID 55, key "+key+", SHA-256 "+sha+", 100 bytes")
        rows=lambda k,ref:[dict(id=55,key=k,ref=ref,size_in_bytes=123)]
        saved=recover_fallback(outcome,[job],77,log,rows)
        self.assertEqual((saved["status"],saved["cipher_cache"],saved["cipher_cache_id"]),("apk",key,"55"))
        self.assertEqual(salvage(saved,[],[],77,REV,log)["cipher_sha"],sha)
        self.assertEqual(recover_fallback(outcome,[job],77,log,lambda *_:[]),outcome)

    def test_unlisted_original_artifact_allows_its_verified_fallback(self):
        receipt=dict(status="apk",ordinal=2,cipher_id="31",cipher_cache="bare-coexist-204-apk-v1-77-1-s2")
        result=salvage(receipt,[],[],77,REV,lambda _: "")
        self.assertEqual((result["cipher_id"],result["cipher_cache"]),("", receipt["cipher_cache"]))
        with self.assertRaises(ValueError): salvage(dict(receipt,cipher_cache=""),[],[],77,REV,lambda _: "")

    def test_next_restore_failure_reports_true_verified_and_pending_parents(self):
        _,accepted=record(inputs())
        jobs={f"slot{n:02}":{"result":"skipped","outputs":{}} for n in range(1,14)}
        jobs["slot01"]={"result":"success","outputs":accepted};jobs["slot02"]["result"]="failure"
        step=CALLER["jobs"]["terminal-12"]["steps"][0]["run"]
        proc,_=dispatch(step,{"NEEDS":json.dumps(jobs)})
        self.assertNotEqual(proc.returncode,0)
        receipt=json.loads(proc.stdout.split("R28_INTERRUPTED_RECEIPT ")[1])
        self.assertEqual((receipt["verified_parent"],receipt["pending_parent"]),(S2_SHA,accepted["sha"]))
        stop=inputs();stop["arm"]["outputs"]["apk_delivery_status"]="apk-size-exceeded"
        stop["read"]["result"]="skipped"
        payload=record(stop)[1]
        jobs["slot01"]={"result":"success","outputs":payload};jobs["slot02"]["result"]="skipped"
        proc,_=dispatch(step,{"NEEDS":json.dumps(jobs)})
        self.assertNotEqual(proc.returncode,0)
        receipt=json.loads(proc.stdout.split("R28_TERMINAL_RECEIPT ")[1])
        self.assertEqual((receipt["status"],receipt["verified_parent"]),("apk-size-exceeded",S2_SHA))

    def test_all_slots_early_apk_late_duplicate_and_reread_only(self):
        receipts=[]
        jobs={}
        for n in range(1,4):
            a=inputs(n)
            if n==3:
                a["read"]["result"]="skipped";a["apk"]["result"]="success"
                a["arm"]["outputs"].update(apk_delivery_status="sealed", apk_encrypted_sha="b"*64,
                       apk_encrypted_bytes="123",apk_artifact_id="2134",apk_cache_key="")
            process,out=record(a,n)
            self.assertEqual(process.returncode,0,process.stderr)
            receipts.append(dict(out,ordinal=n))
            jobs[f"slot{n:02}"]={"result":"success","outputs":out}
        for n in range(4,14):
            jobs[f"slot{n:02}"]={"result":"skipped","outputs":{}}
        body=CALLER["jobs"]["terminal-12"]["steps"][0]["run"]
        p,_=dispatch(body,{"NEEDS":json.dumps(jobs)})
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertIn('"cipher_id":"2134"',p.stdout)
        self.assertEqual(follow(receipts,77,REV)["cipher_id"],"2134")
        with self.assertRaises(ValueError):
            follow([*receipts,receipts[0]],77,REV)
        jobs["slot04"]=jobs["slot01"]
        self.assertNotEqual(dispatch(body,{"NEEDS":json.dumps(jobs)})[0].returncode,0)


if __name__ == "__main__":
    unittest.main()
