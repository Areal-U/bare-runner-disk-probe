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
from recover import ChainStart, R30_S1_SHA, R30_S1_IDENTITY, follow, last_private_slot
from recover_private import read_only, recovery_deadline, JOB_NAME, JOB_MINUTES, STEP_MINUTES, EXIT_MINUTES
from datetime import datetime, timezone
from unittest.mock import Mock

HERE = Path(__file__).resolve().parents[2]
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
    parent = S2_SHA if n == 1 else R30_S1_SHA if n == 2 else f"{n-1:064x}"
    return dispatch(WORKER["jobs"]["result"]["steps"][0]["run"], dict(SLOT_NEEDS=json.dumps(needs),
                    BACKEND=backend,PARENT_SHA=parent,ORDINAL=str(n), VERIFY_ONLY=str(verify).lower()))


class NativeTests(unittest.TestCase):
    def test_normal_action_entry_and_guard(self):
        self.assertEqual(CALLER["on"]["workflow_dispatch"]["inputs"]["build_segments"]["default"],"12")
        self.assertEqual(CALLER["on"]["workflow_dispatch"]["inputs"]["compile_minutes"]["default"],"0")
        self.assertNotIn("slot01", CALLER["jobs"])
        first = CALLER["jobs"]["slot02"]
        self.assertEqual(first["with"]["parent_manifest_id"], "795559195")
        self.assertEqual(first["with"]["parent_run"], "45771045621")
        self.assertEqual(first["with"]["parent_sha"], R30_S1_SHA)
        self.assertEqual(first["with"]["parent_identity"], R30_S1_IDENTITY)
        self.assertEqual(first["needs"], "bind-private-receiver")
        for n in range(2,14):
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
        self.assertEqual(set(lookup["needs"]),{"terminal-12","reread-loss-admission"})
        self.assertFalse(any("upload-artifact" in x.get("uses","") for x in lookup["steps"]))

    def test_received_candidate_and_nonmatching_parent(self):
        n=inputs(2)
        p,o=record(n,2)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual(o["status"],"candidate")
        n["arm"]["outputs"]["parent_frontier_verified"]="false"
        self.assertNotEqual(record(n,2)[0].returncode,0)

    def test_same_run_receipt_only_continuation(self):
        state="manifest_present_visibility_pending"
        n=inputs(2);n["read"]["result"]="skipped";o=n["arm"]["outputs"]
        o.update(private_status=state, private_readback_verified="false", checkpoint_saved="false",
                 checkpoint_manifest_id="716",checkpoint_manifest_sha="e"*64,checkpoint_bytes="1024")
        fields=("checkpoint_manifest_id","checkpoint_manifest_sha","checkpoint_sha","checkpoint_identity",
                "checkpoint_bytes","checkpoint_key","checkpoint_ordinal","producer_sha")
        confirm={k:o[k] for k in fields}
        confirm.update(recovery_status=state,private_readback_verified="false")
        n["confirm-private"]={"result":"success","outputs":confirm}
        p,ret=record(n,2,backend="draft")
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertEqual((ret["status"],ret["manifest_id"],ret["sha"]),(state,"716",o["checkpoint_sha"]))
        self.assertEqual(follow([dict(ret,ordinal=2)],77,REV,ChainStart(2,R30_S1_SHA,R30_S1_IDENTITY))["status"],state)
        jobs={f"slot{j:02}":{"result":"skipped","outputs":{}} for j in range(1,14)}
        jobs["slot02"]={"result":"success","outputs":ret}
        terminal=CALLER["jobs"]["terminal-12"]["steps"][0]["run"]
        resolved,_=dispatch(terminal, {"NEEDS":json.dumps(jobs)})
        self.assertNotEqual(resolved.returncode,0)
        self.assertIn("R28_TERMINAL_RECEIPT",resolved.stdout)
        confirm.update(recovery_status="verified",private_readback_verified="true")
        self.assertEqual(record(n,2,backend="draft")[1]["status"],"candidate")
        for k in fields:
            old=confirm[k]; confirm[k]="wrong"
            self.assertNotEqual(record(n,2,backend="draft")[0].returncode,0)
            confirm[k]=old
        n["confirm-private"]["result"]="failure"
        self.assertNotEqual(record(n,2,backend="draft")[0].returncode,0)
        del n["confirm-private"]
        self.assertNotEqual(record(n,2,backend="draft")[0].returncode,0)
        job=WORKER["jobs"]["confirm-private"]
        self.assertIn(state,job["if"]);self.assertIn("github.run_attempt == '1'",job["if"])
        self.assertEqual(job['needs'],'arm')
        self.assertEqual(job["timeout-minutes"],JOB_MINUTES)
        self.assertEqual(job["steps"][-1]["timeout-minutes"],STEP_MINUTES)
        self.assertIn("recover_private.py",job["steps"][-1]["run"])
        self.assertFalse(any('upload' in s.get('uses','') or 'publish' in s.get('run','') for s in job["steps"]))

    def test_real_attempt_clock_cutoff_for_both_read_only_jobs(self):
        step_start=1_800_000_000; now=step_start+3
        api=Mock(BASE="base")
        e=dict(GITHUB_JOB="recover-draft-checkpoint",GITHUB_RUN_ID="77",GITHUB_RUN_ATTEMPT="2",GITHUB_SHA=REV,
               R28_CHECK_RUN="52",R28_STEP_START=str(step_start))
        def row(offset):
            return dict(id=14,run_id=77,run_attempt=int(e["GITHUB_RUN_ATTEMPT"]),head_sha=REV,status="in_progress",name=JOB_NAME,
                        check_run_url="https://api.github.com/repos/Areal-U/bare-runner-disk-probe/check-runs/52",
                        started_at=datetime.fromtimestamp(step_start-offset,timezone.utc).isoformat())
        item=row(60);api.metadata.return_value=dict(total_count=1,jobs=[item])
        self.assertEqual(recovery_deadline(api,e,now),step_start+(STEP_MINUTES-EXIT_MINUTES)*60)
        item=row(35*60);api.metadata.return_value=dict(total_count=1,jobs=[item])
        self.assertEqual(recovery_deadline(api,e,now),step_start+(JOB_MINUTES-35-EXIT_MINUTES)*60)
        for key,val in (("R28_CHECK_RUN","3"),("GITHUB_SHA","b"*40),("GITHUB_RUN_ATTEMPT","3")):
            with self.assertRaises(ValueError):recovery_deadline(api,{**e,key:val},now)
        e.update(GITHUB_JOB='confirm-private',R28_SLOT='4',GITHUB_RUN_ATTEMPT='1',GITHUB_ACTOR='Areal-U',
                 R28_EXPECTED_RECOVERY_MANIFEST='716',R28_EXPECTED_RECOVERY_MANIFEST_SHA='e'*64)
        item=row(70);item["name"]="Bounded build segment 4 / Confirm original private visibility for slot 4"
        fillers=[dict(item,id=1000+i,status='completed') for i in range(100)]
        api.metadata.side_effect=[dict(total_count=101,jobs=fillers),dict(total_count=101,jobs=[item])]
        self.assertEqual(recovery_deadline(api,e,now),step_start+(STEP_MINUTES-EXIT_MINUTES)*60)
        with self.assertRaises(ValueError):recovery_deadline(api,dict(e,R28_EXPECTED_RECOVERY_MANIFEST=''),now)

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

    def test_canonical_same_vm_retry_never_advances_without_private_receipt(self):
        steps = {s["id"]:s for s in ARM["jobs"]["compile-probe"]["steps"] if "id" in s}
        first, retry = (steps[k] for k in ("peer_put_outcome","retry_relay"))
        self.assertEqual(first["uses"],"./preflight28/bridge/normal_upload")
        self.assertEqual(first["uses"],retry["uses"])
        self.assertEqual(first["with"],retry["with"])
        self.assertEqual((first["with"]["overwrite"],first["with"]["compression-level"],first["with"]["retention-days"]),
                         (False,0,1))
        self.assertIn("steps.resolve_relay_1.outputs.decision == 'retry'",retry["if"])
        self.assertIn("== 'candidate'",CALLER["jobs"]["slot03"]["if"])
        n=inputs(2); n["read"]["result"]="skipped"; o=n["arm"]["outputs"]
        for reason in ("relay-quota-denied","relay-capacity-exceeded","relay-deadline","relay-missing","relay-ambiguous"):
            o.update(relay_stop=reason,relay_no_receipt="true")
            self.assertEqual(record(n,2,backend="draft")[1]["status"],reason)
        o["relay_no_receipt"]="false"
        self.assertNotEqual(record(n,2,backend="draft")[0].returncode,0)
        o.update(private_readback_verified="true",checkpoint_manifest_id="483",checkpoint_manifest_sha="8"*64,checkpoint_bytes="12345")
        self.assertEqual(record(n,2,backend="draft")[1]["status"],"candidate")
        o.update(private_readback_verified="",relay_no_receipt="true",apk_delivery_status="sealed",
                 apk_encrypted_sha="b"*64,apk_encrypted_bytes="421",apk_artifact_id="7")
        n["apk"]["result"]="success"
        self.assertEqual(record(n,2,backend="draft")[1]["status"],"apk")

    def test_exact_workflow_graph_and_embedded_scripts(self):
        workflows=("bare-checkpoint-transfer.yml","bare-r28-native-slot.yml","bare-arm64-probe.yml")
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

    @unittest.skipUnless(os.environ.get("SISO"),"set SISO to the pinned Chromium Siso executable")
    def test_restored_marker_planner_cannot_compile_dirty_work(self):
        shell=next(s["run"] for s in ARM["jobs"]["compile-probe"]["steps"] if s.get("name")=="Verify restored inputs and completed targets")
        self.assertEqual(shell.count("check_restored_targets "),3)
        function=re.search(r"(?ms)^check_restored_targets\(\) \{.*?^\}",shell).group(0)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/".gclient").touch()
            out=root/"out/Bare"
            out.mkdir(parents=True)
            (out/"build.ninja").write_text("rule write\n  command = touch $out && touch compiler-invoked\nbuild marker.o: write\n")
            auto=root/"autoninja"
            auto.write_text('#!/bin/bash\nexec "$SISO" ninja -load= "$@"\n')
            auto.chmod(0o755)
            env={**os.environ,"PATH":str(root)+os.pathsep+os.environ["PATH"],"PYTHONPATH":str(HERE/"preflight28/graph")}
            def plan():
                return subprocess.run(["bash","-euo","pipefail","-c",function+"\ncheck_restored_targets marker.o"],
                                      cwd=root,env=env,text=True,capture_output=True)
            dirty=plan()
            self.assertNotEqual(dirty.returncode,0)
            self.assertIn("Restored target requires compilation",dirty.stderr)
            self.assertFalse((out/"compiler-invoked").exists())
            self.assertFalse((out/"marker.o").exists())
            subprocess.run([str(auto),"-C",str(out),"marker.o"],env=env,cwd=root,check=True,capture_output=True)
            (out/"compiler-invoked").unlink()
            before=(out/".ninja_log").read_bytes()
            clean=plan()
            self.assertEqual(clean.returncode,0,clean.stderr)
            self.assertFalse((out/"compiler-invoked").exists())
            self.assertEqual(before,(out/".ninja_log").read_bytes())

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
        for name in ("slot02", "production"):
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
        def status(verified, partial, aid="", digest="",manifest=""):
            return subprocess.run(["bash","-euo","pipefail","-c",step],env={**os.environ,
                       "R28_SLOT":"4","PARTIAL":partial,"PRIVATE_VERIFIED":verified,"MANIFEST_ID":aid,"DIGEST":digest,"MANIFEST_SHA":manifest},
                       text=True,capture_output=True)
        for name in ("all_private_bytes_verified_manifest_absent","partial_private_parts"):
            result=status("false",name)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(name,result.stdout)
        self.assertNotEqual(status("true","").returncode,0)
        self.assertEqual(status("true","","701","e"*64).returncode,0)
        unresolved=status("false","manifest_present_visibility_pending","716","f"*64,"e"*64)
        self.assertNotEqual(unresolved.returncode,0)
        self.assertIn("Anonymous visibility confirmation is pending",unresolved.stdout)

    def test_next_restore_failure_reports_true_verified_and_pending_parents(self):
        _,accepted=record(inputs(2),2)
        jobs={f"slot{n:02}":{"result":"skipped","outputs":{}} for n in range(1,14)}
        jobs["slot02"]={"result":"success","outputs":accepted};jobs["slot03"]["result"]="failure"
        step=CALLER["jobs"]["terminal-12"]["steps"][0]["run"]
        proc,_=dispatch(step,{"NEEDS":json.dumps(jobs)})
        self.assertNotEqual(proc.returncode,0)
        receipt=json.loads(proc.stdout.split("R28_INTERRUPTED_RECEIPT ")[1])
        self.assertEqual((receipt["verified_parent"],receipt["pending_parent"]),(R30_S1_SHA,accepted["sha"]))
        stop=inputs(2);stop["arm"]["outputs"]["apk_delivery_status"]="apk-size-exceeded"
        stop["read"]["result"]="skipped"
        payload=record(stop,2)[1]
        jobs["slot02"]={"result":"success","outputs":payload};jobs["slot03"]["result"]="skipped"
        proc,_=dispatch(step,{"NEEDS":json.dumps(jobs)})
        self.assertNotEqual(proc.returncode,0)
        receipt=json.loads(proc.stdout.split("R28_TERMINAL_RECEIPT ")[1])
        self.assertEqual((receipt["status"],receipt["verified_parent"]),("apk-size-exceeded",R30_S1_SHA))

    def test_all_slots_early_apk_late_duplicate_and_reread_only(self):
        receipts=[]
        jobs={}
        for n in range(2,4):
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
        scope = ChainStart.from_admission({"R28_REPLAY_MODE":"build-apk","R30_RESUME_S1":"1"})
        self.assertEqual(scope,ChainStart(2,R30_S1_SHA,R30_S1_IDENTITY))
        self.assertEqual(follow(receipts,77,REV,scope)["cipher_id"],"2134")
        with self.assertRaises(ValueError):
            follow([*receipts,receipts[0]],77,REV,scope)
        jobs["slot04"]=jobs["slot02"]
        self.assertNotEqual(dispatch(body,{"NEEDS":json.dumps(jobs)})[0].returncode,0)


if __name__ == "__main__":
    unittest.main()
