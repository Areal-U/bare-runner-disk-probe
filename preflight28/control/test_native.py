"""Run the result-producing Python from the real candidate workflows on regression cases."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

from admission import S2_SHA
from recover import follow, salvage

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
        n["arm"]["result"]="failure";n["arm"]["outputs"]["apk_delivery_status"]="apk-size-exceeded"
        self.assertEqual(record(n,2)[1]["status"],"apk-size-exceeded")
        n=inputs(13);n["read"]["result"]="skipped"
        self.assertEqual(record(n,13,True)[1]["status"],"limit-verified")

    def test_inner_python_and_root_gate(self):
        for wf in (ARM,WORKER,CALLER):
            for job in wf["jobs"].values():
                for step in job.get("steps", []):
                    if step.get("shell") == "python":
                        compile(step["run"], step.get("name", "workflow step"), "exec")
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
