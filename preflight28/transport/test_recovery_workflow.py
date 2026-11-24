"""Check the actual retry workflow names, role fences and full/fallback endpoints."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch
os.environ.setdefault("RUNNER_TEMP","/tmp")
import recovery_workflow as wf
import fresh

class Wire(unittest.TestCase):
    def test_rendered_contract(self):
        head="1"*40
        with patch.dict(os.environ,GITHUB_REPOSITORY="Areal-U/bare-runner-disk-probe",R28_CAMPAIGN=wf.CAMPAIGN,
             GITHUB_RUN_ID="831",GITHUB_RUN_ATTEMPT="1",TRIAL_SHA=head):
            doc=wf.render(head);jobs=doc["jobs"]
            self.assertEqual(doc["on"]["pull_request"]["paths"],[fresh.WORKFLOW])
            self.assertEqual(set(jobs),{"reserve","produce","send","receive"})
            self.assertEqual(jobs["produce"]["permissions"],{"actions":"read"})
            self.assertEqual(jobs["send"]["needs"],"reserve")
            self.assertEqual(jobs["produce"]["needs"],"reserve")
            self.assertIn("github.run_attempt == '1'",jobs["send"]["if"])
            self.assertIn("github.run_attempt == '1'",jobs["produce"]["if"])
            self.assertIn("github.run_attempt != '1'",jobs["receive"]["if"])
            uploaded={}
            for key,job in jobs.items():
                steps=job["steps"]
                for s in steps:
                    if "run" in s:
                        subprocess.run(["bash","-n"],input=s["run"].encode(),check=True)
                        self.assertLess(len(s["run"]),21000)
                    if s.get("uses")==wf.UPLOAD:
                        name=s["with"]["name"].replace("${{ github.run_id }}","831")
                        uploaded[s["id"].removeprefix("put_")]=(name,key,s["with"]["path"])
                self.assertIn('git rev-parse HEAD',steps[0]["run"])
                self.assertIn('credential.helper=',steps[0]["run"])
            self.assertEqual(set(uploaded),{"key","cipher","delta"})
            for kind,src in (("key","send"),("cipher","produce"),("delta","produce")):
                self.assertEqual((fresh.artifact_name(kind),src),uploaded[kind][:2])
            self.assertNotIn("key.pem",uploaded["key"][2]);self.assertIn("writer-key.age",uploaded["key"][2])
            for kind,jobname in (("key","produce"),("cipher","send")):
                s=next(s for s in jobs[jobname]["steps"] if s.get("id")=="wait_"+kind)
                self.assertTrue(s["run"].endswith("wait "+kind))
                self.assertEqual(s["env"]["FRESH_PEER_NAME"],jobs["send" if kind=="key" else "produce"]["name"])
            gate=next(s for s in jobs["produce"]["steps"] if s.get("id")=="fallback")
            self.assertIn("create-rejected-storage-quota",gate["run"])
            self.assertIn("exit 1",gate["run"])
            self.assertIn("steps.put_cipher.outcome == 'failure'",gate["if"])
            self.assertIn("checkpoint.cms",uploaded["cipher"][2]);self.assertNotIn("tar.zst",uploaded["cipher"][2])
            self.assertIn("delta.cms",uploaded["delta"][2]);self.assertIn("cipher-receipt.json",uploaded["delta"][2])
            steps=jobs["send"]["steps"]
            sender=next(s for s in steps if s.get("id")=="send")
            self.assertEqual(sender["env"]["FRESH_MODE"],"${{ steps.wait_cipher.outputs.mode }}")
            self.assertTrue(any("delta.py restore" in s.get("run","") and "== 'delta'" in s["if"] for s in steps))
            self.assertTrue(any(".../exchange.py receive" in s.get("run","").replace("preflight28/transport","...") for s in jobs["receive"]["steps"]))
            self.assertTrue(any("recovery_claim.py verify" in s.get("run","") for s in jobs["receive"]["steps"]))
            self.assertFalse(any("prepare.py produce" in s.get("run","") for s in jobs["receive"]["steps"]))
            self.assertIn("age1ndr7",next(s["run"] for s in steps if "writer-key.age" in s.get("run","")))

if __name__=="__main__":unittest.main()
