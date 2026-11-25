"""Check path, custody and immutable-identity wiring across the three separate VMs."""
import hashlib
import os
from pathlib import Path
import subprocess
import unittest
os.environ.setdefault("RUNNER_TEMP","/tmp")
import thaw_workflow as w
import thaw, thaw_read, handback, thaw_claim


class TestFlow(unittest.TestCase):
    def test_jobs_and_routes(self):
        head="c"*40
        doc=w.render(head);jobs=doc["jobs"]
        self.assertEqual(doc["on"]["pull_request"]["paths"],[thaw_claim.WORKFLOW])
        self.assertEqual(thaw_read.WORKFLOW,handback.WORKFLOW)
        self.assertEqual(set(jobs),{"recover","issue","receive"})
        rec=jobs["recover"];ordinary=jobs["receive"]
        self.assertEqual(rec["name"],handback.JOB_LABEL)
        self.assertEqual(ordinary["permissions"],{"actions":"read"})
        self.assertEqual(ordinary["needs"],"recover")
        self.assertEqual(jobs["issue"]["needs"],"recover")
        roles={}
        paths=[]
        for role,j in jobs.items():
            text=[]
            for s in j["steps"]:
                run=s.get("run","")
                if run:
                    subprocess.run(["bash","-n"],check=True,input=run.encode())
                    self.assertLess(len(run),21000)
                    self.assertNotIn("prepare.py produce",run);text.append(run)
                if s.get("uses")==w.orig.UPLOAD:
                    paths.extend(s["with"]["path"].splitlines())
                    self.assertFalse(s["with"]["overwrite"]);self.assertEqual(s["with"]["retention-days"],1)
            roles[role]="\n".join(text)
        for p in paths:
            self.assertNotIn("private",p)
            self.assertNotIn("key.pem",p)
            self.assertFalse(p.endswith(".tar.zst"))
        uploads={s["id"]:s for j in jobs.values() for s in j["steps"] if s.get("uses")==w.orig.UPLOAD}
        self.assertEqual(uploads["put_request"]["with"]["name"],"r28-thaw-${{ github.run_id }}-request")
        for k,end in (("key","receiver-key"),("descriptor","descriptor")):
            self.assertEqual(w.receipt_name(end).replace("${{ github.run_id }}","92").replace("${{ github.run_attempt }}","3"),thaw_read.label({"run":92,"attempt":3},k))
        existing=next(s for s in rec["steps"] if "thaw.py existing" in s.get("run",""))
        self.assertIn("original_manifest_id",existing["env"]["THAW_ORIGINAL_MANIFEST_ID"])
        self.assertNotIn("GH_TOKEN",next(s for s in ordinary["steps"] if "thaw_read.py read" in s.get("run","")).get("env",{}))
        self.assertIn('env GITHUB_WORKSPACE="$THAW_SOURCE_TREE" TRIAL_SHA='+w.HEAD,roles["receive"])
        self.assertNotIn("exchange.py parent",roles["receive"])
        self.assertTrue(roles["recover"].index("thaw.py audit") < roles["recover"].index("thaw.py publish"))
        self.assertIn("thaw_claim.py verify",roles["issue"])
        self.assertNotIn("thaw_claim.py verify",roles["receive"])
        old=[s for s in rec["steps"] if s.get("with",{}).get("run-id")==str(w.SID)]
        self.assertEqual({int(s["with"]["artifact-ids"]) for s in old},{thaw.KEY_ID,thaw.CIPHER_ID})
        for s in old:
            self.assertEqual(s["with"]["digest-mismatch"],"error")
            self.assertEqual(s["with"]["github-token"],"${{ github.token }}")
        self.assertEqual(w.HEAD,thaw.ORIGINAL_HEAD)


if __name__=="__main__":unittest.main()
