"""Verify the read-only resume can neither publish nor compile or access the old escrow material."""
import re
import subprocess
import unittest
import thaw_resume_workflow as w


class ResumeWorkflowTest(unittest.TestCase):
    def test_resume_from_existing_receipt(self):
        head="a"*40
        doc=w.render(head)
        self.assertEqual(doc["permissions"],{})
        self.assertEqual(doc["env"]["R28_RESUME_PUBLISHED"],"45522666298")
        self.assertEqual(doc["on"]["pull_request"]["paths"],[".github/workflows/bare-r28-s2-thaw.yml"])
        self.assertEqual(set(doc["jobs"]),{"issue","receive"})
        self.assertFalse(doc["concurrency"]["cancel-in-progress"])
        receive,issue=doc["jobs"]["receive"],doc["jobs"]["issue"]
        self.assertEqual(receive["permissions"],{"actions":"read"})
        self.assertEqual(issue["permissions"],{"actions":"read","contents":"write"})
        self.assertEqual(receive["env"],issue["env"])
        self.assertEqual(receive["env"]["MANIFEST_ID"],"789542812")
        for role,j in doc["jobs"].items():
            self.assertNotIn("needs",j)
            self.assertIn(head,j["if"])
            self.assertIn("pull_request.number == 9",j["if"])
            self.assertIn("github.triggering_actor == 'Areal-U'",j["if"])
            for step in j["steps"]:
                cmd=step.get("run","")
                if cmd:
                    subprocess.run(["bash","-n"],check=True,input=cmd.encode())
                    self.assertLess(len(cmd),21000)
                self.assertFalse(re.search(r"prepare.py produce|thaw.py [a-z]|handback.py|thaw_claim.py|reserve|upload-release",cmd))
                if step.get("uses")==w.original.orig.UPLOAD:
                    self.assertTrue(all(p.endswith(("/public.pem","/holder.json","/descriptor.cms")) for p in step["with"]["path"].splitlines()))
                self.assertNotEqual(step.get("uses",""),w.original.orig.RESTORE)
        self.assertEqual(w.single(receive,"Locate authenticated descriptor Artifact")["timeout-minutes"],88)
        self.assertEqual(w.single(issue,"Issue fresh part-scoped GET redirects encrypted to the separate runner")["timeout-minutes"],80)
        self.assertEqual(w.single(issue,"Confirm the immutable private generation and original completed audit")["run"],
                         "python3 preflight28/transport/published_reader.py verify")
        reads=w.single(receive,"Download and hash every private checkpoint byte without repository credentials")
        self.assertNotIn("GH_TOKEN",reads.get("env",{}))
        self.assertIn("R28_CAMPAIGN",w.single(receive,"Independently restore using the exact original code, provenance, and strictly dry APK plan")["run"])


if __name__=="__main__":unittest.main()
