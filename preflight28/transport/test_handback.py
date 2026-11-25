"""Real OAEP/GCM and age recovery with disposable credentials, plus pinned metadata controls."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

import handback as h

RUN,HEAD,JOB,CHECK = 9912,"f"*40,34,89


class HandbackTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.work=Path(tmp.name); self.peer=self.work/"peer"; self.owner=self.work/"owner";self.owner.mkdir()
        self.req=h.request(self.peer,h.public_context(RUN,HEAD,JOB,CHECK))
        self.challenge=self.work/"challenge.zip"
        with zipfile.ZipFile(self.challenge,"x") as z:
            for key in ("public.pem","request.json"):
                z.write(self.peer/key,key)
        raw=self.challenge.read_bytes();self.art=h.artifact_ref(100,h.sha(raw),len(raw))

    def test_real_encrypted_handback_and_changed_binding(self):
        src=self.work/"source"
        self.src=h.request(src,h.public_context(RUN+1,HEAD,JOB+1,CHECK+1))
        pub=(src/"public.pem").read_bytes(); priv=(src/"private.pem").read_bytes()
        with patch.dict(h.SOURCE,original_recipient=h.cert_fpr(pub)):
            # Replace the source fingerprint in the new challenge and physically hash its ZIP.
            self.req["source"]=h.SOURCE
            (self.peer/"request.json").write_bytes(h.encode(self.req))
            with zipfile.ZipFile(self.challenge,"w") as z:
                for key in ("public.pem","request.json"): z.write(self.peer/key,key)
            raw=self.challenge.read_bytes();self.art=h.artifact_ref(100,h.sha(raw),len(raw))
            with patch.object(h,"original",return_value=(priv,pub)) as unwrap:
                params=(None,None,self.challenge,self.art,RUN,HEAD,JOB,self.owner)
                dest=h.respond(*params)
                self.assertEqual(dest,h.respond(*params))
                self.assertEqual(unwrap.call_count,1)
                with self.assertRaises(h.Rejected):
                    h.respond(None,None,self.challenge,self.art,RUN,HEAD,JOB+1,self.owner)
            self.assertNotIn(b"PRIVATE KEY",dest.read_bytes())
            self.assertNotIn(h.base64.b64encode(priv),dest.read_bytes())
            h.record(self.peer/"request-artifact.json",h.encode(self.art))
            h.consume(self.peer,dest,RUN,HEAD)
            self.assertEqual((self.peer/"original-private.pem").read_bytes(),priv)
            self.assertEqual((self.peer/"original-private.pem").stat().st_mode & 0o777,0o600)
            bad=self.work/"altered"
            msg=h.json.loads(dest.read_bytes());enc=bytearray(h.base64.b64decode(msg["cms"]));enc[-1]^=1
            msg.update(cms=h.base64.b64encode(enc).decode("ascii"),cipher_sha=h.sha(enc))
            bad.write_bytes(h.encode(msg))
            with self.assertRaises((ValueError,h.Rejected)):h.consume(self.peer,bad,RUN,HEAD)
            (self.peer/"request-artifact.json").write_bytes(h.encode(dict(self.art,id=201)))
            with self.assertRaises(h.Rejected):h.consume(self.peer,dest,RUN,HEAD)

    def test_private_only_uploader_empty_and_receipt_binding(self):
        packet=b'{"encrypted_fixture":true}'; sha=h.sha(packet)
        service=Mock(BASE="base")
        name=h.response_name(RUN)
        row=dict(id=67,name=name,state="uploaded",size=len(packet),digest="sha256:"+sha,uploader={"id":1})
        receipt=dict(id=self.art["id"],name=f"r28-thaw-{RUN}-request",expired=False,digest="sha256:"+self.art["sha256"],
                     size_in_bytes=self.art["bytes"],workflow_run=dict(id=RUN,head_sha=HEAD,repository_id=h.REPO_ID))
        service.metadata.side_effect=[dict(total_count=0,artifacts=[]),dict(total_count=1,artifacts=[receipt])]
        service.draft.side_effect=[dict(assets=[]),dict(assets=[dict(row,state="starter")]),dict(assets=[row])]
        service.is_owner.side_effect=lambda a:a=={"id":1}
        service.download.side_effect=lambda i,n,d,f:f.write(packet)
        with patch.object(h.time,"sleep"):
            h.wait(self.peer,service,RUN,HEAD,20)
        self.assertEqual((self.peer/"response.json").read_bytes(),packet)
        service.download.assert_called_once()
        self.assertTrue(all(c.args==(h.RELEASE_ID,) for c in service.draft.call_args_list))
        service.metadata.side_effect=[dict(total_count=1,artifacts=[receipt])]
        service.draft.side_effect=[dict(assets=[dict(row,uploader={"id":2})])]
        with self.assertRaisesRegex(h.Rejected,"registered owner"):h.wait(self.peer,service,RUN,HEAD,20)

    def test_physical_recover_role_rejects_wrong_head_and_job(self):
        api=Mock(BASE="/repos/"+h.REPO)
        r=dict(id=RUN,run_attempt=1,path=h.WORKFLOW,event="pull_request",head_sha=HEAD,head_branch=h.BRANCH,
               repository=dict(id=h.REPO_ID),status="in_progress")
        j=dict(id=JOB,run_id=RUN,run_attempt=1,head_sha=HEAD,status="in_progress",name=h.JOB_LABEL,
               check_run_url=f"https://api.github.com/repos/{h.REPO}/check-runs/{CHECK}")
        def pair(job):return [r,dict(total_count=1,jobs=[job])]
        api.metadata.side_effect=pair(j)
        self.assertEqual(h.physical(api,RUN,HEAD,CHECK),JOB)
        api.metadata.side_effect=pair(dict(j,name="compute"))
        with self.assertRaises(h.Rejected):h.physical(api,RUN,HEAD,CHECK)
        api.metadata.side_effect=[dict(r,head_sha="0"*40)]
        with self.assertRaises(h.Rejected):h.physical(api,RUN,HEAD,CHECK)


if __name__=="__main__": unittest.main()
