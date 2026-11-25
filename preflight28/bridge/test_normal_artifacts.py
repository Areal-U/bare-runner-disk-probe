import os
from unittest import TestCase
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import apk_artifact
import artifact_poll
import normal
import owner_recovery


class NormalArtifactTests(TestCase):
    run_id=45526428252
    head="f"*40
    identifier=14982970974

    def row(self,name,ident=None):
        return {"id":ident or self.identifier,"name":name,"workflow_run":{"id":self.run_id,"head_sha":self.head},
                "size_in_bytes":140,"digest":"sha256:"+"1"*64,"expired":False,"expires_at":"2099-01-01T00:00:00Z"}

    def service(self,replies,physical):
        def get(path):
            if path.endswith(f"/artifacts/{self.identifier}"):
                return physical
            self.assertTrue(path.endswith(f"/runs/{self.run_id}/artifacts?per_page=100&page=1"))
            result=replies.pop(0)
            return result if isinstance(result,dict) else {"total_count":len(result),"artifacts":result}
        return get

    def test_terminal_delayed_inventory_recovers_one_immutable_id(self):
        row=self.row(f"bare-personal-204-encrypted-{self.run_id}-1-s1")
        api=self.service([{"total_count":1,"artifacts":[]},[row],[row]],row)
        pauses=[]
        result=apk_artifact.receipt(self.run_id,1,"-s1",self.head,124,str(self.identifier),"1"*64,get=api,sleep=pauses.append)
        self.assertEqual((result["id"],pauses),(self.identifier,[3]))

    def test_terminal_rejects_duplicate_or_mismatched_digest_and_id(self):
        row=self.row(f"bare-personal-204-encrypted-{self.run_id}-1-s1")
        for rows,sdk_id,sdk_digest in (([[row,dict(row,id=self.identifier+1)]],"",""),
                                       ([[row],[row]],str(self.identifier+1),""),
                                       ([[row],[row]],"","2"*64)):
            with self.assertRaises(ValueError):
                apk_artifact.receipt(self.run_id,1,"-s1",self.head,124,sdk_id,sdk_digest,
                                     get=self.service(rows,row),sleep=lambda _:None)

    def test_terminal_no_claim_without_receipt(self):
        result=apk_artifact.receipt(self.run_id,1,"-s1",self.head,124,"","",
                                    get=self.service([[]]*8,None),sleep=lambda _:None)
        self.assertIsNone(result)

    def test_ordinary_peer_wait_backoff_and_sender_scope(self):
        row=self.row(f"r28-{self.run_id}-a1-s01-key")
        bad={"total_count":1,"artifacts":[]}
        replies=[bad,[],[],bad,[],[],[row],[row]]
        with patch.dict(os.environ,GITHUB_RUN_ID=str(self.run_id),R28_SLOT="1",R28_HEAD_SHA=self.head), \
             patch.object(normal.b,"api_json",side_effect=self.service(replies,row)), \
             patch.object(normal.b,"output") as output, patch.object(normal.time,"sleep") as sleep:
            normal.wait("key")
            output.assert_called_once_with(id=self.identifier)
            self.assertEqual([c.args[0] for c in sleep.call_args_list],[8,15,30,60])

    def test_owner_wait_retries_then_checks_original_id(self):
        row=self.row(f"r28-{self.run_id}-a1-s01-outcome")
        bad={"total_count":1,"artifacts":[]}
        for expected in (self.identifier, self.identifier+1):
            with patch.object(normal.b,"api_json",side_effect=self.service([bad,[row],[row]],row)), \
                 patch.object(owner_recovery.time,"sleep"):
                if expected==self.identifier:
                    result=owner_recovery.locate(self.run_id,1,self.head,"a"*64,15,expected)
                    self.assertEqual(result["artifact_id"],self.identifier)
                else:
                    with self.assertRaisesRegex(ValueError,"Unconfirmed immutable"):
                        owner_recovery.locate(self.run_id,1,self.head,"a"*64,15,expected)

    def test_outcome_cutoff_never_reports_absence_on_only_unstable_reads(self):
        clock=[0.]
        with patch.dict(os.environ,GITHUB_RUN_ID=str(self.run_id),R28_SLOT="1",R28_HEAD_SHA=self.head), \
             patch.object(normal,"info",return_value={}), patch.object(normal,"sender_deadline",return_value=100), \
             patch.object(normal.time,"time",return_value=50), patch.object(normal.time,"monotonic",side_effect=lambda:clock[0]), \
             patch.object(normal.time,"sleep",side_effect=lambda sec:clock.__setitem__(0,clock[0]+sec)), \
             patch.object(normal.artifact_poll,"lookup",side_effect=artifact_poll.UnstableInventory("replicating")), \
             patch.object(normal.b,"output") as output:
            with self.assertRaisesRegex(ValueError,"unavailable"):
                normal.wait("outcome")
            output.assert_not_called()
