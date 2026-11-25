"""Check actual reset timing and same-run peer termination before any grant is minted."""
import os
import unittest
from unittest.mock import patch
os.environ.setdefault("RUNNER_TEMP","/tmp")
import thaw_read as r
from test_thaw_read import Draft


class ResumeRateTest(unittest.TestCase):
    def test_reset_late_then_both_actual_denials(self):
        api=Draft(b"current test", "unused")
        obj=api.receipt(api.rows[11])
        times=[1000]
        actual=[]
        def call(host,path,label):
            actual.append((label,times[0]))
            return 1600 if label=="api" and len(actual)==2 else None
        def sleep(seconds):
            times[0]+=seconds
        with patch.object(api,"anonymous_status",side_effect=call), patch.object(r.time,"time",side_effect=lambda:times[0]), \
             patch.object(r.time,"sleep",side_effect=sleep), patch.object(r,"check_peer") as jobs:
            r.private_visibility(api,obj,1800,{},None)
        self.assertEqual(actual,[("direct",1000),("api",1000),("api",1600)])
        self.assertGreater(jobs.call_count,1)

    def test_deadline_and_dead_peer(self):
        api=Draft(b"current test","unused")
        obj=api.receipt(api.rows[11])
        with patch.object(api,"anonymous_status",side_effect=[None,1600]),patch.object(r.time,"time",return_value=1000), \
             self.assertRaisesRegex(r.Rejected,"exceeds remaining"):
            r.private_visibility(api,obj,1500,{},None)
        c={"run":7,"attempt":1,"head":"a"*40}
        job={"id":4,"name":r.ISSUER,"status":"completed","conclusion":"failure","run_id":7,"run_attempt":1,"head_sha":"a"*40}
        with patch.object(r.b,"api_json",return_value={"total_count":1,"jobs":[job]}), \
             self.assertRaisesRegex(r.Rejected,"peer terminated"):
            r.check_peer(c,r.ISSUER)
        for change in ({"run_id":91},{"run_attempt":3},{"head_sha":"b"*40}):
            with patch.object(r.b,"api_json",return_value={"total_count":1,"jobs":[{**job,**change}]}), \
                 self.assertRaisesRegex(r.Rejected,"peer incarnation"):
                r.check_peer(c,r.ISSUER)

    def test_reader_uses_valid_second_origin_only_after_issuer_throttle(self):
        import anon_peer
        api=Draft(b"test","unused");obj=api.receipt(api.rows[11]);c={"run":1}
        with patch.object(api,"anonymous_status",side_effect=[None,1600]),patch.object(anon_peer,"valid",return_value=True) as proof, \
             patch.object(r.time,"sleep",side_effect=AssertionError):
            r.private_visibility(api,obj,1800,c,{"from":"ordinary"})
        proof.assert_called_once_with({"from":"ordinary"},11,c)
        with patch.object(api,"anonymous_status",side_effect=[1600]),patch.object(anon_peer,"valid") as proof, \
             self.assertRaisesRegex(r.Rejected,"Ambiguous"):
            r.private_visibility(api,obj,1800,c,{"from":"ordinary"})
        proof.assert_not_called()

if __name__=="__main__": unittest.main()
