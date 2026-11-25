import copy
from datetime import datetime, timedelta, timezone
import hashlib
from io import BytesIO
import json
from types import SimpleNamespace
import unittest
from zipfile import ZipFile

import inputs
from recover import ChainStart
from receipt_journal import RESULT_JOB, SLOT_STEP


class GraphStopTests(unittest.TestCase):
    def setUp(self):
        self.run=42
        self.head='c'*40
        self.scope=ChainStart()
        self.base=f'r28-{self.run}-a1-s01'
        self.steps={
            'Verify the received APK frontier and establish the segment baseline':'success',
            'Run the real APK target within its time and output budgets':'success',
            'Stop every build writer before making the archive':'success',
            'Classify progress on the fixed APK graph after all writers stop':'failure',
            'Pack the completed intermediate outputs':'skipped','Certify an advanced checkpoint exists before transfer':'skipped',
            'Save a new bounded generation without replacing the producer':'skipped',
            'Persist the original sealed APK receipt':'skipped','Upload the encrypted APK bundle':'skipped',
            'Save only the encrypted APK for retrieval retry':'skipped','Emit terminal peer outcome for this exact slot':'success',
            'Deposit outcome in this run':'success'}
        timestamp='2026-01-01T12:00:00Z'
        def job(num,name,steps):
            return dict(id=num,name='Bounded build segment 1 / path / '+name,head_sha=self.head,run_attempt=1,run_id=self.run,
                status='completed',conclusion='failure',completed_at=timestamp,
                steps=[dict(name=k,conclusion=v,started_at=timestamp,completed_at=timestamp) for k,v in steps.items()])
        self.jobs=[job(10,'Compile or verify authenticated APK slot 1',self.steps),job(11,RESULT_JOB,{SLOT_STEP:'skipped'})]
        note=dict(schema='bare-r28-checkpoint-private-v1', attempt=1,run=self.run,ordinal=1,producer_sha=self.head,
                  parent_sha=self.scope.sha,parent_identity=self.scope.identity,key=f'bare-coexist-204-{self.run}-1-checkpoint-production-s1',status='failed')
        buf=BytesIO()
        with ZipFile(buf,'w') as z: z.writestr('outcome.json',json.dumps(note))
        self.body=buf.getvalue()
        self.art=dict(id=456,name=self.base+'-outcome',size_in_bytes=len(self.body),expires_at='2026-01-02T12:00:00Z',expired=False,
                      created_at=timestamp,digest='sha256:'+hashlib.sha256(self.body).hexdigest(),
                      workflow_run=dict(id=self.run,head_sha=self.head))
        self.cap=SimpleNamespace(metadata=lambda path:self.art,note=lambda aid:self.body)

    def result(self,arts):
        return inputs.graph_stop(self.jobs,arts,[],self.run,self.head,self.scope,self.cap)

    def test_proven_stop_with_or_without_retained_zip(self):
        self.assertEqual(self.result([self.art])['stop_artifact'],'verified-stop-only')
        self.assertIsNone(self.result([])['successor'])
        self.art['expired']=True
        self.cap.note=lambda n:self.fail('expired ZIP requested')
        self.assertEqual(self.result([self.art])['stop_artifact'],'expired-job-evidence-only')

    def test_alternate_or_contradictory_evidence_cannot_issue_a_parent(self):
        altered=copy.deepcopy(self.art)
        altered['name']=self.base+'-receipt'
        self.assertIsNone(self.result([self.art,altered]))
        self.cap.note=lambda n:b'wrong'
        with self.assertRaises(ValueError):
            self.result([self.art])
        seal=next(s for s in self.jobs[0]['steps'] if s['name']=='Upload the encrypted APK bundle')
        seal['conclusion']='success'
        self.assertIsNone(self.result([self.art]))


if __name__=='__main__':
    unittest.main()
