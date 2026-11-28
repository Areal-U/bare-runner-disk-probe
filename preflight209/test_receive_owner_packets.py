"""Offline packet rescue from physical-style GitHub captures using disposable owner and CMS keys."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import receive_owner_packets as rescue
import test_outcome_transport as producer
from test_owner import Service
import checkpoint_packets as packets


@unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'needs age for disposable owner identity')
class OwnerPackets(unittest.TestCase):
    def setUp(self):
        self.producer = producer.OutcomeTransport()
        self.producer.setUp()
        self.addCleanup(self.producer.doCleanups)
        self.archive, _, key, _ = self.producer.make_candidate()
        self.enterContext(patch.dict(os.environ, {'GITHUB_ACTIONS':''}))
        self.enterContext(patch.object(rescue.owner, 'RECIPIENT', producer.owner_recovery.RECIPIENT))
        self.service = Service()
        s = self.service
        self.enterContext(patch.object(rescue.owner, 'DESTINATION_HASH', rescue.owner.sha(rescue.owner.encode(s.dest))))
        n = self.outcome = json.loads((self.producer.normal/'outcome.json').read_bytes())
        self.ctx = {k:n[k] for k in producer.owner_recovery.FIELDS}
        self.root = self.producer.tmp/'owner-inputs'
        self.root.mkdir(mode=0o700)
        self.args = SimpleNamespace(run=n['run'], slot=n['ordinal'], head=n['producer_sha'], claim=97,
                      parent=n['parent_sha'], parent_identity=n['parent_identity'], age_identity=key, inputs=self.root,
                      outcome_id=301,out=self.producer.tmp/'private-checkpoint.tar.zst')
        s.run.update(id=n['run'], head_sha=n['producer_sha'], updated_at='2026-11-28T03:00:00Z')
        for doc in (s.ack,s.ticket):
            doc.update(head=n['producer_sha'],genesis=n['parent_sha'],resume=rescue.owner.unpublished.SELECTOR,
                       recipient=rescue.owner.RECIPIENT)
        s.deposit()
        claim=dict(schema=1,campaign=rescue.owner.CAMPAIGN,repository_id=rescue.owner.REPO_ID,
                   release_id=rescue.owner.RELEASE_ID,branch=rescue.owner.BRANCH,workflow=rescue.owner.WORKFLOW,
                   head=n['producer_sha'],genesis=n['parent_sha'],producer_attempt=1,origin_run=n['run'],
                   recipient=rescue.owner.RECIPIENT,destination_commitment=rescue.owner.DESTINATION_HASH,
                   resume=s.ticket['resume'],ticket_sha=rescue.owner.sha(s.bytes[s.ticket_id]),ticket_asset_id=s.ticket_id,
                   collector_ack_sha=s.ticket['collector_ack_sha'],collector_ack_asset_id=s.ack_id,
                   collector_registration_id=s.ticket['collector_registration_id'])
        self.bot = dict(login=rescue.BOT[0],id=rescue.BOT[1])
        self.when = '2026-11-28T02:00:00Z'
        self.put(97,f'{rescue.owner.CAMPAIGN}-after-{rescue.owner.unpublished.RUN}-claim.json',rescue.owner.encode(claim))
        self.args.claim_sha=rescue.owner.sha(s.bytes[97])
        self.stem = f'r209-{n["run"]}-a1-s01-'
        self.put(301,self.stem+'packet-outcome.json',json.dumps(n,sort_keys=True).encode('ascii'))
        self.args.outcome_sha=rescue.owner.sha(s.bytes[301])
        data=(self.producer.normal/'checkpoint.cms').read_bytes()
        # Split this real CMS into two packets so omission and reordering are tested cheaply.
        self.enterContext(patch.object(packets,'PACKET_BYTES',(len(data)+1)//2))
        self.sidecars=[]
        for i in range(2):
            lo=i*packets.PACKET_BYTES
            material=data[lo:lo+packets.PACKET_BYTES]
            name=f'{self.stem}packet-{i:03}'
            digest=rescue.owner.sha(material)
            aid=310+2*i
            self.put(aid,name,material)
            piece=dict(schema='r209-checkpoint-piece-v1',claim=97,index=i,count=2,offset=lo,bytes=len(material),
                       sha256=digest,outcome=n,meter_barrier=False)
            cache=dict(id=810+i,key=packets.key(i),ref='refs/heads/'+rescue.owner.BRANCH,
                       version=packets.version('packet'),size_in_bytes=len(material)+4096)
            sidecar=dict(schema='bare-personal-209-private-packet-v1',release=rescue.owner.RELEASE_ID,piece=piece,
                         cache=cache,stage=dict(name=name,id=aid,bytes=len(material),sha256=digest))
            self.sidecars.append(sidecar)
            self.put(aid+1,name+'.json',packets.data(sidecar))
        self.release=dict(id=rescue.owner.RELEASE_ID,author=rescue.owner.OWNER,draft=True,
                          url=f'https://api.github.com/repos/{rescue.owner.REPO}/releases/{rescue.owner.RELEASE_ID}',
                          assets=[])
        self.job=dict(id=901,head_sha=n['producer_sha'],head_branch=rescue.owner.BRANCH,run_id=n['run'],run_attempt=1,
                      name='slot01 / Receive private checkpoint slot 1',status='completed',conclusion='failure',
                      started_at='2026-11-28T01:00:00Z',completed_at='2026-11-28T03:00:00Z')

    def put(self,aid,name,data):
        self.service.put(aid,name,data,self.when)
        self.service.assets[-1]['uploader']=self.bot

    def run_rescue(self):
        s=self.service
        for row in s.assets:
            aid=row['id']
            row.setdefault('url',f'https://api.github.com/repos/{rescue.owner.REPO}/releases/assets/{aid}')
            row.setdefault('updated_at',row['created_at'])
            (self.root/f'{aid}.bin').write_bytes(s.bytes[aid])
        for name,value in [('assets',s.assets),('release',self.release),('run',s.run),('publisher',self.job)]:
            (self.root/(name+'.json')).write_text(json.dumps(value))
        return rescue.take(self.args)

    def test_two_complete_packets_open_to_source_archive_and_replay(self):
        result=self.run_rescue()
        self.assertEqual(result['sha256'],rescue.qc.sha(self.archive))
        self.assertFalse(result['canonical_manifest'])
        self.assertEqual(self.args.out.read_bytes(),self.archive.read_bytes())
        self.assertEqual(self.args.out.stat().st_mode & 0o777,0o600)
        self.assertEqual(self.run_rescue(),result)
        self.args.out.write_bytes(b'different previous recovery')
        with self.assertRaisesRegex(ValueError,'different object'):
            self.run_rescue()
        self.assertEqual(self.args.out.read_bytes(),b'different previous recovery')

    def test_foreign_origin_missing_data_and_wrong_key(self):
        s=self.service
        for obj, changes in [(self.args.__dict__,{'claim_sha':'f'*64}), (self.args.__dict__,{'outcome_id':97}),
                             (self.args.__dict__,{'outcome_sha':'f'*64}), (self.args.__dict__,{'parent_identity':'f'*64}),
                             (self.release,{'id':10}), (self.release,{'draft':False}), (self.release,{'author':self.bot}),
                             (s.run,{'run_attempt':2}), (s.run,{'id':777}), (self.job,{'head_sha':'9'*40}),
                             (self.job,{'status':'in_progress'}),(s.bytes,{310:s.bytes[310][::-1]}),
                             (s.bytes,{s.ticket_id:s.bytes[s.ticket_id]+b' '}),(s.bytes,{s.ack_id:b'{}'})]:
            with self.subTest(changes=list(changes)), patch.dict(obj,changes), self.assertRaises((ValueError,KeyError)):
                self.run_rescue()
            self.assertFalse(self.args.out.exists())
        missing=s.assets.pop()
        with self.assertRaisesRegex(ValueError,'missing or unexpected'):
            self.run_rescue()
        s.assets.append(missing)
        self.put(399,self.stem+'manifest.json',b'{}')
        with self.assertRaisesRegex(ValueError,'canonical publication'):
            self.run_rescue()
        s.assets.pop()
        other=self.root/'disposable-other-identity'
        subprocess.run(['age-keygen','-o',other],capture_output=True,check=True)
        with patch.object(self.args,'age_identity',other), self.assertRaises(subprocess.CalledProcessError):
            self.run_rescue()
        self.assertFalse(self.args.out.exists())

    def test_false_packet_receipt_with_physically_consistent_digest_is_rejected(self):
        s=self.service
        for section, changes in [('cache',{'key':'another-key'}),('cache',{'version':'0'*64}),('cache',{'id':810}),
                                 ('piece',{'index':0}),('piece',{'offset':0}),('piece',{'claim':18}),
                                 ('stage',{'id':310}),('root',{'release':1})]:
            modified=copy.deepcopy(self.sidecars[1])
            (modified if section=='root' else modified[section]).update(changes)
            payload=packets.data(modified)
            row=next(r for r in s.assets if r['id']==313)
            with self.subTest(changes=changes), patch.dict(s.bytes,{313:payload}), \
                    patch.dict(row,size=len(payload),digest='sha256:'+rescue.owner.sha(payload)), self.assertRaises(ValueError):
                self.run_rescue()
            self.assertFalse(self.args.out.exists())
