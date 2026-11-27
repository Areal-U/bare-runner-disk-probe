import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

os.environ.setdefault('RUNNER_TEMP', '/tmp')
import cache_delivery as delivery
from test_terminal_draft import Draft


def sha(data):
    return hashlib.sha256(data).hexdigest()


class CacheDelivery(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.folder = Path(temp.name)
        self.data = b'age-encryption.org/v1\nprivate-fixture-payload'
        self.run, self.slot, self.claim = 9001, 1, 12345
        self.head, self.parent = 'a'*40, 'b'*64
        self.key = f'bare-personal-209-terminal-9001-1-s1-{sha(self.data)}'
        self.ref = 'refs/heads/' + delivery.owner.BRANCH
        self.ctx = dict(run=self.run, attempt=1, ordinal=self.slot, producer_sha=self.head,
                        accepted_parent=self.parent, claim=self.claim)
        self.seal = dict(self.ctx, schema=delivery.owner_apk.SCHEMA, recipient=delivery.owner.RECIPIENT,
                         sha=sha(self.data), bytes=len(self.data))
        self.raw = delivery.owner_apk.encode(self.seal)
        (self.folder/'seal.json').write_bytes(self.raw)
        (self.folder/delivery.owner_apk.CIPHER).write_bytes(self.data)
        self.env = dict(GITHUB_RUN_ID=str(self.run), GITHUB_JOB='deliver-cached-apk', GITHUB_RUN_ATTEMPT='1',
                        GITHUB_REPOSITORY=delivery.owner.REPO, GITHUB_REF=self.ref, GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_ACTOR='Areal-U', GITHUB_SHA=self.head, R28_SLOT='1', R28_PARENT_SHA=self.parent,
                        CLAIM=str(self.claim), REGISTERED_CLAIM=str(self.claim), CACHE_ID='77', CACHE_KEY=self.key,
                        CACHE_MATCH=self.key, CACHE_HIT='true', CIPHER_BYTES=str(len(self.data)),
                        CIPHER_SHA=sha(self.data), SEAL_SHA=sha(self.raw), DELIVERY_LATEST='9999999999')
        self.api = Draft()
        self.enterContext(patch.object(delivery.normal,'list_private',self.api.inventory))
        self.enterContext(patch.object(delivery.normal,'put',self.api.put))
        self.visibility = self.enterContext(patch.object(delivery.normal,'visibility',return_value=(True,{})))

    def test_delivery_and_reconciliation_do_not_change_any_original(self):
        result = delivery.publish(self.folder, self.env, self.api)
        self.assertEqual(result, delivery.publish(self.folder, self.env, self.api))
        self.assertEqual(len(self.api.data),3)
        stem = f'r209-{self.run}-a1-s01-'
        self.assertEqual(self.api.data[stem+'apk-seal.json'], self.raw)
        self.assertEqual(self.api.data[stem+'apk.age'], self.data)
        receipt = json.loads(self.api.data[stem+'apk-owner-receipt.json'])
        self.assertEqual(receipt['origin'], self.ctx)
        self.assertEqual(receipt['destination_commitment'], delivery.owner.DESTINATION_HASH)
        self.assertEqual(receipt['source_cache'], {'id':77,'key':self.key,'ref':self.ref})
        self.assertEqual(result['receipt_sha'],sha(self.api.data[stem+'apk-owner-receipt.json']))
        self.visibility.return_value = (False,{})
        with self.assertRaises(ValueError):
            delivery.publish(self.folder,self.env,self.api)

    def test_worker_and_receiver_identity_or_byte_mismatch_rejects_before_write(self):
        for field,value in [('GITHUB_ACTOR','other'),('GITHUB_REPOSITORY','elsewhere'),('GITHUB_JOB','compile-probe'),
                ('GITHUB_EVENT_NAME','pull_request'),('GITHUB_REF','refs/heads/main'),('GITHUB_RUN_ATTEMPT','2'),
                ('CLAIM','99'),('GITHUB_RUN_ID','9002'),('GITHUB_SHA','d'*40),('R28_PARENT_SHA','d'*64),
                ('R28_SLOT','2'),('CACHE_KEY','other'),('CACHE_ID','0'),('CACHE_HIT','false'),('CACHE_MATCH','other'),
                ('SEAL_SHA','d'*64),('CIPHER_BYTES','4'),('DELIVERY_LATEST','1')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                delivery.publish(self.folder, dict(self.env, **{field:value}), self.api)
        for field,value in [('recipient','other'),('schema','old'),('attempt',True),('sha','d'*64)]:
            raw=delivery.owner_apk.encode(dict(self.seal,**{field:value}))
            (self.folder/'seal.json').write_bytes(raw)
            with self.subTest(seal=field), self.assertRaises(ValueError):
                delivery.publish(self.folder, dict(self.env,SEAL_SHA=sha(raw)), self.api)
        self.assertFalse(self.api.data)

    def test_cache_only_two_files_and_supported_types(self):
        extra = self.folder/'extra'; extra.touch()
        with self.assertRaises(ValueError): delivery.publish(self.folder,self.env,self.api)
        extra.unlink()
        p = self.folder/'seal.json'; p.unlink(); p.symlink_to(self.folder/delivery.owner_apk.CIPHER)
        with self.assertRaises(ValueError): delivery.publish(self.folder,self.env,self.api)
        p.unlink(); p.write_bytes(self.raw)
        cipher = self.folder/delivery.owner_apk.CIPHER
        cipher.write_bytes(b'x'*len(self.data))
        with self.assertRaises(ValueError): delivery.publish(self.folder,self.env,self.api)
        self.assertFalse(self.api.data)

    def test_service_identity_uses_exact_source_job_save_interval_and_full_lists(self):
        cache=dict(key=self.key,ref=self.ref,id=77,size_in_bytes=40,created_at='2026-11-27T12:00:02Z')
        step=dict(name=delivery.SAVE_STEP,conclusion='success',
                  started_at='2026-11-27T12:00:01Z',completed_at='2026-11-27T12:00:03Z')
        job=dict(name='slot01 / Compile APK slot 1',run_id=self.run,run_attempt=1,head_sha=self.head,
                 status='completed',conclusion='success',steps=[step])
        lookup=self.enterContext(patch.object(delivery.artifact_poll,'lookup',return_value=None))
        inventory=self.enterContext(patch.object(delivery.recover,'inventory',return_value=[job]))
        def check(items,count):
            delivery.check_service(self.env,self.ctx,lambda _:dict(actions_caches=items,total_count=count))
        check([cache],1)
        for changes in [dict(id=80),dict(ref='refs/heads/main'),dict(key='wrong'),
                        dict(created_at='2026-11-27T12:00:00Z'),dict(created_at='2026-11-27T12:00:04Z')]:
            with self.subTest(changes=changes), self.assertRaises(ValueError): check([dict(cache,**changes)],1)
        for items,count in [([],0),([cache,cache],2),([cache],2)]:
            with self.assertRaises(ValueError): check(items,count)
        for changes in [dict(run_attempt=2),dict(run_id=9002),dict(head_sha='d'*40),dict(steps=[])]:
            inventory.return_value=[dict(job,**changes)]
            with self.assertRaises(ValueError): check([cache],1)
        inventory.return_value=[job]
        lookup.return_value={'id':124}
        with self.assertRaises(ValueError): check([cache],1)


if __name__=='__main__':
    unittest.main()
