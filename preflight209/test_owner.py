import json
from datetime import datetime, timezone, timedelta
from urllib.parse import parse_qs, urlsplit
import unittest
from unittest.mock import patch

import owner


class Service:
    BASE = owner.storage.BASE
    UPLOAD = 'uploads.github.com'

    def __init__(self):
        self.prior = {}
        self.prior_artifacts = []
        self.sealed_caches = []
        self.run = {'id': 118, 'run_attempt': 1, 'head_branch': owner.BRANCH, 'head_sha': '4' * 40,
                    'path': owner.WORKFLOW, 'event': 'workflow_dispatch', 'actor': owner.OWNER,
                    'repository': {'id': owner.REPO_ID}, 'head_repository': {'id': owner.REPO_ID},
                    'created_at': '2026-11-28T00:00:00Z'}
        self.assets, self.bytes, self.posts = [], {}, 0
        self.ack_id, self.ticket_id = 1000, 1001
        self.count = 0
        self.nonce = 'a' * 40
        self.dest = {'apk': 'sample-final', 'cipher': 'sample-cipher', 'ledger': 'sample-ledger'}
        common = dict(schema=1, campaign=owner.CAMPAIGN, repository_id=owner.REPO_ID, release_id=owner.RELEASE_ID,
                      workflow=owner.WORKFLOW, branch=owner.BRANCH, head=self.run['head_sha'], genesis='f' * 64,
                      bare_revision=owner.UPSTREAM, version_name=owner.VERSION, version_code=802000915,
                      package='org.barebrowser.personal', abi='arm64-v8a', recipient=owner.RECIPIENT,
                      final_certificate_sha256=owner.CERT, artifact_ceiling_bytes=owner.CEILING,
                      storage_policy=owner.storage.POLICY, resume=None, destinations=self.dest, registration_nonce=self.nonce,
                      collector_registration_id='Automation_' + '3' * 32, expires_at='2026-12-04T09:00:00Z',
                      storage_valid_until='2027-01-04T09:00:00Z')
        self.ack = dict(common, state='collector-read-back-owner-reservation', observed_at='2026-11-27T10:00:00Z',
                        valid_until='2026-12-04T09:00:00Z', poll_seconds=3600, pickup_retry_seconds=3600)
        self.ticket = dict(common, issued_at='2026-11-27T12:00:00Z', collector_ack_asset_id=1000)

    def put(self, aid, name, data, created='2026-11-27T20:00:00Z'):
        self.assets.append(dict(id=aid, name=name, size=len(data), state='uploaded', created_at=created,
                                uploader=owner.OWNER, digest='sha256:' + owner.sha(data)))
        self.bytes[aid] = data

    def deposit(self):
        self.put(self.ack_id, 'bare-personal-209-ack-' + self.nonce + '.json', owner.encode(self.ack))
        self.ticket['collector_ack_sha'] = owner.sha(self.bytes[self.ack_id])
        suffix = f"-after-{self.ticket['resume']['origin_run']}" if self.ticket['resume'] else ''
        self.ticket['collector_ack_asset_id'] = self.ack_id
        self.put(self.ticket_id, f'bare-personal-209-{self.ticket["head"]}{suffix}-ticket.json', owner.encode(self.ticket))

    def draft(self, rid):
        assert rid == owner.RELEASE_ID
        return {'assets': self.assets.copy()}

    def metadata(self, path):
        q = urlsplit(path)
        if path == self.BASE:
            return dict(id=owner.REPO_ID, full_name=owner.REPO, fork=False, private=False, visibility='public')
        if '/releases/' in q.path:
            return self.assets.copy()
        if q.path.endswith('/attempts/1'):
            return self.prior.get(int(q.path.split('/')[-3]),self.run)
        if q.path.endswith('/actions/caches'):
            return {'total_count':len(self.sealed_caches),'actions_caches':self.sealed_caches}
        if q.path.endswith('/actions/runs'):
            return {'total_count': 0, 'workflow_runs': []}
        if '/actions/runs/' in q.path and q.path.endswith('/artifacts'):
            return {'total_count':len(self.prior_artifacts),'artifacts':self.prior_artifacts}
        if q.path.endswith('/actions/artifacts'):
            return {'total_count': self.count, 'artifacts': []}
        raise AssertionError(path)

    def asset_info(self, release, name, size, digest, aid=None):
        r, = [r for r in release['assets'] if r['name'] == name]
        owner.require(r['state'] == 'uploaded' and r['size'] == size and r['digest'] == 'sha256:'+digest and
                      (aid is None or r['id'] == aid), 'Foreign immutable record')
        return r

    def download(self, aid, size, digest, out):
        out.write(self.bytes[aid])

    def request(self, host, method, path, **kwargs):
        assert host == self.UPLOAD and method == 'POST' and kwargs['auth']
        self.posts += 1
        name, = parse_qs(urlsplit(path).query)['name']
        self.put(2000+self.posts, name, kwargs['body'])
        raise ConnectionResetError('test: service accepted write, reply was lost')


class Owner(unittest.TestCase):
    def setUp(self):
        self.sleep = self.enterContext(patch.object(owner.time, 'sleep'))
        self.s = Service()
        self.expected = owner.sha(owner.encode(self.s.dest))
        self.env = dict(GITHUB_REPOSITORY=owner.REPO, GITHUB_REF='refs/heads/'+owner.BRANCH, GITHUB_RUN_ATTEMPT='1',
                        GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_RUN_ID='118', GITHUB_SHA='4'*40,
                        RUNNER_ENVIRONMENT='github-hosted')
        self.event = dict(sender=owner.OWNER, repository={'id': owner.REPO_ID}, inputs={'mode':'build-apk'})
        self.now = datetime(2026,11,28,0,0,30,tzinfo=timezone.utc)

    def call(self, lease=False, genesis='f'*64, ticket=None, delivery=False):
        with patch.object(owner, 'DESTINATION_HASH', self.expected):
            return owner.bind(owner.PagedOwnerDraft(self.s), self.env, self.event, self.s.ticket_id if ticket is None else ticket, owner.sha(self.s.bytes[self.s.ticket_id]),
                              genesis, verify_only=lease, terminal_delivery=delivery, clock=lambda: self.now)

    def test_happy_with_lost_reply_and_repeat(self):
        self.s.deposit()
        with self.assertRaisesRegex(ValueError,'No first-attempt'):
            self.call(lease=True)
        first = self.call()
        self.assertEqual(first, self.call(lease=True))
        self.assertEqual(first, self.call())
        self.assertEqual(self.s.posts, 1)
        self.s.run['id'] = 119; self.env['GITHUB_RUN_ID'] = '119'
        with self.assertRaises(ValueError): self.call()
        self.assertEqual(self.s.posts, 1)

    def test_unique_private_read_with_digest_resolves_ids(self):
        self.s.ticket['collector_ack_asset_id'] = 'lookup'
        self.s.deposit()
        self.s.ticket['collector_ack_asset_id'] = 'lookup'
        buf = owner.encode(self.s.ticket)
        self.s.bytes[1001] = buf
        self.s.assets[1].update(size=len(buf),digest='sha256:' + owner.sha(buf))
        result = self.call(ticket='lookup')
        self.assertEqual((result['ticket_asset_id'], result['collector_ack_asset_id']), (1001,1000))
        self.assertEqual(self.call(lease=True), result)
        with self.assertRaises(ValueError): self.call(lease=True, ticket=1009)
        self.s.assets.append(dict(self.s.assets[1],id=1009))
        with self.assertRaisesRegex(ValueError, 'duplicate'): self.call(lease=True,ticket='lookup')
        self.assertEqual(self.s.posts,1)

    def test_encrypted_delivery_is_read_only_and_needs_its_own_window(self):
        self.s.deposit()
        with self.assertRaisesRegex(ValueError, 'only read'): self.call(delivery=True)
        with self.assertRaisesRegex(ValueError, 'No first-attempt'): self.call(lease=True,delivery=True)
        first = self.call()
        self.now = datetime(2026,12,4,1,20,tzinfo=timezone.utc)
        with self.assertRaisesRegex(ValueError,'coverage'): self.call(lease=True)
        self.s.count = 5  # A fresh Actions Artifact slot is irrelevant to a sealed direct Draft transfer.
        receipt = self.call(lease=True,delivery=True)
        self.assertEqual(first['claim'],receipt['claim'])
        self.assertEqual(receipt['latest_start']-first['latest_start'],owner.SEGMENT)
        self.assertEqual(self.s.posts,1)
        self.now += timedelta(hours=6)
        with self.assertRaisesRegex(ValueError,'coverage'): self.call(lease=True,delivery=True)

    def test_changed_evidence(self):
        edits = [('version_code',802000415),('bare_revision','3'*40),('branch','bare-coexist-v2.0.4'),
                 ('final_certificate_sha256','9'*64),('recipient','other-receiver'),('genesis','1'*64),
                 ('artifact_ceiling_bytes',owner.CEILING+1),('destinations',{'apk':'other'})]
        for k,v in edits:
            for both in (False,True):
                with self.subTest(k=k,both=both):
                    self.setUp(); self.s.ack[k]=v
                    if both: self.s.ticket[k]=v
                    self.s.deposit()
                    with self.assertRaises(ValueError): self.call()
                    self.assertEqual(self.s.posts,0)

    def test_stale_after_wait(self):
        self.s.deposit();self.now+=timedelta(days=7)
        with self.assertRaisesRegex(ValueError,'coverage'): self.call()
        self.assertEqual(self.s.posts,0)

    def test_inventory_settling_before_claim(self):
        self.s.deposit()
        self.s.count=1
        self.sleep.side_effect = lambda _: setattr(self.s,'count',0)
        self.call()
        self.assertEqual(self.s.posts,1)
        self.sleep.assert_called_once_with(8)

    def test_incomplete_aggregate_and_tampering(self):
        self.s.deposit();self.s.count=1
        with self.assertRaisesRegex(ValueError,'Incomplete'): self.call()
        self.s.count=0; self.s.bytes[1000]+=b' '
        with self.assertRaisesRegex(ValueError,'bytes'): self.call()
        self.assertEqual(self.s.posts,0)

    def test_new_ticket_for_physical_continuation(self):
        self.s.deposit()
        original = self.call()
        self.s.prior[118] = dict(self.s.run, status='completed', conclusion='failure', updated_at='2026-11-28T00:00:12Z')
        self.env['GITHUB_RUN_ID'] = '119'
        self.s.run = dict(self.s.run, id=119, created_at='2026-11-28T00:00:18Z')
        resume = dict(origin_run=118, ordinal=1, manifest_id=9000, manifest_sha='b'*64)
        self.event['inputs']['resume'] = json.dumps(resume)
        self.s.ticket['resume'] = self.s.ack['resume'] = resume
        self.s.ack_id, self.s.ticket_id = 1010, 1011
        self.s.nonce = self.s.ack['registration_nonce'] = self.s.ticket['registration_nonce'] = 'd'*40
        self.s.deposit()
        for key, value in [('conclusion', 'success'), ('status', 'in_progress'), ('head_sha', 'a'*40)]:
            prior = self.s.prior[118]
            with self.subTest(k=key), patch.dict(prior, {key:value}), self.assertRaises(ValueError): self.call()
        with patch.dict(self.event['inputs'], {'resume': json.dumps(dict(resume,ordinal=2))}), self.assertRaises(ValueError):
            self.call()
        saved = dict(id=181, size_in_bytes=10000, expires_at='2026-12-01T00:00:00Z', expired=False,
                     name='bare-personal-209-owner-118-a1-s2')
        self.s.prior_artifacts = [saved]
        with self.assertRaisesRegex(ValueError,'Prior encrypted'): self.call()
        self.s.prior_artifacts.clear()
        partial = dict(id=7002,name='r209-118-a1-s02-apk.age-retry1')
        self.s.assets.append(partial)
        with self.assertRaisesRegex(ValueError,'private terminal'): self.call()
        self.s.assets.pop()
        self.s.sealed_caches = [dict(id=884, key='bare-personal-209-terminal-118-1-s2-'+'f'*64,
                                    ref=self.env['GITHUB_REF'])]
        with self.assertRaisesRegex(ValueError,'sealed cache'): self.call()
        self.s.sealed_caches.clear()
        resumed = self.call()
        self.assertNotEqual(original['claim'], resumed['claim'])
        self.assertEqual(resumed, self.call(lease=True))
        self.assertEqual(self.s.posts, 2)
        self.s.run = dict(self.s.run, id=120)
        self.env['GITHUB_RUN_ID'] = '120'
        with self.assertRaises(ValueError): self.call()
        self.assertEqual(self.s.posts, 2)

    def test_later_logical_slots_need_a_prior_physical_generation(self):
        for ordinal, valid in ((12,True), (98,True), (99,False), (100,False), (0,False)):
            with self.subTest(ordinal=ordinal):
                r=dict(origin_run=118,ordinal=ordinal,manifest_id=1101,manifest_sha='e'*64)
                event={'inputs':{'resume':json.dumps(r)}}
                if valid: self.assertEqual(owner.resume_input(event),r)
                else:
                    with self.assertRaises(ValueError): owner.resume_input(event)

    def test_wrong_origin_attempt(self):
        self.s.deposit(); self.s.run['run_attempt']=2
        with self.assertRaisesRegex(ValueError,'Foreign physical'): self.call()


if __name__ == '__main__':
    unittest.main()
