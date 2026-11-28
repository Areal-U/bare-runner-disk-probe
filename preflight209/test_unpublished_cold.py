"""Recreate admission and slot-one selection after the independently closed publication loss."""
from datetime import timedelta
import json
import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from test_precompile_cold import ServiceWithOrigin, campaign, cold, owner
import unpublished_cold as failure


class UnpublishedService(ServiceWithOrigin):
    def __init__(self):
        super().__init__()
        self.checkpoint_run = dict(failure.ORIGIN['run'], actor=owner.OWNER,
                                   repository={'id': owner.REPO_ID}, head_repository={'id': owner.REPO_ID},
                                   head_commit={'tree_id': failure.ORIGIN['tree'], 'id': failure.HEAD})
        self.checkpoint_jobs = {'total_count': 18, 'jobs': []}
        for source in failure.ORIGIN['jobs']:
            row = dict(source, run_id=failure.RUN, run_attempt=1, head_sha=failure.HEAD, status='completed')
            row['steps'] = [dict(number=n, name=name, conclusion=result) for n, name, result in row['steps']]
            self.checkpoint_jobs['jobs'].append(row)
        origin = dict(id=failure.RUN, head_sha=failure.HEAD, head_branch=owner.BRANCH,
                      repository_id=owner.REPO_ID, head_repository_id=owner.REPO_ID)
        self.controls = [dict(row, expired=False, workflow_run=origin) for row in failure.ORIGIN['artifacts']]
        self.cache_key = None
        self.run['created_at'] = '2026-11-28T06:30:00Z'
        self.ack['head'] = self.ticket['head'] = failure.HEAD
        self.deposit()
        self.previous_claim_id = 1300
        doc = dict(schema=1, campaign=owner.CAMPAIGN, repository_id=owner.REPO_ID, release_id=owner.RELEASE_ID,
                   branch=owner.BRANCH, workflow=owner.WORKFLOW, origin_run=failure.RUN, producer_attempt=1,
                   head=failure.HEAD, genesis=self.genesis, ticket_asset_id=self.ticket_id,
                   ticket_sha=owner.sha(self.bytes[self.ticket_id]), collector_ack_asset_id=self.ack_id,
                   collector_ack_sha=owner.sha(self.bytes[self.ack_id]), prior_claim_asset_id=self.origin_claim,
                   resume=cold.SELECTOR.copy(), collector_registration_id=self.ack['collector_registration_id'],
                   recipient=owner.RECIPIENT, destination_commitment=owner.sha(owner.encode(self.dest)))
        self.put(self.previous_claim_id, f'{owner.CAMPAIGN}-after-{cold.RUN}-claim.json', owner.encode(doc),
                 '2026-11-28T01:14:24Z')
        self.assets[-1]['uploader'] = dict(id=41898282, login='github-actions[bot]')
        self.closed_proof = dict(claim_asset_id=self.previous_claim_id, claim_sha256=owner.sha(owner.encode(doc)),
                                 ledger_sha256=failure.CLOSED_LEDGER_SHA256, ledger_state='closed-no-apk',
                                 intermediate_outcome_pickup=True)
        self.nonce = 'd' * 40
        self.ack_id, self.ticket_id = 1400, 1401
        for record in (self.ticket, self.ack):
            del record['precompile_origin']
            record.update(head=self.run['head_sha'], resume=failure.SELECTOR.copy(), registration_nonce=self.nonce,
                          collector_registration_id='Automation_' + '7' * 32,
                          unpublished_origin=self.closed_proof.copy())
        self.ack['observed_at'] = '2026-11-28T06:00:00Z'
        self.ticket['issued_at'] = '2026-11-28T06:01:00Z'

    def metadata(self, path):
        url = urlsplit(path)
        prefix = f'{self.BASE}/actions/runs/{failure.RUN}'
        if url.path == prefix:
            return self.checkpoint_run
        if url.path == prefix + '/attempts/1/jobs':
            return self.checkpoint_jobs
        if url.path == prefix + '/artifacts':
            return dict(total_count=len(self.controls), artifacts=self.controls)
        if url.path.endswith('/actions/caches') and parse_qs(url.query)['key'][0] == self.cache_key:
            return dict(total_count=1, actions_caches=[])
        return super().metadata(path)


class UnpublishedRecovery(unittest.TestCase):
    def setUp(self):
        self.s = UnpublishedService()
        self.enterContext(patch.object(owner, 'DESTINATION_HASH', owner.sha(owner.encode(self.s.dest))))
        self.enterContext(patch.object(cold, 'ORIGIN_CLAIM_COMMITMENT',
                                      cold.claim_commitment(self.s.origin_claim, self.s.proof['claim_sha256'])))
        self.enterContext(patch.object(failure, 'CLAIM_COMMITMENT',
                                      cold.claim_commitment(self.s.previous_claim_id, self.s.closed_proof['claim_sha256'])))
        self.env = dict(GITHUB_REPOSITORY=owner.REPO, GITHUB_REF='refs/heads/' + owner.BRANCH,
                        GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_ACTOR=owner.OWNER['login'],
                        GITHUB_RUN_ID=str(self.s.run['id']), GITHUB_SHA=self.s.run['head_sha'],
                        RUNNER_ENVIRONMENT='github-hosted')
        self.event = dict(sender=owner.OWNER, repository={'id':owner.REPO_ID},
                          inputs=dict(mode='build-apk', resume=json.dumps(failure.SELECTOR)))
        self.now = owner.instant(self.s.run['created_at']) + timedelta(seconds=30)

    def bind(self, lease=False):
        return owner.bind(owner.PagedOwnerDraft(self.s), self.env, self.event, 'lookup',
                          owner.sha(self.s.bytes[self.s.ticket_id]), self.s.genesis,
                          verify_only=lease, clock=lambda: self.now)

    def test_normal_cold_start_unique_claim_and_read_only_lease(self):
        with patch.dict(os.environ, dict(self.env, R209_RESUME=self.event['inputs']['resume'])), \
                patch.object(campaign.n.b, 'output') as output:
            campaign.start()
        output.assert_called_once_with(ordinal=1, parent=self.s.genesis, parent_identity=self.s.genesis,
                                       genesis=self.s.genesis, origin='', manifest='', manifest_sha='')
        self.s.deposit()
        before = self.s.bytes.copy()
        with self.assertRaisesRegex(ValueError, 'No first-attempt'):
            self.bind(lease=True)
        accepted = self.bind()
        self.assertEqual(self.bind(lease=True), accepted)
        self.assertEqual(self.bind(), accepted)
        claim = json.loads(self.s.bytes[accepted['claim']])
        self.assertEqual(claim['prior_claim_asset_id'], self.s.previous_claim_id)
        self.assertEqual(claim['resume'], failure.SELECTOR)
        self.assertTrue(all(self.s.bytes[k] == v for k, v in before.items()))
        self.s.run['id'] += 1
        self.env['GITHUB_RUN_ID'] = str(self.s.run['id'])
        with self.assertRaises(ValueError):
            self.bind()
        self.assertEqual(self.s.posts, 1)

    def test_missing_certification_or_recoverable_payload_blocks_reissue(self):
        self.s.deposit()
        receiver = next(j for j in self.s.checkpoint_jobs['jobs'] if j['id'] == 140815176684)
        gate = next(step for step in receiver['steps'] if step['number'] == 14)
        for where, diff in [(self.s.checkpoint_run, {'run_attempt':2}), (self.s.checkpoint_run, {'conclusion':'success'}),
                            (self.s.checkpoint_run['head_commit'], {'tree_id':'0'*40}), (gate, {'conclusion':'success'}),
                            (self.s.checkpoint_jobs, {'total_count':17}), (self.s.controls[0], {'id':1}),
                            (self.s.controls[0], {'name':f'r209-{failure.RUN}-a1-s01-outcome'}),
                            (self.s.controls[0]['workflow_run'], {'head_repository_id':1})]:
            with self.subTest(diff=diff), patch.dict(where, diff), self.assertRaises(ValueError):
                self.bind()
        for prefix in [f'r209-{failure.RUN}-', f'bare-personal-209-{failure.RUN}-',
                       f'bare-personal-209-terminal-{failure.RUN}-']:
            self.s.cache_key = prefix
            with self.assertRaisesRegex(ValueError, 'cache'):
                self.bind()
            self.s.cache_key = None
            self.s.assets.append(dict(id=9000, name=prefix+'checkpoint-part'))
            with self.assertRaisesRegex(ValueError, 'Private material'):
                self.bind()
            self.s.assets.pop()
        self.s.controls.pop()
        with self.assertRaisesRegex(ValueError, 'before expiry'):
            self.bind()
        self.assertEqual(self.s.posts, 0)
        self.s.controls.clear()
        self.now = owner.instant('2026-11-29T03:00:00Z')
        self.assertIn('claim', self.bind())

    def test_identical_fake_owner_receipts_and_changed_prior_bytes_rejected(self):
        for field, bad in [('ledger_sha256','0'*64), ('claim_asset_id',712), ('claim_sha256','1'*64),
                           ('ledger_state','open'), ('intermediate_outcome_pickup',False)]:
            with self.subTest(field=field):
                self.s = UnpublishedService()
                for record in (self.s.ack,self.s.ticket):
                    record['unpublished_origin'][field] = bad
                self.s.deposit()
                with self.assertRaises(ValueError):
                    self.bind()
                self.assertEqual(self.s.posts, 0)
        self.s = UnpublishedService()
        self.s.deposit()
        for target in [self.s.previous_claim_id, self.s.origin_claim, 1000,1001,1200,1201]:
            with self.subTest(id=target), patch.dict(self.s.bytes, {target: self.s.bytes[target]+b' '}), \
                    self.assertRaises(ValueError):
                self.bind()
        self.assertEqual(self.s.posts, 0)

    def test_cannot_reuse_any_closed_collector(self):
        for prior_id in (1001, 1201):
            with self.subTest(prior=prior_id):
                self.s = UnpublishedService()
                registration = json.loads(self.s.bytes[prior_id])['collector_registration_id']
                for record in (self.s.ack, self.s.ticket):
                    record['collector_registration_id'] = registration
                self.s.deposit()
                with self.assertRaises(ValueError):
                    self.bind()
                self.assertEqual(self.s.posts, 0)

    def test_selector_excludes_the_other_origin_and_checkpoint_fields(self):
        for value in [dict(failure.SELECTOR, origin_run=cold.RUN), dict(cold.SELECTOR, origin_run=failure.RUN),
                      dict(failure.SELECTOR, ordinal=1), dict(failure.SELECTOR, origin_run=str(failure.RUN))]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                cold.parse_selector(json.dumps(value))
