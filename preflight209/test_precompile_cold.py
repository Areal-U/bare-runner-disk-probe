import copy
from datetime import timedelta
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

os.environ.setdefault('RUNNER_TEMP', '/tmp')
import campaign
import owner
import precompile_cold as cold
from test_owner import Service


FIXED = json.loads(Path(__file__).with_name('precompile-45996971462.json').read_text())


class ServiceWithOrigin(Service):
    def __init__(self):
        super().__init__()
        self.old = copy.deepcopy(FIXED['run'])
        self.jobs = dict(total_count=18, jobs=[
            dict(row, head_sha=self.old['head_sha'], run_id=self.old['id'], run_attempt=1, status='completed')
            for row in copy.deepcopy(FIXED['jobs'])])
        self.prior_artifacts = copy.deepcopy(FIXED['artifacts'])
        self.negative_cache = dict(total_count=0, actions_caches=[])
        self.origin_claim = 1100
        self.genesis = campaign.digest(Path(campaign.__file__).with_name('upstream-lock.json'))
        self.ack['genesis'] = self.ticket['genesis'] = self.genesis
        self.ack['head'] = self.ticket['head'] = cold.HEAD
        self.ack['observed_at'] = '2026-11-27T11:00:00Z'
        self.deposit()
        for row in self.assets:
            row['created_at'] = '2026-11-27T12:00:00Z'
        prior = dict(schema=1, campaign=owner.CAMPAIGN, repository_id=owner.REPO_ID, release_id=owner.RELEASE_ID,
                     branch=owner.BRANCH, workflow=owner.WORKFLOW, origin_run=cold.RUN, producer_attempt=1,
                     head=cold.HEAD, genesis=self.genesis, ticket_asset_id=self.ticket_id,
                     ticket_sha=owner.sha(self.bytes[self.ticket_id]), collector_ack_asset_id=self.ack_id,
                     collector_ack_sha=owner.sha(self.bytes[self.ack_id]),
                     collector_registration_id=self.ack['collector_registration_id'],
                     recipient=owner.RECIPIENT, destination_commitment=owner.sha(owner.encode(self.dest)))
        self.put(self.origin_claim, owner.CLAIM, owner.encode(prior), '2026-11-27T12:15:00Z')
        self.assets[-1]['uploader'] = {'login':'github-actions[bot]', 'id':41898282}
        self.proof = dict(claim_asset_id=self.origin_claim, claim_sha256=owner.sha(self.bytes[self.origin_claim]),
                          ledger_sha256=cold.CLOSED_LEDGER_SHA256, ledger_state='closed-no-apk',
                          intermediate_outcome_pickup=True)
        self.nonce = 'c' * 40
        self.ack_id, self.ticket_id = 1200, 1201
        for record in (self.ticket, self.ack):
            record.update(genesis=self.genesis, head=self.run['head_sha'], resume=cold.SELECTOR.copy(),
                          collector_registration_id='Automation_' + '9'*32, registration_nonce=self.nonce,
                          precompile_origin=copy.deepcopy(self.proof))
        self.ack['observed_at'] = '2026-11-27T13:00:00Z'
        self.ticket['issued_at'] = '2026-11-27T13:00:01Z'

    def metadata(self, path):
        path_only = urlsplit(path).path
        if path_only.endswith('/actions/runs/' + str(cold.RUN)):
            return self.old
        if path_only.endswith(f'/actions/runs/{cold.RUN}/attempts/1/jobs'):
            return self.jobs
        if path_only.endswith('/actions/caches'):
            return self.negative_cache
        return super().metadata(path)


class PrecompileCold(unittest.TestCase):
    def setUp(self):
        self.s = ServiceWithOrigin()
        self.env = dict(GITHUB_REPOSITORY=owner.REPO, GITHUB_REF='refs/heads/' + owner.BRANCH,
                        GITHUB_RUN_ATTEMPT='1', GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_RUN_ID=str(self.s.run['id']), GITHUB_SHA=self.s.run['head_sha'],
                        GITHUB_ACTOR=owner.OWNER['login'], RUNNER_ENVIRONMENT='github-hosted')
        self.event = dict(sender=owner.OWNER, repository={'id':owner.REPO_ID},
                          inputs=dict(mode='build-apk', resume=json.dumps(cold.SELECTOR)))
        self.enterContext(patch.object(owner, 'DESTINATION_HASH', owner.sha(owner.encode(self.s.dest))))
        # Private production references are not test fixtures. Bind the
        # synthetic pair independently, as the closed owner ledger does.
        self.enterContext(patch.object(cold, 'ORIGIN_CLAIM_COMMITMENT',
                                       cold.claim_commitment(self.s.origin_claim, self.s.proof['claim_sha256'])))
        self.now = owner.instant(self.s.run['created_at']) + timedelta(seconds=20)

    def bind(self, *, lease=False):
        return owner.bind(owner.PagedOwnerDraft(self.s), self.env, self.event, 'lookup',
                          owner.sha(self.s.bytes[self.s.ticket_id]), self.s.genesis,
                          verify_only=lease, clock=lambda: self.now)

    def test_fresh_ticket_bound_once_through_normal_entry(self):
        with patch.dict(os.environ, dict(self.env, R209_RESUME=self.event['inputs']['resume'])), \
                patch.object(campaign.n.b, 'output') as out:
            campaign.start()
        out.assert_called_once_with(ordinal=1, parent=self.s.genesis, parent_identity=self.s.genesis,
                                    genesis=self.s.genesis, origin='', manifest='', manifest_sha='')
        self.s.deposit()
        old_claim = self.s.bytes[self.s.origin_claim]
        bound = self.bind()
        self.assertEqual(self.bind(lease=True), bound)
        self.assertEqual(self.bind(), bound)
        self.assertEqual(old_claim, self.s.bytes[self.s.origin_claim])
        self.assertEqual(self.s.posts, 1)
        payload = json.loads(self.s.bytes[bound['claim']])
        self.assertEqual(payload['prior_claim_asset_id'], self.s.origin_claim)
        self.assertEqual(payload['resume'], cold.SELECTOR)
        self.s.run['id'] += 1
        self.env['GITHUB_RUN_ID'] = str(self.s.run['id'])
        with self.assertRaises(ValueError):
            self.bind()
        self.assertEqual(self.s.posts, 1)

    def test_origin_and_receipt_negatives_before_claim(self):
        self.s.deposit()
        worker = next(j for j in self.s.jobs['jobs'] if j['id'] == cold.WORKER)
        compile_step = next(s for s in worker['steps'] if s['number'] == 14)
        for obj, fields in (
            (self.s.old, {'head_sha':self.s.run['head_sha']}), (self.s.old, {'run_attempt':2}),
            (self.s.old, {'conclusion':'success'}), (self.s.jobs, {'total_count':17}),
            (worker, {'id':171}), (compile_step, {'conclusion':'success'}),
            (next(a for a in self.s.assets if a['id'] == self.s.origin_claim),
             {'uploader': {'login':'github-actions[bot]', 'id':17}}),
            (next(a for a in self.s.assets if a['id'] == self.s.ack_id),
             {'uploader': {'login':'github-actions[bot]', 'id':41898282}}),
            (self.s.prior_artifacts[0], {'digest':'sha256:' + '0'*64}),
            (self.s.negative_cache, {'total_count':1})):
            with self.subTest(fields=fields), patch.dict(obj, fields), self.assertRaises(ValueError):
                self.bind()
        for collection, item in ((self.s.prior_artifacts, dict(self.s.prior_artifacts[0], id=1300,
                                                               name=f'r209-{cold.RUN}-a1-s01-outcome')),
                                 (self.s.assets, {'id':1301, 'name':f'r209-{cold.RUN}-a1-s01-part-001'})):
            collection.append(item)
            with self.assertRaises(ValueError):
                self.bind()
            collection.pop()
        self.s.prior_artifacts = []
        with self.assertRaisesRegex(ValueError, 'before expiry'):
            self.bind()
        self.assertEqual(self.s.posts, 0)
        self.now = owner.instant('2026-11-29T00:00:00Z')
        self.assertGreater(self.bind()['claim'], self.s.origin_claim)

    def test_independent_owner_proof(self):
        for field, invalid in [('claim_asset_id',2), ('claim_sha256','a'*64), ('ledger_state','open'),
                               ('ledger_sha256',''), ('ledger_sha256','e'*64), ('intermediate_outcome_pickup',False)]:
            with self.subTest(field=field):
                self.s = ServiceWithOrigin()
                for record in (self.s.ticket, self.s.ack):
                    record['precompile_origin'][field] = invalid
                self.s.deposit()
                with self.assertRaises(ValueError):
                    self.bind()
                self.assertEqual(self.s.posts, 0)
        self.s = ServiceWithOrigin()
        self.s.ack['observed_at'] = '2026-11-27T11:59:00Z'
        self.s.deposit()
        with self.assertRaises(ValueError):
            self.bind()

    def test_matching_replacement_claim_in_release_and_both_documents(self):
        for change_id, change_bytes in ((True, False), (False, True), (True, True)):
            with self.subTest(change_id=change_id, change_bytes=change_bytes):
                self.s = ServiceWithOrigin()
                original = next(a for a in self.s.assets if a['id'] == self.s.origin_claim)
                body = self.s.bytes.pop(self.s.origin_claim)
                new_id = self.s.origin_claim + int(change_id)
                if change_bytes:
                    body += b' '
                original.update(id=new_id, size=len(body), digest='sha256:' + owner.sha(body))
                self.s.bytes[new_id] = body
                for doc in (self.s.ticket, self.s.ack):
                    doc['precompile_origin'].update(claim_asset_id=new_id, claim_sha256=owner.sha(body))
                self.s.deposit()
                with self.assertRaisesRegex(ValueError, 'original claim'):
                    self.bind()
                self.assertEqual(self.s.posts, 0)

    def test_fixed_selector(self):
        for bad in ('null','[]','{"kind":"precompile-cold","origin_run":6}',
                    '{"kind":"other","origin_run":45996971462}',
                    '{"kind":"precompile-cold","origin_run":1,"origin_run":45996971462}',
                    '{"kind":"precompile-cold","origin_run":45996971462,"ordinal":1}'):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                owner.resume_input({'inputs':{'resume':bad}})


if __name__ == '__main__':
    unittest.main()
