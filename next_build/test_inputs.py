import json
from pathlib import Path
import unittest
from unittest.mock import patch

import inputs
from recover import ChainStart, S2_SHA
import test_owner_snapshot


class CampaignRoutingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_owner_snapshot.SnapshotTest()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def read(self, first='completed', latest='completed', *, attempt=1, head=None):
        f = self.fixture
        base = f'actions/runs/{f.run}'
        original = f.metadata[base+'/attempts/1']
        original['status'] = first
        f.metadata[base] = dict(original, status=latest, run_attempt=attempt, head_sha=head or f.head)
        f.write()
        return inputs.campaign(f.locator, inputs.OwnerSnapshot(f.root, f.helper))

    def test_capture_with_existing_terminal_cipher_routes_to_collector(self):
        self.fixture.delivery()
        r = self.read()
        self.assertEqual(r['disposition'], 'collect-and-verify-owner-delivery')
        self.assertFalse(r['build_dispatch'])

    def test_in_progress_and_manual_readback_stay_with_existing_operation(self):
        self.assertEqual(self.read('in_progress','in_progress')['disposition'],'existing-operation-active')
        r = self.read('completed','in_progress', attempt=2)
        self.assertEqual((r['disposition'],r['first_attempt'],r['latest_attempt']),('existing-operation-active',1,2))

    def test_wrong_locator_or_current_head_stops(self):
        with self.assertRaises(ValueError):
            self.read(head='d'*40)
        self.fixture.locator['owner_destination_id'] = 'wrong'
        with self.assertRaises(ValueError):
            self.read()

    def test_missing_or_lost_output_cannot_authorize_s2_replay(self):
        self.assertEqual(self.read()['disposition'], 'reconcile-original-transfer-or-confirm-loss')
        r=inputs.outcome([dict(ordinal=1,producer_sha='a'*40,accepted_parent=S2_SHA,status='relay-ambiguous')],77,'a'*40,ChainStart())
        self.assertEqual(r['disposition'],'reconcile-original-transfer-or-confirm-loss')

    def test_only_last_independent_receipt_selects_latest_parent(self):
        head='a'*40
        records=[]
        parent=S2_SHA
        for ordinal in range(1,13):
            child=f'{ordinal:064x}'
            records.append(dict(ordinal=ordinal, accepted_parent=parent,status='candidate',producer_sha=head,
                         sha=child,identity='c'*64,key=f'bare-coexist-204-77-1-checkpoint-production-s{ordinal}',
                         manifest_id=str(ordinal),manifest_sha='d'*64))
            parent=child
        r=inputs.outcome(records,77,head,ChainStart())
        self.assertNotIn('reviewed_parent',r)
        records.append(dict(ordinal=13,accepted_parent=parent,status='limit-verified',producer_sha=head,sha=parent))
        r=inputs.outcome(records,77,head,ChainStart())
        self.assertEqual(r['reviewed_parent']['sha'],parent)
        records[-2]['manifest_id']=''
        with self.assertRaises(ValueError):
            inputs.outcome(records,77,head,ChainStart())
        records[-1]['accepted_parent']=S2_SHA
        with self.assertRaises(ValueError):
            inputs.outcome(records,77,head,ChainStart())

    def test_foreign_owner_publication_cannot_short_circuit(self):
        d=self.fixture.root
        for filename, doc in [('owner.json',{'owner_destination_id':'other'}),('listing.json',{}),('publication.json',{})]:
            (d/filename).write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            inputs.delivered(self.fixture.locator,d,Path('unused'),Path('unused'))

    def test_ambiguous_or_short_source_pin_rejected(self):
        for oid in ('main','v2.0.4','deadbeef'):
            with self.assertRaises(ValueError):
                inputs.exact(Path('.'),oid)


if __name__ == '__main__':
    unittest.main()
