"""Exercise the production APK resolution, cache receipt, peer stop and certificate entries."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import zipfile
from urllib.parse import parse_qs, urlsplit

import yaml

import test_outcome_transport as src
import admit
import campaign
import terminal
from owner_apk import CIPHER
import test_storage_admission as storefixture


class TerminalReconcile(unittest.TestCase):
    def setUp(self):
        self.prod = src.OutcomeTransport()
        self.prod.setUp()
        self.addCleanup(self.prod.doCleanups)
        self.d = self.prod.tmp / 'sealed'
        self.d.mkdir()
        (self.d/CIPHER).write_bytes(b'age-encryption.org/v1\nsealed-test-data')
        self.cipher = terminal.digest(self.d/CIPHER)
        self.ctx = src.normal.context()
        seal = dict(schema='bare-personal-209-apk-seal-v1', run=17, attempt=1, ordinal=1, producer_sha=self.ctx['producer_sha'],
                    claim=97, accepted_parent=self.ctx['parent_sha'], recipient=terminal.owner.RECIPIENT,
                    bytes=(self.d/CIPHER).stat().st_size, sha=self.cipher)
        (self.d/'seal.json').write_bytes(terminal.owner.encode(seal))
        self.enterContext(patch.dict(os.environ, GH_TOKEN='fixture', R28_OWNER_RECIPIENT=terminal.owner.RECIPIENT))
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as output:
            for path in self.d.iterdir():
                output.write(path,path.name)
        self.zip = stream.getvalue()
        self.name = 'bare-personal-209-owner-17-a1-s1'
        origin = dict(id=17, head_sha=self.ctx['producer_sha'], head_branch=terminal.owner.BRANCH,
                      repository_id=terminal.owner.REPO_ID, head_repository_id=terminal.owner.REPO_ID)
        self.row = dict(id=345,name=self.name,size_in_bytes=len(self.zip),expired=False,
                        digest='sha256:'+hashlib.sha256(self.zip).hexdigest(),expires_at='2099-01-01T00:00:00Z',workflow_run=origin)
        self.key = 'bare-personal-209-terminal-17-1-s1-'+self.cipher
        self.clock = 0
        self.calls = []
        self.present = False
        self.count_delta = 0
        observe = terminal.observe
        def local(run,name,head,*,settled):
            return observe(run,name,head,settled=settled,get=self.get,clock=lambda:self.clock,sleep=self.tick)
        self.enterContext(patch.object(terminal,'observe',local))
        self.enterContext(patch.object(terminal.bridge,'api_json',self.get))
        path = Path(__file__).resolve().parents[1]/'.github/workflows/bare-personal209-slot.yml'
        self.workflow = yaml.safe_load(path.read_text())['jobs']
        self.steps = {s.get('id'):s for s in self.workflow['compile-probe']['steps']}

    def get(self, path):
        self.calls.append(path)
        if '/actions/caches?' in path:
            return dict(total_count=1,actions_caches=[dict(id=789,key=self.key,ref=os.environ['GITHUB_REF'],size_in_bytes=700)])
        if path.endswith('/actions/artifacts/345'):
            return self.row
        self.assertIn('/actions/runs/17/artifacts?',path)
        rows = [self.row] if self.present else []
        return dict(total_count=len(rows)+self.count_delta,artifacts=rows)

    def tick(self, seconds):
        self.clock += seconds

    def invoke(self, mode, **env):
        self.prod.outputs.write_text('')
        with patch.dict(os.environ,env), patch.object(sys,'argv',['terminal.py',mode,str(self.d)]):
            terminal.main()
        return dict(x.split('=',1) for x in self.prod.outputs.read_text().splitlines())

    def final(self, first, retry):
        return self.invoke('resolve-final', R209_FIRST_UPLOAD=first, R209_RETRY_UPLOAD=retry)

    def peer_and_cert(self, artifact, cache, *, private):
        step = self.steps['peer_stop']
        os.environ.update(TERMINAL=artifact or cache, KIND='apk', JOB_STATUS='success')
        subprocess.run(['bash','-eu','-c',step['run']],check=True,cwd=Path(__file__).resolve().parents[1])
        incoming=self.prod.normal/'incoming'
        incoming.mkdir(exist_ok=True)
        shutil.copyfile(self.prod.normal/'outcome.json',incoming/'outcome.json')
        descriptor = self.ctx | src.normal.sender_times(int(time.time()), 9)
        (self.prod.normal/'input.json').write_text(json.dumps(descriptor))
        self.prod.outputs.write_text('')
        src.normal.publish()
        status=dict(x.split('=',1) for x in self.prod.outputs.read_text().splitlines())
        self.assertEqual(status['peer_status'],'apk' if artifact or cache else 'failed')
        with patch.dict(os.environ,WORKER='apk',PEER=status['peer_status'],TERMINAL=artifact,
                        READBACK=status['private_readback_verified'],PRIVATE_RECEIPT='890' if private else '',
                        RECEIPT_SHA='c'*64 if private else '',CIPHER_ID='891' if private else ''):
            campaign.certify()
        self.assertIn('artifact='+(artifact or '890'), self.prod.outputs.read_text().splitlines())

    def test_blocked_initial_gate_and_denied_retry_admit_cache_after_actual_run_inventory(self):
        provider = storefixture.Provider()
        rows = [storefixture.ArtifactPaginationTests.row(i+1) for i in range(20)]
        def incomplete(path):
            if '/actions/artifacts?' not in path:
                return provider.get(path)
            query = parse_qs(urlsplit(path).query)
            page, width = int(query['page'][0]), int(query['per_page'][0])
            return dict(total_count=21, artifacts=rows[(page-1)*width:page*width])
        with self.assertRaisesRegex(terminal.storage.IncompleteArtifactInventory, '20 distinct observed IDs'):
            admit.current_view(incomplete, storefixture.ENV | {'GITHUB_RUN_ID':'17'}, 700, 3, stage='terminal', deadline=0)
        cases = [('failure,skipped,,','skipped,skipped,,'),
                 ('success,failure,absent,','failure,skipped,,'),
                 ('success,failure,absent,','success,failure,absent,')]
        for first,retry in cases:
            with self.subTest(first=first,retry=retry):
                self.calls.clear()
                verified = self.final(first,retry)
                self.assertEqual(verified, {'decision':'absent'})
                self.assertGreaterEqual(len(self.calls), 4)
                receipt = self.invoke('cache-receipt',R209_PRIMARY_ABSENT='true')
                self.assertEqual(receipt,{'cache_id':'789','terminal_status':'cache'})
                self.peer_and_cert('',receipt['cache_id'],private=True)
                (self.prod.normal/'outcome.json').unlink()

    def test_ambiguous_put_preserves_cache_without_terminal_certification(self):
        for first,retry in [('success,failure,,','skipped,skipped,,'),
                            ('success,success,,345','skipped,skipped,,'),
                            ('success,failure,absent,','success,failure,,')]:
            with self.subTest(first=first,retry=retry):
                self.assertEqual(self.final(first,retry),{'decision':'unconfirmed'})
                self.assertEqual(self.invoke('cache-receipt',R209_PRIMARY_ABSENT='false'),
                                 {'cache_id':'789','terminal_status':'cache-preserved-unconfirmed'})
                with self.assertRaises(ValueError):
                    self.peer_and_cert('','',private=False)
                (self.prod.normal/'outcome.json').unlink()

    def test_late_original_is_verified_once_and_foreign_or_contradictory_receipts_rejected(self):
        self.present = True
        def download(argv, **_):
            Path(argv[argv.index('--output')+1]).write_bytes(self.zip)
        with patch.object(terminal.subprocess,'run',side_effect=download):
            found=self.final('success,failure,,','skipped,skipped,,')
            self.assertEqual(found['artifact_id'],'345')
            self.assertEqual(found['decision'],'present')
            for args in [('failure,skipped,,','skipped,skipped,,'),('success,failure,,790','skipped,skipped,,'),
                         ('success,failure,,','success,success,,345')]:
                with self.subTest(args=args), self.assertRaises(ValueError):
                    self.final(*args)
            with patch.dict(self.row['workflow_run'],head_repository_id=1), self.assertRaises(ValueError):
                self.final('success,failure,,','skipped,skipped,,')
            with patch.dict(self.row,digest='sha256:'+'0'*64), self.assertRaises(ValueError):
                self.final('success,failure,,','skipped,skipped,,')
        self.peer_and_cert(found['artifact_id'],'',private=False)
        (self.prod.normal/'outcome.json').unlink()
        with self.assertRaises(ValueError):
            self.peer_and_cert(found['artifact_id'],'789',private=True)

    def test_incomplete_scoped_list_is_never_absence_and_links_feed_both_branches(self):
        self.count_delta=1
        with self.assertRaisesRegex(ValueError,'did not settle'):
            self.final('failure,skipped,,','skipped,skipped,,')
        self.assertNotIn('decision=absent', self.prod.outputs.read_text())
        self.assertIn('terminal_final.outputs.decision',self.steps['cache_receipt']['env']['R209_PRIMARY_ABSENT'])
        self.assertIn('!steps.terminal_final.outputs.artifact_id',self.steps['cache_receipt']['if'])
        self.assertIn('terminal_final.outputs.artifact_id',self.workflow['compile-probe']['outputs']['terminal'])
        self.assertIn('terminal_final.outputs.artifact_id',self.steps['peer_stop']['env']['TERMINAL'])
        self.assertIn("terminal_status == 'cache'",self.workflow['deliver-cached-apk']['if'])
