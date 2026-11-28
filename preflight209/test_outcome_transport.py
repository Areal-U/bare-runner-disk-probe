"""Exercise both ends of the workflow with real Python outcomes and disposable keys."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
import zipfile

import test_checkpoint209

BRIDGE = Path(__file__).resolve().parents[1] / 'preflight28/bridge'
sys.path.insert(0, str(BRIDGE))
os.environ.setdefault('RUNNER_TEMP', tempfile.gettempdir())
import bridge
import normal
import owner_recovery
from test_normal import LocalDraft


class OutcomeTransport(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.normal = self.tmp / 'r28-normal'
        self.normal.mkdir()
        self.outputs = self.tmp / 'outputs'
        genesis = bridge.digest(Path(__file__).with_name('upstream-lock.json'))
        self.env = dict(BARE_GENERATION='2.0.9', GITHUB_REF='refs/heads/bare-coexist-v2.0.9',
                        GITHUB_REPOSITORY=bridge.REPO, GITHUB_RUN_ID='17', GITHUB_RUN_ATTEMPT='1',
                        GITHUB_JOB='compile-probe', GITHUB_EVENT_NAME='workflow_dispatch',
                        GITHUB_SHA='b'*40, R28_HEAD_SHA='b'*40, R28_SLOT='1', R209_GENESIS=genesis,
                        R28_PARENT_SHA=genesis, R28_PARENT_IDENTITY=genesis, R28_COLLECTION_CLAIM='97',
                        RUNNER_TEMP=str(self.tmp), GITHUB_OUTPUT=str(self.outputs), INPUT_OVERWRITE='false')
        self.env.update({'INPUT_RETENTION-DAYS':'1', 'INPUT_IF-NO-FILES-FOUND':'error',
                         'INPUT_COMPRESSION-LEVEL':'0'})
        self.enterContext(patch.dict(os.environ, self.env))
        self.enterContext(patch.object(normal, 'R209', True))
        self.enterContext(patch.object(normal, 'SCHEMA', 'bare-personal-209-checkpoint-v1'))
        self.enterContext(patch.object(normal, 'ROOT', self.normal))
        self.enterContext(patch.object(bridge, 'ROOT', self.normal))
        self.command('names')
        self.name = dict(line.split('=',1) for line in self.outputs.read_text().splitlines())['outcome_name']
        self.assertEqual(self.name, 'r209-17-a1-s01-outcome')

    def command(self, *args):
        subprocess.run([sys.executable, BRIDGE / 'normal.py', *args], check=True, capture_output=True)

    def test_transient_packet_read_preserves_both_outcome_routes(self):
        descriptor = normal.context() | normal.sender_times(int(time.time()), 23)
        (self.normal/'input.json').write_text(json.dumps(descriptor))
        artifact = dict(id=77, workflow_run={'id': 17}, expired=False, size_in_bytes=400,
                        expires_at='2099-01-01T00:00:00Z')
        for partial, expected in ((False, {'id': 77}), (True, {'packets_ready': 'true'})):
            reader = Mock()
            reader.outcome = normal.context() if partial else None
            reader.poll.side_effect = [bridge.TransientReadError('503'), True]
            with self.subTest(partial=partial), patch('packet_receiver.Receiver', return_value=reader), \
                 patch.object(normal.artifact_poll,'lookup',side_effect=[None, None if partial else artifact]), \
                 patch.object(normal,'ordinary_job',return_value=None), patch.object(time,'sleep'), \
                 patch.object(bridge,'output') as output:
                normal.wait('outcome')
                output.assert_called_once_with(**expected)
        reader = Mock(outcome=normal.context())
        with patch('packet_receiver.Receiver',return_value=reader), \
             patch.object(normal.artifact_poll,'lookup',return_value=artifact), \
             self.assertRaisesRegex(ValueError,'both match'):
            normal.wait('outcome')

    def accepted(self, candidate=False, **changes):
        items = [self.normal / 'outcome.json']
        if candidate:
            items.append(self.normal / 'checkpoint.cms')
        env = dict(os.environ, INPUT_NAME=self.name, INPUT_PATH='\n'.join(map(str, items)))
        env.update(changes)
        probe = "require(process.argv[1]).validateScope(process.env)"
        return subprocess.run(['node', '-e', probe, BRIDGE/'normal_upload/index.cjs'],
                              env=env, capture_output=True).returncode == 0

    def test_python_failed_stop_through_workflow_upload_validator(self):
        self.command('stop', '--reason', 'failed')
        self.assertTrue(self.accepted())
        for changes in [
            {'INPUT_NAME':self.name.replace('r209-', 'r28-')},
            {'GITHUB_SHA':'0'*40}, {'R28_PARENT_IDENTITY':'0'*64},
            {'BARE_GENERATION':''}, {'BARE_GENERATION':'2.0.8'},
            {'GITHUB_REF':'refs/heads/bare-coexist-v2.0.4'},
        ]:
            with self.subTest(changes=changes):
                self.assertFalse(self.accepted(**changes))
        path = self.normal / 'outcome.json'
        stop = json.loads(path.read_bytes())
        (self.normal/'incoming').mkdir()
        shutil.copyfile(path,self.normal/'incoming/outcome.json')
        descriptor = dict(normal.context(), **normal.sender_times(int(time.time()), 23))
        (self.normal/'input.json').write_text(json.dumps(descriptor))
        normal.publish()
        fields = dict(line.split('=',1) for line in self.outputs.read_text().splitlines())
        self.assertEqual(fields['peer_status'], 'failed')
        self.assertEqual(fields['private_readback_verified'], 'false')
        self.assertEqual(fields['checkpoint_advanced'], 'false')
        for diff in [dict(schema='bare-r28-checkpoint-private-v1'), dict(run=18),
                     dict(key='bare-coexist-204-17-1-checkpoint-production-s1'), dict(ordinal=2)]:
            with self.subTest(diff=diff):
                path.write_text(json.dumps(stop | diff))
                self.assertFalse(self.accepted())

    def make_candidate(self):
        """Return the original bytes, receiver and test owner for this real CMS outcome."""
        fixture = test_checkpoint209.Checkpoint('test_real_tar')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        archive, record = fixture.archive()
        owner_id = self.tmp / 'test-identity.agekey'
        subprocess.run(['age-keygen','-o',owner_id], check=True, capture_output=True)
        recipient = subprocess.check_output(['age-keygen','-y',owner_id], text=True).strip()
        self.enterContext(patch.dict(os.environ, R28_OWNER_RECIPIENT=recipient))
        self.enterContext(patch.object(owner_recovery, 'RECIPIENT', recipient))
        # Only the hosted free-space check and the private Draft service are simulated.
        self.enterContext(patch.object(bridge, 'disk'))
        draft = LocalDraft()
        self.enterContext(patch.object(bridge, 'auth_api', return_value=draft))
        sender = self.tmp / 'receiver'
        sender.mkdir()
        with patch.object(bridge, 'ROOT', sender):
            bridge.keygen()
        certificate = sender/'public.pem'
        shutil.copyfile(certificate, self.normal / 'writer.pem')
        descriptor = dict(normal.context(), **normal.sender_times(int(time.time()), 23),
                          owner_recovery=owner_recovery.wrap(sender, normal.context(), recipient, 97))
        (self.normal/'input.json').write_text(json.dumps(descriptor))
        normal.seal(archive, record['identity'], record['proof_sha'])
        return archive, sender, owner_id, draft

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'requires age and age-keygen')
    def test_candidate_published_and_recovered_from_same_cms(self):
        archive, sender, owner_id, draft = self.make_candidate()
        self.assertTrue(self.accepted(candidate=True))
        self.assertFalse(self.accepted(candidate=True, R28_PARENT_SHA='a'*64))
        self.assertFalse(self.accepted())
        (sender/'incoming').mkdir()
        shutil.copyfile(self.normal/'input.json',sender/'input.json')
        envelope = self.tmp / 'outcome.zip'
        with zipfile.ZipFile(envelope,'w') as z:
            for name in ('outcome.json','checkpoint.cms'):
                shutil.copyfile(self.normal/name, sender/'incoming'/name)
                z.write(self.normal/name,name)
        with patch.object(normal,'ROOT',sender), patch.object(bridge,'ROOT',sender):
            normal.publish()
        self.assertTrue(any(a['name'] == 'r209-17-a1-s01-manifest.json' for a in draft.assets))
        self.assertIn('private_readback_verified=true',self.outputs.read_text().splitlines())
        service = dict(name=self.name,id=77,expired=False,expires_at='2099-01-01T00:00:00Z',
                       size_in_bytes=envelope.stat().st_size, digest='sha256:'+bridge.digest(envelope),
                       workflow_run=dict(id=17,head_sha=self.env['GITHUB_SHA']))
        ctx=dict(artifact_id=77,run=17,ordinal=1,head=self.env['GITHUB_SHA'],
                 parent_sha=self.env['R28_PARENT_SHA'],claim_id=97)
        receipt=owner_recovery.service_record(service,17,1,ctx['head'],ctx['parent_sha'],97,expect_id=77)
        recovered=self.tmp/'rescued.tar.zst'
        self.assertEqual(owner_recovery.open_saved(envelope,receipt,owner_id,recovered,**ctx),
                         hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(archive.read_bytes(),recovered.read_bytes())
        with self.assertRaises(ValueError):
            owner_recovery.open_saved(envelope,receipt,owner_id,recovered,**(ctx|dict(claim_id=98)))


if __name__ == '__main__':
    unittest.main()
