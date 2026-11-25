"""Offline checks for the same archive + cryptographic handoff used on the VMs."""
import contextlib
import io
import os
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import cohort


class ExchangeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.peer = self.root/'peer'
        self.owner = self.root/'central'
        self.peer.mkdir(); self.owner.mkdir()
        for ext in ('.d','.o'):
            (self.peer/('target'+ext)).write_bytes(b'one unit '+ext.encode())
        cohort.pack(self.peer,['target'])

    def test_scope_and_output_integrity(self):
        archive = self.peer/'shard.zip'
        with patch.dict(os.environ, {'GITHUB_RUN_ATTEMPT':'another'}), self.assertRaises(ValueError):
            cohort.receive(self.owner,['target'],archive)
        with self.assertRaises(ValueError): cohort.receive(self.owner,['missing'],archive)
        bad=self.root/'corrupt'
        with ZipFile(archive) as source, ZipFile(bad,'w') as z:
            for name in source.namelist(): z.writestr(name,b'corrupt' if name=='target.o' else source.read(name))
        with self.assertRaises(ValueError): cohort.receive(self.owner,['target'],bad)

    def test_storage_must_still_allow_each_real_upload(self):
        env = {'RUNNER_TEMP':str(self.root), 'RUNNER_ENVIRONMENT':'github-hosted',
               'GITHUB_RUN_ID':'17', 'GITHUB_RUN_ATTEMPT':'1', 'R28_STORAGE_CEILING':'9999999',
               'R28_STORAGE_UNTIL':str(int(time.time())+3*86400), 'R28_RELAY_BYTE_CEILING':'9000000'}
        with patch.dict(os.environ, env):
            import field
            sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'bridge'))
            import bridge, storage_admission as admission
            repo = {'id':admission.REPO_ID, 'full_name':admission.REPO, 'fork':False, 'private':False, 'visibility':'public'}
            def get(path):
                if path==admission.BASE: return repo
                if '/runs?' in path:
                    ids = [77] if foreign and 'status=queued&' in path else []
                    return {'total_count':len(ids), 'workflow_runs':[{'id':i} for i in ids]}
                return {'total_count':0, 'artifacts':[]}
            foreign = False
            for role, filename in (('ticket','cert.pem'), ('parcel','exchange.der')):
                (self.root/filename).write_bytes(b'measure')
                with patch.object(field,'ROOT',self.root), patch.object(bridge,'api_json',get), contextlib.redirect_stdout(io.StringIO()):
                    field.admit(role)
                    foreign = True
                    with self.assertRaises(admission.StorageUnconfirmed): field.admit(role)
                    foreign = False
                    with patch.dict(os.environ, {'R28_RELAY_BYTE_CEILING':'2097152'}), self.assertRaises(admission.StorageFull): field.admit(role)
                    with patch.dict(os.environ, {'R28_STORAGE_UNTIL':str(int(time.time())+86400)}), self.assertRaises(admission.StorageUnconfirmed): field.admit(role)

    def test_key_stays_on_receiving_vm(self):
        with patch.dict(os.environ, {'RUNNER_TEMP':str(self.root)}):
            import field
        roles={}
        for role in ('peer','central'):
            home=self.root/role
            (home/'clock.json').write_text('{}')
            roles[role]=home
        def run(role, name, waiting=None):
            home=roles[role]
            with patch.object(field,'ROOT',home), patch.object(field,'CLOCK',home/'clock.json'), \
                    patch.object(field,'wait',return_value=waiting), patch('sys.argv',['field.py',name]):
                field.main()
        run('central','cert')
        # Normal VM path stores the peer's pack in its private working tree.
        (self.peer/'peer').mkdir()
        (self.peer/'shard.zip').rename(self.peer/'peer/shard.zip')
        run('peer','seal',self.owner/'cert.pem')
        self.assertFalse((self.peer/'key.pem').exists())
        run('central','open',self.peer/'exchange.der')
        cohort.receive(self.owner,['target'],self.owner/'shard.zip')
        self.assertEqual((self.owner/'import/target.o').read_bytes(),(self.peer/'target.o').read_bytes())


if __name__ == '__main__': unittest.main()
