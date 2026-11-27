"""Exercise the actual compressed checkpoint acceptance and slot certificate."""
import json
import sys
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import checkpoint209 as cp
import input_state
import retained209
from test_retained209 import Retained as RetainedFixture


class Checkpoint(unittest.TestCase):
    def setUp(self):
        self.tree = RetainedFixture('test_missing_slot_output')
        self.tree.setUp()
        self.addCleanup(self.tree.doCleanups)
        self.root = self.tree.base
        self.out = self.tree.out
        roots = {k:self.root / ('src-'+k) for k in ['src','depot_tools']}
        for key,path in input_state.REQUIRED:
            if path == '.':
                roots[key].mkdir(exist_ok=True)
            else:
                p=roots[key]/path
                p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(b'fixed input')
        state=self.out/'.r209'
        input_state.record(state/'inputs.gz',roots)
        (state/'git-heads.json').write_bytes(cp.encode({'root':'e'*40}))
        trial = self.tree.trial('seed')
        (self.out/'checkpoint-trial-restore.json').write_bytes(cp.encode(trial))
        before, after = self.tree.before, self.tree.after
        (state/'frontier.json').write_bytes(cp.encode(after))
        lock=cp.digest(Path(cp.__file__).with_name('upstream-lock.json'))
        self.proof = dict(schema=cp.SCHEMA,run=17,ordinal=1,producer_sha='b'*40,parent_sha=lock,
                          genesis=lock,graph=retained209.graph_id(retained209.source_rows(self.out)),
                          before=len(before),remaining=len(after),target='chrome_public_apk',quiescent=True,
                          inputs=cp.digest(state/'inputs.gz'),plan=cp.digest(state/'frontier.json'),
                          git_heads=cp.digest(state/'git-heads.json'),next_has_headroom=True)
        self.proof['retained']=retained209.create(self.out,before,after,trial)
        (state/'proof.json').write_bytes(cp.encode(self.proof))
        self.record=dict(schema=cp.SCHEMA,attempt=1,run=17,ordinal=1,producer_sha='b'*40,parent_sha=lock,
                         identity=cp.identity(self.proof),proof_sha=cp.digest(state/'proof.json'))

    def archive(self):
        archive=self.root/'checkpoint.zst'
        subprocess.run(['tar','--sort=name','--format=posix','--hard-dereference','--zstd','-cf',str(archive),'out/Bare'],
                       cwd=self.root,check=True)
        return archive, dict(self.record,bytes=archive.stat().st_size,sha256=cp.digest(archive))

    def test_real_tar(self):
        self.assertEqual(cp.check_archive(*self.archive()),self.proof)

    def test_wrong_generation(self):
        archive,rec=self.archive()
        for c in [dict(run=18),dict(schema='bare-r28-checkpoint-private-v1'),dict(parent_sha='a'*64),dict(proof_sha='9'*64)]:
            with self.subTest(c=c),self.assertRaises(ValueError):
                cp.check_archive(archive,rec|c)

    def test_missing_or_changed_output(self):
        (self.out/'a.o').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            cp.check_archive(*self.archive())
        (self.out/'a.o').unlink()
        with self.assertRaises(ValueError):
            cp.check_archive(*self.archive())

    def test_external_link(self):
        (self.out/'badlink').symlink_to('/etc')
        with self.assertRaises(ValueError):
            cp.check_archive(*self.archive())

    def test_bad_source_inventory(self):
        (self.out/'.r209/inputs.gz').write_bytes(b'bad gzip')
        with self.assertRaises((ValueError,OSError)):
            cp.check_archive(*self.archive())


class ServiceOrigin(unittest.TestCase):
    def test_offline_new_generation_boundaries(self):
        os.environ.setdefault('RUNNER_TEMP','/tmp')
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'preflight28/bridge'))
        import owner_recovery as recovery
        parent, head, claim, run, asset = 'a'*64, 'b'*40, 2, 10, 109
        with patch.dict(os.environ,BARE_GENERATION='2.0.9'):
            for slot in [13,99]:
                row = dict(artifact_id=asset,run=run,ordinal=slot,producer_sha=head,parent_sha=parent,
                           claim_id=claim,name=f'r209-{run}-a1-s{slot:02}-outcome',zip_sha256='c'*64)
                recovery.check_saved_origin(row,asset,run,slot,head,parent,claim)
                with self.assertRaises(ValueError):
                    recovery.check_saved_origin(row,asset,run+1,slot,head,parent,claim)
                with self.assertRaises(ValueError):
                    recovery.check_saved_origin(row,asset,run,slot+1,head,parent,claim)
            row.update(ordinal=100, name=f'r209-{run}-a1-s100-outcome')
            with self.assertRaises(ValueError):
                recovery.check_saved_origin(row,asset,run,100,head,parent,claim)


if __name__ == '__main__':
    unittest.main()
