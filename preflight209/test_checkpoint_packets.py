"""Protocol admission and exact extraction regressions for the bounded checkpoint fallback."""
import hashlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch

os.environ.setdefault('RUNNER_TEMP',tempfile.gettempdir())
import checkpoint_packets as p
import checkpoint_send as sender


class Capacity(unittest.TestCase):
    def setUp(self):
        self.storage = 8997424157
        self.service_limit = 10
        self.expiry = int(time.time())+40*p.storage.DAY
        self.ref = 'refs/heads/bare-coexist-v2.0.9'
        self.row = dict(id=10,key='keep',ref=self.ref,version='b'*64,size_in_bytes=self.storage)
        self.rows = [self.row]
        self.usage = (self.storage,1)
        self.deadline = time.time()+30
        self.env = patch.dict(os.environ,dict(R28_STORAGE_CEILING=str(48*1024**3),
                    R28_STORAGE_UNTIL=str(self.expiry),RUNNER_ENVIRONMENT='github-hosted',GITHUB_RUN_ID='123'))
        self.env.start()
        self.service = patch.object(p,'get_before',return_value=self.get)
        self.service.start()

    def tearDown(self):
        self.service.stop()
        self.env.stop()

    def get(self,path):
        if path==p.BASE:
            return dict(id=p.storage.REPO_ID,full_name=p.b.REPO,private=False,fork=False,visibility='public')
        if '/actions/runs?' in path:
            current = ['in_progress'] if 'status=in_progress&' in path else []
            return dict(total_count=len(current),workflow_runs=[dict(id=123,status=s) for s in current])
        if path.endswith('/storage-limit'):
            return dict(max_cache_size_gb=self.service_limit)
        if path.endswith('/retention-limit'):
            self.fail('Ordinary actions:read must not query administrative retention settings')
        if path.endswith('/usage'):
            return dict(active_caches_size_in_bytes=self.usage[0],active_caches_count=self.usage[1])
        if 'actions/caches?per_page=100&page=1' in path:
            return dict(total_count=len(self.rows),actions_caches=self.rows)
        self.fail(path)

    def admit(self,debt=0):
        return p.capacity(p.archive_bound(p.PACKET_BYTES),p.MAX_SEALED,self.deadline,debt=debt)

    def test_billable_ceiling_unknown_aggregate_and_expiry(self):
        self.assertGreater(self.admit(),0)
        self.service_limit=11
        with self.assertRaisesRegex(ValueError,'free capacity'): self.admit()
        self.service_limit=10
        with patch.dict(os.environ,{'R28_STORAGE_UNTIL':str(int(time.time())+60)}):
            with self.assertRaisesRegex(ValueError,'expires'): self.admit()
        self.usage=(10*1024**3,1)
        with self.assertRaises(p.storage.StorageFull): self.admit()
        self.usage=(self.storage,1)
        with patch.dict(os.environ,{'R28_RELAY_BYTE_CEILING':str(3*1024**3)}):
            with self.assertRaisesRegex(ValueError,'Full relay'): self.admit()

    def test_maximum_size_measured_groups_and_delayed_credits(self):
        group,seconds=sender.plan(self.admit())
        self.assertGreaterEqual(group,1)
        self.assertLess(group,p.MAX_COUNT)
        self.assertEqual(seconds,sender.START_SECONDS+240*p.MAX_COUNT+720*math.ceil(p.MAX_COUNT/group))
        size_debt=0
        barriers=[]
        for i in range(p.MAX_COUNT):
            size=min(p.PACKET_BYTES,p.MAX_SEALED-i*p.PACKET_BYTES)
            next_size=min(p.PACKET_BYTES,max(0,p.MAX_SEALED-(i+1)*p.PACKET_BYTES))
            spare=p.capacity(p.archive_bound(size),p.MAX_SEALED,self.deadline,debt=size_debt)
            barrier=i==p.MAX_COUNT-1 or spare<p.archive_bound(next_size)+p.MAX_COUNT*p.archive_bound(0)
            if barrier:
                barriers.append(i)
                size_debt=0
            else:
                size_debt+=p.archive_bound(size)
            # Explicitly retain every ACK even when the provider meter stays stale.
            self.rows.append(dict(self.row,id=i+20,key='ack'+str(i),size_in_bytes=1024))
        self.assertEqual(len(barriers),math.ceil(p.MAX_COUNT/group))
        self.assertLessEqual((p.MAX_COUNT*240+len(barriers)*720),seconds)

    def test_release_requires_positive_high_and_low_aggregate(self):
        row=dict(self.row,id=99)
        piece={'meter_barrier':True}
        with patch.object(p,'snapshot',side_effect=[({99:row},(0,0)),({99:row},(self.storage,1))]), \
                patch.object(p,'pause') as wait:
            p.before_delete(piece,row,self.deadline)
            self.assertEqual(wait.call_count,1)
        with patch.object(p,'exact',side_effect=[row,None,None]), \
                patch.object(p,'snapshot',side_effect=[({},(self.storage,1)),({},(0,0))]),patch.object(p,'pause') as wait:
            sender.await_release(piece,row,self.deadline)
            self.assertEqual(wait.call_count,2)
        with patch.object(p,'snapshot',return_value=({},(0,0))):
            with self.assertRaisesRegex(ValueError,'disappeared'): p.before_delete(piece,row,self.deadline)


class SafeTar(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name)
        self.ws=self.root/'workspace'
        self.ws.mkdir()
        (self.ws/'preflight209').symlink_to(p.HERE,target_is_directory=True)
        self.env=patch.dict(os.environ,dict(GITHUB_WORKSPACE=str(self.ws),RUNNER_TEMP=str(self.root),
                                           R209_PACKET_KIND='packet',BARE_GENERATION='2.0.9'))
        self.env.start()
        p.stage_hook()
        p.reset('packet')
        self.archive=self.root/'cache.tzst'

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def create(self,extra=None):
        raw=self.root/'test.tar'
        with tarfile.open(raw,'w',format=tarfile.PAX_FORMAT) as archive:
            for name,body in [('piece.bin',b'encrypted'),('piece.json',b'{}'),('piece.sig',b'sig')]:
                info=tarfile.TarInfo(str(p.PACKET_PATH/name))
                info.size=len(body)
                info.pax_headers={'mtime':'12345.00001'}
                archive.addfile(info,io.BytesIO(body))
            if extra:
                archive.addfile(extra)
        subprocess.run(['zstd','-qf',raw,'-o',self.archive],check=True)
        return subprocess.run([p.checked_hook(),'-xf',self.archive,'-P','-C',self.ws,'--use-compress-program','unzstd'],
                              capture_output=True)

    def test_valid_pax_and_refuse_links_traversal_absolutes_duplicates(self):
        self.assertEqual(self.create().returncode,0)
        self.assertEqual((p.folder('packet')/'piece.bin').read_bytes(),b'encrypted')
        for name,kind in [('../escaped',tarfile.REGTYPE),(str(self.root/'escaped'),tarfile.REGTYPE),
                          (str(p.PACKET_PATH/'aside'),tarfile.LNKTYPE),(str(p.PACKET_PATH/'link'),tarfile.SYMTYPE),
                          (str(p.PACKET_PATH/'piece.bin'),tarfile.REGTYPE)]:
            p.reset('packet')
            info=tarfile.TarInfo(name);info.type=kind;info.linkname='../escaped'
            self.assertNotEqual(self.create(info).returncode,0)
            self.assertFalse((self.root/'escaped').exists())

    def test_substituted_or_non_executable_hook_fails_closed(self):
        hook=p.checked_hook()
        hook.chmod(0o600)
        with self.assertRaisesRegex(ValueError,'executable'): p.checked_hook()
        hook.chmod(0o700)
        hook.write_text('foreign')
        with self.assertRaisesRegex(ValueError,'substituted'): p.checked_hook()

    @unittest.skipUnless(os.environ.get('R209_TEST_PINNED_SDK'),'optional pinned official Linux SDK archive smoke')
    def test_real_pinned_archive_commands(self):
        # Adapt only the upstream CLI entrypoint to exercise its actual create and
        # restore methods offline. The bundled methods and their transitive code are unchanged.
        client=Path(os.environ['R209_TEST_PINNED_SDK'])/'dist/restore-only/index.js'
        blob=client.read_bytes()
        self.assertEqual(hashlib.sha1(f'blob {len(blob)}\0'.encode()+blob).hexdigest(),p.BLOBS['restore'])
        entry=b'(0, restoreImpl_1.restoreOnlyRun)(true);'
        self.assertEqual(blob.count(entry),1)
        local=self.root/'pinned-archive.cjs'
        local.write_bytes(blob.replace(entry,b'''const tar = __nccwpck_require__(95321);
const u = __nccwpck_require__(98299);
(async()=>{const method=await u.getCompressionMethod();
 const path=process.argv[3]; const dir=process.argv[4];
 if(process.argv[2]==='save'){
 const resolved=await u.resolvePaths([dir]); await tar.createTar(path,resolved,method);
 }else{await tar.extractTar(path,method);}
})().catch(e=>{console.error(e.message);process.exitCode=1});'''))
        folder=p.folder('packet')
        for name in p.BOUNDS['packet']: (folder/name).write_bytes(name.encode())
        cmd=['node',str(local)]
        subprocess.run(cmd+['save',str(self.root),str(p.PACKET_PATH)],cwd=self.ws,check=True,capture_output=True)
        p.reset('packet')
        env=dict(os.environ,PATH=str(p.checked_hook().parent)+os.pathsep+os.environ['PATH'])
        proc=subprocess.run(cmd+['restore',str(self.archive),str(p.PACKET_PATH)],cwd=self.ws,env=env,capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stdout+proc.stderr)
        self.assertEqual((folder/'piece.bin').read_bytes(),b'piece.bin')
        self.assertIn(str(p.checked_hook()).encode(),proc.stdout)


if __name__=='__main__':
    unittest.main()
