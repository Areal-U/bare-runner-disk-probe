import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_artifact as public
from source_artifact import seed, source

PIN={'CHROMIUM_REV':'1'*40,'BARE_REV':'2'*40,'DEPOT_REV':'3'*40}
TREE='4'*40
NOW=1_800_000_000
CAMPAIGN='bare-personal-204-r29'
DISK=SimpleNamespace(f_bavail=110*1024**3,f_frsize=1,f_favail=10_000_000)
def utc(s):return datetime.fromtimestamp(s,timezone.utc).isoformat()

def fixture():
    source_run,android_run=40,41
    source_head,android_head='5'*40,'6'*40
    cmp=dict(spec=dict(PIN,url=source.CHROMIUM,scope='chromium',revision=PIN['CHROMIUM_REV']),tree=TREE,
             sha256='7'*64,files=100,bytes=400,checkout_bytes=800,direct_s=231,seeded_s=71,download_s=24,
             make_s=131,upload_s=17,producer_finish_to_receiver_transfer_start_s=9,seeded_new_pack_bytes=0)
    row=dict(id=85,name='bare-public-git-40-1',size_in_bytes=500,expired=False,expires_at=utc(NOW+86400),
             digest='sha256:'+'8'*64,workflow_run=dict(id=source_run,head_sha=source_head,repository_id=public.REPO_ID,head_repository_id=public.REPO_ID))
    meta={'actions/artifacts/85':row,'actions/runs/40/artifacts?per_page=100':dict(artifacts=[row],total_count=1)}
    for run,head,mode,names in ((source_run,source_head,'source-chromium',public.SOURCE_JOBS),
                                (android_run,android_head,'source-android',(public.ANDROID_JOB,))):
        meta[f'actions/runs/{run}/attempts/1']=dict(id=run,head_sha=head,head_branch=public.REF,actor={'id':292261483},
            repository={'id':public.REPO_ID},head_repository={'id':public.REPO_ID},run_attempt=1,event='workflow_dispatch',
            path=public.WORKFLOW,display_title=f'Bare next-build trial {mode} {head}',status='completed',conclusion='success')
        jobs=[dict(id=run*10+i,name=name,conclusion='success',head_sha=head,run_id=run,run_attempt=1) for i,name in enumerate(names)]
        meta[f'actions/runs/{run}/attempts/1/jobs?per_page=100']=dict(jobs=jobs,total_count=len(jobs))
    meta[f'contents/.github/workflows/bare-arm64-probe.yml?ref={android_head}']=dict(type='file',encoding='base64',
            content=base64.b64encode(''.join(f'      {k}: {v}\n' for k,v in PIN.items()).encode()).decode())
    prior={**{k:cmp[k] for k in ('spec','tree','sha256','bytes','files','checkout_bytes')},'artifact':dict(id=85)}
    meta[f'contents/next_build/trials/android-source-receipt.json?ref={android_head}']=dict(type='file',encoding='base64',content=base64.b64encode(json.dumps(prior).encode()).decode())
    state=dict(head=PIN['CHROMIUM_REV'],tree=TREE,packs=['root.pack'])
    q=dict(chromium=PIN['CHROMIUM_REV'],chromium_tree=TREE,depot=PIN['DEPOT_REV'],root_extra_pack_bytes=0,v8='9'*40,
           android_dependency_entries=261,android_sdk_files=['aapt2'],android_ndk_files=['.../api-level.h'],
           before=state,after=state,source_pack_sha256='7'*64,source_artifact_id=85,compiled=False,runhooks=False,full_seeded_fetch_s=370)
    def line(tag,obj):
        return '2026-11-25T20:30:45.203Z '+tag+' '+json.dumps(obj)+'\r\n'
    logs={401:line('BARE_SOURCE_COMPARISON',cmp),410:line('BARE_ANDROID_SOURCE_RESULT',q)
          +line('BARE_ANDROID_ARTIFACT_FETCH_S',22)+line('BARE_ANDROID_SOURCE_FLOOR',dict(free=40*public.GIB,inodes=3000000))}
    args=(CAMPAIGN,source_run,source_head,android_run,android_head,utc(NOW+600*60),2,PIN)
    return args,meta,logs

class SourcePlan(unittest.TestCase):
    def issue(self,args,meta,logs):
        return public.issue(*args,metadata=meta.__getitem__,read_log=logs.__getitem__,now=NOW)

    def test_immutable_android_report_and_economics(self):
        args,meta,logs=fixture()
        plan=self.issue(args,meta,logs)
        self.assertEqual(plan['qualification']['net_s'],73)
        for action in ('ambiguous','full-slower','wrong-solution','wrong-run','one-use','too-short','old-campaign','changed-pins','stale-inputs','truncated','other-qualified-pack','other-qualified-id'):
            args,meta,logs=fixture()
            if action=='ambiguous':logs[401]*=2
            if action=='full-slower':logs[410]=logs[410].replace('"full_seeded_fetch_s": 370','"full_seeded_fetch_s": 500')
            if action=='wrong-solution':logs[410]=logs[410].replace('"android_dependency_entries": 261','"android_dependency_entries": 1')
            if action=='wrong-run':meta['actions/runs/40/attempts/1']['actor']['id']=1
            if action=='one-use':args=(*args[:6],1,args[7])
            if action=='too-short':args=(*args[:5],utc(NOW+350*60),*args[6:])
            if action=='old-campaign':args=('bare-personal-204-r28',*args[1:])
            if action=='changed-pins':args=(*args[:-1],dict(PIN,BARE_REV='a'*40))
            if action=='stale-inputs':meta['contents/.github/workflows/bare-arm64-probe.yml?ref='+'6'*40]['content']=base64.b64encode(b'old').decode()
            if action=='other-qualified-pack':logs[410]=logs[410].replace('7'*64,'b'*64)
            if action=='other-qualified-id':logs[410]=logs[410].replace('"source_artifact_id": 85','"source_artifact_id": 55')
            if action=='truncated':meta['actions/runs/40/artifacts?per_page=100']['total_count']=2
            with self.subTest(action=action),self.assertRaises(ValueError):self.issue(args,meta,logs)

    def test_use_guards_and_download(self):
        args,meta,logs=fixture();plan=self.issue(args,meta,logs)
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);event=root/'event'
            event.write_text(json.dumps({'inputs':{}}))
            env=dict(PIN,SEGMENT_ORDINAL='1',GITHUB_EVENT_PATH=str(event),GITHUB_REPOSITORY=public.REPO,
                     GITHUB_REF='refs/heads/bare-coexist-v2.0.4',GITHUB_RUN_ATTEMPT='1',GITHUB_ACTOR='Areal-U',
                     CHECKPOINT_BACKEND='draft',VERIFY_FRONTIER_ONLY='false',R28_PARENT_RUN='',R28_COLLECTION_CLAIM='40',
                     R28_STORAGE_CEILING='3000000000',R28_STORAGE_UNTIL=str(NOW+24*3600))
            def usable(p=plan,e=env,c=CAMPAIGN,now=NOW):
                return public.usable(p,e,c,meta.__getitem__,now)
            self.assertEqual(usable(),plan['receipt'])
            for k,v in (('GITHUB_RUN_ATTEMPT','2'),('R28_PARENT_RUN','50'),('R28_COLLECTION_CLAIM',''),
                        ('VERIFY_FRONTIER_ONLY','true'),('SEGMENT_ORDINAL','3'),('R28_STORAGE_CEILING','1'),('CHROMIUM_REV','a'*40)):
                with self.subTest(k=k),self.assertRaises(ValueError):usable(e=dict(env,**{k:v}))
            with self.assertRaises(ValueError):usable(now=NOW+86400)
            with self.assertRaises(ValueError):usable(c='bare-personal-204-r28')
            event.write_text(json.dumps({'inputs':{'mode':'recover-lost-slot'}}))
            with self.assertRaises(ValueError):usable()

            # Exercise the actual ZIP -> exact sole pack -> read-only builder receipt staging code.
            report=dict(plan['receipt']); data=b'public-test-objects'; report.update(bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            for name,extra in [('source.pack',False),('source.pack',True),('../other',False)]:
                result=root/'exchange';result.mkdir()
                buf=io.BytesIO()
                with zipfile.ZipFile(buf,'w') as archive:
                    archive.writestr(name,data)
                    if extra:archive.writestr('other','unexpected')
                blob=buf.getvalue();asset=dict(plan['artifact'],size_in_bytes=len(blob),digest='sha256:'+hashlib.sha256(blob).hexdigest())
                with patch.object(public,'usable',return_value=report),patch.object(public.os,'statvfs',return_value=DISK),patch.object(public.subprocess,'Popen',return_value=Pipe(blob)):
                    if name=='source.pack' and not extra:
                        public.stage(dict(plan,artifact=asset),result,env,CAMPAIGN)
                        self.assertEqual((result/'public-source-seed'/'source.pack').read_bytes(),data)
                    else:
                        with self.assertRaises(ValueError):public.stage(dict(plan,artifact=asset),result,env,CAMPAIGN)
                        self.assertFalse((result/'public-source-seed').exists())
                shutil.rmtree(result)

class Pipe:
    def __init__(self,blob): self.stdout=io.BytesIO(blob)
    def __enter__(self):return self
    def __exit__(self,*args):return False
    def wait(self,timeout):return 0
    def poll(self):return 0

class GitSeed(unittest.TestCase):
    def test_verified_git_objects_and_clean_target(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);git=root/'origin';git.mkdir()
            subprocess.run(['git','-C',str(git),'init','-q'],check=True)
            (git/'DEPS').write_text('deps = {}\n');source.git(git,'add','DEPS')
            source.git(git,'-c','user.name=test','-c','user.email=test@example.invalid','commit','-qm','fixture')
            rev=source.value(git,'rev-parse','HEAD');tree=source.value(git,'rev-parse','HEAD^{tree}')
            pack=root/'source.pack'
            with pack.open('wb') as f:source.git(git,'pack-objects','--all','--stdout',stdout=f)
            report=dict(spec=dict(PIN,CHROMIUM_REV=rev,url=source.CHROMIUM,scope='chromium',revision=rev),
                        sha256=source.digest(pack),bytes=pack.stat().st_size,files=1,checkout_bytes=10,tree=tree)
            dest=root/'src'
            with patch.object(seed.os,'statvfs',return_value=DISK):
                for bad in (dict(report,sha256='0'*64),dict(report,spec=dict(report['spec'],scope='v8')),dict(report,tree='0'*40)):
                    with self.assertRaises(ValueError):seed.restore(bad,pack,dest,rev)
                    self.assertFalse(dest.exists())
                seed.restore(report,pack,dest,rev)
                self.assertEqual((dest/'DEPS').read_text(),'deps = {}\n')
                self.assertEqual(source.value(dest,'remote','get-url','origin'),source.CHROMIUM)
                (dest/'sentinel').write_text('keep')
                with self.assertRaises(ValueError):seed.restore(report,pack,dest,rev)
                self.assertTrue((dest/'sentinel').exists())

class OrdinaryEntry(unittest.TestCase):
    def test_normal_shell_reads_only_selected_bytes_and_recovers_empty(self):
        normal=source.PIN_FILE.read_text()
        start=normal.index('        # Both paths')
        shell='\n'.join(line[8:] for line in normal[start:normal.index('        df -B1 /work',start)].splitlines())
        self.assertIn("ready=true",normal)
        self.assertIn("steps.source_seed.outputs.ready == 'true'",normal)
        self.assertEqual(normal.count('gclient sync --no-history --nohooks --revision "src@$CHROMIUM_REV" --jobs 4'),1)
        for ready,action,expected,success in (
                ('true','accept',['seeded'],True),
                ('true','fail-sync',['seeded','direct'],True),
                ('true','fail-restore',['direct'],True),
                ('false','leftover',['direct'],True),
                ('false','existing',[],False)):
            with self.subTest(action=action),tempfile.TemporaryDirectory() as td:
                root=Path(td); dest=root/'chromium';dest.mkdir()
                (dest/'.gclient').write_text('normal-fixed')
                bin_dir=root/'bin';bin_dir.mkdir(); ex=root/'exchange'; seeded=ex/'public-source-seed'
                seeded.mkdir(parents=True);(seeded/'receipt.json').write_text('{}')
                helper=ex/'next_build'/'source_seed.py';helper.parent.mkdir()
                helper.write_text("from pathlib import Path\nimport sys,os\np=Path(sys.argv[-2])\n"
                   "if os.environ['MODE']=='fail-restore':\n (p.parent/'.bare-input-timeout').mkdir()\n sys.exit(19)\n"
                   "p.mkdir()\n(p/'seeded').touch()\n")
                (bin_dir/'gclient').write_text("""#!/bin/sh
set -eu
test "$(cat .gclient)" = normal-fixed
test "$*" = "sync --no-history --nohooks --revision src@revision --jobs 4"
if test -e src/seeded; then
  echo seeded >> "$TRACE"
  if test "$MODE" = fail-sync; then mkdir .gclient_tmp; exit 18; fi
else
  test ! -e src
  test ! -e .gclient_tmp
  echo direct >> "$TRACE"
  mkdir src
fi
""")
                (bin_dir/'git').write_text('#!/bin/sh\necho revision\n')
                for file in bin_dir.iterdir(): file.chmod(0o755)
                if action=='existing':
                    (dest/'src').mkdir();(dest/'src'/'sentinel').touch()
                trace=root/'trace';env=dict(os.environ,CHROMIUM_REV='revision',SOURCE_READY=ready,MODE=action,
                                            TRACE=str(trace),PATH=str(bin_dir)+':'+os.environ['PATH'])
                run=subprocess.run(['bash','-eu','-o','pipefail','-c',shell.replace('/exchange',str(ex)).replace('/work/chromium',str(dest))],
                                   cwd=dest,env=env,capture_output=True,text=True)
                self.assertEqual(run.returncode==0,success,run.stderr)
                self.assertEqual(trace.read_text().splitlines() if trace.exists() else [],expected)
                self.assertFalse(list(dest.glob('.bare-stage.*')))
                if action=='existing': self.assertTrue((dest/'src'/'sentinel').exists())


if __name__=='__main__':unittest.main()
