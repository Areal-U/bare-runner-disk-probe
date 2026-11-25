#!/usr/bin/env python3
"""Issue or consume one immutable same-repository public Chromium input, using GETs only."""
import argparse
import base64
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from urllib.request import Request, urlopen

sys.path.insert(0,str(Path(__file__).resolve().parent))
import source_seed as seed
from source_seed import source

REPO = 'Areal-U/bare-runner-disk-probe'
REPO_ID = 1450926240
REF = 'bare-next-build-prep-20261125'
WORKFLOW = '.github/workflows/bare-disk-probe.yml'
GIB = 1024**3
# Direct R27 source checkout/deps consumed 44.5 GB. Preserve the normal 20 GiB floor
# as well as temporary source.pack/ZIP space before choosing this optional route.
DIRECT_FLOOR = 45*GIB + 20*GIB
require = source.require


def epoch(value):
    parsed = datetime.fromisoformat(value.replace('Z','+00:00'))
    require(parsed.tzinfo is not None, 'UTC timestamp required')
    return parsed.timestamp()


def get(path):
    if not os.environ.get('GH_TOKEN'):
        req = Request(f'https://api.github.com/repos/{REPO}/{path}',headers={'User-Agent':'bare-next-public-source'})
        with urlopen(req,timeout=25) as response:
            return json.load(response)
    cmd = ['gh','api','--method','GET',f'repos/{REPO}/{path}']
    return json.loads(subprocess.check_output(cmd, timeout=25))


def successful_jobs(run, head, mode, names, metadata=get):
    data = metadata(f'actions/runs/{run}/attempts/1')
    require(data['id']==run and data['head_sha']==head and data['head_branch']==REF and
            data['actor']['id']==292261483 and data['repository']['id']==data['head_repository']['id']==REPO_ID and
            data['run_attempt']==1 and data['event']=='workflow_dispatch' and data['path']==WORKFLOW and
            data['display_title']==f'Bare next-build trial {mode} {head}' and
            data['status']=='completed' and data['conclusion']=='success', 'Not the approved successful source-only run')
    jobs=metadata(f'actions/runs/{run}/attempts/1/jobs?per_page=100')
    require(len(jobs['jobs'])==jobs['total_count']<=100, 'Incomplete source producer job inventory')
    records={}
    for name in names:
        rows=[j for j in jobs['jobs'] if j['name']==name]
        require(len(rows)==1 and rows[0]['conclusion']=='success' and rows[0]['head_sha']==head and
                rows[0]['run_id']==run and rows[0]['run_attempt']==1,'Unexpected physical source producer job')
        records[name]=rows[0]['id']
    return records


SOURCE_JOBS = ('source-comparison / prepare', 'source-comparison / compare')
ANDROID_JOB = 'android-source-import / full-android-checkout'
# Fastest of the directly observed complete fetch step durations on R27 and R28.
DIRECT_SECONDS = min(803, 784, 508)


def job_log(job):
    path=f'repos/{REPO}/actions/jobs/{job}/logs'
    if os.environ.get('GH_TOKEN') or os.environ.get('GH_HOST') or shutil.which('gh') and subprocess.run(
            ['gh','auth','status','--hostname','github.com'],capture_output=True,timeout=8).returncode==0:
        return subprocess.check_output(['gh','api','--method','GET',path],timeout=45).decode('utf-8-sig')
    req=Request('https://api.github.com/'+path,headers={'User-Agent':'bare-next-public-source'})
    with urlopen(req,timeout=45) as stream:
        return stream.read().decode('utf-8-sig')


def log_reader(directory):
    if directory is None:
        return job_log
    def captured(job):
        record=json.loads((directory/f'{job}.json').read_bytes())
        require(record['repo_full_name']==REPO and record['job_id']==job
                and isinstance(record['log'],str)
                and hashlib.sha256(record['log'].encode()).hexdigest()==record['log_sha256'],
                'Different owner-captured GitHub job log')
        return record['log']
    return captured


def logged(log, key):
    # Ignore echoed Python/shell lines, annotations and markers from other jobs.
    pattern=r'^(?:[0-9T:.+Z-]+ )?'+re.escape(key)+r' ([^\r\n]+)\r?$'
    matches=re.findall(pattern,log,re.MULTILINE)
    require(len(matches)==1, f'Missing or ambiguous hosted measurement {key}')
    return json.loads(matches[0])


def qualification(result, fetch, floor, receipt, uses):
    expected=receipt['spec']
    require(result['chromium']==expected['CHROMIUM_REV'] and result['depot']==expected['DEPOT_REV']
            and result['chromium_tree']==receipt['tree'] and result['root_extra_pack_bytes']==0
            and result['before']['packs']==result['after']['packs'] and result['before']['packs']
            and all(result[which]['head']==expected['CHROMIUM_REV'] and result[which]['tree']==receipt['tree']
                    for which in ('before','after'))
            and result['android_dependency_entries']>100 and result['android_sdk_files'] and result['android_ndk_files']
            and re.fullmatch('[0-9a-f]{40}',result['v8']) and result['compiled'] is False and result['runhooks'] is False
            and result['source_pack_sha256']==receipt['sha256'] and result['source_artifact_id']>0
            and floor['free']>=20*GIB and floor['inodes']>=20000,'Missing full Linux+Android qualification')
    full=result['full_seeded_fetch_s']
    require(all(type(v) in (int,float) and math.isfinite(v) and v>0 for v in (full,fetch)),
            'Missing full-solution elapsed time')
    overhead=sum(receipt[k] for k in ('make_s','upload_s','producer_finish_to_receiver_transfer_start_s'))
    # Same 1,445,132,120-byte hosted pack on local scratch, ZIP stored-size identical:
    # explicit outer+inner validation versus extraction alone added 2.08, 2.83, 4.18s.
    # The hosted download step already includes extraction. Reserve only the incremental work.
    local_margin=max(1,math.ceil(5*receipt['bytes']/1_445_132_120))
    gain=uses*(DIRECT_SECONDS-full-fetch-local_margin)-overhead
    require(gain>0, 'Measured complete solution does not beat the fastest observed direct fetch')
    return round(gain,3)


def source_asset(row, run, head):
    require(row['workflow_run']['id']==run and row['workflow_run']['head_sha']==head and
            row['workflow_run']['repository_id']==row['workflow_run']['head_repository_id']==REPO_ID and
            row['name']==f'bare-public-git-{run}-1' and row['expired'] is False and
            type(row['id']) is int and row['id']>0 and re.fullmatch(r'sha256:[0-9a-f]{64}',row['digest']) and
            0 < row['size_in_bytes'] <= source.CAP['chromium'],'Foreign or expired source artifact')
    return {k:row[k] for k in ('id','name','size_in_bytes','digest','expires_at')}


def economics(receipt, n):
    values=[receipt[k] for k in ('direct_s','seeded_s','download_s','make_s','upload_s','producer_finish_to_receiver_transfer_start_s')]
    require(all(type(v) in (int,float) and math.isfinite(v) and v>=0 for v in values),'Invalid measured timing')
    direct,seeded,download,make,upload,handoff=values
    return n*(direct-seeded-download)-make-upload-handoff


def read_source(run, head, pins, metadata=get, read_log=job_log):
    require(re.fullmatch('[0-9a-f]{40}',head),'Expected exact reviewed source producer revision')
    jobs=successful_jobs(run,head,'source-chromium',SOURCE_JOBS,metadata)
    comparison_log=read_log(jobs[SOURCE_JOBS[1]])
    report=logged(comparison_log,'BARE_SOURCE_COMPARISON')
    seed.check(report,pins['CHROMIUM_REV'])
    require(all(report['spec'][k]==v for k,v in pins.items()), 'Selected source pins differ')
    assets=metadata(f'actions/runs/{run}/artifacts?per_page=100')
    require(len(assets['artifacts'])==assets['total_count']<=100, 'Incomplete producer artifact inventory')
    rows=[r for r in assets['artifacts'] if r['name']==f'bare-public-git-{run}-1']
    require(len(rows)==1,'Missing or ambiguous source artifact')
    asset=source_asset(rows[0],run,head)
    require(asset==source_asset(metadata(f'actions/artifacts/{asset["id"]}'),run,head),'Source metadata changed')
    return report,jobs,asset,hashlib.sha256(comparison_log.encode()).hexdigest()


def receipt(run, head, pins, metadata=get, read_log=job_log):
    report,jobs,asset,_=read_source(run,head,pins,metadata,read_log)
    attempt=metadata(f'actions/runs/{run}/attempts/1')
    asset=dict(asset,workflow_run=run,attempt=1,producer_sha=head,producer_job=jobs[SOURCE_JOBS[0]],
               producer_workflow_id=attempt['workflow_id'])
    return {**{k:report[k] for k in ('spec','tree','sha256','bytes','files','checkout_bytes')},'artifact':asset}


def reviewed_file(path, sha, metadata):
    row=metadata(f'contents/{path}?ref={sha}')
    require(row['encoding']=='base64' and row['type']=='file','Missing reviewed source qualification input')
    return base64.b64decode(row['content']).decode()


def issue(campaign, run, head, android_run, android_head, needed_until, slots, pins,
          metadata=get, read_log=job_log, now=None):
    require(re.fullmatch(r'bare-personal-204-r[1-9][0-9]{1,3}(?:-[a-z0-9]{1,12})?',campaign) and
            campaign!='bare-personal-204-r28','Only a separate owner-reviewed campaign may opt in')
    require(all(re.fullmatch('[0-9a-f]{40}',s) for s in (head,android_head)) and 2<=slots<=12,
            'Need exact reviewed producer revisions and at least two planned uses')
    report,jobs,asset,comparison_log_sha256=read_source(run,head,pins,metadata,read_log)
    require(report['seeded_new_pack_bytes']==0 and economics(report,slots)>0, 'No verified saving at the planned reuse count')
    android=successful_jobs(android_run,android_head,'source-android',(ANDROID_JOB,),metadata)
    normal = reviewed_file('.github/workflows/bare-arm64-probe.yml',android_head,metadata)
    prior = json.loads(reviewed_file('next_build/trials/android-source-receipt.json',android_head,metadata))
    for key, value in pins.items():
        require(re.findall(r'^      '+key+r': ([0-9a-f]{40})$',normal,re.M)==[value],
                'Qualified normal builder used different pins')
    android_log=read_log(android[ANDROID_JOB])
    qresult=logged(android_log,'BARE_ANDROID_SOURCE_RESULT')
    qfetch=logged(android_log,'BARE_ANDROID_ARTIFACT_FETCH_S')
    qfloor=logged(android_log,'BARE_ANDROID_SOURCE_FLOOR')
    require(all(prior[k]==report[k] for k in ('spec','tree','sha256','bytes','files','checkout_bytes'))
            and prior['artifact']['id']==qresult['source_artifact_id'], 'Qualified source bytes or producer identity differ')
    net=qualification(qresult,qfetch,qfloor,report,slots)
    proof=dict(run=android_run,head=android_head,job=android[ANDROID_JOB],result=qresult,fetch=qfetch,floor=qfloor,
               direct_best_s=DIRECT_SECONDS,net_s=net,log_sha256=hashlib.sha256(android_log.encode()).hexdigest(),qualified_artifact=prior['artifact'])
    now=time.time() if now is None else now
    # Reserve 350 min of computation and 92 min for the original publisher and control tail
    # per interval, and 45 min for source at the last planned slot. Recheck before use.
    require(now + (442*(slots-1)+45)*60 <= epoch(needed_until) <= epoch(asset['expires_at']),
            'The planned uses do not fit inside this actual Artifact lifetime')
    return dict(schema=1, qualification=proof, campaign=campaign, source_run=run, source_head=head, producer_jobs=jobs, artifact=asset,
                needed_until=needed_until, planned_slots=slots, comparison_log_sha256=comparison_log_sha256, receipt=report)


def usable(plan, env, campaign, metadata=get, now=None):
    now=time.time() if now is None else now
    slot=int(env['SEGMENT_ORDINAL'])
    require(campaign!='bare-personal-204-r28' and campaign==plan['campaign'] and
            env['GITHUB_REPOSITORY']==REPO and env['GITHUB_REF']=='refs/heads/bare-coexist-v2.0.4'
            and env['GITHUB_RUN_ATTEMPT']=='1' and env['GITHUB_ACTOR']=='Areal-U' and
            env['CHECKPOINT_BACKEND']=='draft' and env['VERIFY_FRONTIER_ONLY']=='false' and
            env['R28_PARENT_RUN']=='' and 1<=slot<=plan['planned_slots']<=12 and plan['planned_slots']>=2
            and env['R28_COLLECTION_CLAIM'].isdigit() and int(env['R28_COLLECTION_CLAIM'])>0,
            'Outside selected initial campaign slots')
    event=json.loads(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    require(event['inputs'].get('mode','build-apk')=='build-apk' and str(event['inputs'].get('build_segments','12'))=='12', 'Only first campaign computation')
    r=plan['receipt']
    seed.check(r,env['CHROMIUM_REV'])
    require(plan['schema']==1 and all(r['spec'][k]==env[k] for k in ('DEPOT_REV','BARE_REV','CHROMIUM_REV'))
            and r['seeded_new_pack_bytes']==0 and economics(r,plan['planned_slots'])>0, 'Input or benefit changed')
    q=plan['qualification']
    require(q['qualified_artifact']['id']==q['result']['source_artifact_id'] and q['direct_best_s']==DIRECT_SECONDS and q['net_s']==qualification(q['result'],q['fetch'],q['floor'],r,plan['planned_slots']),
            'Full-solution qualification changed')
    a=plan['artifact']
    require(now+(442*(plan['planned_slots']-slot)+45)*60<=epoch(plan['needed_until'])<=
            min(epoch(a['expires_at']),int(env['R28_STORAGE_UNTIL'])),
            'Insufficient lifetime for the remaining planned uses')
    require(source_asset(metadata(f'actions/artifacts/{a["id"]}'),plan['source_run'],plan['source_head'])==a,
            'Different immutable Artifact at use')
    require(0<int(env['R28_STORAGE_CEILING']) and a['size_in_bytes']<=int(env['R28_STORAGE_CEILING']),
            'No valid current free-storage ceiling')
    return r


def bounded_copy(src, dst, n):
    digest=hashlib.sha256()
    left=n
    while left:
        block=src.read(min(left,1024**2))
        require(block,'Incomplete source payload')
        dst.write(block);digest.update(block);left-=len(block)
    require(src.read(1)==b'', 'Source exceeds expected size')
    return digest.hexdigest()


def stage(plan, exchange, env, campaign):
    r=usable(plan,env,campaign)
    s=os.statvfs(exchange)
    a=plan['artifact']
    require(s.f_bavail*s.f_frsize>=DIRECT_FLOOR+2*max(r['bytes'],a['size_in_bytes']) and s.f_favail>=2*r['files']+20000,
            'Insufficient host space/inodes alongside the normal dependency checkout')
    dest=exchange/'public-source-seed'
    require(not os.path.lexists(dest), 'Seed directory already exists')
    with tempfile.TemporaryDirectory(dir=exchange,prefix='.source-stage-') as td:
        work=Path(td)
        z=work/'source.zip'
        cmd=['gh','api','--method','GET',f'repos/{REPO}/actions/artifacts/{a["id"]}/zip']
        with subprocess.Popen(cmd,stdout=subprocess.PIPE) as fetch:
            try:
                with z.open('xb') as f:
                    outer=bounded_copy(fetch.stdout,f,a['size_in_bytes'])
            finally:
                fetch.stdout.close()
                if fetch.poll() is None and 'outer' not in locals():
                    fetch.kill()
            require(fetch.wait(timeout=15)==0 and 'sha256:'+outer==a['digest'],'Wrong source ZIP')
        with zipfile.ZipFile(z) as archive:
            files=archive.infolist()
            require(len(files)==1 and files[0].filename=='source.pack' and files[0].file_size==r['bytes'],
                    'Unexpected source-only transfer')
            with archive.open(files[0]) as data,(work/'source.pack').open('xb') as f:
                require(bounded_copy(data,f,r['bytes'])==r['sha256'],'Wrong source pack digest')
        z.unlink()
        (work/'receipt.json').write_text(json.dumps(r))
        # Only the verified public bytes and receipt are shared with the container builder.
        work.chmod(0o755)
        for p in work.iterdir(): p.chmod(0o444)
        work.rename(dest)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    cmds=p.add_subparsers(dest='mode',required=True)
    make=cmds.add_parser('issue',help='Generate an uninstalled optional manifest from a completed hosted run')
    for k in ('campaign','source_run','tested_head','android_run','android_head','needed_until','slots'):
        make.add_argument(k)
    read=cmds.add_parser('receipt',help='Emit an exact public producer input for a new full-solution qualification')
    read.add_argument('source_run',type=int);read.add_argument('tested_head')
    for sub in (read,make):
        sub.add_argument('--owner-captured-job-logs',type=Path,help='Exact responses collected with the authenticated GitHub connector by this operator')
    imp=cmds.add_parser('stage')
    imp.add_argument('manifest',type=Path);imp.add_argument('exchange',type=Path)
    args=p.parse_args()
    if args.mode=='receipt':
        print(json.dumps(receipt(args.source_run,args.tested_head,source.pins(),read_log=log_reader(args.owner_captured_job_logs)),indent=2,sort_keys=True))
    elif args.mode=='issue':
        spec=issue(args.campaign,int(args.source_run),args.tested_head,int(args.android_run),args.android_head,
                   args.needed_until,int(args.slots),source.pins(),read_log=log_reader(args.owner_captured_job_logs))
        print(json.dumps(spec,indent=2,sort_keys=True))
    else:
        path=Path(__file__).resolve().parents[1]/'preflight28/control'
        sys.path.insert(0,str(path))
        from registration import CAMPAIGN
        stage(json.loads(args.manifest.read_bytes()),args.exchange,os.environ,CAMPAIGN)


if __name__=='__main__':
    try:main()
    except (KeyError,ValueError,OSError,zipfile.BadZipFile,subprocess.SubprocessError) as exc:
        raise SystemExit('Public source input declined: '+str(exc))
