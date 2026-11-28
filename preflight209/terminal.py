"""Resolve the encrypted terminal in this physical run before reporting completion."""
import argparse
from pathlib import Path
import sys
import shutil
import os
import json
import zipfile
import hashlib
import subprocess
import tempfile
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preflight28/bridge'))
import artifact_poll
import bridge
import storage_admission as storage
import owner
from checkpoint209 import require, digest


def final_history(env):
    """Classify only uploads known to have run. A failed GET never certifies absence."""
    first = env['R209_FIRST_UPLOAD'].split(',')
    retry = env['R209_RETRY_UPLOAD'].split(',')
    attempted, ids = [], set()
    require(len(first) == len(retry) == 4, 'Missing upload history fields')
    for gate, put, verdict, returned in (first, retry):
        require(gate in ('skipped','success','failure') and put in ('skipped','success','failure') and
                (put != 'skipped') == (gate == 'success') and verdict in ('','absent') and
                (put != 'skipped' or not (verdict or returned)) and
                (not returned or (verdict != 'absent' and returned.isascii() and returned.isdigit() and int(returned) > 0)),
                'Unrecognized physical upload history')
        if put != 'skipped':
            attempted.append((verdict, returned))
        if returned:
            ids.add(int(returned))
    require(first[0] != 'skipped' and ((retry[0] != 'skipped') == (first[2] == 'absent')) and
            len(ids) <= 1, 'Conflicting physical upload attempts or IDs')
    safe_absence = all(verdict == 'absent' and not returned for verdict, returned in attempted)
    return bool(attempted), ids, safe_absence


def observe(run, name, head, *, settled, get=None, clock=time.monotonic, sleep=time.sleep):
    end = clock()+70
    api = get if get is not None else bridge.api_before(end)
    first_negative = None
    while clock() < end:
        try:
            row = artifact_poll.lookup(run,name,api,repo=bridge.REPO,head=head)
        except (artifact_poll.UnstableInventory, bridge.TransientReadError):
            first_negative = None
        else:
            now = clock()
            if now >= end:
                break
            if row is not None:
                return row
            if first_negative is None:
                first_negative = now
            elif now-first_negative >= settled:
                return None
        sleep(min(4,max(0,end-clock())))
    raise ValueError('Original APK Artifact presence or absence did not settle')


def main():
    p = argparse.ArgumentParser()
    p.add_argument('mode', choices=['resolve','resolve-final','cache-prepare','cache-receipt'])
    p.add_argument('local', type=Path)
    p.add_argument('--id', type=int)
    args = p.parse_args()
    run = int(os.environ['GITHUB_RUN_ID'])
    slot = int(os.environ['R28_SLOT'])
    name = f'bare-personal-209-owner-{run}-a1-s{slot}'
    names = {'seal.json','Bare-Personal-2.0.9-arm64-v8a.tar.age'}
    require({p.name for p in args.local.iterdir()} == names, 'Unexpected encrypted files')
    seal = json.loads((args.local/'seal.json').read_bytes())
    cipher = args.local/'Bare-Personal-2.0.9-arm64-v8a.tar.age'
    seal_sha = digest(args.local/'seal.json')
    require(seal['schema']=='bare-personal-209-apk-seal-v1' and seal['run']==run and seal['ordinal']==slot
            and seal['attempt']==1 and seal['claim']==int(os.environ['R28_COLLECTION_CLAIM'])
            and seal['accepted_parent']==os.environ['R28_PARENT_SHA']
            and seal['producer_sha']==os.environ['GITHUB_SHA'] and seal['recipient']==os.environ['R28_OWNER_RECIPIENT']
            and cipher.is_file() and not cipher.is_symlink() and digest(cipher)==seal['sha']
            and cipher.stat().st_size==seal['bytes'], 'Mismatched encrypted APK source')
    cache_key = f"bare-personal-209-terminal-{run}-1-s{slot}-{seal['sha']}"
    print('R209_ENCRYPTED_ORIGIN',json.dumps(dict(run=run,slot=slot,seal_sha=seal_sha,cipher_sha=seal['sha'],
          cipher_bytes=seal['bytes'],claim=seal['claim'],parent=seal['accepted_parent'],head=seal['producer_sha'])))
    if args.mode=='cache-prepare':
        storage.cache_fallback(bridge.api_json,os.environ,cipher.stat().st_size+(args.local/'seal.json').stat().st_size)
        dest = Path('.r209-owner-cache')
        dest.mkdir(mode=0o700)
        for name in names:
            shutil.copy2(args.local/name,dest/name)
        bridge.output(cache_key=cache_key,seal_sha=seal_sha,cipher_sha=seal['sha'],cipher_bytes=seal['bytes'],
                      claim=seal['claim'],parent=seal['accepted_parent'],ordinal=slot)
        return
    if args.mode=='cache-receipt':
        from urllib.parse import urlencode
        query = urlencode({'key':cache_key,'ref':os.environ['GITHUB_REF'],'per_page':100})
        for wait in [0,3,6,9,15]:
            time.sleep(wait)
            data = bridge.api_json('/repos/'+bridge.REPO+'/actions/caches?'+query)
            rows = data['actions_caches']
            require(len(rows)==data['total_count'] and len(rows)<=100, 'Incomplete cache receipt listing')
            exact = [r for r in rows if r['key']==cache_key and r['ref']==os.environ['GITHUB_REF']]
            if exact:
                require(len(exact)==1 and type(exact[0]['id']) is int and exact[0]['id']>0
                        and 0<exact[0]['size_in_bytes']<=seal['bytes']+2*1024**2, 'Unconfirmed cache identity')
                status = 'cache' if os.environ.get('R209_PRIMARY_ABSENT')=='true' else 'cache-preserved-unconfirmed'
                bridge.output(cache_id=exact[0]['id'],terminal_status=status)
                print('R209_ENCRYPTED_CACHE', exact[0]['id'], cache_key, seal_sha)
                return
        raise ValueError('Cache write not independently visible')
    final = args.mode == 'resolve-final'
    attempted, ids, safe_absence = final_history(os.environ) if final else (True,{args.id} if args.id else set(),True)
    a = observe(run,name,os.environ['GITHUB_SHA'],settled=8 if final else 60)
    if a is None and (final or not ids):
        bridge.output(decision='absent' if safe_absence and not ids else 'unconfirmed')
        return
    require(a and attempted and not a['expired'] and a['workflow_run']['id'] == run
            and a['workflow_run']['head_sha'] == os.environ['GITHUB_SHA'] and
            (not ids or a['id'] in ids) and a['workflow_run']['head_branch'] == owner.BRANCH and
            a['workflow_run']['repository_id'] == a['workflow_run']['head_repository_id'] == owner.REPO_ID,
            'Encrypted terminal artifact is missing, mismatched or had no physical PUT')
    # No credential goes to the signed-URL host (curl strips Authorization on redirect).
    with tempfile.TemporaryDirectory() as d:
        path = Path(d)/'terminal.zip'
        subprocess.run(['curl','--silent','--show-error','--fail','--location','--proto','=https',
                        '--proto-redir','=https','--max-time','240','--output',str(path),'--config','-'],
                       input=('header = "Authorization: Bearer '+os.environ['GH_TOKEN']+'"\nurl = "https://api.github.com/repos/'
                              +bridge.REPO+'/actions/artifacts/'+str(a['id'])+'/zip"\n').encode(),check=True)
        require(path.stat().st_size == a['size_in_bytes'] and 'sha256:'+digest(path) == a['digest'],
                'Downloaded provider artifact receipt changed')
        expected = {p.name:p for p in args.local.iterdir()}
        require(set(expected) == {'seal.json','Bare-Personal-2.0.9-arm64-v8a.tar.age'}, 'Unexpected upload contents')
        with zipfile.ZipFile(path) as z:
            require(len(z.infolist()) == len(expected) and set(z.namelist()) == set(expected), 'Wrong owner ZIP members')
            for n, file in expected.items():
                require(z.getinfo(n).file_size == file.stat().st_size, 'Owner file size differs')
                with z.open(n) as stream:
                    h = hashlib.sha256()
                    while block := stream.read(1024**2):
                        h.update(block)
                require(h.hexdigest() == digest(file), 'Owner bytes differ')
    bridge.output(decision='present',artifact_id=a['id'],artifact_digest=a['digest'],expires_at=a['expires_at'])
    print('R209_OWNER_ARTIFACT', json.dumps({k:a[k] for k in ['id','name','size_in_bytes','digest','expires_at']}))


if __name__ == '__main__':
    main()
