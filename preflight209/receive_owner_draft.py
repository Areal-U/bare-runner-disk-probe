"""Receive three physical owner-Draft assets produced by the same run's independent cache recovery.

--inputs is a signed-in capture of run.json, worker.json, worker.log,
recovery.json, recovery.log, release.json, assets.json (complete per_page=100
release assets page(s)), and one {numeric-asset-id}.bin for each of the three
selected assets. Keep this folder private. --ticket, --ledger and origin match
the registered terminal. The output can be used by owner_apk.py open.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

import owner
import owner_apk as qc
from receive_owner_zip import check_run
from receipt_journal import timestamp


WORKER_STEP='Find the exact physical immutable cache after the save attempt'
RECOVERY_STEP='Deposit and read back the original sealed pair'
SCHEMA='bare-personal-209-private-cache-receipt-v1'


def job_note(job, logfile, ctx, name, step, marker):
    qc.require(job['name'].split(' / ')[-1] == name and job['run_id'] == ctx['run'] and job['run_attempt'] == 1 and
               job['head_branch'] == owner.BRANCH and job['head_sha'] == ctx['producer_sha'] and
               job['status'] == 'completed' and type(job['id']) is int and job['id'] > 0, 'Foreign recovery or source job')
    intervals=[s for s in job['steps'] if s['name']==step and s['conclusion']=='success']
    qc.require(len(intervals)==1 and intervals[0].get('completed_at'), 'Required recovery step did not succeed')
    notes=[]
    with logfile.open(encoding='utf-8-sig') as log:
        for line in log:
            parts=line.rstrip('\r\n').split(' ',2)
            if len(parts)==3 and parts[1]==marker:
                instant=timestamp(parts[0])
                qc.require(int(timestamp(intervals[0]['started_at'])) <= instant < int(timestamp(intervals[0]['completed_at']))+1,
                           'Receipt note outside physical original step')
                notes.append(parts[2])
    qc.require(len(notes)==1,'Missing or duplicate physical receipt log')
    return notes[0]


def full_assets(raw, release):
    pages = [raw] if isinstance(raw,list) and (not raw or isinstance(raw[0],dict)) else raw
    qc.require(isinstance(pages,list) and 0<len(pages)<=11 and all(isinstance(p,list) for p in pages) and
               all(len(p)==100 for p in pages[:-1]) and len(pages[-1])<100,'Incomplete original private Draft inventory')
    rows=[a for group in pages for a in group]
    ids={a['id']:a for a in rows}
    qc.require(len(rows)==len(ids) and all(ids.get(r['id'],{}).get('name')==r['name'] for r in release['assets']),
               'Inconsistent private Draft inventory')
    return rows


def asset(rows, name, cap, inputs):
    row=qc.collector.private_row(rows,name,retry=True)
    other=[r for r in rows if r['name'] in (name,name+'-retry1') and r['id']!=row['id']]
    qc.require((row['name']==name or len(other)==1) and
               all(r['name']==name and r['state']=='starter' and r['size']==0 for r in other),
               'Conflicting private Draft residue')
    path=inputs/(str(row['id'])+'.bin')
    qc.require(stat.S_ISREG(path.lstat().st_mode) and 0<path.stat().st_size==row['size']<=cap and
               row['digest']=='sha256:'+qc.sha(path), 'Private asset bytes differ from physical service digest')
    return dict(id=row['id'],name=row['name'],bytes=row['size'],sha256=row['digest'][7:]),path


def take(args):
    ctx=qc.origin(args)
    register=qc.route(qc.document(args.ticket),qc.document(args.ledger),ctx,'cipher')
    d=args.inputs
    check_run(qc.document(d/'run.json'),ctx)
    worker=qc.document(d/'worker.json')
    recovery=qc.document(d/'recovery.json')
    qc.require(recovery['conclusion']=='success' and worker['id']!=recovery['id'], 'Independent recovery job did not succeed')
    cache_note=job_note(worker,d/'worker.log',ctx,f"Compile APK slot {ctx['ordinal']}",WORKER_STEP,'R209_ENCRYPTED_CACHE')
    outcome=json.loads(job_note(recovery,d/'recovery.log',ctx,f"Recover original encrypted cache slot {ctx['ordinal']}",
                               RECOVERY_STEP,'R209_PRIVATE_TERMINAL'))
    release=qc.document(d/'release.json')
    qc.require(release['id']==owner.RELEASE_ID and release['draft'] is True and
               release['url']==f'https://api.github.com/repos/{owner.REPO}/releases/{owner.RELEASE_ID}',
               'Different original private Draft')
    rows=full_assets(qc.document(d/'assets.json'),release)
    stem=f"r209-{ctx['run']}-a1-s{ctx['ordinal']:02}-"
    ref,receipt_path=asset(rows,stem+'apk-owner-receipt.json',4096,d)
    seal_ref,seal_path=asset(rows,stem+'apk-seal.json',4096,d)
    cipher_ref,cipher_path=asset(rows,stem+'apk.age',qc.CIPHER_CAP,d)
    seal=qc.document(seal_path)
    qc.check_seal(seal,ctx)
    qc.require(seal_path.read_bytes()==qc.encode(seal),'Noncanonical Private Draft seal')
    qc.check_cipher(cipher_path,seal)
    cache=qc.document(receipt_path)['source_cache']
    key=f"bare-personal-209-terminal-{ctx['run']}-1-s{ctx['ordinal']}-{seal['sha']}"
    qc.require(type(cache['id']) is int and cache['id']>0 and cache==dict(id=cache['id'],key=key,ref='refs/heads/'+owner.BRANCH)
               and cache_note==f"{cache['id']} {key} {seal_ref['sha256']}", 'Original physical cache source differs')
    expected=dict(schema=SCHEMA,origin=ctx,repository_id=owner.REPO_ID,release_id=owner.RELEASE_ID,
                  recipient=owner.RECIPIENT,destination_commitment=owner.DESTINATION_HASH,source_cache=cache,
                  cipher=cipher_ref,seal=seal_ref)
    qc.require(qc.encode(qc.document(receipt_path))==qc.encode(expected) and qc.encode(outcome)==qc.encode(dict(
               run=ctx['run'],ordinal=ctx['ordinal'],claim=ctx['claim'],receipt_id=ref['id'],receipt_sha=ref['sha256'],
               cipher_id=cipher_ref['id'],seal_id=seal_ref['id'])), 'Recovered private receipt or attested IDs differ')
    result=dict(schema=qc.DRAFT_SOURCE_SCHEMA,origin=ctx,destination=register['owner_destination_id'],
                repository_id=owner.REPO_ID,release_id=owner.RELEASE_ID,job_id=recovery['id'],worker_id=worker['id'],
                receipt_id=ref['id'],receipt_sha256=ref['sha256'],cache_id=cache['id'],cache_key=key,
                cipher_id=cipher_ref['id'],seal_id=seal_ref['id'],seal_sha256=seal_ref['sha256'],
                ciphertext_sha256=cipher_ref['sha256'],bytes=cipher_ref['bytes'])
    qc.check_source(result,ctx,register,seal)
    args.out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    qc.require(not args.out.exists() and not args.out.is_symlink(),'Choose a new private pickup directory')
    with tempfile.TemporaryDirectory(dir=args.out.parent) as t:
        stage=Path(t)/'pickup';stage.mkdir(mode=0o700)
        shutil.copyfile(cipher_path,stage/qc.CIPHER)
        qc.check_cipher(stage/qc.CIPHER,seal)
        (stage/'seal.json').write_bytes(qc.encode(seal))
        (stage/'source.json').write_bytes(qc.encode(result))
        stage.rename(args.out)
    return result


if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('inputs','ticket','ledger','out'):
        p.add_argument('--'+key,type=Path,required=True)
    for key in ('run','slot','claim'):
        p.add_argument('--'+key,type=int,required=True)
    for key in ('head','parent'):
        p.add_argument('--'+key,required=True)
    print(json.dumps(take(p.parse_args()),sort_keys=True))
