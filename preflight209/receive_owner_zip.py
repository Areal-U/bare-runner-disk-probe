"""Unpack a downloaded first-attempt GitHub owner Artifact for private publication.

Supply unmodified authenticated GET responses: --run-info (run/attempts/1),
--job (the compiler job), --inventory (run/artifacts?per_page=100, optionally
gh api --paginate --slurp), --artifact (actions/artifacts/ID). --id and the
origin inputs come from the independent owner registration and original run.
The private output contains only the encrypted payload, its seal and a pickup receipt.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import tempfile
import zipfile

import owner
import owner_apk as qc
from receipt_journal import checked_artifact, one_artifact, timestamp

STEP = 'Publish owner-encrypted APK only'
RETRY = 'Retry same encrypted upload once after a complete negative receipt'


def inventory(raw):
    pages = [raw] if isinstance(raw, dict) else raw
    qc.require(isinstance(pages, list) and 0 < len(pages) <= 16, 'Incomplete Artifact inventory')
    size = pages[0]['total_count']
    rows = [a for page in pages for a in page['artifacts']]
    qc.require(type(size) is int and 0 <= size <= 1500 and all(p['total_count'] == size for p in pages) and
               all(isinstance(p['artifacts'],list) and len(p['artifacts']) <= 100 for p in pages) and
               len(rows) == size == len({a['id'] for a in rows}), 'Incomplete or changing Artifact inventory')
    return rows


def check_run(run,ctx):
    rid, head, slot = ctx['run'], ctx['producer_sha'], ctx['ordinal']
    qc.require(run['id'] == rid and run['run_attempt'] == 1 and run['head_sha'] == head and
               run['head_branch'] == owner.BRANCH and run['path'] == owner.WORKFLOW and
               run['event'] == 'workflow_dispatch' and run['repository']['id'] == run['head_repository']['id'] == owner.REPO_ID and
               owner.owner_account(run['actor']), 'Foreign workflow, actor, attempt or revision')


def source(run, job, listing, direct, ctx, aid, now):
    check_run(run,ctx)
    rid,head,slot=ctx['run'],ctx['producer_sha'],ctx['ordinal']
    qc.require(type(job['id']) is int and job['id'] > 0 and job['run_id'] == rid and job['run_attempt'] == 1 and
               job['head_sha'] == head and job['head_branch'] == owner.BRANCH and
               job['name'].split(' / ')[-1] == f'Compile APK slot {slot}', 'Unexpected original upload job')
    row = one_artifact(inventory(listing), f'bare-personal-209-owner-{rid}-a1-s{slot}')
    qc.require(row and row['id'] == direct['id'] == aid and type(aid) is int and aid > 0 and
               type(row['size_in_bytes']) is int and 0 < row['size_in_bytes'] <= qc.CIPHER_CAP + 2*1024**2 and
               row['expired'] is False and timestamp(row['created_at']) <= now < timestamp(row['expires_at']),
               'Missing, oversized, expired or wrong physical owner Artifact')
    for obj in [row, direct]:
        wf = obj.get('workflow_run')
        if wf or obj is row:
            qc.require(wf and wf['id'] == rid and wf['head_sha'] == head and wf['head_branch'] == owner.BRANCH and
                       wf['repository_id'] == wf['head_repository_id'] == owner.REPO_ID, 'Foreign Artifact repository or run')
    # May pick up as soon as the original upload step closes, including a lost response.
    created=timestamp(row['created_at'])
    steps=[s for s in job['steps'] if s['name'] in (STEP,RETRY) and s.get('completed_at') and
           s.get('conclusion') in ('success','failure','cancelled') and
           int(timestamp(s['started_at'])) <= created < int(timestamp(s['completed_at']))+1]
    qc.require(len(steps)==1,'Missing or ambiguous original upload interval')
    checked_artifact(row, rid, head, {**job,'completed_at':job.get('completed_at') or steps[0]['completed_at']},
                     steps[0]['name'], lambda unused: direct)
    return row


def take(args, clock=lambda: datetime.now(timezone.utc).timestamp()):
    ctx = qc.origin(args)
    owner_route = qc.route(qc.document(args.ticket), qc.document(args.ledger), ctx, 'cipher')
    run, job = qc.document(args.run_info), qc.document(args.job)
    row = source(run,job,qc.document(args.inventory),qc.document(args.artifact),ctx,args.id,clock())
    qc.require(stat.S_ISREG(args.zip.lstat().st_mode) and args.zip.stat().st_size == row['size_in_bytes'] and
               'sha256:' + qc.sha(args.zip) == row['digest'], 'Downloaded ZIP differs from provider digest/length')
    args.out.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    qc.require(not args.out.exists() and not args.out.is_symlink(), 'Choose a new private pickup directory')
    with tempfile.TemporaryDirectory(dir=args.out.parent) as temporary:
        stage = Path(temporary)/'pickup'
        stage.mkdir(mode=0o700)
        with zipfile.ZipFile(args.zip) as archive:
            infos = archive.infolist()
            qc.require(len(infos) == 2 and {i.orig_filename for i in infos} == {'seal.json',qc.CIPHER} and
                       all(i.filename == i.orig_filename and not i.flag_bits & 1 and
                           stat.S_IFMT(i.external_attr >> 16) in (0,stat.S_IFREG) and
                           i.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) and
                           0 < i.compress_size <= row['size_in_bytes'] for i in infos), 'Wrong encrypted ZIP members or representation')
            qc.require(0 < archive.getinfo('seal.json').file_size <= 4096, 'Wrong seal size')
            raw = archive.read('seal.json')
            seal = json.loads(raw)
            qc.check_seal(seal,ctx)
            qc.require(raw == qc.encode(seal), 'Noncanonical or duplicate seal fields')
            cipher = stage/qc.CIPHER
            qc.require(archive.getinfo(qc.CIPHER).file_size == seal['bytes'], 'Wrong archived ciphertext length')
            with archive.open(qc.CIPHER) as src, cipher.open('xb') as dst:
                left=seal['bytes']
                while left:
                    block=src.read(min(1024**2,left))
                    qc.require(block, 'Truncated archived ciphertext')
                    dst.write(block)
                    left-=len(block)
                qc.require(not src.read(1),'Excess ciphertext bytes')
            qc.check_cipher(cipher,seal)
            (stage/'seal.json').write_bytes(raw)
        taken=clock()
        qc.require(taken < timestamp(row['expires_at']), 'Provider expiry passed before full ZIP verification')
        result=dict(schema=qc.SOURCE_SCHEMA,origin=ctx,destination=owner_route['owner_destination_id'],
                    artifact_id=row['id'],artifact_name=row['name'],artifact_sha256=row['digest'][7:],
                    artifact_bytes=row['size_in_bytes'],job_id=job['id'],expires_at=row['expires_at'],
                    picked_up_at=datetime.fromtimestamp(taken,timezone.utc).isoformat().replace('+00:00','Z'),
                    seal_sha256=qc.sha(stage/'seal.json'),ciphertext_sha256=seal['sha'],bytes=seal['bytes'])
        qc.check_source(result,ctx,owner_route,seal)
        (stage/'source.json').write_bytes(qc.encode(result))
        stage.rename(args.out)
    return result


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    for key in ('run-info','job','inventory','artifact','ticket','ledger','zip','out'):
        p.add_argument('--'+key,type=Path,required=True)
    for key in ('run','slot','claim','id'):
        p.add_argument('--'+key,type=int,required=True)
    for key in ('parent','head'):
        p.add_argument('--'+key,required=True)
    print(json.dumps(take(p.parse_args()),sort_keys=True))


if __name__ == '__main__':
    main()
