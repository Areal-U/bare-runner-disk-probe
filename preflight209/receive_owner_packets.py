"""Recover a complete sealed checkpoint on the registered owner's private machine.

Use authenticated GitHub captures in --inputs: run.json, publisher.json, release.json,
assets.json (all private release-asset pages), and {id}.bin for the physical claim,
its ticket and ACK, packet-outcome, packet sidecars and data. Pin the claim ID/SHA
from the owner's registration and the outcome ID/SHA from the original private Draft.
Supply the same accepted parent SHA and frontier identity used by this exact slot.
--age-identity stays with the owner. A verified tar is a private recovery copy;
the normal canonical manifest is still required to start a continuation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

os.environ.setdefault('RUNNER_TEMP', tempfile.gettempdir())

import owner
import owner_recovery
from receive_owner_draft import full_assets
from receive_owner_zip import check_run
import owner_apk as qc

BOT = ('github-actions[bot]', 41898282)


def load_json(path, cap):
    data = owner_recovery.bounded(path, cap)
    def unique(pairs):
        record = dict(pairs)
        qc.require(len(record) == len(pairs), 'Duplicate JSON fields in owner evidence')
        return record
    return json.loads(data, object_pairs_hook=unique)


def uploaded(rows, name, cap, folder, *, start, end, uploader, retry=False):
    row = qc.collector.private_row(rows, name, retry=retry)
    if retry:
        other = [r for r in rows if r['id'] != row['id'] and r['name'] in (name, name+'-retry1')]
        qc.require((row['name'] == name and not other) or
                   (len(other) == 1 and other[0]['name'] == name and other[0]['state'] == 'starter'
                    and other[0]['size'] == 0), 'Conflicting private stage or retry residue')
    aid = row['id']
    physical_url = f'https://api.github.com/repos/{owner.REPO}/releases/assets/{aid}'
    qc.require(row['url'] == physical_url and (row['uploader']['login'], row['uploader']['id']) == uploader and
               start <= owner.instant(row['created_at']) <= owner.instant(row['updated_at']) <= end and
               type(row['size']) is int and 0 < row['size'] <= cap, 'Foreign private asset, uploader or interval')
    path = folder / f'{aid}.bin'
    qc.require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size == row['size'],
               'Missing or incomplete private asset bytes')
    return dict(id=aid, name=row['name'], bytes=row['size'], sha256=row['digest'][7:]), path


def document(row, cap):
    ref, path = row
    qc.require(qc.sha(path) == ref['sha256'], 'Private service and downloaded record digests differ')
    return load_json(path, cap)


def original(args, ctx, rows, run):
    # Bind the independently supplied physical claim and each of its two owner documents.
    genesis = qc.sha(Path(__file__).with_name('upstream-lock.json'))
    claims = [r for r in rows if r['id'] == args.claim]
    qc.require(len(claims) == 1 and claims[0]['digest'] == 'sha256:'+args.claim_sha, 'Other physical claim')
    name = claims[0]['name']
    start, end = owner.instant(run['created_at']), owner.instant(run['updated_at'])
    cr = uploaded(rows, name, 16384, args.inputs, start=start, end=end, uploader=BOT)
    claim = document(cr, 16384)
    resume = owner.cold.parse_selector(json.dumps(claim['resume'])) if 'resume' in claim else None
    suffix = '-after-' + str(resume['origin_run']) if resume else ''
    qc.require(type(claim.get('schema')) is int and claim['schema'] == 1 and name == owner.CAMPAIGN + suffix + '-claim.json' and cr[0]['id'] == args.claim and
               owner.pick(claim, ('campaign','repository_id','release_id','branch','workflow','head','genesis',
                                  'producer_attempt','origin_run','recipient','destination_commitment')) ==
               dict(campaign=owner.CAMPAIGN, repository_id=owner.REPO_ID, release_id=owner.RELEASE_ID, branch=owner.BRANCH,
                    workflow=owner.WORKFLOW, head=ctx['producer_sha'], genesis=genesis, producer_attempt=1,
                    origin_run=ctx['run'], recipient=owner.RECIPIENT, destination_commitment=owner.DESTINATION_HASH),
               'Claim does not bind this physical run, head and owner')
    account = owner.OWNER['login'], owner.OWNER['id']
    def receipt(name, prefix):
        ref, path = uploaded(rows, name, 16384, args.inputs, start=owner.instant('1970-01-01T00:00:00Z'),
                             end=start, uploader=account)
        qc.require((ref['id'], ref['sha256']) == (claim[prefix+'_asset_id'], claim[prefix+'_sha']),
                   'Receipt differs from immutable original claim')
        return document((ref, path), 16384)
    ticket = receipt(f'{owner.CAMPAIGN}-{ctx["producer_sha"]}{suffix}-ticket.json', 'ticket')
    ack = receipt(f'{owner.CAMPAIGN}-ack-{ticket["registration_nonce"]}.json', 'collector_ack')
    owner.validate_route(ticket, ack, head=ctx['producer_sha'], genesis=genesis, created=start, now=start, resume=resume)
    qc.require(ticket['collector_ack_asset_id'] in ('lookup', claim['collector_ack_asset_id']) and
               ticket['collector_ack_sha'] == claim['collector_ack_sha'] and
               ticket['collector_registration_id'] == claim['collector_registration_id'], 'Different finite receiver')
    qc.require(qc.hash_string(args.parent_identity, 64) and
               ((ctx['ordinal'] == 1 and args.parent == args.parent_identity == genesis) or
                (ctx['ordinal'] > 1 and genesis not in (args.parent, args.parent_identity))),
               'The supplied physical checkpoint parent differs from the selected slot')


def take(args):
    import checkpoint_packets as packets
    ctx = qc.origin(args)
    qc.require(not os.environ.get('GITHUB_ACTIONS') and os.environ.get('BARE_GENERATION') == '2.0.9',
               'Owner checkpoint decryption requires the independent 2.0.9 collection environment')
    rid, slot, head = ctx['run'], ctx['ordinal'], ctx['producer_sha']
    d = args.inputs
    run = load_json(d/'run.json', 256*1024)
    check_run(run, ctx)
    job = load_json(d/'publisher.json', 512*1024)
    qc.require(job['name'].split(' / ')[-1] == f'Receive private checkpoint slot {slot}' and
               job['status'] == 'completed' and job['conclusion'] in ('failure', 'cancelled', 'timed_out') and
               job['run_id'] == rid and job['run_attempt'] == 1 and job['head_sha'] == head and
               job['head_branch'] == owner.BRANCH and type(job['id']) is int and job['id'] > 0,
               'The original packet publisher has not closed with a recoverable failure')
    release = load_json(d/'release.json', 8*1024**2)
    qc.require(release['id'] == owner.RELEASE_ID and release['draft'] is True and owner.owner_account(release['author'])
               and release['url'] == f'https://api.github.com/repos/{owner.REPO}/releases/{owner.RELEASE_ID}',
               'Different owner or original private Draft')
    rows = full_assets(load_json(d/'assets.json', 16*1024**2), release)
    original(args, ctx, rows, run)
    stem = f'r209-{rid}-a1-s{slot:02}-'
    canonical = stem + 'manifest.json'
    qc.require(not any(r['name'] in (canonical, canonical+'-retry1') and r['state'] == 'uploaded' for r in rows),
               'A canonical publication already exists; reconcile that immutable manifest')
    def stage(name, limit):
        return uploaded(rows, stem+name, limit, d, start=owner.instant(job['started_at']),
                        end=owner.instant(job['completed_at']), uploader=BOT, retry=True)
    root = stage('packet-outcome.json', 65536)
    qc.require((root[0]['id'], root[0]['sha256']) == (args.outcome_id, args.outcome_sha), 'Other private outcome')
    outcome = document(root, 65536)
    qc.require(root[1].read_bytes() == json.dumps(outcome, sort_keys=True).encode('ascii'),
               'Outcome bytes differ from the original packet source form')
    total = outcome['sealed_bytes']
    expected_context = dict(schema='bare-personal-209-checkpoint-v1', key=f'bare-personal-209-{rid}-1-checkpoint-s{slot}',
                            run=rid, attempt=1, ordinal=slot, producer_sha=head, parent_sha=args.parent,
                            parent_identity=args.parent_identity, status='candidate')
    qc.require(all(type(outcome.get(k)) is type(v) and outcome[k] == v for k,v in expected_context.items()) and
               type(total) is int and 0 < total <= owner_recovery.b.CAP + 16*1024**2 and
               qc.hash_string(outcome['sealed_sha'],64) and owner_recovery.RECIPIENT == owner.RECIPIENT,
               'Wrong checkpoint or owner on the private packet stage')
    owner_recovery.checked(outcome['owner_recovery'], outcome, owner.RECIPIENT, args.claim, outcome['recipient_fpr'])
    count = (total + packets.PACKET_BYTES-1) // packets.PACKET_BYTES
    expected = {'packet-outcome.json'} | {f'packet-{i:03}{ext}' for i in range(count) for ext in ('','.json')}
    names = {r['name'][len(stem):].removesuffix('-retry1') for r in rows if r['name'].startswith(stem+'packet-')}
    qc.require(names == expected, 'Private packet stage has missing or unexpected members')
    key_context = {k:outcome[k] for k in owner_recovery.FIELDS}
    used_caches = set()
    private_parent = args.out.parent.stat()
    qc.require(stat.S_ISDIR(private_parent.st_mode) and private_parent.st_uid == os.getuid() and
               not private_parent.st_mode & 0o077, 'Output requires an owner-private directory')
    with tempfile.TemporaryDirectory(prefix='.r209-owner-', dir=args.out.parent) as scratch:
        work = Path(scratch)
        cipher = work/'checkpoint.cms'
        with cipher.open('xb') as sealed:
            for i in range(count):
                name = f'packet-{i:03}'
                ref, packet = stage(name, packets.PACKET_BYTES)
                sidecar_row = stage(name+'.json', 96*1024)
                sidecar = document(sidecar_row, 96*1024)
                qc.require(sidecar_row[1].read_bytes() == packets.data(sidecar), 'Noncanonical private receipt')
                piece, cache = sidecar['piece'], sidecar['cache']
                offset = i * packets.PACKET_BYTES
                size = min(total-offset, packets.PACKET_BYTES)
                qc.require(sidecar['schema'] == 'bare-personal-209-private-packet-v1' and
                           sidecar['release'] == owner.RELEASE_ID and sidecar['stage'] == ref and
                           set(sidecar) == {'schema','release','piece','cache','stage'} and
                           set(piece) == {'schema','claim','index','count','offset','bytes','sha256','outcome','meter_barrier'} and
                           all(type(piece[k]) is int for k in ('claim','index','count','offset','bytes')) and
                           piece['schema'] == 'r209-checkpoint-piece-v1' and piece['outcome'] == outcome and
                           (piece['index'], piece['claim'], piece['count'], piece['offset'], piece['bytes'], piece['sha256']) ==
                           (i, args.claim, count, offset, size, ref['sha256']) and ref['bytes'] == size and
                           type(piece['meter_barrier']) is bool and type(cache['id']) is int and cache['id'] > 0 and
                           cache['id'] not in used_caches and cache['ref'] == 'refs/heads/'+owner.BRANCH and
                           packets.service_row(cache) == cache and cache['version'] == packets.version('packet') and
                           cache['key'] == packets.generation_key(key_context,args.claim,i) and
                           cache['size_in_bytes'] <= packets.archive_bound(packets.PACKET_BYTES) and sealed.tell() == offset,
                           'Foreign, overlapping or inconsistent private packet receipt')
                used_caches.add(cache['id'])
                hasher = hashlib.sha256()
                with packet.open('rb') as source:
                    for block in iter(lambda: source.read(4*1024**2), b''):
                        hasher.update(block)
                        sealed.write(block)
                qc.require(hasher.hexdigest() == ref['sha256'], 'Private packet bytes differ from the physical asset')
        digest = owner_recovery.decrypt_checkpoint(work, outcome, args.age_identity, cipher, args.out,
                    run=rid, ordinal=slot, head=head, parent_sha=args.parent, claim_id=args.claim)
    return dict(status='private-owner-copy', run=rid, ordinal=slot, claim=args.claim, packet_outcome=args.outcome_id,
                publisher_job=job['id'], packets=count, bytes=outcome['bytes'], sha256=digest, canonical_manifest=False)


if __name__ == '__main__':
    os.umask(0o077)
    os.environ['BARE_GENERATION'] = '2.0.9'
    p = argparse.ArgumentParser(description=__doc__)
    for field in ('inputs','age-identity','out'):
        p.add_argument('--'+field, type=Path, required=True)
    for field in ('claim','run','slot','outcome-id'):
        p.add_argument('--'+field, type=int, required=True)
    for field in ('head','parent','parent-identity','claim-sha','outcome-sha'):
        p.add_argument('--'+field, required=True)
    print(json.dumps(take(p.parse_args()), sort_keys=True))
