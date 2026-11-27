"""Deliver an already sealed pair from this physical worker's exact cache."""
import io
import json
import os
from pathlib import Path
import stat
import sys
import time
from types import SimpleNamespace
from urllib.parse import urlencode

import owner
import owner_apk
from owner import require

import artifact_poll
import bridge
import normal
import recover
import terminal_draft


SAVE_STEP = 'Save exact original ciphertext and seal for independent fallback'
RECEIPT_SCHEMA = 'bare-personal-209-private-cache-receipt-v1'
SUFFIXES = ('apk.age', 'apk-seal.json', 'apk-owner-receipt.json')


def check_origin(env):
    ctx = owner_apk.origin(SimpleNamespace(run=int(env['GITHUB_RUN_ID']), claim=int(env['CLAIM']),
                                           slot=int(env['R28_SLOT']), head=env['GITHUB_SHA'],
                                           parent=env['R28_PARENT_SHA']))
    require(env['GITHUB_JOB'] == 'deliver-cached-apk' and env['GITHUB_RUN_ATTEMPT'] == '1'
            and env['GITHUB_REPOSITORY'] == owner.REPO and env['GITHUB_REF'] == 'refs/heads/' + owner.BRANCH
            and env['GITHUB_ACTOR'] == owner.OWNER['login'] and env['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
            and env['CLAIM'] == env['REGISTERED_CLAIM']
            and owner_apk.hash_string(env['SEAL_SHA'], 64) and owner_apk.hash_string(env['CIPHER_SHA'], 64)
            and str(int(env['CACHE_ID'])) == env['CACHE_ID'] and int(env['CACHE_ID']) > 0
            and 0 < int(env['CIPHER_BYTES']) <= owner_apk.CIPHER_CAP,
            'Foreign physical origin, claim or sealed bytes')
    key = f"bare-personal-209-terminal-{ctx['run']}-1-s{ctx['ordinal']}-{env['CIPHER_SHA']}"
    require(env['CACHE_KEY'] == key, 'Wrong terminal cache for this worker')
    return ctx


def check_service(env, ctx, get):
    run, slot = ctx['run'], ctx['ordinal']
    name = f'bare-personal-209-owner-{run}-a1-s{slot}'
    require(artifact_poll.lookup(run, name, get, repo=owner.REPO, head=ctx['producer_sha']) is None,
            'An original owner Artifact exists: reconcile it first')
    key, ref = env['CACHE_KEY'], env['GITHUB_REF']
    query = urlencode(dict(key=key, ref=ref, per_page=100))
    rows = get(f'/repos/{owner.REPO}/actions/caches?{query}')
    items = rows['actions_caches']
    require(len(items) == rows['total_count'] <= 100, 'Incomplete exact source cache inventory')
    exact = [r for r in items if r['key'] == key and r['ref'] == ref]
    require(len(exact) == 1 and type(exact[0]['id']) is int and exact[0]['id'] == int(env['CACHE_ID'])
            and 0 < exact[0]['size_in_bytes'] <= int(env['CIPHER_BYTES']) + 2 * 1024**2,
            'Source cache disappeared or changed identity')
    jobs = recover.inventory(f'actions/runs/{run}/attempts/1/jobs', 'jobs')
    suffix = f' / Compile APK slot {slot}'
    workers = [j for j in jobs if j['name'].endswith(suffix) and j.get('conclusion') != 'skipped']
    require(len(workers) == 1 and workers[0]['run_id'] == run and workers[0]['run_attempt'] == 1
            and workers[0]['head_sha'] == ctx['producer_sha'] and workers[0]['status'] == 'completed',
            'Missing or ambiguous physical producer')
    recover.same_time_as_upload(exact[0], workers[0], SAVE_STEP)


def check_files(folder, env, ctx):
    require(not folder.is_symlink() and folder.is_dir() and
            {p.name for p in folder.iterdir()} == {owner_apk.CIPHER, 'seal.json'},
            'Unexpected cache contents')
    seal_file, cipher = folder/'seal.json', folder/owner_apk.CIPHER
    require(stat.S_ISREG(seal_file.lstat().st_mode) and 0 < seal_file.stat().st_size <= 4096,
            'Invalid seal file')
    raw = seal_file.read_bytes()
    seal = json.loads(raw)
    owner_apk.check_seal(seal, ctx)
    require(owner.sha(raw) == env['SEAL_SHA'] and seal['sha'] == env['CIPHER_SHA']
            and seal['bytes'] == int(env['CIPHER_BYTES']), 'Conflicting worker or cache seals')
    owner_apk.check_cipher(cipher, seal)
    return raw, cipher


def publish(folder, env, api, *, clock=time.time):
    ctx = check_origin(env)
    require(env['CACHE_HIT'] == 'true' and env['CACHE_MATCH'] == env['CACHE_KEY'], 'Not an exact cache hit')
    raw, cipher = check_files(folder, env, ctx)
    prefix = f"r209-{ctx['run']}-a1-s{ctx['ordinal']:02}"
    options = dict(origin_prefix=prefix)
    size = int(env['CIPHER_BYTES'])
    initial = normal.list_private(api)
    present = [normal.existing(initial, suffix, **options) for suffix in SUFFIXES]
    # Reserve the normal writer's original and single residue-recovery name for each missing object.
    require(len(initial['assets']) + 2 * present.count(None) <= 1000, 'Insufficient private Draft capacity')
    def check_time():
        require(clock() <= int(env['DELIVERY_LATEST']), 'Owner transfer window closed')
    check_time()
    with cipher.open('rb') as data:
        part = normal.put(SUFFIXES[0], data, 0, size, env['CIPHER_SHA'], **options)
    api.download(part['id'], size, env['CIPHER_SHA'], None)
    check_time()
    seal = normal.put(SUFFIXES[1], io.BytesIO(raw), 0, len(raw), env['SEAL_SHA'], **options)
    seen = io.BytesIO()
    api.download(seal['id'], len(raw), env['SEAL_SHA'], seen)
    require(seen.getvalue() == raw, 'Private seal bytes differ')
    receipt = dict(schema=RECEIPT_SCHEMA, origin=ctx, repository_id=owner.REPO_ID, release_id=owner.RELEASE_ID,
                   recipient=owner.RECIPIENT, destination_commitment=owner.DESTINATION_HASH,
                   source_cache=dict(id=int(env['CACHE_ID']), key=env['CACHE_KEY'], ref=env['GITHUB_REF']),
                   cipher=part, seal=seal)
    check_time()
    saved = normal.put_json(SUFFIXES[2], receipt, **options)
    seen = io.BytesIO()
    api.download(saved['id'], saved['bytes'], saved['sha256'], seen)
    require(json.loads(seen.getvalue()) == receipt, 'Private receipt differs')
    final = normal.list_private(api)
    rows = [normal.existing(final, s, **options) for s in SUFFIXES]
    require(all(row and row['id'] == rec['id'] and row['digest'] == 'sha256:' + rec['sha256']
                and row['size'] == rec['bytes'] for row, rec in zip(rows, (part, seal, saved))),
            'Private objects changed during readback')
    require(normal.visibility(api, rows, clock() + 480)[0], 'Anonymous denial not confirmed for private objects')
    return dict(run=ctx['run'], ordinal=ctx['ordinal'], claim=ctx['claim'], receipt_id=saved['id'],
                receipt_sha=saved['sha256'], cipher_id=part['id'], seal_id=seal['id'])


def main(mode):
    env = os.environ
    ctx = check_origin(env)
    check_service(env, ctx, bridge.api_json)
    if mode == 'authorize':
        bridge.output(key=env['CACHE_KEY'])
        return
    require(mode == 'deposit', 'Unknown delivery mode')
    result = terminal_draft.reconciled_deposit(lambda: publish(Path('.r209-owner-cache'), env, bridge.auth_api()))
    bridge.output(**result)
    print('R209_PRIVATE_TERMINAL', json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    main(sys.argv[1])
