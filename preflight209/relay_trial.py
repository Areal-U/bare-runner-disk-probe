"""A bounded two-packet transport trial on three standard hosted runners.

Its source tree, simulated controller stop, and restore run belong only to
the disk-probe workflow. No trial manifest can become a build predecessor.
"""
import argparse
import http.client
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile
from urllib.parse import parse_qs, urlsplit

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent/'preflight28/bridge'), str(HERE.parent/'preflight28/graph')]
import bridge
import checkpoint209 as checkpoint
import graph
import input_state
import normal
import owner
import retained209
import storage_admission as storage

PATH = '.github/workflows/bare-disk-probe.yml'
REF = 'refs/heads/' + owner.BRANCH
CEILING = 10 * 1024**3
SISO_SHA = '19733a6faf64ad02594b19d5d4a08c7271e57e44a90934a37ef246ebe3c81d9d'
PACKET = 256 * 1024**2
TARGET = 'chrome_public_apk'
NINJA = """rule cc
  command = /usr/bin/cc -ffreestanding -nostdinc -MMD -MF $out.d -c $in -o $out
  depfile = $out.d
  deps = gcc
  description = CC $out
rule finish
  command = cp $in $out
  description = COPY $out
build relay.o: cc ../../relay.c
build chrome_public_apk: finish relay.o
"""


def physical_trial():
    env = os.environ
    event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_bytes())
    run_id = bridge.env_int('GITHUB_RUN_ID')
    require = checkpoint.require
    run = bridge.api_json(f'/repos/{owner.REPO}/actions/runs/{run_id}')
    require(env['GITHUB_REPOSITORY'] == owner.REPO and env['GITHUB_REF'] == REF and
            env['GITHUB_WORKFLOW_REF'] == owner.REPO+'/'+PATH+'@'+REF and
            env['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and env['GITHUB_RUN_ATTEMPT'] == '1' and
            event['repository']['id'] == run['repository']['id'] == run['head_repository']['id'] == owner.REPO_ID and
            owner.owner_account(event['sender']) and owner.owner_account(run['actor']) and
            env['GITHUB_ACTOR'] == owner.OWNER['login'] and env['RUNNER_ENVIRONMENT'] == 'github-hosted' and
            run['event'] == 'workflow_dispatch' and run['path'] == PATH and run['run_attempt'] == 1 and
            run['id'] == run_id and run['status'] == 'in_progress' and run['head_branch'] == owner.BRANCH and
            event['inputs']['checkpoint_trial'] == 'true' and
            event['inputs']['expected_head'] == run['head_sha'] == env['GITHUB_SHA'] and
            checkpoint.valid_hex(run['head_sha'], 40) and checkpoint.valid_hex(event['inputs']['owner_alias_sha'])
            and env['R209_DRAFT_ALIAS_SHA'] == event['inputs']['owner_alias_sha'], 'Wrong diagnostic dispatch')
    created = int(owner.instant(run['created_at']).timestamp())
    require(created <= time.time() < created + 140*60, 'Physical diagnostic window expired')
    return created


def lease(created):
    checkpoint.require(normal.slot() in (1,2) and os.environ['GITHUB_JOB']=='lease', 'Wrong trial registration')
    import unpublished_cold as origin
    by = normal.b.auth_api()
    release = normal.list_private(by)
    # The closed campaign is used exclusively to read its immutable cost ceiling
    # and policy expiry. It is never leased to collect this diagnostic.
    name = f'{owner.CAMPAIGN}-after-{owner.cold.RUN}-claim.json'
    row, = [a for a in release['assets'] if a['name'] == name]
    digest = row['digest'].removeprefix('sha256:')
    checkpoint.require(owner.cold.claim_commitment(row['id'], digest) == origin.CLAIM_COMMITMENT,
                       'Different historical policy source')
    _, claim = owner.doc(by, release, name, row['id'], digest,
                         owner.instant(origin.ORIGIN['run']['updated_at']), producer_claim=True)
    start = owner.instant(origin.ORIGIN['run']['created_at'])
    _, ticket = owner.doc(by, release, f'{owner.CAMPAIGN}-{origin.HEAD}-after-{owner.cold.RUN}-ticket.json',
                          claim['ticket_asset_id'], claim['ticket_sha'], start)
    _, ack = owner.doc(by, release, f"{owner.CAMPAIGN}-ack-{ticket['registration_nonce']}.json",
                       claim['collector_ack_asset_id'], claim['collector_ack_sha'], start)
    ceiling, until = storage.policy(ticket, ack)
    config = os.environ | dict(R28_STORAGE_CEILING=str(min(CEILING, ceiling)), R28_STORAGE_UNTIL=str(until))
    # Only the two small peer controls use Artifact storage in this diagnostic.
    storage.admit(by.metadata, config, 2*1024**2, 1, stage='peer')
    storage.cache_fallback(by.metadata, config, PACKET + 2*1024**2)
    checkpoint.require(len(release['assets']) + 26 <= 1000, 'Insufficient private Draft trial room')
    record = normal.context() | dict(purpose='checkpoint-relay-trial-only', expires=created+140*60,
                                     workflow=PATH, storage_ceiling=min(CEILING, ceiling), storage_until=until)
    binding = normal.put_json('diagnostic-binding.json', record)
    raw = io.BytesIO()
    by.download(binding['id'], binding['bytes'], binding['sha256'], raw)
    checkpoint.require(json.loads(raw.getvalue()) == record, 'Private diagnostic binding readback failed')
    bridge.output(claim=binding['id'], storage_ceiling=min(CEILING, ceiling), storage_until=until,
                  latest_start=created+(25 if normal.slot()==1 else 80)*60, draft_id=bridge.RELEASE)


def report_quota(stage):
    # REST limits are shared and roll over hourly. Record the actual reset
    # along with the timestamp so two different windows are never subtracted.
    conn = http.client.HTTPSConnection('api.github.com', timeout=8)
    try:
        conn.request('GET','/rate_limit',headers={
            'Authorization':'Bearer '+os.environ['GH_TOKEN'], 'User-Agent':'r209-diagnostic-read',
            'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'})
        reply = conn.getresponse()
        if reply.status == 200:
            core=json.loads(reply.read(16384))['resources']['core']
            fields={k:core[k] for k in ('limit','used','remaining','reset')}
            if all(type(v) is int and v>=0 for v in fields.values()):
                print('R209_TRIAL_REST_QUOTA '+json.dumps(dict(stage=stage,epoch=int(time.time()),**fields)),flush=True)
                return
    except (OSError,http.client.HTTPException,ValueError,KeyError):
        pass
    finally:
        conn.close()
    print('R209_TRIAL_REST_QUOTA_UNAVAILABLE stage='+stage,flush=True)


def stage_siso(dest):
    lock = json.loads((HERE/'upstream-lock.json').read_bytes())
    url = ('https://chrome-infra-packages.appspot.com/dl/build/siso/linux-amd64/+/git_revision:'
           + lock['siso_revision'])
    dest.parent.mkdir(parents=True, exist_ok=True)
    package = dest.parent/'siso-trial.zip'
    subprocess.run(['curl','--fail','--silent','--show-error','--location','--proto','=https',
                    '--proto-redir','=https','--retry','2','--max-time','90',url,'-o',package],check=True)
    with zipfile.ZipFile(package) as z, z.open('siso') as raw, dest.open('xb') as binary:
        shutil.copyfileobj(raw,binary)
    package.unlink()
    checkpoint.require(checkpoint.digest(dest) == SISO_SHA, 'Incorrect fixed trial Siso binary')
    dest.chmod(0o755)


def sources(root):
    roots = {name:root/name for name in ('src','depot_tools')}
    for category, name in sorted(input_state.REQUIRED):
        path = roots[category]/name
        if name == '.':
            path.mkdir(parents=True, exist_ok=True)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            if name != 'third_party/siso/cipd/siso':
                path.write_text('diagnostic source inventory witness\n')
    (roots['src']/'relay.c').write_text('int relay(int x) { return x + 1; }\n')
    subprocess.run(['git','init','--quiet',roots['src']],check=True)
    return roots


def frontier(out, siso):
    return retained209.as_list(graph.run(out,[str(siso),'ninja','-offline'],[TARGET],dry=True))


def make_sample(root, siso, padding):
    roots = sources(root)
    os.chdir(roots['src'])
    actual_siso = roots['src']/'third_party/siso/cipd/siso'
    shutil.copy2(siso, actual_siso)
    out = roots['src']/'out/Bare'
    state = out/'.r209'
    state.mkdir(parents=True)
    (out/'build.ninja').write_text(NINJA)
    shutil.copyfile(HERE/'relay-trial-args.gn',out/'args.gn')
    before = frontier(out, actual_siso)
    executed = graph.run(out,[str(actual_siso),'ninja','-offline'],['relay.o'],dry=False,isolated_logs=True)
    after = frontier(out, actual_siso)
    checkpoint.require(set(executed) == {('relay.o',)} and len(before)==2 and len(after)==1,
                       'Miniature Siso graph did not advance by one real compile')
    with (out/'transport-size-witness.bin').open('xb') as f:
        while padding:
            count=min(padding, 1024**2)
            f.write(os.urandom(count))
            padding-=count
    input_state.record(state/'inputs.gz',roots)
    (state/'git-heads.json').write_bytes(checkpoint.encode({'trial_head':os.environ['GITHUB_SHA']}))
    (state/'frontier.json').write_bytes(checkpoint.encode(after))
    fs = out/'.siso_fs_state'
    # This is a transport fixture, not a Chromium interval. All fields that
    # describe the interval controller are explicitly scoped to the diagnostic.
    trial = dict(format='bare-apk-trial',version=1,phase='seed',reason='output-limit',target=TARGET,
                 diagnostic_controller_fixture=True, failed_steps=[], failed_step_count=0, forced_kill=False,
                 ready_for_restore_test=True,artifact_ready=False,container_quiescence_verified=True,
                 command=['autoninja','-C','out/Bare','-j','2','-metrics_json',
                          '/exchange/slot209/siso-metrics-seed.json',TARGET],
                 close=dict(saved=True,journal_ready=False,errors=[],
                            state=dict(size=fs.stat().st_size,sha256=checkpoint.digest(fs))))
    (out/'checkpoint-trial-restore.json').write_bytes(checkpoint.encode(trial))
    proof = dict(schema=checkpoint.SCHEMA,run=bridge.env_int('GITHUB_RUN_ID'),ordinal=1,
                 producer_sha=os.environ['GITHUB_SHA'],parent_sha=os.environ['R209_GENESIS'],
                 genesis=os.environ['R209_GENESIS'],graph=graph.fixed_graph(out),before=len(before),
                 remaining=len(after),target=TARGET,quiescent=True,inputs=checkpoint.digest(state/'inputs.gz'),
                 git_heads=checkpoint.digest(state/'git-heads.json'),plan=checkpoint.digest(state/'frontier.json'),
                 next_has_headroom=True)
    proof['retained']=retained209.create(out,before,after,trial)
    (state/'proof.json').write_bytes(checkpoint.encode(proof))
    file=root/'sample.tar.zst'
    subprocess.run(['tar','--sort=name','--format=posix','--hard-dereference','--zstd','-cf',file,'out/Bare'],
                   check=True)
    rec=normal.context()|dict(identity=checkpoint.identity(proof),proof_sha=checkpoint.digest(state/'proof.json'),
                             bytes=file.stat().st_size,sha256=checkpoint.digest(file))
    checkpoint.check_archive(file,rec)
    return file, rec


def candidate():
    checkpoint.require(normal.slot()==1 and os.environ['GITHUB_JOB']=='compile-probe', 'Wrong sample producer')
    # Only the diagnostic authenticator needs the worker's read credential.
    for key in ('GH_TOKEN', 'TRIAL_READ_TOKEN'):
        os.environ.pop(key, None)
    root = Path(os.environ['RUNNER_TEMP'])/'relay-trial-work'
    root.mkdir()
    siso = root/'tools/siso'
    stage_siso(siso)
    sample, rec = make_sample(root,siso,PACKET+1024)
    normal.seal(sample,rec['identity'],rec['proof_sha'])
    length = (normal.ROOT/'checkpoint.cms').stat().st_size
    checkpoint.require(PACKET < length < PACKET+16*1024**2, 'Trial must contain two production-size packets')
    bridge.output(kind='checkpoint', next_has_headroom='true')
    print(f'R209_TRIAL_SAMPLE sealed_bytes={length} sha256={rec["sha256"]} actual_siso_local=1 pending=1')


def route():
    checkpoint.require(normal.slot()==1 and os.environ['GITHUB_JOB']=='compile-probe', 'Wrong trial relay invocation')
    import outcome_relay
    real = bridge.api_json
    old = [dict(id=1000+i,name=f'diagnostic-row-{i}',size_in_bytes=100+i,
                expired=False,expires_at='2099-01-01T00:00:00Z') for i in range(20)]
    def recorded_count(path,*args,**kwargs):
        if path.startswith(storage.BASE+'/actions/artifacts?'):
            q=parse_qs(urlsplit(path).query)
            width,page=int(q['per_page'][0]),int(q['page'][0])
            return dict(total_count=21,artifacts=old[(page-1)*width:page*width])
        return real(path,*args,**kwargs)
    # Fault injection is process-local, after authentication of the hosted trial.
    # Run-scoped Artifact lookup, repository/runner checks and cache remain live.
    try:
        bridge.api_json=recorded_count
        decision=outcome_relay.plan()
    finally:
        bridge.api_json=real
    checkpoint.require(decision['decision']=='packets', 'Recorded 21/20 did not select the alternate relay')
    bridge.output(**decision)
    print('R209_TRIAL_ROUTE recorded_total=21 recorded_visible=20 decision='+decision['decision'])


def check_restore(root, siso, file, manifest):
    proof = checkpoint.check_archive(file,manifest)
    roots = sources(root)
    shutil.copy2(siso,roots['src']/'third_party/siso/cipd/siso')
    os.chdir(roots['src'])
    subprocess.run(['tar','--zstd','--extract','--no-same-owner','--same-permissions',
                    '--delay-directory-restore','-f',file],check=True)
    out=roots['src']/'out/Bare'
    checkpoint.require(retained209.content(retained209.source_rows(out)) == proof['retained']['tree'],
                       'Independent extracted checkpoint differs')
    checkpoint.require(input_state.restore(out/'.r209/inputs.gz',roots)['skipped']==0,'Trial source restore differed')
    checkpoint.require(frontier(out,roots['src']/'third_party/siso/cipd/siso') ==
                       json.loads((out/'.r209/frontier.json').read_bytes()),'Fresh-runner Siso frontier differs')
    return proof


def restore():
    checkpoint.require(normal.slot()==2 and os.environ['GITHUB_JOB']=='compile-probe',
                       'Only the fresh ordinary worker can confirm the diagnostic predecessor')
    # This is the same read-only job that normally follows an accepted slot.
    # Its ephemeral key already decrypted the publisher's scoped descriptors
    # and normal.acquire validated every part and the entire downloaded archive.
    bridge.api_json(f'/repos/{owner.REPO}/releases/{bridge.RELEASE}', expected='denied')
    fields=normal.info()
    manifest=fields['source']
    mid=bridge.env_int('R28_PARENT_MANIFEST')
    sha=os.environ['R28_PARENT_MANIFEST_SHA']
    checkpoint.require(fields['source_manifest_id']==mid and fields['source_manifest_sha']==sha and
                       manifest['run']==bridge.env_int('GITHUB_RUN_ID') and manifest['attempt']==1 and
                       manifest['ordinal']==1 and manifest['producer_sha']==os.environ['GITHUB_SHA'] and
                       manifest['sha256']==os.environ['R28_PARENT_SHA'] and
                       manifest['identity']==os.environ['R28_PARENT_IDENTITY'], 'Wrong authenticated trial predecessor')
    for key in ('GH_TOKEN', 'TRIAL_READ_TOKEN'):
        os.environ.pop(key, None)
    root=Path(os.environ['RUNNER_TEMP'])/'relay-trial-work'
    root.mkdir()
    siso=root/'tools/siso'
    stage_siso(siso)
    archive=normal.ROOT/'checkpoint.tar.zst'
    proof=check_restore(root,siso,archive,manifest)
    bridge.output(kind='trial-restored',trial_manifest=mid,trial_manifest_sha=sha,
                  trial_sha=manifest['sha256'], trial_identity=manifest['identity'])
    print(f'R209_TRIAL_RESTORED run={manifest["run"]} head={manifest["producer_sha"]} manifest={mid}'
          f' bytes={manifest["bytes"]} sha256={manifest["sha256"]} remaining={proof["remaining"]} ordinary_read_only=true')


def certify():
    env=os.environ
    checkpoint.require(normal.slot()==2 and env['GITHUB_JOB']=='certify' and
                       env['WORKER']=='trial-restored' and env['PEER']=='verify-only' and env['READBACK']=='false' and
                       env['ADVANCED']=='false' and env['TRIAL_MANIFEST'].isdecimal() and
                       env['TRIAL_MANIFEST']==env['R28_PARENT_MANIFEST'] and
                       all(checkpoint.valid_hex(env[k]) and env[k]==env[v] for k,v in (
                           ('TRIAL_MANIFEST_SHA','R28_PARENT_MANIFEST_SHA'),
                           ('TRIAL_SHA','R28_PARENT_SHA'),('TRIAL_IDENTITY','R28_PARENT_IDENTITY'))),
                       'Second worker, peer and original certified generation did not agree')
    bridge.output(kind='trial-restored',manifest=env['TRIAL_MANIFEST'],manifest_sha=env['TRIAL_MANIFEST_SHA'],
                  parent=env['TRIAL_SHA'],parent_identity=env['TRIAL_IDENTITY'])


if __name__=='__main__':
    os.umask(0o077)
    arg=argparse.ArgumentParser(description=__doc__)
    arg.add_argument('mode',choices=('lease','candidate','route','restore','certify'))
    mode=arg.parse_args().mode
    created=physical_trial()
    if mode in ('lease','route','certify'):
        report_quota(f'slot{normal.slot()}-{mode}')
    if mode=='lease':
        lease(created)
    else:
        {'candidate':candidate,'route':route,'restore':restore,'certify':certify}[mode]()
