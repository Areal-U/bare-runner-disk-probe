"""Read one verified public source pack and exercise Bare's ordinary Linux/Android checkout."""
import ast
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pinned_block(lines, first, last):
    first_hits = [i for i, line in enumerate(lines) if line == '        ' + first]
    require(len(first_hits) == 1, 'Ambiguous normal workflow line: ' + first)
    end = lines.index('        ' + last, first_hits[0]) + 1
    chunk = lines[first_hits[0]:end]
    require(all(not line or line.startswith('        ') for line in chunk), 'Unexpected indentation in normal workflow')
    return '\n'.join(line[8:] for line in chunk) + '\n'


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], text=True).strip()


def stat_disk(root):
    fs = os.statvfs(root)
    return {'free':fs.f_bavail * fs.f_frsize, 'inodes':fs.f_favail}


def shell_material(normal):
    lines = normal.splitlines()
    builder = pinned_block(lines, 'base_image="$REQUESTED_BASE"', 'bash builder.sh start')
    # The normal fetch step includes an earlier export with the same text elsewhere. Bind its own step.
    fetch_step = normal.split('    - name: Fetch only the pinned Chromium revision and Android dependencies\n')
    require(len(fetch_step) == 2, 'Missing unique normal fetch step')
    fetch_lines = fetch_step[1].split('\n    - name: ', 1)[0].splitlines()
    pre = pinned_block(fetch_lines, 'export DEPOT_TOOLS_UPDATE=0 DEPOT_TOOLS_METRICS=0', 'GCLIENT')
    sync = pinned_block(fetch_lines, 'gclient sync --no-history --nohooks --revision "src@$CHROMIUM_REV" --jobs 4',
                        '[[ $(git -C src rev-parse HEAD) == "$CHROMIUM_REV" ]]')
    return builder, pre, sync


def setup():
    from source_reuse import pins, PIN_FILE
    trial_dir = Path(__file__).resolve().parent
    from datetime import datetime, timezone, timedelta
    sys.path.insert(0, str(PIN_FILE.parents[2] / 'preflight28/bridge'))
    import bridge
    receipt = json.loads((trial_dir / 'android-source-receipt.json').read_text())
    lock = pins(); spec = receipt['spec']; a = receipt['artifact']
    require(all(lock[k] == spec[k] for k in lock) and spec['scope'] == 'chromium', 'Fixture pins differ from this normal workflow')
    meta = bridge.api_json(f'/repos/{bridge.REPO}/actions/artifacts/{a["id"]}')
    run = bridge.api_json(f'/repos/{bridge.REPO}/actions/runs/{a["workflow_run"]}')
    jobs = bridge.api_json(f'/repos/{bridge.REPO}/actions/runs/{a["workflow_run"]}/attempts/1/jobs?per_page=100')
    producers = [j for j in jobs['jobs'] if j['id'] == a['producer_job']]
    require(jobs['total_count'] == len(jobs['jobs']) and len(producers) == 1, 'Incomplete or ambiguous source jobs')
    producer, = producers
    require(producer['run_id'] == run['id'] and producer['run_attempt'] == 1 and producer['head_sha'] == a['producer_sha']
            and producer['name'] == 'source-comparison / prepare' and producer['conclusion'] == 'success', 'Wrong source producer job')
    require(run['path'] == '.github/workflows/bare-disk-probe.yml' and run['actor']['id'] == run['triggering_actor']['id'] == 292261483
            and run['actor']['login'] == run['triggering_actor']['login'] == 'Areal-U', 'Unapproved source operator')
    require(all(meta[k] == a[k] for k in ('id','size_in_bytes','digest','name','expires_at')) and meta['expired'] is False
            and meta['workflow_run']['id'] == a['workflow_run'] and meta['workflow_run']['head_sha'] == a['producer_sha']
            and meta['workflow_run']['repository_id'] == 1450926240 and meta['workflow_run']['head_repository_id'] == 1450926240
            and run['event'] == 'workflow_dispatch' and run['workflow_id'] == a['producer_workflow_id']
            and run['run_attempt'] == a['attempt'] and run['head_branch'] == 'bare-next-build-prep-20261125'
            and run['head_sha'] == a['producer_sha'] and run['conclusion'] == 'success', 'Bound source artifact or successful producer differs')
    require(datetime.fromisoformat(meta['expires_at'].replace('Z','+00:00')) > datetime.now(timezone.utc) + timedelta(minutes=10),
            'Source fixture too close to expiry for this download')
    root = Path(os.environ['RUNNER_TEMP']) / 'android-source'
    root.mkdir()
    disk = stat_disk(root)
    # Normal R27 checkout used 44.52 GB on both hosted VMs. Include seed transfer, 25% variation, 20 GiB floor.
    require(disk['free'] >= 80_000_000_000 and disk['inodes'] >= 4_000_000, 'Insufficient fresh disk/inodes for Android DEPS')
    official = root / 'bare'
    subprocess.run(['git','init','-q',str(official)],check=True)
    git(official,'fetch','--no-tags','--depth=1','https://github.com/BareBrowser/bare-browser.git',lock['BARE_REV'])
    git(official,'checkout','--quiet','--detach','FETCH_HEAD')
    require(git(official,'rev-parse','HEAD') == lock['BARE_REV'], 'Bare pin differs')
    exchange = official / 'exchange'; exchange.mkdir(exist_ok=True)
    dest = exchange / 'next_build'; (dest / 'trials').mkdir(parents=True)
    shutil.copy(trial_dir.parent / 'source_seed.py', dest)
    for name in ('source_reuse.py','android_sync.py','android-source-receipt.json'):
        shutil.copy(trial_dir / name, dest / 'trials')
    workflow = PIN_FILE.read_text(); builder, pre, sync = shell_material(workflow)
    seed = 'python3 -I /exchange/next_build/source_seed.py restore /exchange/next_build/trials/android-source-receipt.json /exchange/seed/source.pack /work/chromium/src "$CHROMIUM_REV"\n'
    # Reuse metadata from the same filesystem in the unprivileged builder, not host wall clocks.
    runner = '/exchange/next_build/trials/android_sync.py'
    (dest / 'checkout.sh').write_text('set -euo pipefail\n' + 'python3 '+runner+' boot\n' + pre + '\npython3 '+runner+' pre\n' + seed +
        '\npython3 '+runner+' before\n' + sync + '\npython3 '+runner+' after\n')
    snapshot = re.findall(r'^      UBUNTU_SNAPSHOT_URL: (https://snapshot\.ubuntu\.com/ubuntu/[0-9TZ]+)$', workflow, re.M)
    base = re.findall(r'\[\[ \$EXPECTED_BASE == (ubuntu@sha256:[0-9a-f]{64}) \]\]', workflow)
    require(len(snapshot) == len(base) == 1, 'Normal immutable Ubuntu image or APT snapshot changed')
    (root/'builder.sh').write_text('set -euo pipefail\n' + builder)
    with open(os.environ['GITHUB_ENV'],'a') as out:
        for k,v in {**lock, 'UBUNTU_SNAPSHOT_URL':snapshot[0], 'REQUESTED_BASE':base[0], 'ANDROID_TRIAL':str(root)}.items():
            print(k+'='+v,file=out)
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for k,v in {'run':a['workflow_run'],'id':a['id'],'root':str(root)}.items(): print(k+'='+str(v),file=out)
    print('BARE_ANDROID_SOURCE_ADMIT', json.dumps(dict(disk=disk, expected_zip=a['size_in_bytes'], exact_id=a['id'], expires_at=a['expires_at'])))


def pack_info(root):
    return {p.name:p.stat().st_size for p in sorted((root/'.git/objects/pack').glob('*.pack'))}


def stage(which):
    # All files here belong to the ephemeral builder UID. The normal owner/campaign state is never read.
    root=Path('/work'); record=root/'source-diagnostic.json'; state=json.loads(record.read_text()) if record.exists() else {}
    src=root/'chromium/src'; rcpt=json.loads((Path(__file__).parent/'android-source-receipt.json').read_text())
    state[which] = {'time':time.time(), 'monotonic':time.monotonic(), **stat_disk(root)}
    if which in ('before','after'):
        state[which].update(head=git(src,'rev-parse','HEAD'), tree=git(src,'rev-parse','HEAD^{tree}'), packs=pack_info(src))
        require(state[which]['head'] == rcpt['spec']['revision'] and state[which]['tree'] == rcpt['tree'], 'Source commit or tree mismatch')
    if which == 'boot':
        require(state[which]['free'] >= 70_000_000_000 and state[which]['inodes'] >= 4_000_000, 'Builder /work too small for the measured source-only stage')
    if which=='after':
        require(state['before']['packs'] == state['after']['packs'], 'gclient changed or fetched Chromium root packs')
        entries=ast.literal_eval((src.parent/'.gclient_entries').read_text().split('=',1)[1])
        require('src' in entries and 'src/v8' in entries and len(entries)>100, 'Full gclient dependency entries missing')
        v8=git(src,'rev-parse','HEAD:v8'); require(git(src/'v8','rev-parse','HEAD') == v8, 'Resolved V8 differs from the Chromium gitlink')
        buildtools=src/'third_party/android_sdk/public/build-tools'; ndk=src/'third_party/android_toolchain/ndk'
        aapt=[p for p in buildtools.glob('*/aapt2') if os.access(p,os.X_OK)]
        sysroot=[p for p in ndk.glob('toolchains/llvm/prebuilt/*/sysroot/usr/include/android/api-level.h') if p.is_file()]
        require(aapt and sysroot, 'Missing resolved Android SDK build tools or NDK sysroot')
        state.update(chromium=rcpt['spec']['revision'], chromium_tree=rcpt['tree'], depot=rcpt['spec']['DEPOT_REV'],
                     source_artifact_id=rcpt['artifact']['id'], source_pack_sha256=rcpt['sha256'],
                     v8=v8,android_sdk_files=[str(p.relative_to(src)) for p in aapt],android_ndk_files=[str(p.relative_to(src)) for p in sysroot],
                     android_dependency_entries=len(entries),root_extra_pack_bytes=0,runhooks=False,compiled=False,
                     seed_s=round(state['before']['monotonic']-state['pre']['monotonic'],3),
                     full_seeded_fetch_s=round(state['after']['monotonic']-state['boot']['monotonic'],3),
                     sync_only_s=round(state['after']['monotonic']-state['before']['monotonic'],3))
        print('BARE_ANDROID_SOURCE_RESULT '+json.dumps(state,sort_keys=True),flush=True)
    record.write_text(json.dumps(state,indent=2)+'\n')


def watch(args):
    root=Path(os.environ['ANDROID_TRIAL']); low=stat_disk(root); start=time.monotonic()
    proc=subprocess.Popen(args,start_new_session=True)
    try:
        while proc.poll() is None:
            reading=stat_disk(root);low={k:min(v,reading[k]) for k,v in low.items()}
            require(reading['free']>=20*1024**3 and reading['inodes']>=20000,'Android diagnostic disk/inode floor reached')
            require(time.monotonic()-start<40*60,'Normal 40-minute source timeout reached')
            time.sleep(3)
        require(proc.returncode==0,'Normal Linux/Android source check failed')
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid,signal.SIGTERM)
            # The hosted VM is disposable. Stop the container as well as its exec client.
            subprocess.run(['docker','compose','stop','-t','3','chromium-builder'], check=False, timeout=25)
        print('BARE_ANDROID_SOURCE_FLOOR '+json.dumps(low),flush=True)


if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('op',choices=('setup','watch','boot','pre','before','after'));p.add_argument('args',nargs=argparse.REMAINDER);ns=p.parse_args()
    if ns.op=='setup': setup()
    elif ns.op=='watch': watch(ns.args)
    else: stage(ns.op)
