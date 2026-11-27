"""Run the normal Chromium target against its new generation's exact frontier."""
import argparse
import json
import os
from pathlib import Path
import shutil
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'preflight28/graph')]
import input_state
import build_trial
import graph
import retained209
from checkpoint209 import digest, encode, identity, require, SCHEMA, check_archive

SRC = Path('/work/chromium/src')
OUT = SRC / 'out/Bare'
STATE = OUT / '.r209'
WORK = Path('/exchange/slot209')


def plan():
    return sorted([list(outputs), action] for outputs, action in
                  graph.run(OUT, ['autoninja'], ['chrome_public_apk'], dry=True, timeout_seconds=900).items())


def adjust_git_inputs():
    heads = {}
    # GN has .git/HEAD dependencies (including ANGLE) outside gclient's
    # source-tree identity. Freeze only the detached, content-bound HEADs.
    for base, dirs, _ in os.walk(SRC):
        if '.git' in dirs:
            dirs.remove('.git')
            head = Path(base) / '.git/HEAD'
            raw = head.read_text().strip()
            require(len(raw) == 40 and all(c in '0123456789abcdef' for c in raw), 'Non-detached dependency')
            heads[str(Path(base).relative_to(SRC))] = raw
            os.utime(head, ns=(1_000_000_000, 1_000_000_000))
        if Path(base) == SRC and 'out' in dirs:
            dirs.remove('out')
    return heads


def prepare(record_path):
    require(Path.cwd() == SRC and not OUT.exists(), 'Source root or fresh output differs')
    heads = adjust_git_inputs()
    if record_path:
        rec = json.loads(record_path.read_text())
        check_archive(WORK/'parent.tar.zst', rec)
        subprocess.run(['tar', '--zstd', '--extract', '--no-same-owner', '--delay-directory-restore',
                        '-f', str(WORK/'parent.tar.zst')], check=True)
        require(encode(heads) == (STATE/'git-heads.json').read_bytes(), 'Source checkout revisions differ')
        result = input_state.restore(STATE/'inputs.gz')
        print('restore_input_verification', json.dumps(result), flush=True)
        require(result['skipped'] == 0, 'Source snapshot differs from accepted parent')
        require((OUT/'args.gn').read_bytes() == Path('/exchange/args.gn').read_bytes(), 'Restored GN args changed')
        parent = json.loads((STATE/'proof.json').read_bytes())
        require(graph.fixed_graph(OUT) == parent['graph'], 'Restored GN graph changed')
    else:
        OUT.mkdir(parents=True)
        shutil.copyfile('/exchange/args.gn', OUT/'args.gn')
        subprocess.run(['gn','gen','out/Bare'], check=True)
        STATE.mkdir()
        (STATE/'git-heads.json').write_bytes(encode(heads))
        print('cold_source_snapshot', input_state.record(STATE/'inputs.gz'), flush=True)
    before = plan()
    require(before, 'APK already present or no scheduled real target')
    if record_path:
        require(encode(before) == (STATE/'frontier.json').read_bytes(), 'Fresh runner APK plan differs from accepted parent')
    (WORK/'before.json').write_bytes(encode(before))
    (WORK/'graph').write_text(graph.fixed_graph(OUT))
    print('R209_COMPILE_ADMITTED remaining=' + str(len(before)), flush=True)


def discard_runtime_log_links():
    # glog's per-process absolute links are generated on the current VM and
    # point outside the build. Never follow a link supplied by the archive.
    for level in ('INFO','WARNING','ERROR','FATAL'):
        path = OUT/('siso.'+level)
        if path.is_symlink():
            target = os.readlink(path)
            require(re.fullmatch(r'/tmp/siso\.[-A-Za-z0-9_.]+\.log\.'+level+r'\.[0-9-]+\.[0-9]+',target),
                    'Unexpected Siso external diagnostic link')
            path.unlink()


def close():
    # Caller stopped the sole container with this volume, observed it offline,
    # and restarted its idle command before this call.
    trial = json.loads((WORK/'trial.json').read_text())
    print('R209_COMPILE_EXIT', json.dumps({key:trial.get(key) for key in
          ('phase','reason','returncode','forced_kill','failed_step_count','artifact_ready','completed_output_count',
           'new_completed_output_count','elapsed_seconds','ready_for_restore_test','available_compile_seconds')}),
          flush=True)
    require(trial['target'] == 'chrome_public_apk' and not trial.get('forced_kill')
            and not trial.get('controller_error') and isinstance(trial.get('close'),dict) and not trial['close']['errors'] and not trial['failed_steps']
            and trial.get('oom_kill_count', 0) == 0, 'Compiler failure or incomplete quiescence proof')
    trial['container_quiescence_verified'] = True
    (WORK/'trial.json').write_bytes(encode(trial))
    discard_runtime_log_links()
    before = json.loads((WORK/'before.json').read_bytes())
    after = plan()
    print('R209_TARGET_FRONTIER before=%d after=%d' % (len(before),len(after)), flush=True)
    require(graph.fixed_graph(OUT) == (WORK/'graph').read_text(), 'Actual target changed GN graph')
    old = {tuple(k): v for k,v in before}
    require(len(after) < len(before) and all(old.get(tuple(k)) == v for k,v in after),
            'No positive frontier or unexpected new edge')
    if trial['artifact_ready']:
        require(trial['reason'] == 'completed' and trial['returncode'] == 0 and not after
                and (OUT/'apks/ChromePublic.apk').is_file(), 'Terminal APK frontier differs')
        (WORK/'kind').write_text('apk')
        return
    require(trial['ready_for_restore_test'] and after and not (OUT/'apks/ChromePublic.apk').exists(),
            'Interrupted compile cannot be resumed')
    (STATE/'frontier.json').write_bytes(encode(after))
    # The existing controller checks this directly before resuming a costly
    # interrupted terminal edge near the time limit.
    (OUT/'checkpoint-trial-restore.json').write_bytes(encode(trial))
    retained = retained209.create(OUT, before, after, trial)
    estimate = build_trial.tree_snapshot(OUT, include_paths=False)
    can_resume = (estimate['archive_input_estimate_bytes'] < build_trial.PRODUCTION_OUTPUT_LIMIT - 1024**3
                  and estimate['entries'] < build_trial.PRODUCTION_OUTPUT_ENTRY_LIMIT - 10000)
    print('R209_WORKING_SET', json.dumps({k:v for k,v in estimate.items() if k != 'paths'}), 'next_slot_has_headroom', can_resume, flush=True)
    proof = {
        'schema': SCHEMA, 'run': int(os.environ['GITHUB_RUN_ID']), 'ordinal': int(os.environ['R28_SLOT']),
        'producer_sha': os.environ['R28_HEAD_SHA'], 'parent_sha': os.environ['R28_PARENT_SHA'],
        'genesis': os.environ['R209_GENESIS'], 'target': trial['target'], 'quiescent': True,
        'graph': graph.fixed_graph(OUT), 'before': len(before), 'remaining': len(after),
        'inputs': digest(STATE/'inputs.gz'), 'plan': digest(STATE/'frontier.json'),
        'git_heads': digest(STATE/'git-heads.json'), 'next_has_headroom': can_resume,
    }
    proof['retained'] = retained
    (STATE/'proof.json').write_bytes(encode(proof))
    (WORK/'proof.json').write_bytes(encode(proof))
    print('checkpoint_identity', identity(proof), 'remaining',len(after), flush=True)
    sys.path.insert(0, str(ROOT/'preflight28/transport'))
    from pack_draft import pack
    tar = ['tar', '--sort=name', '--hard-dereference','--format=posix',
           '--pax-option=delete=atime,delete=ctime','-cf','-', 'out/Bare']
    pack(WORK/'next.tar.zst', 'auto', estimate['archive_input_estimate_bytes'], tar,
         deadline=int(os.environ['R209_SENDER_UNTIL'])-15*60)
    (WORK/'kind').write_text('checkpoint')


if __name__ == '__main__':
    os.umask(0o077)
    p = argparse.ArgumentParser()
    p.add_argument('operation', choices=['prepare','close'])
    p.add_argument('--record', type=Path)
    a = p.parse_args()
    prepare(a.record) if a.operation == 'prepare' else close()
