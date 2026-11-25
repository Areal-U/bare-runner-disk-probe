"""Measure the Git portion of gclient sync for one immutable Chromium input on fresh clients."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import time
from urllib.request import urlopen

CHROMIUM = 'https://chromium.googlesource.com/chromium/src.git'
V8 = 'https://chromium.googlesource.com/v8/v8.git'
DEPOT = 'https://chromium.googlesource.com/chromium/tools/depot_tools.git'
CAP = {'v8': 192 * 1024**2, 'chromium': 7 * 1024**3 // 2}
ZIP_MARGIN = 2 * 1024**2
PIN_FILE = Path(__file__).resolve().parents[2] / '.github/workflows/bare-arm64-probe.yml'


def require(value, message):
    if not value:
        raise ValueError(message)


def git(path, *args, **kwargs):
    return subprocess.run(['git', '-C', str(path), *args], check=True, **kwargs)


def value(path, *args):
    return git(path, *args, stdout=subprocess.PIPE, text=True).stdout.strip()


def pins(path=PIN_FILE):
    result = {}
    for key in ('BARE_REV', 'CHROMIUM_REV', 'DEPOT_REV'):
        hits = re.findall(r'^      ' + key + r': ([0-9a-f]{40})$', path.read_text(), re.M)
        require(len(hits) == 1, 'Expected one immutable normal workflow pin: ' + key)
        result[key] = hits[0]
    return result


def resolve(scope):
    locked = pins()
    rev = locked['CHROMIUM_REV']
    if scope == 'chromium':
        return {**locked, 'url': CHROMIUM, 'revision': rev, 'scope': scope}
    url = f'https://chromium.googlesource.com/chromium/src/+/{rev}/?format=JSON'
    with urlopen(url, timeout=60) as response:
        data = response.read(1024**2 + 1)
    require(len(data) <= 1024**2 and data.startswith(b")]}'\n"), 'Unexpected Chromium tree response')
    rows = [entry for entry in json.loads(data[5:])['entries'] if entry['name'] == 'v8']
    require(len(rows) == 1 and rows[0]['type'] == 'commit' and rows[0]['mode'] == 0o160000 and
            re.fullmatch(r'[0-9a-f]{40}', rows[0]['id']), 'Expected V8 gitlink at the selected Chromium revision')
    return {**locked, 'url': V8, 'revision': rows[0]['id'], 'scope': scope}


def digest(path):
    with path.open('rb') as stream:
        result = hashlib.sha256()
        for block in iter(lambda: stream.read(1024**2), b''):
            result.update(block)
        return result.hexdigest()


def elapsed(start):
    return round(time.monotonic() - start, 4)


def fresh(path):
    path.mkdir(parents=True, exist_ok=False)
    git(path, 'init', '-q')


def pack(spec, work, cap):
    start = time.monotonic()
    repo = work / 'pristine'
    fresh(repo)
    def cap_writes():
        resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))

    git(repo, '-c', 'fetch.unpackLimit=1', 'fetch', '-q', '--no-tags', '--depth=1', spec['url'],
        spec['revision'], preexec_fn=cap_writes)
    require(value(repo, 'rev-parse', 'FETCH_HEAD') == spec['revision'], 'Wrong source revision')
    # A single stream from the trusted upstream server is already a self-contained shallow pack.
    # Export only object bytes. Local Git config, hooks, credentials and refs do not enter the bundle.
    packs = list((repo / '.git/objects/pack').glob('*.pack'))
    require(len(packs) == 1, 'Expected a single shallow Git pack')
    entries = git(repo, 'ls-tree', '-lr', '-z', 'FETCH_HEAD', stdout=subprocess.PIPE).stdout.rstrip(b'\x00').split(b'\x00')
    fields = [row.split(b'\t', 1)[0].split() for row in entries if row]
    checkout_bytes = sum(int(size) for mode, kind, oid, size in fields if kind == b'blob')
    size = packs[0].stat().st_size
    require(0 < size <= cap - ZIP_MARGIN, 'One-day source experiment cap exceeded')
    target = work / 'source.pack'
    os.link(packs[0], target)
    return {'spec': spec, 'tree': value(repo, 'rev-parse', 'FETCH_HEAD^{tree}'), 'bytes': size,
            'checkout_bytes': checkout_bytes, 'files': len(fields), 'sha256': digest(target), 'make_s': elapsed(start)}


def restore(report, package, dest):
    spec = report['spec']
    require(package.stat().st_size == report['bytes'] and digest(package) == report['sha256'], 'Downloaded pack SHA or length mismatch')
    fresh(dest)
    git(dest, 'remote', 'add', 'origin', spec['url'])
    (dest / '.git/shallow').write_text(spec['revision'] + '\n')
    with package.open('rb') as stream:
        git(dest, 'index-pack', '--strict', '--stdin', stdin=stream, stdout=subprocess.DEVNULL)
    require(value(dest, 'rev-parse', spec['revision'] + '^{tree}') == report['tree'], 'Downloaded pack has wrong tree')
    git(dest, 'checkout', '--quiet', '--detach', spec['revision'])


def setup_client(root, source_url, revision):
    # Use a real DEPS edge against the canonical repository. Recursion and hooks are excluded
    # to compare the complete chosen Git dependency without installing unrelated SDKs/CIPD.
    fixture = root / 'fixture'
    fresh(fixture)
    (fixture / 'DEPS').write_text('deps = ' + repr({'srcdep': source_url + '@' + revision}) + '\n')
    git(fixture, 'add', 'DEPS')
    git(fixture, '-c', 'user.name=Bare input trial', '-c', 'user.email=input@example.invalid',
        'commit', '-qm', 'One pinned normal dependency')
    origin = fixture.as_uri()
    git(fixture, 'remote', 'add', 'origin', origin)
    (root / '.gclient').write_text('solutions = ' + repr([dict(name='fixture', url=origin, managed=False)]) +
                                   "\ntarget_os = ['linux', 'android']\ncache_dir = None\n")


def verify(dest, report):
    revision = report['spec']['revision']
    require(value(dest, 'rev-parse', 'HEAD') == revision and value(dest, 'rev-parse', 'HEAD^{tree}') == report['tree'],
            'gclient returned an unexpected revision or tree')
    git(dest, 'fsck', '--no-reflogs', '--no-dangling', '--connectivity-only', revision, stdout=subprocess.DEVNULL)
    require(not value(dest, 'status', '--porcelain', '--untracked-files=no'), 'Modified input files')


def clients(report, package, work, depot):
    spec = report['spec']
    result = {}
    # Candidate first: a remote baseline cannot warm its object or HTTP caches. Both start with
    # a fresh gclient workspace and use the same pinned, separately prepared gclient executable.
    for name in ('seeded', 'direct'):
        root = work / name
        setup_client(root, spec['url'], spec['revision'])
        dest = root / 'srcdep'
        start = time.monotonic()
        if name == 'seeded':
            restore(report, package, dest)
        seed_s = elapsed(start)
        pack_dir = dest / '.git/objects/pack'
        previous_packs = {p.name for p in pack_dir.glob('*.pack')}
        env = {**os.environ, 'DEPOT_TOOLS_UPDATE': '0', 'DEPOT_TOOLS_METRICS': '0', 'GIT_TERMINAL_PROMPT': '0',
               'PATH': str(depot) + os.pathsep + os.environ['PATH']}
        subprocess.run([sys.executable, str(depot / 'gclient.py'), 'sync', '--no-history', '--nohooks', '--noprehooks', '--jobs', '4'],
                       cwd=root, env=env, check=True)
        require((root / '.gclient_entries').is_file(), 'gclient did not record its dependency')
        verify(dest, report)
        require(value(dest, 'rev-list', '--count', 'HEAD') == '1', 'Expected a single reachable source commit')
        result[name + '_s'] = elapsed(start)
        result[name + '_unpack_s'] = seed_s
        result[name + '_new_pack_bytes'] = sum(p.stat().st_size for p in pack_dir.glob('*.pack') if p.name not in previous_packs)
        result[name + '_git_bytes'] = int(subprocess.check_output(['du', '-sb', str(dest / '.git')]).split()[0])
        # Both worktrees can be gigabytes. Discard only the disposable workspace created above.
        shutil.rmtree(root)
    return result


def decision(result, report, upload_s, download_s, reuses):
    require(1 <= reuses <= 12 and all(math.isfinite(v) and v >= 0 for v in (upload_s, download_s)), 'Invalid durations or planned uses')
    direct = result['direct_s']
    per_use = download_s + result['seeded_s']
    one_time = report['make_s'] + upload_s
    saving = direct - per_use
    return {**result, **report, 'upload_s': upload_s, 'download_s': download_s, 'planned_uses': reuses,
            'min_uses_to_save_time': math.floor(one_time / saving) + 1 if saving > 0 else None,
            'net_s_over_planned_uses': round(reuses * saving - one_time, 4),
            'scope': 'selected Git dependency only; queue, retention across runs, SDK/CIPD, hooks and build outputs outside timed scope'}


def check_room(work, data, cap):
    require(0 < data['bytes'] <= cap - ZIP_MARGIN, 'Source receipt outside cap')
    disk = os.statvfs(work)
    # Retained transfer, Git unpack/index and working tree; neither checkout overlaps the other.
    needed = 3 * data['bytes'] + data['checkout_bytes'] + 2 * 1024**3
    require(disk.f_bavail * disk.f_frsize >= needed and disk.f_favail >= 2 * data['files'] + 20000,
            'Insufficient receiver disk space or inodes')
    print(f'need_bytes={needed} available={disk.f_bavail * disk.f_frsize} available_inodes={disk.f_favail}')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('stage', choices=['produce','receive','admit','room','local'])
    p.add_argument('scope', choices=CAP)
    p.add_argument('work', type=Path)
    args = p.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    cap = CAP[args.scope]
    if args.stage == 'admit':
        sys.path.insert(0, str(PIN_FILE.parents[2] / 'preflight28/bridge'))
        import bridge, storage_admission
        actual = (args.work / 'source.pack').stat().st_size
        require(0 < actual <= cap - ZIP_MARGIN, 'Invalid source pack bytes')
        storage_admission.admit(bridge.api_json, os.environ, actual + ZIP_MARGIN, 1, stage='control')
        return
    if args.stage == 'room':
        check_room(args.work, json.loads(os.environ['SOURCE_RECEIPT']), cap)
        return
    spec = resolve(args.scope)
    if args.stage in ('produce', 'local'):
        require(shutil.disk_usage(args.work).free >= cap + 2 * 1024**3, 'Insufficient producer disk for a bounded fetch')
        data = pack(spec, args.work, cap)
    if args.stage == 'produce':
        with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
            print('receipt=' + json.dumps(data, separators=(',', ':')), file=output)
        print(json.dumps(data, indent=2))
    else:
        if args.stage == 'receive':
            data = json.loads(os.environ['SOURCE_RECEIPT'])
        check_room(args.work, data, cap)
        require(data['spec'] == spec and 0 < data['bytes'] <= cap - ZIP_MARGIN, 'Source receipt does not match reviewed inputs')
        depot = args.work / 'depot_tools'
        fresh(depot)
        git(depot, 'fetch', '-q', '--depth=1', '--no-tags', DEPOT, spec['DEPOT_REV'])
        git(depot, 'checkout', '-q', '--detach', spec['DEPOT_REV'])
        require(value(depot, 'rev-parse', 'HEAD') == spec['DEPOT_REV'], 'gclient pin mismatch')
        results = clients(data, args.work / 'source.pack', args.work, depot)
        if args.stage == 'local':
            result = {'place': 'isolated local clients; service transfer and queue unmeasured', 'producer': data, 'receiver': results}
            print(json.dumps(result, indent=2))
            (args.work / 'local-source-comparison.json').write_text(json.dumps(result, indent=2) + '\n')
            return
        result = decision(results, data, float(os.environ['UPLOAD_S']), float(os.environ['DOWNLOAD_S']), int(os.environ['REUSES']))
        handoff = (int(os.environ['DOWNLOAD_START']) - int(os.environ['PUBLISHED'])) / 1e9
        result['producer_finish_to_receiver_transfer_start_s'] = handoff
        result['net_s_with_observed_one_time_handoff'] = round(result['net_s_over_planned_uses'] - max(0, handoff), 4)
        print('BARE_SOURCE_COMPARISON ' + json.dumps(result, sort_keys=True), flush=True)
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as summary:
            print('### Pinned gclient Git input comparison\n\n```json\n' + json.dumps(result, indent=2) + '\n```', file=summary)


if __name__ == '__main__':
    main()
