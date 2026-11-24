#!/usr/bin/env python3
"""Bounded resource and delivery checks for a single Bare runner segment."""
import argparse
import concurrent.futures
from datetime import datetime
import http.client
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

MIB = 1024 ** 2
GIB = 1024 ** 3
BYTE_CAPS = {'apk': 450 * MIB, 'cipher': 451 * MIB, 'checkpoint': 7 * GIB // 2}
FLOOR = 20 * GIB
INODE_FLOOR = 20_000
OUT_CAP = 18 * GIB
ENTRY_CAP = 525_000
# R20 grew by 509,147,136 bytes while free space fell by 511,643,648 bytes
# within 25.49 seconds. These margins are trial thresholds, not physical bounds.
STOP_MARGIN = GIB
FAST_MARGIN = 2 * GIB
STOP_ENTRIES = 10_000
FAST_ENTRIES = 20_000
# Leave one complete historically observed late burst, even between cheap polls.
QUIESCE_BYTES = 512 * MIB
QUIESCE_ENTRIES = STOP_ENTRIES // 2


class GuardError(Exception):
    def __init__(self, status, **details):
        super().__init__(status)
        self.record = {'status': status, **details}


def check_size(kind, path):
    mode = path.lstat()
    if not stat.S_ISREG(mode.st_mode) or mode.st_size == 0:
        raise GuardError('invalid-file', kind=kind, size=mode.st_size)
    if mode.st_size > BYTE_CAPS[kind]:
        raise GuardError('size-exceeded', kind=kind, size=mode.st_size, limit=BYTE_CAPS[kind], retry=False)
    return {'status': 'within-size-limit', 'kind': kind, 'size': mode.st_size, 'limit': BYTE_CAPS[kind]}


def disk(path):
    fs = os.statvfs(path)
    return {'device': os.stat(path).st_dev, 'free_bytes': fs.f_bavail * fs.f_frsize, 'free_inodes': fs.f_favail}


def reserve(space, extra_bytes, extra_inodes, floor=FLOOR, inode_floor=INODE_FLOOR):
    if min(extra_bytes, extra_inodes) < 0 or floor < FLOOR or inode_floor < INODE_FLOOR:
        raise ValueError('Invalid incremental allocation or safety floor')
    result = dict(space, future_bytes=extra_bytes, future_inodes=extra_inodes,
                  byte_floor=floor, inode_floor=inode_floor)
    if space['free_bytes'] < floor + extra_bytes or space['free_inodes'] < inode_floor + extra_inodes:
        raise GuardError('insufficient-space', **result)
    return {'status': 'space-reserved', **result}


def cache_budget(entries, capacity=10 * GIB, safety=128 * MIB):
    """Deduplicate referenced physical objects; an unsettled write has its own reservation."""
    distinct = {}
    for record in entries:
        identity = record['physical_id']
        size = record['bytes']
        if not isinstance(identity, str) or not identity or type(size) is not int or size <= 0:
            raise ValueError('Invalid cache object or outstanding reservation')
        if distinct.setdefault(identity, size) != size:
            raise ValueError('Conflicting sizes for the same cache identity')
    total = sum(distinct.values())
    headroom = capacity - safety - total
    record = {'objects': len(distinct), 'peak_bytes': total, 'headroom': headroom}
    if headroom < 0:
        raise GuardError('cache-budget-exceeded', **record)
    return {'status': 'within-cache-budget', **record}


def compile_seconds(job_start, now, job_minutes=350):
    if not 40 < job_minutes <= 350 or not 0 < job_start <= now:
        raise ValueError('Invalid job epoch or duration')
    return max(0, int(job_start + (job_minutes - 40) * 60 - now))


def job_clock(check_run):
    repo = 'Areal-U/bare-runner-disk-probe'
    if os.environ['GITHUB_REPOSITORY'] != repo or not os.environ.get('JOB_READ_TOKEN'):
        raise ValueError('Job clock requires the authorized repository and read credential')
    run = int(os.environ['GITHUB_RUN_ID'])
    attempt = int(os.environ['GITHUB_RUN_ATTEMPT'])
    allowed_sha = {os.environ['GITHUB_SHA']}
    if os.environ.get('GITHUB_EVENT_NAME') == 'pull_request':
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
        allowed_sha.add(event['pull_request']['head']['sha'])
    path = f'/repos/{repo}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'
    headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'bare-trial-clock',
               'Authorization': 'Bearer ' + os.environ['JOB_READ_TOKEN']}
    for retry in range(3):
        conn = http.client.HTTPSConnection('api.github.com', timeout=10)
        try:
            conn.request('GET', path, headers=headers)
            response = conn.getresponse()
            if response.status != 200:
                raise ValueError(f'Job start lookup HTTP {response.status}')
            listing = json.load(response)
            jobs = listing['jobs']
            matches = [j for j in jobs if j['run_id'] == run and j['run_attempt'] == attempt
                       and j['head_sha'] in allowed_sha and j['status'] == 'in_progress'
                       and j['check_run_url'] == f'https://api.github.com/repos/{repo}/check-runs/{check_run}']
            if len(jobs) != listing['total_count'] or len(matches) != 1:
                raise ValueError('No unambiguous active check run clock')
            start = datetime.fromisoformat(matches[0]['started_at'].replace('Z', '+00:00'))
            if not start.tzinfo or start.timestamp() > time.time():
                raise ValueError('Invalid job start')
            return int(start.timestamp())
        except (OSError, ValueError, http.client.HTTPException):
            if retry == 2:
                raise
            time.sleep(2)
        finally:
            conn.close()


def tree(path):
    wall = time.monotonic()
    cpu = time.thread_time()
    logical = allocated = entries = 0
    pending = [path]
    while pending:
        try:
            directory = os.scandir(pending.pop())
        except FileNotFoundError:
            continue
        with directory as contents:
            for item in contents:
                try:
                    info = item.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if stat.S_ISDIR(info.st_mode):
                    pending.append(item.path)
                elif stat.S_ISREG(info.st_mode):
                    logical += info.st_size
                allocated += info.st_blocks * 512
                entries += 1
    return {'estimate': max(allocated, logical) + entries * 2048, 'entries': entries,
            'scan_seconds': time.monotonic() - wall, 'scan_cpu_seconds': time.thread_time() - cpu}


def pressure(sample, fs, terminal):
    byte_margin = min(OUT_CAP - sample['estimate'], fs['free_bytes'] - FLOOR)
    inode_margin = min(ENTRY_CAP - sample['entries'], fs['free_inodes'] - INODE_FLOOR)
    if byte_margin <= STOP_MARGIN or inode_margin <= STOP_ENTRIES:
        return 'stop', 5
    if terminal or byte_margin <= FAST_MARGIN or inode_margin <= FAST_ENTRIES:
        return 'fast', 5
    return 'normal', 30


class QuiescenceBudget:
    """Escalate a graceful stop before a further observed burst would cross a floor."""
    def __init__(self, sample, fs, out_cap=OUT_CAP, entry_cap=ENTRY_CAP, floor=FLOOR):
        self.limits = (out_cap, entry_cap, floor)
        self.tree = sample.copy()
        self.previous = fs.copy()
        self.margin = [QUIESCE_BYTES, QUIESCE_ENTRIES, QUIESCE_BYTES, QUIESCE_ENTRIES]

    def risk(self, sample, fs):
        out_cap, entry_cap, floor = self.limits
        growth = [sample['estimate'] - self.tree['estimate'], sample['entries'] - self.tree['entries'],
                  self.previous['free_bytes'] - fs['free_bytes'], self.previous['free_inodes'] - fs['free_inodes']]
        self.margin = [max(old, new) for old, new in zip(self.margin, growth)]
        self.tree, self.previous = sample.copy(), fs.copy()
        remaining = [out_cap - sample['estimate'], entry_cap - sample['entries'],
                     fs['free_bytes'] - floor, fs['free_inodes'] - INODE_FLOOR]
        labels = ('archive-estimate', 'archive-entries', 'free-bytes', 'free-inodes')
        return next((label for label, space, guard in zip(labels, remaining, self.margin) if space <= guard), None)


def memory():
    root = Path('/sys/fs/cgroup')
    result = {}
    for item in ('memory.current', 'memory.peak', 'memory.events'):
        file = root / item
        if file.is_file():
            raw = file.read_text().strip()
            result[item] = (dict((x.split()[0], int(x.split()[1])) for x in raw.splitlines())
                            if item == 'memory.events' else int(raw))
    return result


def log_event(f, event, **fields):
    record = {'event': event, 'time': time.time(), **fields}
    f.write(json.dumps(record, separators=(',', ':'), sort_keys=True) + '\n')
    f.flush()


def monitor(args):
    command = args.cmd[1:] if args.cmd[:1] == ['--'] else args.cmd
    if not command or not args.output.is_dir():
        raise ValueError('Missing checked output tree or build command')
    wall_remaining = compile_seconds(args.job_start, time.time(), args.job_minutes)
    limit = time.monotonic() + wall_remaining
    # Run inside the build container so SIGINT reaches Siso and every compiler.
    state = {'reason': None}
    def cancel(signum, frame):
        state['reason'] = 'cancelled'
    old = {sig: signal.signal(sig, cancel) for sig in (signal.SIGTERM, signal.SIGINT)}
    proc = None
    group_alive = False
    try:
        with args.jsonl.open('x', encoding='utf-8') as out, concurrent.futures.ThreadPoolExecutor(max_workers=1) as scan:
            def emit(label, **fields):
                log_event(out, label, **fields)
            sample, fs = tree(args.output), disk(args.output)
            level, interval = pressure(sample, fs, args.terminal)
            mem_before = memory()
            emit('start', **sample, **fs, **mem_before, level=level, remaining=wall_remaining, interval=interval)
            if level == 'stop' or time.monotonic() >= limit or state['reason']:
                raise GuardError('compile-not-started', level=level, remaining=wall_remaining)
            proc = subprocess.Popen(command, start_new_session=True)
            group_alive = True
            scan_from = time.monotonic()
            cheap_from = scan_from
            future = None
            scans = 1
            peak_bytes, peak_entries = sample['estimate'], sample['entries']
            min_free, min_inodes = fs['free_bytes'], fs['free_inodes']
            int_time = None
            settle = None
            while proc.poll() is None:
                now = time.monotonic()
                fs = disk(args.output)
                min_free, min_inodes = min(min_free, fs['free_bytes']), min(min_inodes, fs['free_inodes'])
                if future is not None and future.done():
                    sample = future.result()
                    future = None
                    scans += 1
                    peak_bytes = max(peak_bytes, sample['estimate'])
                    peak_entries = max(peak_entries, sample['entries'])
                    emit('scan', **sample, **fs, **memory())
                level, interval = pressure(sample, fs, args.terminal)
                if settle is not None:
                    interval = 5
                if now - cheap_from >= 5:
                    emit('space', **fs, **memory(), level=level, interval=interval)
                    cheap_from = now
                if future is None and now - scan_from >= interval:
                    future = scan.submit(tree, args.output)
                    scan_from = now
                if int_time is None:
                    if level == 'stop' or now >= limit or state['reason']:
                        state['reason'] = state['reason'] or ('resource-margin' if level == 'stop' else 'time-budget')
                        emit('interrupt', reason=state['reason'], **fs, **sample)
                        try:
                            os.killpg(proc.pid, signal.SIGINT)
                        except ProcessLookupError:
                            pass
                        int_time = now
                        settle = QuiescenceBudget(sample, fs)
                        scan_from = now - 5
                risk = settle.risk(sample, fs) if settle is not None else None
                if int_time is not None and (risk or now - int_time >= 120):
                    emit('kill', reason=risk or 'grace-timeout', elapsed=now-int_time, **fs, **sample)
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    state['reason'] = 'forced-kill'
                time.sleep(0.5)
            proc.wait()
            if future is not None:
                future.result()
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                group_alive = False
            else:
                raise GuardError('unsettled-process-group')
            final = tree(args.output)
            fs = disk(args.output)
            peak_bytes = max(peak_bytes, final['estimate'])
            peak_entries = max(peak_entries, final['entries'])
            min_free, min_inodes = min(min_free, fs['free_bytes']), min(min_inodes, fs['free_inodes'])
            mem_after = memory()
            oom = (mem_after.get('memory.events', {}).get('oom_kill', 0) >
                   mem_before.get('memory.events', {}).get('oom_kill', 0))
            ok = (not oom and not state['reason'] and proc.returncode == 0 and peak_bytes < OUT_CAP and
                  peak_entries < ENTRY_CAP and min_free >= FLOOR and min_inodes >= INODE_FLOOR)
            emit('settled', ok=ok, reason=state['reason'], returncode=proc.returncode,
                 scans=scans + 1, peak_estimate=peak_bytes, peak_entries=peak_entries, min_free=min_free,
                 min_inodes=min_inodes, oom_kill=oom, **fs, **mem_after, **final)
            if not ok:
                raise GuardError('build-not-eligible', reason=state['reason'], returncode=proc.returncode)
            return {'status': 'completed', 'file': str(args.jsonl)}
    finally:
        if proc is not None and group_alive:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        for sig, handler in old.items():
            signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    p = parser.add_subparsers(dest='action', required=True)
    cache = p.add_parser('cache')
    cache.add_argument('inventory', type=Path)
    clock = p.add_parser('job-clock')
    clock.add_argument('--check-run', type=int, required=True)
    size = p.add_parser('size')
    size.add_argument('kind', choices=BYTE_CAPS)
    size.add_argument('path', type=Path)
    s = p.add_parser('space')
    s.add_argument('path', type=Path)
    s.add_argument('--bytes', dest='future_bytes', type=int, required=True)
    s.add_argument('--inodes', dest='future_inodes', type=int, required=True)
    s.add_argument('--floor-bytes', default=FLOOR, type=int)
    s.add_argument('--floor-inodes', default=INODE_FLOOR, type=int)
    for name in ('deadline', 'monitor'):
        a = p.add_parser(name)
        a.add_argument('--job-start', type=float, required=True)
        a.add_argument('--job-minutes', type=int, default=350)
        if name == 'monitor':
            a.add_argument('--output', type=Path, required=True)
            a.add_argument('--jsonl', type=Path, required=True)
            a.add_argument('--terminal', action='store_true')
            a.add_argument('cmd', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        if args.action == 'job-clock':
            print(job_clock(args.check_run))
            return 0
        if args.action == 'cache':
            result = cache_budget(json.loads(args.inventory.read_text()))
        elif args.action == 'space':
            result = reserve(disk(args.path), args.future_bytes, args.future_inodes, args.floor_bytes, args.floor_inodes)
        elif args.action == 'size':
            result = check_size(args.kind, args.path)
        elif args.action == 'deadline':
            print(compile_seconds(args.job_start, time.time(), args.job_minutes))
            return 0
        else:
            result = monitor(args)
        print(json.dumps(result, sort_keys=True))
        return 0
    except GuardError as e:
        print(json.dumps(e.record, sort_keys=True), file=sys.stderr)
        return 65 if e.record['status'] == 'size-exceeded' else 66
    except (OSError, ValueError) as e:
        print(str(e), file=sys.stderr)
        return 66


if __name__ == '__main__':
    sys.exit(main())
