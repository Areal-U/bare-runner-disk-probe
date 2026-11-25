"""Handle the two VM trial's per-attempt, short-lived, encrypted handoff."""
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from cohort import MAX_PAYLOAD

ROOT = Path(os.environ['RUNNER_TEMP'])/'next-split'
ROOT.mkdir(parents=True, exist_ok=True)
CLOCK = ROOT/'clock.json'


def snapshot():
    v = os.statvfs(ROOT)
    info = Path('/proc/meminfo').read_text().splitlines()
    return {'epoch': time.time(), 'disk_free': shutil.disk_usage(ROOT).free,
            'inodes_free': v.f_favail, 'mem_available_kib': int(next(s for s in info if s.startswith('MemAvailable:')).split()[1])}


def stamp(name):
    times = json.loads(CLOCK.read_text()) if CLOCK.exists() else {}
    times[name] = snapshot()
    if name == "first":
        times[name]["epoch"] = float((ROOT.parent/"first").read_text())
    CLOCK.write_text(json.dumps(times, sort_keys=True))


def openssl(*args):
    subprocess.run(['openssl', *args], cwd=ROOT, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def wait(kind, filename, maximum):
    repo = os.environ['GITHUB_REPOSITORY']
    run = os.environ['GITHUB_RUN_ID']
    name = f'split-{kind}-{run}-{os.environ["GITHUB_RUN_ATTEMPT"]}'
    endpoint = f'repos/{repo}/actions/runs/{run}/artifacts?per_page=100'
    dest = ROOT/kind
    dest.mkdir()
    start = time.monotonic()
    while time.monotonic()-start < 300:
        # Strict timestamps, run and attempt names prevent stale handoffs, including reruns.
        res = subprocess.check_output(['gh','api',endpoint], text=True, timeout=30)
        hits = [a for a in json.loads(res)['artifacts'] if a['name']==name]
        if hits:
            if len(hits)!=1 or hits[0]['expired'] or not 0 < hits[0]['size_in_bytes'] <= maximum + 65536:
                raise ValueError('invalid Artifact count or size')
            subprocess.run(['gh','run','download',run,'--repo',repo,'--name',name,'--dir',str(dest)],check=True,timeout=60)
            result = dest/filename
            if list(dest.iterdir()) != [result] or not result.is_file() or result.is_symlink() or result.stat().st_size>maximum:
                raise ValueError('unexpected Artifact content')
            return result
        time.sleep(4)
    raise TimeoutError('sibling did not provide its bounded handoff')


def admit(kind):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'bridge'))
    import bridge
    import storage_admission
    filename, cap = {'ticket': ('cert.pem', 4096), 'parcel': ('exchange.der', MAX_PAYLOAD)}[kind]
    path = ROOT/filename
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= cap:
        raise ValueError('missing or out-of-bounds trial output')
    name = f'split-{kind}-{os.environ["GITHUB_RUN_ID"]}-{os.environ["GITHUB_RUN_ATTEMPT"]}'
    decision = storage_admission.admit(bridge.api_json, os.environ, path.stat().st_size + 65536,
                                       1, stage='control', exact_name=name)
    if decision != 'admitted':
        raise ValueError('same-attempt named Artifact already exists')


def split_result():
    a = json.loads(CLOCK.read_text())
    b = json.loads((ROOT/'peer-clock.json').read_text())
    merged = json.loads((ROOT/'central/join.json').read_text())
    serial = json.loads((ROOT/'solo/solo.json').read_text())
    if not all(merged[k]==serial[k] for k in ('archive','objects_and_deps','units','noop')):
        raise ValueError('merged output differs from independently rebuilt one-runner control')
    clocks = lambda v,k: v[k]['epoch']
    epoch = min(clocks(a,'first'),clocks(b,'first'))
    total = clocks(a,'merged') - epoch
    solo = clocks(a,'first')-epoch + (clocks(a,'ready_for_key')-clocks(a,'first')) + (clocks(a,'prep_done')-clocks(a,'prep_start')) + serial['seconds']
    result = {'units':serial['units'], 'archive_sha256':serial['archive'], 'object_and_depfile_manifest_sha256':serial['objects_and_deps'],
              'zero_central_recompiles_of_peer':True, 'merged_noop':merged['noop'], 'serial_noop':serial['noop'],
              'hosted_pair_elapsed_s':total, 'one_host_comparator_s':solo, 'net_saving_s':solo-total,
              'peer_start_minus_central_s':clocks(b,'first')-clocks(a,'first'),
              'encrypted_payload_bytes': (ROOT/'parcel'/'exchange.der').stat().st_size,
              'owner_timeline':a,'peer_timeline':b,
              'interpretation': 'Sample only. Serial rebuild followed merge on the owner; shared setup measured once and serial filesystem may be warm. Retain single host if no net gain. Positive result needs the actual proposed production group, full parent distribution and independent confirmation.'}
    msg=json.dumps(result,sort_keys=True,indent=2)
    print(msg)
    if 'GITHUB_STEP_SUMMARY' in os.environ:
        with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f: f.write('```json\n'+msg+'\n```\n')


def main():
    op = sys.argv[1]
    if op=='admit': admit(sys.argv[2])
    elif op=='stamp': stamp(sys.argv[2])
    elif op=='cert':
        os.umask(0o077)
        openssl('req','-x509','-newkey','rsa:3072','-nodes','-days','1','-subj','/CN=single-attempt-split',
                '-keyout','key.pem','-out','cert.pem')
    elif op=='seal':
        from zipfile import ZipFile, ZIP_STORED
        cert = wait('ticket','cert.pem',4096)
        stamp('key_received')
        with ZipFile(ROOT/'parcel.zip','x',ZIP_STORED) as z:
            z.write(ROOT/'peer/shard.zip','shard.zip')
            z.write(CLOCK,'peer-clock.json')
        openssl('cms','-encrypt','-binary','-aes-256-cbc','-in','parcel.zip','-outform','DER','-out','exchange.der',str(cert))
        if (ROOT/'exchange.der').stat().st_size>MAX_PAYLOAD: raise ValueError('peer exceeds byte ceiling')
    elif op=='open':
        from zipfile import ZipFile
        packet=wait('parcel','exchange.der',MAX_PAYLOAD)
        stamp('cipher_arrived')
        openssl('cms','-decrypt','-binary','-inform','DER','-in',str(packet),'-recip','cert.pem','-inkey','key.pem','-out','parcel.zip')
        with ZipFile(ROOT/'parcel.zip') as z:
            if sorted(z.namelist())!=['peer-clock.json','shard.zip'] or sum(i.file_size for i in z.infolist())>MAX_PAYLOAD:
                raise ValueError('unexpected parcel')
            for name in z.namelist(): (ROOT/name).write_bytes(z.read(name))
    elif op=='report': split_result()
    else: raise ValueError('unknown field operation')

if __name__=='__main__': main()
