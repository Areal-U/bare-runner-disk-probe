"""Finite, exact-key encrypted checkpoint relay shared by the two physical jobs."""
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'preflight28/bridge'))
import bridge as b
import normal
import owner_recovery
import storage_admission as storage

MIB = 1024**2
PACKET_BYTES = 256*MIB
MAX_SEALED = b.CAP+16*MIB
MAX_COUNT = math.ceil(MAX_SEALED/PACKET_BYTES)
PACKET_PATH = Path('.r209-checkpoint-packet')
ACK_PATH = Path('.r209-checkpoint-receipt')
PATHS = {'packet': PACKET_PATH, 'receipt': ACK_PATH}
BOUNDS = {'packet': {'piece.json': 64*1024, 'piece.sig': 1024, 'piece.bin': PACKET_BYTES},
          'receipt': {'receipt.json': 8192, 'receipt.sig': 1024}}
PIN = 'caa296126883cff596d87d8935842f9db880ef25'
BLOBS = {'save': '8fc460647e95ba42e86a935727b832eb1aebbda4',
         'restore': 'f8be2b24e7a9daff5a4f468730e73756b6199e48'}
REQUIRE = b.require
BASE = storage.BASE


def max_draft_assets():
    # Payload and metadata per piece plus outcome, canonical archive and intent/manifest.
    return 4*MAX_COUNT+10


def data(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, bound):
    info = path.lstat()
    REQUIRE(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= bound and
            path.resolve() == path.absolute(), 'Non-regular, linked or oversized packet file')
    return info.st_size


def read_json(path, bound):
    regular(path, bound)
    return json.loads(path.read_bytes())


def until(deadline):
    remaining = deadline - time.time()
    REQUIRE(remaining > 0, 'Checkpoint packet time budget exhausted')
    return remaining


def pause(deadline):
    time.sleep(min(10, until(deadline)))


def get_before(deadline):
    return b.api_before(time.monotonic()+until(deadline))


def key(index, kind='packet'):
    ctx = normal.context()
    claim = b.env_int('R28_COLLECTION_CLAIM')
    REQUIRE(normal.R209, 'Not the 2.0.9 production generation')
    return generation_key(ctx,claim,index,kind)


def generation_key(ctx,claim,index,kind='packet'):
    REQUIRE(type(claim) is int and claim>0 and type(index) is int and 0 <= index < MAX_COUNT and kind in PATHS,
            'Unknown packet slot, index or kind')
    generation = sha(data(dict(ctx, claim=claim)))
    return f'r209-{ctx["run"]}-a1-s{ctx["ordinal"]:02}-c{claim}-{generation}-{kind}-{index:02}'


def folder(kind):
    return Path(os.environ['GITHUB_WORKSPACE']) / PATHS[kind]


def reset(kind):
    path = folder(kind)
    REQUIRE(path.parent.resolve() == path.parent, 'Ambiguous runner workspace')
    if path.exists() or path.is_symlink():
        REQUIRE(path.is_dir() and not path.is_symlink(), 'Unexpected prior staging path')
        shutil.rmtree(path)
    path.mkdir(mode=0o700)


def checked_files(kind, directory):
    REQUIRE(directory.resolve() == directory.absolute() and directory.is_dir() and
            {p.name for p in directory.iterdir()} == set(BOUNDS[kind]), 'Unexpected relay archive files')
    return sum(regular(directory/name, limit) for name,limit in BOUNDS[kind].items())


def archive_bound(size):
    # POSIX headers, packet JSON, signatures and worst-case zstd framing.
    return size + MIB


def version(kind):
    # Exact Linux/zstd version composition in the pinned cache action.
    return sha(f'{PATHS[kind]}|zstd-without-long|1.0'.encode())


def service_row(row):
    REQUIRE(isinstance(row,dict) and type(row.get('id')) is int and row['id'] > 0 and
            type(row.get('size_in_bytes')) is int and row['size_in_bytes'] > 0 and
            all(isinstance(row.get(k),str) and row[k] for k in ('key','ref','version')),
            'Invalid cache service receipt')
    return {k:row[k] for k in ('id','key','ref','version','size_in_bytes')}


def exact(cache_key, deadline):
    get = get_before(deadline)
    ref = os.environ['GITHUB_REF']
    query = urlencode(dict(key=cache_key, ref=ref, per_page=100))
    answer = get(BASE+'/actions/caches?'+query)
    rows = answer['actions_caches']
    REQUIRE(isinstance(rows,list) and type(answer['total_count']) is int and
            len(rows)==answer['total_count']<=100, 'Incomplete exact cache lookup')
    hits = [service_row(row) for row in rows if row['key']==cache_key and row['ref']==ref]
    REQUIRE(len(hits)<=1, 'Ambiguous immutable cache version')
    if hits:
        kind = 'receipt' if '-receipt-' in cache_key else 'packet'
        REQUIRE(hits[0]['version']==version(kind) and hits[0]['size_in_bytes'] <=
                archive_bound(PACKET_BYTES if kind=='packet' else 0), 'Wrong cache version or size')
        return hits[0]
    return None


def wait_row(cache_key, deadline):
    while True:
        row = exact(cache_key,deadline)
        if row:
            return row
        pause(deadline)


def inventory(get):
    seen = {}
    total = None
    for page in range(1,52):
        value = get(f'{BASE}/actions/caches?per_page=100&page={page}')
        rows, n = value['actions_caches'],value['total_count']
        REQUIRE(type(n) is int and 0<=n<=5000 and isinstance(rows,list) and
                (total is None or total==n) and len(rows)==min(100,max(0,n-100*(page-1))),
                'Incomplete repository cache inventory')
        total = n
        for value in rows:
            row = service_row(value)
            REQUIRE(row['id'] not in seen, 'Duplicate physical cache')
            seen[row['id']] = row
        if len(seen)==total:
            return seen
    raise ValueError('Unbounded repository cache inventory')


def meter(get):
    value = get(BASE+'/actions/cache/usage')
    size,count = value['active_caches_size_in_bytes'],value['active_caches_count']
    REQUIRE(all(type(v) is int and v>=0 for v in (size,count)), 'Unconfirmed cache meter')
    return size,count


def snapshot(deadline):
    get = get_before(deadline)
    while True:
        rows = inventory(get)
        usage = meter(get)
        if rows==inventory(get) and usage==meter(get):
            return rows,usage
        pause(deadline)


def accounted(view):
    rows,usage = view
    return usage==(sum(r['size_in_bytes'] for r in rows.values()),len(rows))


def capacity(required_bytes, pending_whole_bytes, latest_epoch, *, debt=0, lead=0):
    """Return additional unallocated bytes after this write and unsettled prior writes."""
    env = os.environ
    REQUIRE(type(required_bytes) is int and 0<required_bytes<=archive_bound(PACKET_BYTES) and
            type(pending_whole_bytes) is int and 0<pending_whole_bytes<=MAX_SEALED and
            type(debt) is int and debt>=0, 'Invalid packet admission amounts')
    get = get_before(latest_epoch)
    ceiling,expiry = storage.config(env)
    storage.public_host(get(BASE),env.get('RUNNER_ENVIRONMENT'))
    storage.check_active_runs(get,env)
    configured = storage.integer(get(BASE+'/actions/cache/storage-limit')['max_cache_size_gb'],'service cache limit')
    REQUIRE(configured<=10, 'Service permits cache growth beyond free capacity')
    REQUIRE(lead in (0,normal.JOB_MINUTES*60), 'Unknown storage lead')
    cap = min(configured*1024**3,ceiling)
    # ALL public transfers, framing and ACKs must fit the authenticated transfer allowance.
    count = math.ceil(pending_whole_bytes/PACKET_BYTES)
    REQUIRE(pending_whole_bytes+count*2*MIB<=ceiling, 'Full relay exceeds ticket byte ceiling')
    rows,usage = snapshot(latest_epoch)
    storage.check_active_runs(get,env)
    until(latest_epoch)
    # The finite owner Artifact policy bounds operations through independent readback.
    # Cache free capacity is separately service-enforced, including after interruption.
    # Only owner administration could read or change retention configuration.
    REQUIRE(max(time.time()+lead,latest_epoch)+normal.PUBLISH_MINUTES*60<=expiry,
            'Storage lease expires before the transfer and readback window ends')
    occupied = max(usage[0],sum(r['size_in_bytes'] for r in rows.values()))
    spare = cap-occupied-debt-required_bytes-storage.CACHE_FLOOR-storage.CONTROL_RESERVE
    print(f'R209_PACKET_CAPACITY ceiling={cap} occupied={occupied} pending_debt={debt} '
          f'write={required_bytes} whole={pending_whole_bytes} spare={spare}',flush=True)
    if spare<0:
        raise storage.StorageFull('Checkpoint packet would displace existing caches or exceed the free ceiling')
    return spare


def stage_tools():
    dest = Path(os.environ['RUNNER_TEMP'])/'r209-cache-client'
    dest.mkdir(mode=0o700, exist_ok=True)
    def git(*args):
        return subprocess.run(['git','-C',str(dest),*args],env={**os.environ,'GIT_TERMINAL_PROMPT':'0'},
                              check=True, stdout=subprocess.PIPE, timeout=90).stdout.strip()
    if not (dest/'.git').is_dir():
        git('init','-q')
        git('sparse-checkout','set','--no-cone','/dist/save-only/','/dist/restore-only/')
        git('-c','credential.helper=','-c','http.extraHeader=','fetch','--no-tags','--depth=1',
            'https://github.com/actions/cache.git',PIN)
        git('checkout','--quiet','--detach','FETCH_HEAD')
    REQUIRE(git('rev-parse','HEAD').decode()==PIN, 'Wrong cache SDK commit')
    for mode in BLOBS:
        tool(mode)
    REQUIRE(shutil.which('zstd') and shutil.which('unzstd'), 'Required pinned cache compression unavailable')
    stage_hook()


def stage_hook():
    source = HERE/'packet_tar.py'
    regular(source,32*1024)
    directory = Path(os.environ['RUNNER_TEMP'])/'r209-cache-safe-bin'
    directory.mkdir(mode=0o700,exist_ok=True)
    REQUIRE(directory.resolve()==directory and directory.stat().st_mode&0o077==0, 'Unsafe tar hook directory')
    dest = directory/'tar'
    if not dest.exists():
        with dest.open('xb') as f:
            f.write(source.read_bytes())
        dest.chmod(0o700)
    checked_hook()


def checked_hook():
    source = HERE/'packet_tar.py'
    dest = Path(os.environ['RUNNER_TEMP'])/'r209-cache-safe-bin/tar'
    regular(source,32*1024)
    regular(dest,32*1024)
    REQUIRE(dest.stat().st_mode&0o777==0o700 and dest.read_bytes()==source.read_bytes() and
            dest.parent.resolve()==dest.parent and dest.parent.stat().st_mode&0o077==0,
            'Missing, substituted or non-executable safe extraction hook')
    return dest


def tool(mode):
    path = Path(os.environ['RUNNER_TEMP'])/'r209-cache-client'/'dist'/f'{mode}-only'/'index.js'
    size = regular(path,64*MIB)
    digest = hashlib.sha1(f'blob {size}\0'.encode())
    with path.open('rb') as source:
        while buf:=source.read(MIB):
            digest.update(buf)
    REQUIRE(digest.hexdigest()==BLOBS[mode], 'Pinned official cache client bytes changed')
    return path


def outputs(raw):
    lines = raw.splitlines()
    parsed = {}
    while lines:
        first,*lines = lines
        found = re.fullmatch(r'(cache-hit|cache-matched-key|cache-primary-key)<<(ghadelimiter_[\w-]+)',first)
        REQUIRE(found and len(lines)>=2 and lines[1]==found[2] and found[1] not in parsed,
                'Unrecognized cache client receipt')
        parsed[found[1]] = lines[0]
        lines = lines[2:]
    return parsed


def sdk(mode,kind,index,deadline):
    cache_key = key(index,kind)
    path = tool(mode)
    REQUIRE(os.environ.get('ACTIONS_RUNTIME_TOKEN') and os.environ.get('ACTIONS_RESULTS_URL'),
            'Cache transport needs the authenticated Actions runtime')
    # Isolate action outputs and suppress the service client's console text/commands.
    with tempfile.TemporaryDirectory(dir=os.environ['RUNNER_TEMP']) as temp:
        out = Path(temp)/'output'
        out.touch(mode=0o600)
        env = {k:v for k,v in os.environ.items() if not k.startswith(('INPUT_','STATE_','NODE_'))
               and k not in ('GH_TOKEN','GITHUB_TOKEN','ACTIONS_STEP_DEBUG')}
        env.update(INPUT_KEY=cache_key, INPUT_PATH=str(PATHS[kind]), INPUT_ENABLECROSSOSARCHIVE='false',
                   GITHUB_OUTPUT=str(out), GITHUB_STATE=os.devnull, RUNNER_DEBUG='0')
        if mode=='restore':
            hook = checked_hook()
            env.update({'INPUT_FAIL-ON-CACHE-MISS':'true','INPUT_LOOKUP-ONLY':'false',
                        'PATH':str(hook.parent)+os.pathsep+env['PATH'],
                        'R209_PACKET_KIND':kind})
            REQUIRE(shutil.which('tar',path=env['PATH'])==str(hook),'Safe cache extraction hook does not resolve')
        # R209_PACKET_NODE is set only by the local node24 action.
        proc = subprocess.run([os.environ['R209_PACKET_NODE'],str(path)],cwd=os.environ['GITHUB_WORKSPACE'],
                              env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
                              timeout=min(300,until(deadline)))
        if mode=='restore':
            REQUIRE(proc.returncode==0 and regular(out,8192)>0, 'Official cache restore failed')
            result = outputs(out.read_text())
            REQUIRE(result=={'cache-hit':'true','cache-primary-key':cache_key,'cache-matched-key':cache_key},
                    'Official cache restore did not return the exact primary key')
        return proc.returncode


def save(kind,index,deadline,whole_bytes,*,debt=0):
    measured = checked_files(kind,folder(kind))
    bound = archive_bound((folder(kind)/'piece.bin').stat().st_size if kind=='packet' else 0)
    cache_key = key(index,kind)
    existing = exact(cache_key, deadline)
    if existing:
        # ACKs are deterministic and the restored signed content is checked by
        # each endpoint. A lost PUT response cannot authorize another save.
        REQUIRE(kind=='receipt', 'Unreconciled existing packet. Preserve it for recovery')
        return existing
    capacity(bound,whole_bytes,deadline,debt=debt)
    sdk('save',kind,index,deadline)
    bound_end = min(deadline,time.time()+120)
    while True:
        row = exact(cache_key,bound_end)
        if row:
            break
        # A short piece may reach private storage before the initial save's REST
        # index becomes visible to the sender. Recover only its signed receipt.
        ack = exact(key(index,'receipt'),bound_end) if kind=='packet' else None
        if ack:
            restore('receipt',index,ack,bound_end)
            piece = read_json(folder('packet')/'piece.json',64*1024)
            row = read_json(folder('receipt')/'receipt.json',8192)['source']
            verify_receipt(piece,row)
            break
        pause(bound_end)
    REQUIRE(row['size_in_bytes']<=bound,'Physical cache grew beyond reservation')
    return row


def restore(kind,index,row,deadline):
    cache_key = key(index,kind)
    REQUIRE(exact(cache_key,deadline)==row,'Cache changed before restore')
    reset(kind)
    sdk('restore',kind,index,deadline)
    checked_files(kind,folder(kind))
    REQUIRE(exact(cache_key,deadline)==row,'Cache changed during restore')


def signature(folder,filename,private):
    b.openssl('dgst','-sha256','-sign',private,'-out',folder/(filename+'.sig'),folder/(filename+'.json'),timeout=15)


def verify(folder,filename,cert):
    b.fingerprint(cert)
    key = b.openssl('x509','-pubkey','-noout','-in',cert,capture=True,timeout=15)
    with tempfile.NamedTemporaryFile(dir=os.environ['RUNNER_TEMP']) as file:
        file.write(key)
        file.flush()
        b.openssl('dgst','-sha256','-verify',file.name,'-signature',folder/(filename+'.sig'),
                  folder/(filename+'.json'),timeout=15)


def validate_outcome(outcome,cert):
    ctx = normal.context()
    REQUIRE(isinstance(outcome,dict) and normal.same(outcome),'Foreign outcome context')
    if outcome['status'] in normal.STOPS:
        REQUIRE(set(outcome)==set(ctx)|{'status'}, 'Unexpected control-only fields')
        return 0
    fields = {'status','bytes','sha256','identity','proof_sha','sealed_bytes','sealed_sha','recipient_fpr','owner_recovery'}
    REQUIRE(outcome['status']=='candidate' and set(outcome)==set(ctx)|fields and
            type(outcome['bytes']) is int and type(outcome['sealed_bytes']) is int and
            0<outcome['bytes']<=b.CAP and outcome['bytes']<outcome['sealed_bytes']<=outcome['bytes']+16*MIB and
            all(b.sha(outcome[k]) for k in ('sha256','identity','proof_sha','sealed_sha','recipient_fpr')) and
            outcome['recipient_fpr']==b.fingerprint(cert), 'Invalid sealed checkpoint or writer')
    wrapper = outcome['owner_recovery']
    REQUIRE(isinstance(wrapper,dict) and set(wrapper)=={'format','context','owner','claim_id','writer_fpr','sha256','age'},
            'Unexpected owner wrapper fields')
    owner_recovery.checked(wrapper,ctx,os.environ['R28_OWNER_RECIPIENT'],b.env_int('R28_COLLECTION_CLAIM'),
                           outcome['recipient_fpr'])
    return outcome['sealed_bytes']


def read_piece(index,cert=None):
    directory = folder('packet')
    checked_files('packet',directory)
    verify(directory,'piece',cert or normal.ROOT/'incoming/public.pem')
    piece = read_json(directory/'piece.json',64*1024)
    REQUIRE(set(piece)=={'schema','claim','index','count','offset','bytes','sha256','outcome','meter_barrier'} and
            piece['schema']=='r209-checkpoint-piece-v1' and type(piece['claim']) is int and
            piece['claim']==b.env_int('R28_COLLECTION_CLAIM') and type(piece['meter_barrier']) is bool and
            all(type(piece[k]) is int for k in ('index','count','offset','bytes')) and
            piece['index']==index and data(piece)==(directory/'piece.json').read_bytes(),
            'Wrong signed packet context or layout')
    total = validate_outcome(piece['outcome'],normal.ROOT/'public.pem')
    count = max(1,math.ceil(total/PACKET_BYTES))
    REQUIRE(piece['count']==count and 0<=index<count and piece['offset']==index*PACKET_BYTES and
            piece['bytes']==min(PACKET_BYTES,total-piece['offset'])==(directory/'piece.bin').stat().st_size and
            piece['sha256']==b.digest(directory/'piece.bin'),'Damaged or reordered packet')
    return piece


def receipt_record(piece,row,stage):
    control = piece['outcome']['status']!='candidate'
    size,digest = (len(data(piece)),sha(data(piece))) if control else (piece['bytes'],piece['sha256'])
    REQUIRE(set(stage)=={'name','id','bytes','sha256'} and type(stage['id']) is int and stage['id']>0 and
            stage['bytes']==size and stage['sha256']==digest and
            stage['name'] in (normal.private_stem()+f'-packet-{piece["index"]:03}',
                              normal.private_stem()+f'-packet-{piece["index"]:03}-retry1'),
            'Private stage receipt does not bind the selected packet')
    REQUIRE(row['key']==key(piece['index']) and row['ref']==os.environ['GITHUB_REF'] and
            row['version']==version('packet'),'Unbound packet source')
    return {'schema':'r209-checkpoint-receipt-v1','claim':piece['claim'],'index':piece['index'],
            'piece_sha':sha(data(piece)),'source':service_row(row),'private_stage':stage}


def make_receipt(piece,row,private_stage):
    reset('receipt')
    directory = folder('receipt')
    record = receipt_record(piece,row,private_stage)
    (directory/'receipt.json').write_bytes(data(record))
    signature(directory,'receipt',normal.ROOT/'key.pem')
    return record


def verify_receipt(piece,row):
    directory = folder('receipt')
    checked_files('receipt',directory)
    verify(directory,'receipt',normal.ROOT/'writer.pem')
    record = read_json(directory/'receipt.json',8192)
    REQUIRE(record==receipt_record(piece,row,record['private_stage']) and
            (directory/'receipt.json').read_bytes()==data(record),'Unmatched private packet acknowledgement')
    return record


def before_delete(piece,row,deadline):
    if not piece['meter_barrier']:
        return
    deadline = min(deadline,time.time()+360)
    while True:
        rows,usage = snapshot(deadline)
        REQUIRE(rows.get(row['id'])==row,'Packet disappeared before meter high watermark')
        if accounted((rows,usage)):
            print(f'R209_PACKET_METER_HIGH id={row["id"]} bytes={usage[0]} count={usage[1]}',flush=True)
            return
        pause(deadline)


if __name__=='__main__':
    REQUIRE(sys.argv[1:]==['stage-tools'],'Expected stage-tools')
    stage_tools()
