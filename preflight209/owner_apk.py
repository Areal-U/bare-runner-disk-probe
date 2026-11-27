"""Seal one completed Bare Personal 2.0.9 APK and verify its private delivery."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'preflight28' / 'collector'))
import production as collector
from launcher_labels import EXPECTED, manifest_tree, observed_labels
from apk_seal import CIPHER_CAP, RECIPIENT

VERSION = '2.0.9'
CODE = '802000915'
PACKAGE = 'org.barebrowser.personal'
BARE = '019a612f7bb758da20c33ecf43c086e696391aec'
CHROMIUM = '52bdd21723d5db0c9ab11716d38feac74828cf84'
OFFICIAL_APK = '09305d8e345c28339cc983393e50d7bddf51ca07f213760e21e4556ba6fbf9fa'
APK_CAP = 450 * 1024**2
CIPHER = 'Bare-Personal-2.0.9-arm64-v8a.tar.age'
SCHEMA = 'bare-personal-209-apk-seal-v1'
SOURCE_SCHEMA = 'bare-personal-209-owner-zip-v1'
DRAFT_SOURCE_SCHEMA = 'bare-personal-209-owner-draft-v1'
ORIGIN_KEYS = ('run', 'attempt', 'ordinal', 'producer_sha', 'accepted_parent', 'claim')
# From the signed official arm64 2.0.9 manifest. One provider declares three authorities.
PROVIDERS = {
    'org.chromium.chrome.browser.util.ChromeFileProvider': ('.FileProvider',),
    'org.chromium.chrome.browser.download.DownloadFileProvider': ('.DownloadFileProvider',),
    'org.chromium.ui.dragdrop.DropDataContentProvider': ('.DropDataProvider',),
    'org.chromium.ui.base.ClipboardTextDataProvider': ('.ClipboardTextDataProvider',),
    'org.chromium.chrome.browser.pdf.PdfContentProvider': ('.PdfContentProvider',),
    'org.chromium.chrome.browser.provider.ChromeBrowserProvider': ('.ChromeBrowserProvider', '.browser', ''),
    'org.chromium.chrome.browser.provider.PageContentProvider': ('.PageContentProvider',),
    'org.chromium.chrome.browser.screenshotprovider.ScreenshotContentProvider': ('.ScreenshotContentProvider',),
    'org.chromium.chrome.browser.autofill.AutofillThirdPartyModeContentProvider': ('.AutofillThirdPartyModeContentProvider',),
}
PERMISSION_SUFFIXES = ('.permission.CHILD_SERVICE', '.permission.READ_WRITE_BOOKMARK_FOLDERS',
                       '.TOS_ACKED', '.permission.C2D_MESSAGE', '.permission.DEBUG')
NATIVE = {'lib/arm64-v8a/' + n for n in ('libchrome.so', 'libchromium_android_linker.so',
                                        'libcrashpad_handler_trampoline.so')}
MAIN = 'com.google.android.apps.chrome.Main'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(4 * 1024**2), b''):
            h.update(chunk)
    return h.hexdigest()


def document(path):
    return json.loads(path.read_bytes())


def encode(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode('ascii')


def hash_string(value, length):
    return type(value) is str and re.fullmatch(rf'[0-9a-f]{{{length}}}', value) is not None


def origin(args):
    require(args.run > 0 and args.claim > 0 and 1 <= args.slot <= 99 and
            hash_string(args.head, 40) and hash_string(args.parent, 64), 'Invalid production identity')
    return dict(run=args.run, attempt=1, ordinal=args.slot, producer_sha=args.head,
                accepted_parent=args.parent, claim=args.claim)


def check_seal(record, expected):
    required = set(ORIGIN_KEYS) | {'schema', 'recipient', 'sha', 'bytes'}
    require(set(record) == required and record['schema'] == SCHEMA and record['recipient'] == RECIPIENT and
            all(type(record[k]) is type(expected[k]) and record[k] == expected[k] for k in ORIGIN_KEYS) and
            hash_string(record['sha'], 64) and type(record['bytes']) is int and 0 < record['bytes'] <= CIPHER_CAP,
            'Wrong version, originating run, slot, claim, parent or ciphertext seal')


def check_report(report, apk, slot, observed_sha=None):
    expected = dict(format='bare-apk-trial', version=1, target='chrome_public_apk', build_dir='out/Bare',
                    phase='seed' if slot == 1 else 'restore', reason='completed', returncode=0,
                    artifact_ready=True, forced_kill=False, failed_step_count=0, container_quiescence_verified=True)
    require(all(type(report.get(k)) is type(v) and report[k] == v for k, v in expected.items()) and
            not report.get('controller_error') and report.get('oom_kill_count', 0) == 0 and
            report.get('failed_steps') == [] and isinstance(report.get('close'), dict) and
            report['close'].get('errors') == [], 'Real APK target has no clean successful result')
    seen = report['apk']
    st = apk.lstat()
    require(stat.S_ISREG(st.st_mode) and type(seen) is dict and seen.get('path') == 'out/Bare/apks/ChromePublic.apk'
            and type(seen.get('size')) is int and 0 < seen['size'] == st.st_size <= APK_CAP and
            seen.get('arm64_member') in NATIVE and seen.get('sha256') == (sha(apk) if observed_sha is None else observed_sha),
            'Exact output APK differs from the completed trial')
    return seen


def check_manifest(root, package):
    require(root.get('package') == package, 'Wrong manifest package')
    providers = root.findall('application/provider')
    observed = {p.attrib['name']: sorted(p.attrib['authorities'].split(';')) for p in providers}
    expected = {name: sorted(package+s for s in group) for name,group in PROVIDERS.items()}
    permissions = [node.attrib['name'] for node in root.findall('permission')]
    require(len(providers) == len(PROVIDERS) and observed == expected and
            sorted(permissions) == sorted(package + s for s in PERMISSION_SUFFIXES),
            'Incomplete or conflicting provider authorities or private permission declarations')
    if package == PACKAGE:
        for node in root.iter():
            for key, value in node.attrib.items():
                if key in ('name', 'permission', 'readPermission', 'writePermission', 'taskAffinity'):
                    require(not (value == 'org.barebrowser' or value.startswith('org.barebrowser.')) or
                            value.startswith(PACKAGE + '.'), 'Manifest still references official app identity')



def check_native(archive):
    infos = [i for i in archive.infolist() if i.filename.startswith('lib/') and not i.is_dir()]
    require(len(infos) == len(NATIVE) and {i.filename for i in infos} == NATIVE, 'Wrong native library set')
    for item in infos:
        with archive.open(item) as stream:
            h = stream.read(64)
            require(len(h) == 64 and h[:7] == b'\x7fELF\x02\x01\x01' and
                    struct.unpack_from('<HH', h, 16) == (3, 183), 'Invalid ARM64 ELF')
            off, = struct.unpack_from('<Q', h, 32)
            size, count = struct.unpack_from('<HH', h, 54)
            require(64 <= off <= 65536 and size == 56 and 0 < count <= 256 and
                    off + size * count <= item.file_size, 'Malformed ELF program table')
            stream.read(off - 64)
            headers = [struct.unpack('<IIQQQQQQ', stream.read(56)) for _ in range(count)]
            loads = [p for p in headers if p[0] == 1]
            require(loads and all(p[7] >= 16384 and (p[7] & (p[7] - 1)) == 0 and
                                (p[2] - p[3]) % p[7] == 0 and p[2] + p[5] <= item.file_size and p[5] <= p[6]
                                for p in loads), 'Unaligned or truncated ARM64 ELF load segment')


def check_launchers(labels):
    expected = {MAIN + suffix for suffix in ('', 'IconDark', 'IconRetro', 'NewIcon')}
    require(labels['enabled'] == [MAIN] and set(labels['launchers']) == expected,
            'Missing, unexpected or differently enabled launcher')
    require(labels['application'] == [EXPECTED] and all(v == [EXPECTED] for v in labels['launchers'].values()),
            'Unexpected application or launcher label')


def observe_apk(apk, sdk, observation):
    aapt = sdk / 'aapt2'
    badging = subprocess.check_output([str(aapt), 'dump', 'badging', str(apk)], text=True, timeout=120)
    lines = badging.splitlines()
    observed = [dict(re.findall(r"\b(\w+)='([^']*)'", s)) for s in lines if s.startswith('package:')]
    observation['packages'] = [{k: item.get(k) for k in ('name','versionName','versionCode')} for item in observed]
    observation['abi_rows'] = [s for s in lines if s.startswith('native-code:')]
    # Preserve the raw application labels even if parsing a broken launcher/resource fails partway.
    observation['badging_labels'] = sorted({s.partition(':')[2] for s in lines if s.startswith('application-label')})
    observation['labels'] = observed_labels(aapt, apk, badging)


def check_apk(apk, sdk, certificate, observation=None, stage=None):
    if observation is None:
        observation = {}
        observe_apk(apk, sdk, observation)
    stage = stage or (lambda name: None)
    aapt = sdk / 'aapt2'
    stage('package_and_abi')
    require(observation['packages'] == [dict(name=PACKAGE, versionName=VERSION, versionCode=CODE)] and
            observation['abi_rows'] == ["native-code: 'arm64-v8a'"], 'Wrong package, versionCode, versionName or ABI')
    stage('launcher_labels')
    labels = observation['labels']
    check_launchers(labels)
    stage('coexistence_manifest')
    xml = subprocess.check_output([str(aapt), 'dump', 'xmltree', str(apk), '--file', 'AndroidManifest.xml'],
                                  text=True, timeout=120)
    check_manifest(manifest_tree(xml), PACKAGE)
    stage('signer')
    collector.verify_signer(apk, certificate, sdk / 'lib/apksigner.jar')
    stage('zip_alignment')
    env = dict(os.environ, LD_LIBRARY_PATH=str(sdk / 'lib64') + os.pathsep + os.getenv('LD_LIBRARY_PATH', ''))
    subprocess.run([str(sdk / 'zipalign'), '-c', '-P', '16', '4', str(apk)], check=True, timeout=120, env=env)
    stage('zip_integrity')
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)) and archive.testzip() is None, 'Duplicate or corrupt APK entry')
        stage('bundled_ubo')
        with archive.open('assets/bare/ublock_origin.crx') as crx:
            require(hashlib.sha256(crx.read(4568085)).hexdigest() == collector.UBO_SHA, 'Wrong bundled uBO')
        stage('arm64_elf')
        check_native(archive)
    return labels


def metadata(expected, seen):
    return dict(origin=expected, apk='ChromePublic.apk', package=PACKAGE, version_name=VERSION,
                version_code=CODE, abi='arm64-v8a', bytes=seen['size'], sha256=seen['sha256'],
                signer_sha256=collector.CI_CERT, embedded_ublock_origin_sha256=collector.UBO_SHA,
                bare_revision=BARE, chromium_revision=CHROMIUM)


def empty_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(path.is_dir() and not path.is_symlink() and not any(path.iterdir()), 'Output directory must be empty')


STAGES = ('candidate_bytes','manifest_observations','production_identity','siso_trial','package_and_abi',
          'launcher_labels','coexistence_manifest','signer','zip_alignment','zip_integrity','bundled_ubo','arm64_elf','encryption')


def failure_reason(error):
    if isinstance(error, subprocess.CalledProcessError):
        return f'subprocess returned {error.returncode}'
    if isinstance(error, (ValueError, KeyError, zipfile.BadZipFile)):
        return str(error)[:500]
    return type(error).__name__


def seal(args):
    obs = dict(run=args.run, ordinal=args.slot, producer_sha=args.head)
    stages = {k: 'not_reached' for k in STAGES}
    current = None
    def stage(name):
        nonlocal current
        if current:
            stages[current] = 'passed'
        current = name
        stages[name] = 'running'
    report_error = None
    try:
        report = document(args.report)
        obs['trial'] = {k: report.get(k) for k in ('phase','reason','returncode','failed_step_count')}
    except (OSError, ValueError, TypeError, AttributeError) as error:
        report_error = error
        obs['trial_error'] = failure_reason(error)
    try:
        stage('candidate_bytes')
        st = args.apk.lstat()
        obs['size'] = st.st_size
        require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= APK_CAP, 'Missing or oversized APK candidate')
        obs['sha256'] = sha(args.apk)
        stage('manifest_observations')
        observe_apk(args.apk, args.sdk, obs)
        stage('production_identity')
        ctx = origin(args)
        stage('siso_trial')
        if report_error:
            raise report_error
        seen = check_report(report, args.apk, args.slot, obs['sha256'])
        check_apk(args.apk, args.sdk, collector.CI_CERT, obs, stage)
        stage('encryption')
        sealed = encrypt(args, ctx, seen)
        stages[current] = 'passed'
        obs['result'] = 'accepted'
        return sealed
    except Exception as error:
        if current:
            stages[current] = 'failed'
        obs['result'] = 'rejected'
        obs['reason'] = failure_reason(error)
        raise
    finally:
        print('R209_APK_QC ' + json.dumps(dict(obs, stages=stages), sort_keys=True, ensure_ascii=True),
              file=sys.stderr, flush=True)


def encrypt(args, ctx, seen):
    empty_directory(args.out)
    with tempfile.TemporaryDirectory(dir=args.out) as stage:
        cipher = Path(stage) / CIPHER
        with cipher.open('xb') as output, subprocess.Popen(['age', '-r', RECIPIENT], stdin=subprocess.PIPE,
                                                           stdout=output) as age:
            try:
                with age.stdin, tarfile.open(fileobj=age.stdin, mode='w|', format=tarfile.USTAR_FORMAT) as tar:
                    entry = tarfile.TarInfo('ChromePublic.apk')
                    entry.size = seen['size']
                    with args.apk.open('rb') as data:
                        tar.addfile(entry, data)
                    payload = encode(metadata(ctx, seen))
                    entry = tarfile.TarInfo('apk-metadata.json')
                    entry.size = len(payload)
                    tar.addfile(entry, io.BytesIO(payload))
            finally:
                age.stdin.close()
            require(age.wait() == 0, 'Owner encryption failed')
        record = dict(schema=SCHEMA, **ctx, recipient=RECIPIENT, sha=sha(cipher), bytes=cipher.stat().st_size)
        check_seal(record, ctx)
        check_cipher(cipher, record)
        (Path(stage) / 'seal.json').write_bytes(encode(record))
        os.rename(cipher, args.out / CIPHER)
        os.rename(Path(stage) / 'seal.json', args.out / 'seal.json')
    return record


def check_cipher(path, seal_record):
    require(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_size == seal_record['bytes'] and
            sha(path) == seal_record['sha'], 'Ciphertext bytes differ from authenticated source')
    with path.open('rb') as stream:
        require(stream.readline(64) == b'age-encryption.org/v1\n', 'Invalid age ciphertext')


def unpack(tarfile_path, ctx, directory, sdk):
    require(0 < tarfile_path.stat().st_size <= CIPHER_CAP, 'Oversized private tar')
    with tarfile.open(tarfile_path, 'r:') as bundle:
        members = []
        for member in bundle:
            require(len(members) < 2 and member.isreg() and not member.sparse, 'Unexpected clear bundle member')
            members.append(member)
        require([m.name for m in members] == ['ChromePublic.apk', 'apk-metadata.json'] and
                0 < members[0].size <= APK_CAP and 0 < members[1].size <= 16384, 'Wrong clear bundle schema')
        meta = json.loads(bundle.extractfile(members[1]).read())
        digest = meta.get('sha256')
        require(hash_string(digest, 64) and encode(meta) == encode(metadata(ctx, {'size': members[0].size, 'sha256': digest})),
                'Clear payload metadata or production lineage differs')
        apk = directory / 'ChromePublic.apk'
        with bundle.extractfile(members[0]) as src, apk.open('xb') as dst:
            shutil.copyfileobj(src, dst, 1024**2)
    require(apk.stat().st_size == meta['bytes'] and sha(apk) == digest, 'Decrypted APK digest differs')
    check_apk(apk, sdk, collector.CI_CERT)
    return meta


def open_private(args):
    ctx = origin(args)
    received = check_private_cipher(args)
    empty_directory(args.out)
    with tempfile.TemporaryDirectory(dir=args.out) as stage:
        stage = Path(stage)
        tarpath = stage / 'release.tar'
        subprocess.run(['age', '-d', '-i', str(args.identity), '-o', str(tarpath), str(args.cipher)], check=True)
        meta = unpack(tarpath, ctx, stage, args.sdk)
        meta['private_cipher'] = received
        (stage / 'clear-receipt.json').write_bytes(encode(meta))
        for name in ('ChromePublic.apk', 'clear-receipt.json'):
            os.rename(stage / name, args.out / name)
    return meta


def generation(value):
    if type(value) is int and value >= 0:
        return value
    require(isinstance(value, str) and re.fullmatch(r'(?:0|[1-9][0-9]{0,18})', value),
            'Invalid private file generation')
    return int(value)


def route(ticket, ledger, ctx, kind='apk'):
    # owner.py checks these same independently registered IDs before the first compilation.
    import owner
    dest = ticket['destinations']
    expected_terminal = {k: ctx[k] for k in ('attempt','ordinal','accepted_parent')}
    require(ledger.get('production_head') == ctx['producer_sha'] and type(ledger.get('run')) is int and
            ledger['run'] == ctx['run'] and type(ledger.get('origin_claim')) is int and
            ledger['origin_claim'] == ctx['claim'] and encode(ledger.get('terminal')) == encode(expected_terminal),
            'Private ledger has no matching claimed physical run, attempt, parent and terminal slot')
    require(set(dest) == {'apk', 'cipher', 'ledger'} and
            owner.sha(owner.encode(dest)) == owner.DESTINATION_HASH and ticket['head'] == ctx['producer_sha'] and
            ticket['campaign'] == owner.CAMPAIGN and ticket['repository_id'] == owner.REPO_ID and
            ticket['release_id'] == owner.RELEASE_ID and ticket['branch'] == owner.BRANCH and
            ticket['workflow'] == owner.WORKFLOW and ticket['bare_revision'] == BARE and
            ticket['version_name'] == ledger['version_name'] == VERSION and
            ticket['version_code'] == ledger['version_code'] == int(CODE) and
            ledger['upstream_commit'] == BARE and ticket['abi'] == ledger['abi'] == 'arm64-v8a' and
            ticket['package'] == ledger['package'] == PACKAGE and ticket['recipient'] == ledger['recipient'] == RECIPIENT and
            ledger['schema'] == 'bare-personal-209-owner-ledger-v1' and ledger['account_id'] == 'personal' and
            ledger['owner_apk']['library_file_id'] == dest['apk'] and
            ledger['owner_ciphertext']['library_file_id'] == dest['cipher'],
            'Wrong independent ticket, owner reservation, account, version or run head')
    cert = collector.s1_label_resume.checked_final_certificate(ledger['final_certificate_sha256'])
    require(ticket['final_certificate_sha256'] == cert, 'Different final signing certificate')
    reserved = ledger['owner_apk' if kind == 'apk' else 'owner_ciphertext']
    filename = 'Bare-Personal-2.0.9-arm64-v8a.apk' if kind == 'apk' else CIPHER
    require(reserved['name'] == Path(reserved['path']).name == filename, 'Wrong owner reservation object')
    return dict(owner_destination_id=dest[kind], final_certificate_sha256=cert, account_id='personal',
                final_path=reserved['path'], reserved_version=generation(reserved['version_id']))


def check_pair(args):
    ctx = origin(args)
    owner = route(document(args.ticket), document(args.ledger), ctx)
    meta = document(args.receipt)
    received = meta.pop('private_cipher')
    cipher_owner = route(document(args.ticket), document(args.ledger), ctx, 'cipher')
    check_cipher_receipt(received, ctx, cipher_owner)
    require(encode(meta) == encode(metadata(ctx, {'size': args.original.stat().st_size, 'sha256': sha(args.original)})),
            'Clear intake receipt differs from original build and selected owner slot')
    check_apk(args.signed, args.sdk, owner['final_certificate_sha256'])
    result = collector.compare_signing_payload(args.original, meta, args.signed, owner, args.sdk / 'lib/apksigner.jar')
    return dict(schema='bare-personal-209-owner-signing-pair-v1', origin=ctx,
                destination=owner['owner_destination_id'], certificate_sha256=owner['final_certificate_sha256'],
                private_cipher=received, **result)


def checked_listing(listing, dest):
    rows = [i for i in listing['items'] if i.get('library_file_id') == dest]
    require(listing['surface'] == 'library' and len(rows) == 1 and rows[0].get('is_shared', False) is False,
            'Missing private owner listing, shared or ambiguous object')
    return rows[0]


def check_published(args):
    ctx = origin(args)
    owner = route(document(args.ticket), document(args.ledger), ctx)
    pair = document(args.pair)
    check_cipher_receipt(pair['private_cipher'], ctx, route(document(args.ticket), document(args.ledger), ctx, 'cipher'))
    listing, publication = document(args.listing), document(args.publication)
    item = checked_listing(listing, owner['owner_destination_id'])
    require(generation(item['version_id']) == generation(publication['version']) > owner['reserved_version'],
            'Wrong final publication generation')
    require(pair['schema'] == 'bare-personal-209-owner-signing-pair-v1' and
            encode(pair['origin']) == encode(ctx) and pair['destination'] == owner['owner_destination_id'] and
            pair['certificate_sha256'] == publication['certificate_sha256'] == owner['final_certificate_sha256'] and
            hash_string(pair['input_sha256'], 64) and type(pair['matched_entries']) is int and pair['matched_entries'] > 0 and
            hash_string(pair['signed_sha256'], 64) and pair['signed_sha256'] == publication['signed_sha256'],
            'Final private publication differs from checked original and owner signing result')
    check_apk(args.apk, args.sdk, owner['final_certificate_sha256'])
    return dict(origin=ctx, **collector.owner_check(owner, listing, publication, args.apk, args.sdk / 'lib/apksigner.jar'))


def check_cipher_receipt(received, ctx, owner):
    require(encode(received['origin']) == encode(ctx) and received['destination'] == owner['owner_destination_id'] and
            type(received['version']) is int and received['version'] > owner['reserved_version'] and
            isinstance(received['file_id'], str) and received['file_id'] and hash_string(received['ciphertext_sha256'], 64) and
            type(received['bytes']) is int and 0 < received['bytes'] <= CIPHER_CAP,
            'Missing complete, correctly bound owner ciphertext readback')
    seal = dict(schema=SCHEMA,**ctx,recipient=RECIPIENT,sha=received['ciphertext_sha256'],bytes=received['bytes'])
    check_source(received['source'],ctx,owner,seal)


def check_source(pickup, ctx, owner_route, seal):
    from receipt_journal import timestamp
    require(encode(pickup['origin']) == encode(ctx) and pickup['destination'] == owner_route['owner_destination_id'] and
            type(pickup['job_id']) is int and pickup['job_id'] > 0 and
            pickup['seal_sha256'] == hashlib.sha256(encode(seal)).hexdigest() and
            pickup['ciphertext_sha256'] == seal['sha'] and type(pickup['bytes']) is int and pickup['bytes'] == seal['bytes'],
            'Different physical run, private destination or seal')
    if pickup['schema'] == SOURCE_SCHEMA:
        require(pickup['artifact_name'] == f"bare-personal-209-owner-{ctx['run']}-a1-s{ctx['ordinal']}" and
                type(pickup['artifact_id']) is int and pickup['artifact_id'] > 0 and
                type(pickup['artifact_bytes']) is int and 0 < pickup['artifact_bytes'] <= CIPHER_CAP + 2*1024**2 and
                hash_string(pickup['artifact_sha256'],64) and timestamp(pickup['picked_up_at']) < timestamp(pickup['expires_at']),
                'Wrong provider Artifact or pickup timestamp')
    elif pickup['schema'] == DRAFT_SOURCE_SCHEMA:
        import owner
        require(pickup['repository_id'] == owner.REPO_ID and pickup['release_id'] == owner.RELEASE_ID and
                all(type(pickup[k]) is int and pickup[k] > 0 for k in ('receipt_id','cipher_id','seal_id','worker_id','cache_id')) and
                len({pickup[k] for k in ('receipt_id','cipher_id','seal_id')}) == 3 and hash_string(pickup['receipt_sha256'],64) and
                pickup['cache_key'] == f"bare-personal-209-terminal-{ctx['run']}-1-s{ctx['ordinal']}-{seal['sha']}",
                'Wrong private Draft recovery receipt or original cache')
    else:
        raise ValueError('Unknown owner handoff receipt')


def check_private_cipher(args):
    ctx = origin(args)
    owner = route(document(args.ticket), document(args.ledger), ctx, 'cipher')
    record = document(args.seal)
    check_seal(record, ctx)
    pickup = document(args.source)
    check_source(pickup,ctx,owner,record)
    check_cipher(args.cipher, record)
    item = checked_listing(document(args.listing), owner['owner_destination_id'])
    pub = document(args.publication)
    require(item['kind'] == 'file' and item['surface'] == 'library' and item['path'] == owner['final_path'] and
            item['file_id'] == pub['file_id'] and pub['library_file_id'] == owner['owner_destination_id'] and
            generation(item['version_id']) == generation(pub['version']) > owner['reserved_version'] and
            item['size_bytes'] == record['bytes'] and pub['sha256'] == record['sha'],
            'Private ciphertext version, identity, publication or complete readback differs')
    return dict(origin=ctx, destination=owner['owner_destination_id'], version=int(item['version_id']),
                source=pickup,
                file_id=item['file_id'], ciphertext_sha256=record['sha'], bytes=record['bytes'])


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    ops = parser.add_subparsers(dest='op', required=True)
    commands = {
        'seal': (seal, ('apk','report','sdk','out')),
        'cipher-published': (check_private_cipher, ('cipher','seal','source','listing','publication','ticket','ledger')),
        'open': (open_private, ('cipher','seal','source','identity','sdk','out','listing','publication','ticket','ledger')),
        'pair': (check_pair, ('original','signed','receipt','ticket','ledger','sdk')),
        'published': (check_published, ('listing','ticket','ledger','publication','pair','apk','sdk')),
    }
    for name, (_, paths) in commands.items():
        cmd = ops.add_parser(name)
        for key in paths:
            cmd.add_argument('--' + key, type=Path, required=True)
        for key, typ in [('run',int), ('head',str), ('slot',int), ('parent',str), ('claim',int)]:
            cmd.add_argument('--' + key, type=typ, required=True)
    args = parser.parse_args()
    print(json.dumps(commands[args.op][0](args), sort_keys=True))


if __name__ == '__main__':
    main()
