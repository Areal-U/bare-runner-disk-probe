"""Small schema/source controls; optional real APK/ELF/SDK and isolated age/signing replay."""
import argparse
from contextlib import redirect_stderr
import io
import json
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile
import owner_apk as qc
import owner
import receive_owner_zip as pickup
import receive_owner_draft as draft


def context(**updates):
    data = dict(run=71231, slot=2, claim=7481, parent='a'*64, head='d'*40)
    return argparse.Namespace(**dict(data, **updates))


def report(path, slot=2):
    return dict(format='bare-apk-trial', version=1, phase='restore' if slot != 1 else 'seed',
                target='chrome_public_apk', build_dir='out/Bare', reason='completed', returncode=0,
                artifact_ready=True, forced_kill=False, failed_step_count=0, failed_steps=[], container_quiescence_verified=True,
                close={'errors': []}, apk={'path':'out/Bare/apks/ChromePublic.apk', 'size':path.stat().st_size,
                    'sha256':qc.sha(path), 'arm64_member':'lib/arm64-v8a/libchrome.so'})


def api_source(d, sealed, owner_args, extra=False):
    ctx=qc.origin(context())
    run=dict(id=ctx['run'],run_attempt=1,head_sha=ctx['producer_sha'],head_branch=owner.BRANCH,
             path=owner.WORKFLOW,event='workflow_dispatch',actor=owner.OWNER,
             repository={'id':owner.REPO_ID},head_repository={'id':owner.REPO_ID})
    job=dict(id=881,run_id=ctx['run'],run_attempt=1,head_sha=ctx['producer_sha'],head_branch=owner.BRANCH,
             name='slot01 / Compile APK slot 2',steps=[dict(name=pickup.STEP,conclusion='success',
             started_at='2026-12-01T00:01:10Z',completed_at='2026-12-01T00:01:17Z')],completed_at=None)
    arch=d/'provider.zip'
    with zipfile.ZipFile(arch,'w') as z:
        for name in ('seal.json',qc.CIPHER):
            z.write(sealed/name,name)
        if extra: z.writestr('other',b'forbidden')
    row=dict(id=1190,name=f"bare-personal-209-owner-{ctx['run']}-a1-s{ctx['ordinal']}",size_in_bytes=arch.stat().st_size,
             digest='sha256:'+qc.sha(arch),expired=False,created_at='2026-12-01T00:01:11Z',expires_at='2026-12-02T00:01:11Z',
             workflow_run=dict(id=ctx['run'],head_sha=ctx['producer_sha'],head_branch=owner.BRANCH,
                               repository_id=owner.REPO_ID,head_repository_id=owner.REPO_ID))
    def save(name,obj):
        p=d/name; p.write_bytes(qc.encode(obj)); return p
    return context(run_info=save('r.json',run),job=save('j.json',job),inventory=save('i.json',dict(total_count=1,artifacts=[row])),
                   artifact=save('a.json',row),id=row['id'],zip=arch,out=d/'retrieved',**owner_args)


class Admission(unittest.TestCase):
    def test_seal_lineage_and_shape(self):
        expected = qc.origin(context())
        good = dict(schema=qc.SCHEMA, **expected, recipient=qc.RECIPIENT, bytes=120, sha='b'*64)
        qc.check_seal(good, expected)
        for field, wrong in [('schema','2.0.4'),('run',1),('attempt',True),('ordinal',1),('claim','7481'),
                             ('producer_sha','c'*40),('accepted_parent','0'*64),('recipient','other'),
                             ('bytes',qc.CIPHER_CAP+1),('sha','a')]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                qc.check_seal(dict(good, **{field:wrong}), expected)

    def test_provider_zip_controls(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); sealed=d/'sealed';sealed.mkdir()
            cipher=sealed/qc.CIPHER; cipher.write_bytes(b'age-encryption.org/v1\n'+bytes(80))
            record=dict(schema=qc.SCHEMA,**qc.origin(context()),recipient=qc.RECIPIENT,sha=qc.sha(cipher),bytes=cipher.stat().st_size)
            (sealed/'seal.json').write_bytes(qc.encode(record))
            fake=d/'private.json'; fake.write_text('{}')
            def args(extra=False):
                return api_source(d,sealed,dict(ticket=fake,ledger=fake),extra)
            a=args()
            when=pickup.timestamp('2026-12-01T00:02:00Z')
            with patch.object(qc,'route',return_value=dict(owner_destination_id='test-dest')):
                result=pickup.take(a,clock=lambda:when)
                self.assertEqual(qc.sha(a.out/qc.CIPHER),record['sha'])
                self.assertEqual(result['artifact_id'],a.id)
                for mode in ('wrong-attempt','wrong-job','wrong-id','old','different-sha','extra','expired','wrong-run','truncated','duplicate','different-seal'):
                    b=args(extra=mode=='extra'); b.out=d/'refused'
                    row=qc.document(b.artifact)
                    if mode=='wrong-attempt': b.run_info.write_bytes(qc.encode(dict(qc.document(b.run_info),run_attempt=2)))
                    if mode=='wrong-job': b.job.write_bytes(qc.encode(dict(qc.document(b.job),run_attempt=2)))
                    if mode=='wrong-id': b.id=3
                    if mode=='old': b.inventory.write_bytes(qc.encode(dict(total_count=1,artifacts=[dict(row,name='bare-personal-204')])))
                    if mode=='different-sha': b.artifact.write_bytes(qc.encode(dict(row,digest='sha256:'+'0'*64)))
                    if mode=='wrong-run': b.run+=1
                    if mode=='truncated': b.inventory.write_bytes(qc.encode(dict(total_count=2,artifacts=[row])))
                    if mode=='duplicate': b.inventory.write_bytes(qc.encode(dict(total_count=2,artifacts=[row,dict(row,id=66)])))
                    if mode=='different-seal': b.claim+=1
                    with self.subTest(mode=mode), self.assertRaises(ValueError):
                        pickup.take(b, clock=lambda:when+(86400 if mode=='expired' else 0))
                    self.assertFalse(b.out.exists())

    def test_retry_step_and_bad_zip_encoding(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); s=d/'sealed';s.mkdir()
            data=b'age-encryption.org/v1\n'+bytes(22)
            (s/qc.CIPHER).write_bytes(data)
            record=dict(schema=qc.SCHEMA,**qc.origin(context()),recipient=qc.RECIPIENT,
                        sha=qc.sha(s/qc.CIPHER),bytes=len(data))
            (s/'seal.json').write_bytes(qc.encode(record))
            f=d/'unused'; f.write_text('{}'); routes=dict(ticket=f,ledger=f)
            when=pickup.timestamp('2026-12-01T00:02:00Z')
            with patch.object(qc,'route',return_value=dict(owner_destination_id='test')):
                a=api_source(d,s,routes); j=qc.document(a.job);j['steps'][0]['name']=pickup.RETRY
                a.job.write_bytes(qc.encode(j));self.assertEqual(pickup.take(a,clock=lambda:when)['job_id'],j['id'])
                for mode in ('symlink','bzip2','wrong-inner-bytes'):
                    a=api_source(d,s,routes);a.out=d/'fail'
                    with zipfile.ZipFile(a.zip,'w') as z:
                        z.write(s/'seal.json','seal.json')
                        zinfo=zipfile.ZipInfo(qc.CIPHER)
                        if mode=='symlink': zinfo.external_attr=0o120777<<16
                        if mode=='bzip2': zinfo.compress_type=zipfile.ZIP_BZIP2
                        z.writestr(zinfo,bytes(len(data)) if mode=='wrong-inner-bytes' else data)
                    row=dict(qc.document(a.artifact),size_in_bytes=a.zip.stat().st_size,digest='sha256:'+qc.sha(a.zip))
                    a.artifact.write_bytes(qc.encode(row));a.inventory.write_bytes(qc.encode(dict(total_count=1,artifacts=[row])))
                    with self.subTest(mode=mode), self.assertRaises(ValueError):pickup.take(a,clock=lambda:when)
                    self.assertFalse(a.out.exists())

    def test_library_generations(self):
        for x in (0,'0',1,'1',12,'12'):
            self.assertEqual(qc.generation(x),int(x))
        for x in ('00','01','-0','-1',-1,True,None,' 0','0.0'):
            with self.subTest(x=x), self.assertRaises(ValueError):
                qc.generation(x)

    def test_logical_slots(self):
        for slot in (1, 12, 13, 99):
            self.assertEqual(qc.origin(context(slot=slot))['ordinal'],slot)
        for slot in (0,100):
            with self.assertRaises(ValueError): qc.origin(context(slot=slot))

    def test_private_draft_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp); ctx=qc.origin(context()); part=d/'123.bin';part.write_bytes(b'age-encryption.org/v1\n'+bytes(70))
            seal=dict(schema=qc.SCHEMA,**ctx,recipient=qc.RECIPIENT,sha=qc.sha(part),bytes=part.stat().st_size)
            def save(p,x):
                (d/p).write_bytes(qc.encode(x))
            save('124.bin',seal)
            testtime='2026-11-27T07:45:50.1234567Z'
            key=f"bare-personal-209-terminal-{ctx['run']}-1-s{ctx['ordinal']}-{seal['sha']}"
            def job(name, ident,step):
                return dict(id=ident,name='slot02 / '+name,run_id=ctx['run'],run_attempt=1,status='completed',conclusion='success',
                            head_sha=ctx['producer_sha'],head_branch=owner.BRANCH,steps=[dict(name=step,conclusion='success',
                            started_at='2026-11-27T07:45:49Z',completed_at='2026-11-27T07:46:06Z')])
            prefix=f"r209-{ctx['run']}-a1-s{ctx['ordinal']:02}-"
            def partref(idx,suffix):
                f=d/(str(idx)+'.bin'); return dict(id=idx,name=prefix+suffix,bytes=f.stat().st_size,sha256=qc.sha(f))
            a=partref(123,'apk.age'); b=partref(124,'apk-seal.json')
            cache=dict(id=4433,key=key,ref='refs/heads/'+owner.BRANCH)
            raw=dict(schema=draft.SCHEMA,origin=ctx,repository_id=owner.REPO_ID,release_id=owner.RELEASE_ID,
                     recipient=owner.RECIPIENT,destination_commitment=owner.DESTINATION_HASH,source_cache=cache,cipher=a,seal=b)
            save('125.bin',raw); c=partref(125,'apk-owner-receipt.json')
            out=dict(run=ctx['run'],ordinal=ctx['ordinal'],claim=ctx['claim'],receipt_id=c['id'],
                     receipt_sha=c['sha256'],cipher_id=123,seal_id=124)
            save('run.json',dict(id=ctx['run'],run_attempt=1,head_sha=ctx['producer_sha'],head_branch=owner.BRANCH,
                 path=owner.WORKFLOW,event='workflow_dispatch',actor=owner.OWNER,
                 repository=dict(id=owner.REPO_ID),head_repository=dict(id=owner.REPO_ID)))
            save('worker.json',job('Compile APK slot 2',455,draft.WORKER_STEP))
            recover=job('Recover original encrypted cache slot 2',345,draft.RECOVERY_STEP);save('recovery.json',recover)
            (d/'worker.log').write_text(testtime+' R209_ENCRYPTED_CACHE 4433 '+key+' '+b['sha256']+'\n')
            log=testtime+' R209_PRIVATE_TERMINAL '+json.dumps(out)+'\n';(d/'recovery.log').write_text(log)
            rows=[dict(id=r['id'],name=r['name'],size=r['bytes'],digest='sha256:'+r['sha256'],state='uploaded') for r in (a,b,c)]
            rel=dict(id=owner.RELEASE_ID,draft=True,url=f'https://api.github.com/repos/{owner.REPO}/releases/{owner.RELEASE_ID}',assets=rows)
            rel.update(tag_name="untagged-"+"a"*20,html_url=f"https://github.com/{owner.REPO}/releases/tag/untagged-"+"a"*20)
            save('release.json',rel); save('assets.json',rows); save('private.json',{})
            args=context(inputs=d,ledger=d/'private.json',ticket=d/'private.json',out=d/'pickup')
            with patch.object(qc,'route',return_value=dict(owner_destination_id='test')):
                result=draft.take(args)
                self.assertEqual(result['schema'],qc.DRAFT_SOURCE_SCHEMA)
                self.assertNotIn('artifact_id',result)
                self.assertEqual(qc.sha(args.out/qc.CIPHER),seal['sha'])
                # This independent receiver binds the physical recovery job, fixed Release API ID,
                # and all three downloaded terminal objects after a subsequent owner editor save.
                fresh = "untagged-"+"b"*20
                save('release.json',dict(rel,tag_name=fresh,html_url=f"https://github.com/{owner.REPO}/releases/tag/{fresh}"))
                args.out=d/'rotated'
                self.assertEqual(draft.take(args),result)
                args.out=d/'fail'
                for why in ('public','moved-release','wrong-claim','failed-job','wrong-step-record','two-cipher-ids','incomplete-source','cipher-bytes'):
                    release = dict(rel,draft=False) if why=='public' else rel
                    save('release.json',dict(release,url=release['url']+'/foreign') if why=='moved-release' else release)
                    save('recovery.json',dict(recover,conclusion='failure') if why=='failed-job' else recover)
                    (d/'recovery.log').write_text(log.replace('R209_PRIVATE_TERMINAL','ignored') if why=='wrong-step-record' else log)
                    args.claim=2 if why=='wrong-claim' else ctx['claim']
                    save('assets.json',rows+[dict(rows[0],name=a['name']+'-retry1',id=200)] if why=='two-cipher-ids' else
                         rows[:-1] if why=='incomplete-source' else rows)
                    if why=='cipher-bytes':part.write_bytes(bytes(2))
                    with self.subTest(why=why), self.assertRaises(ValueError): draft.take(args)
                    self.assertFalse(args.out.exists())

    def test_report_controls(self):
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'ChromePublic.apk'
            f.write_bytes(b'concrete fixture')
            base=report(f)
            qc.check_report(base,f,2)
            qc.check_report(report(f,1),f,1)
            for k,v in [('phase','seed'),('version',True),('failed_step_count',1),('returncode',False),
                        ('target','apk'),('container_quiescence_verified',False),('failed_steps',['err']),('close',{'errors':['x']}),
                        ('forced_kill',True),('artifact_ready',False),('reason','target-timeout')]:
                with self.subTest(k=k), self.assertRaises(ValueError):
                    qc.check_report(dict(base,**{k:v}),f,2)
            for k,v in [('path','other.apk'),('sha256','0'*64),('size',False),('arm64_member','lib/x86/libfoo.so')]:
                with self.subTest(k=k), self.assertRaises(ValueError):
                    qc.check_report(dict(base,apk=dict(base['apk'],**{k:v})),f,2)

    def test_missing_disabled_alias(self):
        launchers = {qc.MAIN+s:['Bare Personal'] for s in ('','IconRetro','IconDark','NewIcon')}
        labels = dict(enabled=[qc.MAIN],application=['Bare Personal'],launchers=launchers)
        qc.check_launchers(labels)
        for change in [dict(launchers={k:v for k,v in launchers.items() if not k.endswith('IconRetro')}),
                       dict(enabled=[qc.MAIN,qc.MAIN+'NewIcon'])]:
            with self.assertRaises(ValueError):
                qc.check_launchers(dict(labels,**change))


def run(*args, **kwargs):
    return subprocess.run([str(x) for x in args], capture_output=True, check=True, **kwargs)


def fixture(d, sdk, jar, key, official):
    # Real official 2.0.9 ELF and extension bytes. Only the reduced manifest is synthesized.
    ns = 'http://schemas.android.com/apk/res/android'
    ET.register_namespace('android',ns)
    def node(root, tag, **attrs):
        return ET.SubElement(root, tag, {'{'+ns+'}'+k:v for k,v in attrs.items()})
    root=ET.Element('manifest', {'package':qc.PACKAGE,'{'+ns+'}versionCode':qc.CODE,'{'+ns+'}versionName':qc.VERSION})
    node(root,'uses-sdk',minSdkVersion='29',targetSdkVersion='36')
    for p in qc.PERMISSION_SUFFIXES:
        node(root,'permission',name=qc.PACKAGE+p,protectionLevel='signature')
    app=node(root,'application',label='Bare Personal')
    node(app,'activity',name='.Browser',exported='true')
    for suffix in ('','IconRetro','IconDark','NewIcon'):
        alias=node(app,'activity-alias',name=qc.MAIN+suffix,targetActivity='.Browser',exported='true',
                   enabled='false' if suffix else 'true')
        intent=node(alias,'intent-filter')
        node(intent,'action',name='android.intent.action.MAIN')
        node(intent,'category',name='android.intent.category.LAUNCHER')
    for name,group in qc.PROVIDERS.items():
        node(app,'provider',name=name,authorities=';'.join(qc.PACKAGE+s for s in group),exported='false')
    xml=d/'AndroidManifest.xml'
    ET.ElementTree(root).write(xml,encoding='utf-8')
    res=d/'res/values';res.mkdir(parents=True)
    (res/'strings.xml').write_text('<resources><string name="fixture">Bare Personal</string></resources>')
    run(sdk/'aapt2','compile','--dir',d/'res','-o',d/'res.zip')
    raw,aligned,apk=d/'unsigned.apk',d/'aligned.apk',d/'ChromePublic.apk'
    run(sdk/'aapt2','link','-I',jar,'--manifest',xml,d/'res.zip','-o',raw)
    with zipfile.ZipFile(official) as src,zipfile.ZipFile(raw,'a') as out:
        for name in sorted(qc.NATIVE|{'assets/bare/ublock_origin.crx'}):
            with src.open(name) as old,out.open(name,'w') as new:
                shutil.copyfileobj(old,new,1024**2)
    env=dict(os.environ, LD_LIBRARY_PATH=str(sdk/'lib64')+os.pathsep+os.getenv('LD_LIBRARY_PATH',''))
    run(sdk/'zipalign','-P','16','-f','4',raw,aligned,env=env)
    raw.unlink()
    run('java','-jar',sdk/'lib/apksigner.jar','sign','--ks',key,'--ks-key-alias','chromiumdebugkey',
        '--ks-pass','pass:chromium','--v4-signing-enabled','false','--out',apk,aligned)
    aligned.unlink()
    return apk


@unittest.skipUnless(os.getenv('R209_OFFICIAL_APK'), 'requires explicitly selected real SDK and official 2.0.9 APK')
class AndroidReplay(unittest.TestCase):
    def test_real_official_and_private_flow(self):
        sdk,official,jar,key = [Path(os.environ['R209_'+n]) for n in
                                ('TEST_SDK','OFFICIAL_APK','ANDROID_JAR','PUBLIC_TEST_KEY')]
        self.assertEqual(qc.sha(official),qc.OFFICIAL_APK)
        xml=run(sdk/'aapt2','dump','xmltree',official,'--file','AndroidManifest.xml').stdout.decode()
        qc.check_manifest(qc.manifest_tree(xml),'org.barebrowser')
        with zipfile.ZipFile(official) as z:
            qc.check_native(z)
            self.assertEqual(hashlib.sha256(z.read('assets/bare/ublock_origin.crx')).hexdigest(),qc.collector.UBO_SHA)
        with tempfile.TemporaryDirectory() as temp:
            directory=Path(temp)
            source=directory/'trial.json'
            source.write_bytes(qc.encode(report(official)))
            log=io.StringIO()
            with redirect_stderr(log),self.assertRaisesRegex(ValueError,'Wrong package'):
                qc.seal(context(apk=official,report=source,sdk=sdk,out=directory/'forbidden'))
            self.assertFalse((directory/'forbidden').exists())
            evidence=json.loads(log.getvalue().split('R209_APK_QC ')[1])
            self.assertEqual((evidence['result'],evidence['size'],evidence['sha256']),
                             ('rejected',official.stat().st_size,qc.OFFICIAL_APK))
            self.assertEqual(evidence['packages'],[dict(name='org.barebrowser',versionName=qc.VERSION,versionCode=qc.CODE)])
            self.assertEqual(evidence['abi_rows'],["native-code: 'arm64-v8a'"])
            self.assertEqual(len(evidence['labels']['launchers']),4)
            self.assertEqual(evidence['labels']['application'],['Bare'])
            self.assertEqual(evidence['stages']['package_and_abi'],'failed')
            self.assertEqual(evidence['stages']['encryption'],'not_reached')
            self.assertEqual((evidence['run'],evidence['ordinal'],evidence['trial']['reason']),
                             (context().run,context().slot,'completed'))

        if os.getenv('R209_PRIOR_SIGNED'):
            old=Path(os.environ['R209_PRIOR_SIGNED'])
            actual=run('java','-jar',sdk/'lib/apksigner.jar','verify','--print-certs',old).stdout.decode()
            cert=actual.split('certificate SHA-256 digest: ')[1].splitlines()[0]
            self.assertEqual(qc.collector.s1_label_resume.checked_final_certificate(cert),cert)
            with self.assertRaisesRegex(ValueError,'Wrong package'):
                qc.check_apk(old,sdk,cert)
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            apk=fixture(d,sdk,jar,key,official)
            info=d/'trial.json'; info.write_bytes(qc.encode(report(apk)))
            identity=d/'test.agekey';run('age-keygen','-o',identity)
            recipient=run('age-keygen','-y',identity).stdout.decode().strip()
            with patch.object(qc,'RECIPIENT',recipient):
                sealed=d/'sealed'
                record=qc.seal(context(apk=apk,report=info,sdk=sdk,out=sealed))
                self.assertEqual({f.name for f in sealed.iterdir()},{'seal.json',qc.CIPHER})
                clear=d/'clear'
                args=context(seal=sealed/'seal.json',cipher=sealed/qc.CIPHER,sdk=sdk,out=clear,identity=identity)
                # Exercise the same post-signing/readback APIs using isolated signing material and
                # an unpublished owner-reply fixture. Never read the owner's signing/decryption key.
                import owner
                def store(name, value):
                    p=d/name; p.write_bytes(qc.encode(value)); return p
                signing=d/'replay.p12'
                run('keytool','-genkeypair','-keyalg','RSA','-keysize','2048','-storetype','PKCS12',
                    '-dname','CN=Disposable fixture','-validity','1','-keystore',signing,
                    '-storepass','test-password','-alias','fixture')
                cert=hashlib.sha256(run('keytool','-exportcert','-keystore',signing,'-alias','fixture',
                                       '-storepass','test-password').stdout).hexdigest()
                signed=d/'signed.apk'
                run('java','-jar',sdk/'lib/apksigner.jar','sign','--ks',signing,'--ks-key-alias','fixture',
                    '--ks-pass','pass:test-password','--v4-signing-enabled','false','--out',signed,apk)
                destinations = {'apk':'test-APK', 'cipher':'test-cipher','ledger':'test-ledger'}
                common = dict(version_name=qc.VERSION,version_code=int(qc.CODE),abi='arm64-v8a',package=qc.PACKAGE,
                              recipient=recipient,final_certificate_sha256=cert)
                ticket=dict(common,head=args.head,campaign=owner.CAMPAIGN,repository_id=owner.REPO_ID,
                            release_id=owner.RELEASE_ID,branch=owner.BRANCH,workflow=owner.WORKFLOW,
                            destinations=destinations,bare_revision=qc.BARE)
                def reserved(name, obj):
                    return dict(name=name,path='/test/'+name,library_file_id=destinations[obj],version_id='0')
                ledger=dict(common, schema='bare-personal-209-owner-ledger-v1', upstream_commit=qc.BARE,
                            account_id='personal',production_head=args.head,run=args.run,origin_claim=args.claim,
                            terminal={k:qc.origin(args)[k] for k in ('attempt','ordinal','accepted_parent')},
                            owner_apk=reserved('Bare-Personal-2.0.9-arm64-v8a.apk','apk'),
                            owner_ciphertext=reserved(qc.CIPHER,'cipher'))
                owner_args = dict(ticket=store('ticket.json',ticket),ledger=store('ledger.json',ledger))
                def listed(reserv, size):
                    return dict(kind='file',surface='library',path=reserv['path'],library_file_id=reserv['library_file_id'],
                                file_id='provider-opaque-version-1',version_id='1',size_bytes=size)
                def capture(row):
                    return store('listing.json',dict(surface='library',items=[row]))
                # A real private Library list omits is_shared=false, as in the prior signed pickup.
                row=listed(ledger['owner_ciphertext'],record['bytes'])
                publication=dict(file_id=row['file_id'],library_file_id=row['library_file_id'],
                                 version=1,sha256=record['sha'])
                with patch.object(owner,'DESTINATION_HASH',owner.sha(owner.encode(destinations))), \
                     patch.object(qc.collector.s1_label_resume,'OWNER_CERT_COMMITMENT',hashlib.sha256(cert.encode()).hexdigest()):
                    pz=api_source(d,sealed,owner_args)
                    picked=pickup.take(pz,clock=lambda:pickup.timestamp('2026-12-01T00:02:00Z'))
                    self.assertEqual(picked['ciphertext_sha256'],record['sha'])
                    args2=context(listing=capture(row),publication=store('pub-c.json',publication),
                                  cipher=pz.out/qc.CIPHER,seal=pz.out/'seal.json',source=pz.out/'source.json',**owner_args)
                    args=argparse.Namespace(**dict(vars(args2),sdk=sdk,out=clear,identity=identity))
                    receipt=qc.open_private(args)
                    self.assertEqual(qc.sha(clear/'ChromePublic.apk'),receipt['sha256'])
                    self.assertEqual(receipt['origin'],qc.origin(context()))
                    with self.assertRaises(ValueError):
                        qc.open_private(argparse.Namespace(**dict(vars(args),run=2)))
                    self.assertEqual(qc.check_private_cipher(args2)['ciphertext_sha256'],record['sha'])
                    args2.listing=capture(dict(row,is_shared=True))
                    with self.assertRaisesRegex(ValueError,'shared'):
                        qc.check_private_cipher(args2)
                    pairargs=context(original=clear/'ChromePublic.apk',signed=signed,receipt=clear/'clear-receipt.json',
                                     sdk=sdk,**owner_args)
                    pair=qc.check_pair(pairargs)
                    self.assertGreater(pair['matched_entries'],4)
                    with self.assertRaisesRegex(ValueError,'Wrong final signer'):
                        qc.check_pair(argparse.Namespace(**dict(vars(pairargs),signed=apk)))
                    row=listed(ledger['owner_apk'],signed.stat().st_size)
                    pub=dict(file_id=row['file_id'],library_file_id=row['library_file_id'],
                             version=1,signed_sha256=qc.sha(signed),certificate_sha256=cert)
                    pubargs=context(listing=capture(row),publication=store('published.json',pub),sdk=sdk,
                                    pair=store('pair.json',pair),apk=signed,**owner_args)
                    self.assertEqual(qc.check_published(pubargs)['signed_sha256'],pair['signed_sha256'])
                    for k,v in [('version',0),('signed_sha256','c'*64),('file_id','foreign')]:
                        pubargs.publication=store('bad-pub.json',dict(pub,**{k:v}))
                        with self.subTest(k=k), self.assertRaises(ValueError):
                            qc.check_published(pubargs)
                    with self.assertRaisesRegex(ValueError,'Wrong independent ticket'):
                        qc.route(dict(ticket,destinations=dict(destinations,apk='different')),ledger,qc.origin(context()))
                with (sealed/qc.CIPHER).open('r+b') as bad:
                    bad.seek(-1,2); value=bad.read(1); bad.seek(-1,2); bad.write(bytes([value[0]^1]))
                with self.assertRaisesRegex(ValueError,'Ciphertext bytes differ'):
                    qc.check_cipher(sealed/qc.CIPHER,record)


if __name__=='__main__':
    unittest.main()
