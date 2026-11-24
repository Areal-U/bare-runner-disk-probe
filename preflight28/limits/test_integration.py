"""Verify that the proposed production integration preserves its existing entry points.

Pass a checkout of the fixed bf70ddbf producer. Changes are applied only to a temp copy.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
from unittest.mock import patch
import yaml


HERE = Path(__file__).resolve().parent
WORKFLOWS = Path('.github/workflows')
ARM = WORKFLOWS / 'bare-arm64-probe.yml'
TRANSFER = WORKFLOWS / 'bare-checkpoint-transfer.yml'
FILES = {'build_trial.py':'5102b18404ccdfe8071549f411e28f75f1b10dec7d0f6007056339dc8e94094a',
         str(ARM):'7f4ba3e8ff94e91777a4bf0b400bfc0e4250cafaa485ad43b050818ea565911b',
         str(TRANSFER):'5cfc45c4033c052330ff00247ccde69f800828539df879f9eddd04800b039407'}


def apply_candidate(fixed, work):
    for name, expected in FILES.items():
        data = (fixed/name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == expected, name
        dest = work/name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    subprocess.run(['git','apply','--check', str(HERE/'production-limits.patch')], cwd=work, check=True)
    subprocess.run(['git','apply',str(HERE/'production-limits.patch')], cwd=work, check=True)
    shutil.copyfile(HERE/'guard.py',work/'guard.py')


def test_entry(work):
    spec = importlib.util.spec_from_file_location('trial_test', work/'build_trial.py')
    trial = importlib.util.module_from_spec(spec); spec.loader.exec_module(trial)
    def boundary(*args, **kwargs):
        assert args[4] == 274*60+13
        raise StopIteration
    argv = ['build_trial.py','--phase','restore','--production','--seconds',str(274*60+13),
            '--result','unused.json','--log','unused.log']
    for clock,expected in [('',False), ('1900000000',True)]:
        with patch.object(trial.Path,'cwd',return_value=trial.SOURCE_ROOT), patch.object(trial.sys,'argv',argv), \
                patch.dict(os.environ,COMPILE_STOP_EPOCH=clock), patch.object(trial,'run_trial',side_effect=boundary), \
                contextlib.redirect_stderr(io.StringIO()):
            try:
                trial.main()
            except StopIteration:
                assert expected
            except SystemExit as e:
                assert e.code == 2 and not expected
            else:
                raise AssertionError('Did not exercise production timing argument')
    progress={}
    for label, count in [('S LINK ./chrome',1), ('S R8 final',2), ('F LINK ./chrome',1), ('F R8 final',0)]:
        trial.update_siso_status(progress, ('[1/10] 1s '+label+'\n').encode())
        assert len(progress['terminal_actions']) == count
    print('PASS production CLI 274:13 guarded by a job clock, concurrent LINK/DEX status lifecycle')


def test_readback(work):
    arm=yaml.safe_load((work/ARM).read_text()); transfer=yaml.safe_load((work/TRANSFER).read_text())
    checks=transfer['jobs']['read-back-apk']['steps']; verify=next(s['run'] for s in checks if s['name']=='Verify the exact encrypted APK bytes')
    assert 'preflight28/limits/guard.py' in (work/ARM).read_text()
    for guard_case in ['apk-size-exceeded','cipher-size-exceeded','350 - 105', 'COMPILE_STOP_EPOCH']:
        assert guard_case in (work/ARM).read_text()
    assert any('apk_delivery_status' in job.get('outputs',{}) for job in arm['jobs'].values())
    good=b'age-encryption.org/v1\nfixture'; expected=hashlib.sha256(good).hexdigest()
    for folder in ('bare-apk-artifact','bare-apk-delivery'):
        (work/folder).mkdir(); (work/folder/'Bare-Personal-2.0.4-arm64-v8a.tar.age').write_bytes(good)
    for label,art,cache,key,match,ok in [('artifact', 'success','','','',True),('cache','','true','k','k',True),
                                    ('both','success','true','k','k',True),('missing','failure','false','k','',False),
                                    ('unavailable artifact + good cache','failure','true','k','k',True)]:
        env=dict(os.environ, RUNNER_TEMP=str(work),ARTIFACT_ID='11',ARTIFACT_OK=art,CACHE_HIT=cache,
                 EXPECTED_CACHE=key,CACHE_MATCH=match,EXPECTED_BYTES=str(len(good)),EXPECTED_SHA=expected)
        process=subprocess.run(['bash','-euo','pipefail','-c',verify],env=env,capture_output=True)
        assert (process.returncode==0)==ok, (label,process.stderr)
        print('PASS patched receiver:',label)
    (work/'bare-apk-delivery/Bare-Personal-2.0.4-arm64-v8a.tar.age').write_bytes(good+b'x')
    env.update(ARTIFACT_OK='success',CACHE_HIT='true',EXPECTED_CACHE='k',CACHE_MATCH='k')
    assert subprocess.run(['bash','-euo','pipefail','-c',verify],env=env,capture_output=True).returncode!=0
    print('PASS conflicting retrieved bytes stop')


def test_upload_receipt(work):
    arm = yaml.safe_load((work/ARM).read_text())
    steps=arm['jobs']['compile-probe']['steps']
    resolve=next(x['run'] for x in steps if x.get('id') == 'seal_receipt')
    fallback=next(x['if'] for x in steps if x.get('id') == 'apk_fallback_budget')
    assert "steps.seal_receipt.outputs.id == ''" in fallback
    fake_gh=work/'gh'
    fake_gh.write_text('#!/bin/sh\nprintf "%s" "$LISTING"\nexit "$GH_RC"\n')
    fake_gh.chmod(0o755)
    name='bare-personal-204-encrypted-100-1'
    valid={'id':17,'name':name,'expired':False}
    for title,returned,lookup,rc,expected_id,ok in [
            ('returned','8',[],0,'8',True), ('lost response','',[valid],0,'17',True),
            ('missing','',[],0,None,True), ('lookup unavailable','',[],1,None,True),
            ('collision','',[valid,dict(valid,id=19)],0,None,False)]:
        output=work/'outputs'
        output.write_text('')
        env=dict(os.environ,PATH=str(work)+':'+os.environ['PATH'],RETURNED_ID=returned,
                 ENCRYPTED_SHA='0'*64,ENCRYPTED_BYTES='23',GITHUB_RUN_ID='100',GITHUB_RUN_ATTEMPT='1',
                 GITHUB_REPOSITORY='Areal-U/bare-runner-disk-probe',GITHUB_STEP_SUMMARY=str(work/'summary'),
                 GITHUB_OUTPUT=str(output), LISTING=json.dumps({'total_count':len(lookup),'artifacts':lookup}), GH_RC=str(rc))
        response=subprocess.run(['bash','-euo','pipefail','-c',resolve],env=env,capture_output=True)
        assert (response.returncode == 0) == ok and output.read_text().strip() == ('id='+expected_id if expected_id else '')
        print('PASS patched ambiguous upload receipt:',title)


if __name__ == '__main__':
    cli=argparse.ArgumentParser(description=__doc__); cli.add_argument('fixed',type=Path)
    fixed=cli.parse_args().fixed.resolve()
    with tempfile.TemporaryDirectory() as name:
        work=Path(name); apply_candidate(fixed,work); test_entry(work); test_readback(work); test_upload_receipt(work)
