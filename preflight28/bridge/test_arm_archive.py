"""Exercise the ordinary private-route pack and fixed validation entry points."""
import gzip
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT/'checkpoint.py'
ADAPTER = ROOT/'preflight28/bridge/check_archive.py'
ARM = ROOT/'.github/workflows/bare-arm64-probe.yml'

class PrivateArchiveTests(unittest.TestCase):
    def test_host_owns_the_two_frontier_logs(self):
        steps = yaml.safe_load(ARM.read_bytes())['jobs']['compile-probe']['steps']
        for identifier, suffix, line in [('frontier','before','{"parent_frontier_verified":true}'),
                                         ('frontier_finish','after','{"frontier_status":"candidate"}')]:
            script = next(s['run'] for s in steps if s.get('id') == identifier)
            dst = 'exchange/checkpoint/frontier-' + suffix + '.log'
            self.assertIn("' | tee " + dst, script)
            self.assertNotIn('tee /' + dst, script)
            pipeline = script[script.index('docker compose exec'):script.index('\n',script.index("' | tee " + dst))]
            with tempfile.TemporaryDirectory() as tmp:
                output = Path(tmp)/dst
                output.parent.mkdir(parents=True)
                for status in (0,11):
                    env=dict(os.environ,LINE=line,STATUS=str(status),EXPECTED_KEY='key',TRIAL_PHASE='restore')
                    # The builder streams its output; the host opens its own log even under umask 077.
                    command='set -eo pipefail\numask 077\ndocker() { printf "%s\\n" "$LINE"; return "$STATUS"; }\n'+pipeline
                    proc=subprocess.run(['bash','-c',command],env=env,cwd=tmp,capture_output=True)
                    self.assertEqual(proc.returncode,status,proc.stderr)
                    self.assertEqual(output.read_text().strip(),line)
                    self.assertEqual(output.stat().st_mode & 0o777,0o600)

    def test_oversize_is_a_successful_terminal_with_no_upload(self):
        steps = yaml.safe_load(ARM.read_bytes())['jobs']['compile-probe']['steps']
        seal = next(s['run'] for s in steps if s.get('id') == 'apk_seal')
        guard = ROOT/'preflight28/limits/guard.py'
        for kind, limit in (('apk',450),('cipher',451)):
            start = 'if docker compose exec -T chromium-builder python3 -I /exchange/guard.py size apk' if kind=='apk' else 'if python3 -I "$RUNNER_TEMP/bare-ci/guard.py" size cipher'
            branch = seal[seal.index(start):].split('\nfi\n',1)[0]+'\nfi\n'
            self.assertIn("echo 'terminal=true'",seal[:seal.index(start)])
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)
                (path/'bare-ci').mkdir()
                (path/'bare-ci/guard.py').symlink_to(guard)
                file=path/'payload'
                with file.open('wb') as f:
                    f.truncate(limit*1024**2+1)
                env=dict(os.environ,RUNNER_TEMP=str(path),GITHUB_OUTPUT=str(path/'result'),
                         delivery=str(path),name=file.name,GUARD=str(guard),FIXTURE=str(file))
                command='docker() { python3 -I "$GUARD" size apk "$FIXTURE"; }\n'+branch+'exit 91\n'
                result=subprocess.run(['bash','-euo','pipefail','-c',command],env=env,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual((path/'result').read_text().splitlines(),['status='+kind+'-size-exceeded','ready=false'])
                file.unlink()
                self.assertEqual(subprocess.run(['bash','-euo','pipefail','-c',command],env=env,capture_output=True).returncode,66)

    def test_production_pack(self):
        arm = yaml.safe_load(ARM.read_bytes())
        job = arm['jobs']['compile-probe']
        byid = {s.get('id'): s for s in job['steps']}
        run = byid['pack-checkpoint']['run']
        # Exercise the actual shell used on the isolated volume, apart from the host codec.
        start = run.index("docker compose exec -T chromium-builder bash -euc '\n    cd /work/chromium/src\n    # This archive")
        body = run[start:].split("bash -euc '\n",1)[1].split("'\n",1)[0].replace('/work/chromium/src','.')
        with tempfile.TemporaryDirectory() as tmp:
            work=Path(tmp); out=work/'out/Bare'
            (out/'apks').mkdir(parents=True); (out/'obj').mkdir()
            (out/'build.ninja.d').write_text('build.ninja.stamp: apks/Trichrome.ssargs ../../DEPS\n')
            (out/'apks/Trichrome.ssargs').write_text('--sample\n')
            (out/'apks/needed.ap_').write_bytes(b'nonterminal intermediate')
            (out/'obj/prebuilt.apk').write_bytes(b'nonterminal module')
            def archive():
                p=subprocess.run(['bash','-euo','pipefail','-c',body],cwd=work,capture_output=True)
                return p
            def check(data):
                path=work/'sample.zst'; path.write_bytes(data)
                return subprocess.run([sys.executable,str(ADAPTER),str(CHECK),'validate-archive',str(path),'--production'],capture_output=True)
            raw=archive(); self.assertEqual(raw.returncode,0,raw.stderr)
            enc=subprocess.run(['zstd','-q','-9','-c'],input=raw.stdout,capture_output=True,check=True).stdout
            result=check(enc); self.assertEqual(result.returncode,0,result.stderr)
            self.assertNotEqual(check(enc[:-2]).returncode,0)
            public=work/'legacy.gz'; public.write_bytes(gzip.compress(raw.stdout))
            self.assertNotEqual(subprocess.run([sys.executable,str(CHECK),'validate-archive',str(public),'--production'],capture_output=True).returncode,0)
            # A latent terminal target cannot silently enter the private checkpoint.
            (out/'apks/ChromePublic.apk').write_bytes(b'apk');self.assertNotEqual(archive().returncode,0)
            hostile=subprocess.run(['tar','-cf','-','out/Bare'],cwd=work,capture_output=True,check=True)
            tagged=subprocess.run(['zstd','-q','-c'],input=hostile.stdout,capture_output=True,check=True)
            self.assertNotEqual(check(tagged.stdout).returncode,0)
            (out/'apks/ChromePublic.apk').unlink(); (out/'obj/escape').symlink_to('/etc/passwd')
            malicious=archive(); self.assertEqual(malicious.returncode,0)
            enc=subprocess.run(['zstd','-q','-c'],input=malicious.stdout,capture_output=True,check=True).stdout
            self.assertNotEqual(check(enc).returncode,0)
        self.assertEqual(job['permissions'], {'actions':'read'})
        for key in ['restore-checkpoint','save-checkpoint','measure-checkpoint','scale-budget']:
            if key in byid:self.assertIn('backend',byid[key]['if'])
        publisher=arm['jobs']['draft-publisher']
        self.assertEqual(publisher['permissions'],{'actions':'read','contents':'write'})
        self.assertTrue(all('docker compose' not in step.get('run','') for step in publisher['steps']))

if __name__=='__main__': unittest.main(verbosity=2)
