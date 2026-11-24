"""Exercise the ordinary private-route pack and fixed validation entry points."""
import gzip
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
    def test_production_pack(self):
        arm = yaml.safe_load(ARM.read_bytes())
        job = arm['jobs']['compile-probe']
        byid = {s.get('id'): s for s in job['steps']}
        run = byid['pack-checkpoint']['run']
        # Exercise the actual shell used on the isolated volume, apart from the host codec.
        start = run.index("docker compose exec -T chromium-builder bash -euc '\n    cd /work/chromium/src\n    # This archive")
        body = run[start:].split("bash -euc '\n",1)[1].split("' |\n",1)[0].replace('/work/chromium/src','.')
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
