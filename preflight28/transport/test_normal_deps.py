"""Reproduce the immutable package scripts and builder settings without fetching packages."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[2]
ARM = ROOT / ".github/workflows/bare-arm64-probe.yml"
WORKFLOW = yaml.safe_load(ARM.read_text())
STEPS = WORKFLOW["jobs"]["compile-probe"]["steps"]


class NormalDepsTests(unittest.TestCase):
    def test_fixed_scripts_and_renderer(self):
        with tempfile.TemporaryDirectory() as folder:
            scratch = Path(folder)
            with patch.dict(os.environ, {"RUNNER_TEMP":folder, "GITHUB_WORKSPACE":str(ROOT)}):
                import normal_deps
                replay = 'python3 -I "$RUNNER_TEMP/verified-six/receive_six.py" replay "$RUNNER_TEMP/verified-six"'
                def local_stage(script):
                    # Stop only at the first external byte read after creating the fixed receipts.
                    if replay in script:
                        self.assertTrue(script.rstrip().endswith(replay))
                        script = script.replace(replay, "true")
                    subprocess.run(["bash", "-euo", "pipefail", "-c", script], check=True)
                with patch.object(normal_deps, "shell", local_stage):
                    normal_deps.stage()
            expected = {
                "round26-pool-install.py": "c99035a293eb9e78fb5b2c5ceb136dfa920d73a7c28e7ff43a8734110d8a815d",
                "verified-six/receive_six.py": "e68454af99b97c0d00230764d6546711c94ddbd57c744e7686819c63a3086a03",
                "verified-six/public_urls.py": "1e5df94632a2a01db64d1225401e1754aa86552cdb874937e13ab44a9bf7487d",
                "verified-six/receipts.json": "0e07cf7378adb98e54164297bbfee7ed4e884b3d1a62ceef8e8b572bbe703fb3",
            }
            self.assertEqual({name:hashlib.sha256((scratch/name).read_bytes()).hexdigest() for name in expected},expected)
            current = next(s["run"] for s in STEPS if s.get("id") == "prepare")
            def dockerfile(source, backend):
                python = source.split("python3 - <<'PYTHON'\n",1)[1].split("\nPYTHON",1)[0]
                docker = scratch/"docker"
                docker.mkdir(exist_ok=True)
                path = docker/"Dockerfile"
                path.write_text("FROM --platform=linux/amd64 ubuntu:22.04\nRUN apt-get update \\\n    && apt-get install --yes foo\n")
                env = dict(os.environ, BARE_BASE_IMAGE="ubuntu@sha256:"+"a"*64, PROBE_MODE="checkpoint-production",
                           CHECKPOINT_BACKEND=backend, UBUNTU_SNAPSHOT_URL="https://snapshot.ubuntu.com/ubuntu/20261112T093000Z")
                subprocess.run(["python3","-"],input=python,text=True,cwd=scratch,check=True,env=env)
                return path.read_bytes()
            self.assertEqual(hashlib.sha256(dockerfile(current, "draft")).hexdigest(),
                             "0440868cfd15f3e43359c5d4e81908925a8be73bb5c886dd02e3b4ddf3367ab2")
            self.assertNotIn(b"Acquire::Retries=3", dockerfile(current,"cache"))
            seal = current.split("<<'APT_SEAL'\n",1)[1].split("\nAPT_SEAL",1)[0]
            self.assertEqual(hashlib.sha256(seal.encode()).hexdigest(),
                             "f10a72fc1346fe1b7398eac9a8d1165e4d608ed598e876789bf8b9aab7589580")
            install = next(s["run"] for s in STEPS if s["name"] == "Install build tools and apply the pinned Bare patches")
            self.assertIn("python3 -I /exchange/round26-pool-install.py", install)
            self.assertIn('git sparse-checkout', next(s["run"] for s in STEPS if "anonymously" in s["name"]))

    def test_expired_lease_prevents_real_trial_entry(self):
        trial = next(s["run"] for s in STEPS if s.get("id") == "trial")
        condition = 'if [[ $PROBE_MODE == checkpoint-production ]]; then\n  [[ $COLLECTOR_LATEST_START'
        start = trial.index(condition)
        end = trial.index('docker compose exec -T', start)
        body = 'set -euo pipefail\n' + trial[start:end]
        for value, expected in [("",1),("123; false",1),(str(int(time.time())-5),1),(str(int(time.time())+60),0)]:
            with self.subTest(value=value):
                result = subprocess.run(["bash","-c",body], env=dict(os.environ,PROBE_MODE="checkpoint-production",
                                        COLLECTOR_LATEST_START=value),capture_output=True)
                self.assertEqual(result.returncode,expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
