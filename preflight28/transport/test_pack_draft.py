"""Normal entrance -> pack -> receiver for both Draft codecs and the old cache."""
import gzip
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import time
import unittest

import yaml

from pack_draft import CompressedSizeExceeded, MEASURED_TAR_BYTES, pack

REPO = Path(__file__).resolve().parents[2]


class PackDraftTests(unittest.TestCase):
    def test_normal_entry_restore_and_legacy_cache(self):
        arm = yaml.safe_load((REPO / '.github/workflows/bare-arm64-probe.yml').read_text())
        caller = yaml.safe_load((REPO / '.github/workflows/bare-checkpoint-transfer.yml').read_text())
        dispatch = caller['on']['workflow_dispatch']['inputs']['checkpoint_compression']
        self.assertEqual((dispatch['default'], dispatch['options']), ('auto', ['auto', 'compact']))
        steps = arm['jobs']['compile-probe']['steps']
        packing = next(step for step in steps if step.get('id') == 'pack-checkpoint')
        setting = '${{ inputs.checkpoint_compression }}'
        slot = yaml.safe_load((REPO / '.github/workflows/bare-r28-native-slot.yml').read_text())
        calls = [job for job in caller['jobs'].values() if job.get('uses', '').endswith('/bare-r28-native-slot.yml')]
        self.assertTrue(calls)
        self.assertTrue(all(job['with']['checkpoint_compression'] == setting for job in calls))
        self.assertEqual(slot['jobs']['arm']['with']['checkpoint_compression'], setting)
        self.assertEqual(packing['env']['CHECKPOINT_COMPRESSION'], setting)
        self.assertIn('preflight28/transport/pack_draft.py', packing['run'])
        self.assertIn('du -sbx out/Bare', packing['run'])
        restoring = next(s['run'] for s in steps if s['name'] == 'Verify restored inputs and completed targets')
        self.assertIn('tar -xzf /exchange/checkpoint/checkpoint-input.tar.gz', restoring)
        self.assertIn('zstd -qdc -M128MB', restoring)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / 'out/Bare'
            src.mkdir(parents=True)
            (src / 'build.ninja.d').write_text('build.ninja.stamp: ../../DEPS\n')
            (src / 'sample.o').write_bytes(b'compiled example' * 2000)
            command = ['tar', '-C', str(root), '-cf', '-', 'out/Bare']
            tar = subprocess.check_output(command)
            validator = [sys.executable, str(REPO / 'checkpoint.py')]
            adapter = [sys.executable, str(REPO / 'preflight28/bridge/check_archive.py'), validator[-1]]
            for name, profile, amount, level in [('auto', 'auto', MEASURED_TAR_BYTES, 4),
                                                 ('big', 'auto', MEASURED_TAR_BYTES + 1, 9),
                                                 ('compact', 'compact', 1, 9), ('cache', None, 1, None)]:
                with self.subTest(name=name):
                    encoded = root / name
                    restored = root / ('received-' + name)
                    restored.mkdir()
                    if profile:
                        self.assertEqual(pack(encoded, profile, amount, command), level)
                        subprocess.run([*adapter, 'validate-archive', str(encoded), '--production'], check=True)
                        decoded = subprocess.check_output(['zstd', '-qdc', '-M128MB', '--', str(encoded)])
                    else:
                        encoded.write_bytes(gzip.compress(tar))
                        subprocess.run([*validator, 'validate-archive', str(encoded), '--production'], check=True)
                        subprocess.run(['tar', '-C', str(restored), '-xzf', str(encoded)], check=True)
                    if profile:
                        subprocess.run(['tar', '-C', str(restored), '-xf', '-'], input=decoded, check=True)
                    self.assertEqual((restored / 'out/Bare/sample.o').read_bytes(), (src / 'sample.o').read_bytes())

    def test_shared_deadline_protects_seal_and_relay(self):
        arm = yaml.safe_load((REPO / '.github/workflows/bare-arm64-probe.yml').read_text())
        steps = arm['jobs']['compile-probe']['steps']
        body = next(step['run'] for step in steps if step.get('id') == 'pack-checkpoint')
        start = body.index('if [[ $CHECKPOINT_BACKEND == draft ]]; then\n  pack_timeout=30m')
        script = body[start:body.index('within_pack_deadline docker compose exec', start)]
        now = int(time.time())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for clock, job_start, sender, expect, status in [
                ('normal', now, now + 12_000, now + 1800, 0),
                ('sender', now, now + 1100, now + 200, 0),
                ('compute', now - 20_000, now + 12_000, now + 100, 0),
                ('expired', now, now + 890, now - 10, 124),
            ]:
                with self.subTest(clock=clock):
                    (root/'bare-probe-start').write_text(str(job_start))
                    claim = root / clock
                    command = script + 'echo "$pack_deadline"; within_pack_deadline touch "$CLAIM"'
                    env = dict(os.environ, CHECKPOINT_BACKEND='draft', RUNNER_TEMP=tmp,
                               SENDER_OUTCOME_DEADLINE=str(sender), CLAIM=str(claim))
                    result = subprocess.run(['bash', '-euo', 'pipefail', '-c', command],
                                            env=env, text=True, capture_output=True)
                    self.assertEqual(result.returncode, status, result.stderr)
                    self.assertLessEqual(abs(int(result.stdout.splitlines()[0]) - expect), 2)
                    self.assertEqual(claim.exists(), status == 0)

    def test_retry_only_on_size_and_never_publish_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rng = random.Random(28)
            blocks = [rng.randbytes(180) for _ in range(3000)]
            data = b''.join(rng.choice(blocks) for _ in range(20000))
            raw = root / 'raw'
            raw.write_bytes(data)
            compact = subprocess.check_output(['zstd', '-q', '-T2', '-9', '-c'], input=data)
            fast = subprocess.check_output(['zstd', '-q', '-T2', '-4', '-c'], input=data)
            self.assertGreater(len(fast), len(compact))
            trace = root / 'attempts'
            source = ['bash', '-euc', 'echo call >> "$1"; cat "$2"', '--', str(trace), str(raw)]
            path = root / 'candidate'
            with self.assertRaisesRegex(CompressedSizeExceeded, 'insufficient time'):
                pack(path, 'auto', len(data), source, cap=len(compact), deadline=time.time() + 60)
            self.assertFalse(path.exists())
            self.assertEqual(trace.read_text().splitlines(), ['call'])
            trace.unlink()
            self.assertEqual(pack(path, 'auto', len(data), source, cap=len(compact), deadline=time.time() + 1799), 9)
            self.assertEqual(path.read_bytes(), compact)
            self.assertEqual(trace.read_text().splitlines(), ['call', 'call'])
            with self.assertRaises(FileExistsError):
                pack(path, 'compact', 1, source)
            path.unlink()
            for profile, command, cap, error in [('compact', source, 1, CompressedSizeExceeded),
                                                 ('auto', ['bash', '-c', 'cat "$1"; exit 1', '--', str(raw)], 1, RuntimeError),
                                                 ('unknown', source, 1, ValueError)]:
                with self.subTest(profile=profile), self.assertRaises(error):
                    pack(path, profile, 1, command, cap=cap)
                self.assertFalse(path.exists())
                self.assertFalse(list(root.glob('.pack-*')))


if __name__ == '__main__':
    unittest.main()
