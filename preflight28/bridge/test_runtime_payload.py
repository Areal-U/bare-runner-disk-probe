"""Verify the restricted sender reads actual supplementary outputs and FileArg bytes."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import verify_payload

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import checkpoint as ck


class RuntimePayloadTest(unittest.TestCase):
    def test_limited_sender_requires_all_bytes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            out = root / 'out/Bare'
            for sub in ('apks', 'gen', 'obj'):
                (out / sub).mkdir(parents=True)
            (out / 'apks/Trichrome.ssargs').write_text('--test\n')
            (out / 'build.ninja.d').write_text('build.ninja.stamp: apks/Trichrome.ssargs ../../DEPS\n')
            identity = {'ci_revision': 'b' * 40}
            ident = ck.canonical_hash(identity)
            (out / 'checkpoint-provenance.json').write_text(json.dumps(dict(format=ck.PROVENANCE_FORMAT,
                            version=ck.CHECKPOINT_VERSION, identity=identity, identity_sha256=ident)))
            group = ['obj/out.jar']
            edge = ck.canonical_hash(group)
            (out / group[0]).write_bytes(b'jar')
            dynamic = 'gen/extra.dex'
            binding = 'gen/paths.json'
            (out / dynamic).write_bytes(b'dex')
            original_input = json.dumps({'files': [dynamic]}).encode()
            (out / binding).write_bytes(original_input)
            record = dict(rule='android/proguard', action='target', primary=group[0],
                          files={dynamic: [3, hashlib.sha256(b'dex').hexdigest()]},
                          fileargs={binding + ':files': hashlib.sha256(original_input).hexdigest()})
            proof = dict(format='bare-apk-segment-frontier-v3', target='chrome_public_apk', parent_sha256='a' * 64,
                         before=[edge, 'f' * 64], after=['f' * 64], closed_groups=[group], witnesses=[group],
                         runtime_stamps={edge: record})
            evidence = json.dumps(proof).encode()
            (out / 'checkpoint-segment-frontier.json').write_bytes(evidence)
            sealed = dict(producer_sha=identity['ci_revision'], identity=ident, parent_sha=proof['parent_sha256'],
                          proof_sha=hashlib.sha256(evidence).hexdigest())
            archive = root / 'next.tar.zst'

            def check():
                subprocess.run(['tar', '--zstd', '-cf', str(archive), '-C', str(root), 'out/Bare'], check=True)
                verify_payload.check(archive, sealed)

            check()
            (out / dynamic).write_bytes(b'bad')
            with self.assertRaisesRegex(ValueError, 'stamp absent or changed'):
                check()
            (out / dynamic).unlink()
            with self.assertRaisesRegex(ValueError, 'stamp absent or changed'):
                check()
            (out / dynamic).write_bytes(b'dex')
            (out / binding).write_bytes(original_input + b' ')
            with self.assertRaisesRegex(ValueError, 'source absent or changed'):
                check()
