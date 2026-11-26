"""Round-trip the production controller's private restore samples through zstd."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
import build_trial
import checkpoint as ck


class PrivateContinuationSampleTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.out = self.root / 'out/Bare'
        self.alias = self.root / ck.HOST_ALIAS
        self.program = self.root / ck.HOST_PROGRAM
        self.marker = self.root / ck.ERRORPRONE_MARKER
        self.marker.parent.mkdir(parents=True)
        self.program.parent.mkdir(parents=True)
        self.program.write_bytes(b'utility')
        self.program.chmod(0o755)
        self.alias.symlink_to(ck.HOST_LINK_TEXT)
        self.marker.touch()
        self.trial = self.root / ck.CONTINUATION_TRIAL
        self.record = self.root / ck.CONTINUATION_RECORD
        self.archive = self.root / 'checkpoint.tar.zst'
        self.revision = '1' * 40
        identity = {'ci_revision': self.revision}
        self.identity = ck.canonical_hash(identity)
        (self.root / ck.PROVENANCE_RECORD).write_text(json.dumps(dict(format=ck.PROVENANCE_FORMAT,
            version=ck.CHECKPOINT_VERSION, identity=identity, identity_sha256=self.identity)))
        objects = []
        for i in range(3):
            obj = self.out / 'obj' / f'reuse{i}.o'
            obj.write_bytes(bytes([i]))
            objects.append(ck.object_metadata(obj, self.root))
        self.record.write_text(json.dumps(dict(format=ck.CONTINUATION_FORMAT, version=2, reuse_markers=objects)))

    def prepare_trial(self, paths, production=True):
        names = [p.relative_to(self.out).as_posix() for p in paths]
        ninja = self.out / '.ninja_log'
        ninja.write_text('# ninja log v5\n' + ''.join(f'1\t3\t42\t{n}\t0000000000000001\n' for n in names))
        metrics = self.root / 'metrics.jsonl'
        metrics.write_text(''.join(json.dumps({'step_id': n, 'outputs': [n]}) + '\n' for n in names))
        complete = build_trial.completed_outputs(metrics, ninja, self.root, production=production)
        self.trial.write_text(json.dumps(dict(format='bare-apk-trial', version=1, phase='restore',
            target='chrome_public_apk', build_dir='out/Bare', artifact_ready=False, ready_for_restore_test=True,
            container_quiescence_verified=True, production_limits={}, reason='time-limit',
            completed_outputs=complete, new_completed_outputs=complete)))
        return [r['path'] for r in complete]

    def write_witness(self, files):
        group = sorted(files)
        edge = ck.canonical_hash(group)
        future = ck.canonical_hash(['future'])
        ninja = (self.out / '.ninja_log').read_bytes()
        proof = dict(ninja_log=[len(ninja), hashlib.sha256(ninja).hexdigest()], format='bare-apk-segment-frontier-v4', target='chrome_public_apk', graph='9' * 64,
                     before=[edge, future], after=[future], closed_groups=[group], witnesses=[files],
                     zero_witness_steps={edge: group[0]})
        (self.root / ck.SEGMENT_FRONTIER).write_text(json.dumps(proof))
        return proof

    def record_samples(self, private=True):
        with patch.object(ck, 'PRIVATE_ANDROID_SAMPLES', private):
            return ck.record_continuation(self.trial, self.record, self.root, production=True)

    def verify(self, accepted=True):
        subprocess.run(['tar', '--zstd', '-cf', str(self.archive), '-C', str(self.root), 'out/Bare'], check=True)
        result = subprocess.run([sys.executable, str(REPO / 'preflight28/bridge/check_archive.py'),
            str(REPO / 'checkpoint.py'), 'verify-continuation', str(self.archive), '--production',
            '--ci-revision', self.revision, '--expected-identity', self.identity], capture_output=True, text=True)
        if accepted:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        return result.stderr

    def test_real_controller_and_private_reader(self):
        self.assertNotIn(self.alias.name, self.prepare_trial([self.alias], production=False))
        self.assertIn(self.alias.name, self.prepare_trial([self.alias, self.marker]))
        with self.assertRaisesRegex(ValueError, 'no verifiable'):
            self.record_samples(private=False)
        self.assertEqual(self.record_samples()['recorded'], 1)
        result = self.verify()
        self.assertEqual(result['paths'], [ck.HOST_ALIAS])
        self.assertEqual(len(result['reuse_markers']), 3)
        self.assertEqual(len(json.loads(self.record.read_bytes())['outputs']), 1)

    def test_other_zero_files_and_arbitrary_symlink_are_excluded(self):
        other = self.out / 'other.stamp'
        other.touch()
        link = self.out / 'other_alias'
        link.symlink_to(ck.HOST_LINK_TEXT)
        self.assertNotIn(link.name, self.prepare_trial([other, link]))
        with self.assertRaisesRegex(ValueError, 'No current frontier|no verifiable'):
            self.record_samples()

    def test_incorrect_link_or_referent_on_disk_and_in_tar(self):
        self.prepare_trial([self.alias])
        self.record_samples()
        self.alias.unlink()
        self.alias.symlink_to('./' + ck.HOST_LINK_TEXT)
        self.assertIn('Wrong archived host utility link', self.verify(False))
        with self.assertRaisesRegex(ValueError, 'Unexpected fixed'):
            self.record_samples()
        self.alias.unlink()
        self.alias.write_bytes(self.program.read_bytes())
        self.assertIn('Wrong archived host utility link', self.verify(False))
        with self.assertRaisesRegex(ValueError, 'Unexpected fixed'):
            self.record_samples()
        self.alias.unlink()
        self.alias.symlink_to(ck.HOST_LINK_TEXT)
        self.program.chmod(0o644)
        self.assertIn('lost executable mode', self.verify(False))
        with self.assertRaisesRegex(ValueError, 'fixed executable'):
            self.record_samples()
        self.program.chmod(0o755)
        self.program.write_bytes(b'changed')
        self.assertIn('content differs', self.verify(False))
        self.program.unlink()
        self.assertIn('Missing archived continuation output', self.verify(False))

    def test_only_empty_regular_errorprone_with_nonempty_persistent_objects(self):
        self.prepare_trial([self.marker])
        self.write_witness({self.marker.relative_to(self.out).as_posix(): [0, ck.EMPTY_SHA256]})
        self.record_samples()
        record = json.loads(self.record.read_bytes())
        self.marker.write_bytes(b'stale')
        with self.assertRaisesRegex(ValueError, 'Error Prone completion marker'):
            self.record_samples()
        record['outputs'][0].update(size=5, sha256=hashlib.sha256(b'stale').hexdigest())
        self.record.write_text(json.dumps(record))
        self.assertIn('Invalid continuation output evidence', self.verify(False))
        self.marker.unlink()
        self.marker.touch()
        self.record_samples()
        self.marker.unlink()
        self.marker.symlink_to('other-zero-file')
        self.assertIn('Invalid archived continuation output', self.verify(False))
        self.marker.unlink()
        self.marker.touch()
        (self.out / 'obj/reuse0.o').write_bytes(b'')
        with self.assertRaisesRegex(ValueError, 'Persistent reuse marker differs'):
            self.record_samples()
        self.assertIn('Invalid archived continuation output', self.verify(False))

    @unittest.skipUnless(os.environ.get('SISO'), 'requires the pinned Siso executable')
    def test_current_siso_pair_with_only_empty_material_roundtrips(self):
        sys.path.insert(0, str(REPO / 'preflight28/graph'))
        self.addCleanup(sys.path.remove, str(REPO / 'preflight28/graph'))
        import segment_graph as sg
        previous = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, previous)
        (self.root / '.gclient').touch()
        (self.root / 'src.txt').touch()
        (self.out / 'build.ninja').write_text(
            'rule pair\n  command = touch first.zero second.zero\n'
            'rule end\n  command = touch future\n'
            'build first.zero | second.zero: pair ../../src.txt\n'
            'build future: end first.zero second.zero\nbuild chrome_public_apk: phony future\n')
        command = [os.environ['SISO'], 'ninja', '-load=']
        baseline = self.root / 'start'
        sg.begin(self.out, baseline, 'a' * 64, command, bootstrap=True)
        metrics = self.root / 'siso-metrics-restore.json'
        subprocess.run([*command, '-C', str(self.out), '-metrics_json', str(metrics), 'first.zero'],
                       check=True, capture_output=True)
        completed = build_trial.completed_outputs(metrics, self.out / '.ninja_log', self.root, production=True)
        trial = self.root / 'trial-restore.json'
        trial.write_text(json.dumps(dict(format='bare-apk-trial', version=1, phase='restore',
            target='chrome_public_apk', build_dir='out/Bare', artifact_ready=False, ready_for_restore_test=True,
            container_quiescence_verified=True, production_limits={}, reason='time-limit', metrics_path=str(metrics),
            failed_step_count=0, forced_kill=False, completed_outputs=completed, new_completed_outputs=completed)))
        self.assertEqual(sg.finish(self.out, baseline, trial, command)['frontier_status'], 'candidate')
        self.trial.write_bytes(trial.read_bytes())
        self.assertEqual(self.record_samples()['recorded'], 2)
        self.assertEqual(self.verify()['verified'], 2)
        ninja = self.out / '.ninja_log'
        old_log = ninja.read_bytes()
        ninja.write_bytes(old_log + b'# replay\n')
        with self.assertRaisesRegex(ValueError, 'Ninja completion log differs'):
            self.record_samples()
        self.assertIn('Ninja completion log differs', self.verify(False))
        ninja.write_bytes(old_log)
        record = json.loads(self.record.read_bytes())
        # Leave just the first progress sample: the receiver still requires the
        # other member of its GN group, including its regular-file bytes.
        record['outputs'] = record['outputs'][:1]
        self.record.write_text(json.dumps(record))
        (self.out / 'second.zero').write_text('stale')
        self.assertIn('Incomplete archived material group', self.verify(False))

    def test_no_proof_downgrade_partial_group_or_replayed_step(self):
        name = self.marker.relative_to(self.out).as_posix()
        self.prepare_trial([self.marker])
        proof = self.write_witness({name: [0, ck.EMPTY_SHA256]})
        path = self.root / ck.SEGMENT_FRONTIER
        self.record_samples()
        path.unlink()
        self.assertIn('Missing archived witness', self.verify(False))
        with self.assertRaisesRegex(ValueError, 'No current frontier'):
            self.record_samples()
        for mutation in ('v3', 'partial', 'old-step', 'wrong-digest', 'missing-current', 'unclosed'):
            with self.subTest(mutation=mutation):
                bad = json.loads(json.dumps(proof))
                if mutation == 'v3':
                    bad['format'] = 'bare-apk-segment-frontier-v3'
                elif mutation == 'partial':
                    bad['closed_groups'][0].append('unlisted')
                elif mutation == 'old-step':
                    bad['zero_witness_steps'][next(iter(bad['zero_witness_steps']))] = 'old'
                elif mutation == 'wrong-digest':
                    bad['witnesses'][0][name][1] = '1' * 64
                elif mutation == 'missing-current':
                    del bad['zero_witness_steps']
                else:
                    bad['after'] = bad['before']
                path.write_text(json.dumps(bad))
                # Even a rebuilt outer witness pointer may not bless it.
                outer = json.loads(self.record.read_bytes())
                outer['outputs'][0]['frontier_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
                self.record.write_text(json.dumps(outer))
                with self.assertRaises(ValueError):
                    self.record_samples()
                self.verify(False)
