"""A Siso restat can skip a command only when *all* previous outputs survive."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from graph import canonical
from retained import stamp_metadata
import segment_graph as sg


class RuntimeRestatTest(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        root = Path(self.work.name)
        self.out = root / 'out/Bare'
        self.out.mkdir(parents=True)
        self.declared = 'example.jar'
        self.sidecar = self.declared + '.md5.stamp'
        self.group = canonical([self.declared])
        self.witness = canonical(['compiled'])
        future = canonical(['remaining'])
        self.graph = 'b' * 64
        self.codec = 'a' * 64
        self.parent_records = {}
        for name in (self.declared, self.sidecar, 'compiled', 'remaining'):
            data = name.encode()
            (self.out / name).write_bytes(data)
            self.parent_records[name] = f'f:0:{len(data)}:{hashlib.sha256(data).hexdigest()}'
        self.parent_records.pop('compiled')
        self.baseline = root / 'original'
        self.trial = root / 'trial'
        self.trial.write_text(json.dumps(dict(target=sg.TARGET, phase='restore', failed_step_count=0, forced_kill=False,
            ready_for_restore_test=True, reason='time-limit', metrics_path=str(root / 'siso-metrics-restore.json'))))
        (root / 'siso-metrics-restore.json').touch()
        (self.out / '.ninja_log').write_text('# ninja log v5\n')
        self.planned = {self.group: [self.declared], self.witness: ['compiled'], future: ['remaining']}
        self.rule = {self.group: ['android/compile_java', self.declared, 'compile']}
        patches = (
            patch.object(sg, 'fixed_graph', return_value=self.graph),
            patch.object(sg, 'plan', return_value={future: ['remaining']}),
            patch.object(sg, 'successful_witnesses', return_value=(
                [{'compiled': sg.file_record(self.out, 'compiled')}], {self.witness: ('compiled',)}, {},
                {self.group: {self.sidecar}}, {self.group: {}})),
            patch.object(sg, 'run', return_value={}),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def finish(self):
        self.baseline.write_text(json.dumps(dict(format=sg.FORMAT, target=sg.TARGET, graph=self.graph, parent_sha256=self.codec,
            planned_groups=self.planned, stamp_rules=self.rule, files=self.parent_records)))
        return sg.finish(self.out, self.baseline, self.trial, [], host_quiesced=True)

    def test_unchanged_restatted_edge_preserves_all_runtime_bytes_in_receipt(self):
        self.assertEqual(self.finish()['frontier_status'], 'candidate')
        proof = json.loads((self.out / sg.PROOF).read_bytes())
        self.assertEqual(stamp_metadata(proof, canonical)[self.sidecar], sg.file_record(self.out, self.sidecar))

    def test_preexisting_declared_without_old_or_new_required_sidecar_is_rejected(self):
        del self.parent_records[self.sidecar]
        (self.out / self.sidecar).unlink()
        with self.assertRaisesRegex(ValueError, 'without success evidence'):
            self.finish()

    def test_new_unlogged_or_changed_required_sidecar_is_rejected(self):
        previous_record = self.parent_records.pop(self.sidecar)
        with self.assertRaisesRegex(ValueError, 'without success evidence'):
            self.finish()
        self.parent_records[self.sidecar] = previous_record
        (self.out / self.sidecar).write_bytes(b'different bytes')
        with self.assertRaisesRegex(ValueError, 'without success evidence'):
            self.finish()
