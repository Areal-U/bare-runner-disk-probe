"""Exercise both ends of the pinned Android log-only checksum contract."""
import copy
import hashlib
import json
import struct
import zipfile
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from retained import KOTLIN_JARS, NOMINAL_GROUPS, stamp_metadata
import segment_graph as sg


def empty_class(binary_name, implementation):
    # An ordinary Java 8 class with no declared fields, methods or attributes.
    def utf8(text):
        raw = text.encode()
        return b'\x01' + struct.pack('>H', len(raw)) + raw
    pool = utf8(binary_name) + b'\x07\x00\x01' + utf8('java/lang/Object') + b'\x07\x00\x03'
    if implementation:
        # A legal unused constant makes the implementation bytes distinct.
        pool += utf8('implementation')
    return (bytes.fromhex('cafebabe00000034') + struct.pack('>H', 6 if implementation else 5) + pool
            + struct.pack('>7H', 0x21, 2, 4, 0, 0, 0, 0))


def write_jar(path, name, *, omit='', wrong_class=False):
    # Fixed Tabmodel module index, plus small valid class files for this fixture.
    module = bytes.fromhex(
        '00000003000000020000000400000000000000000a430a246f72672e6368726f6d69756d2e636872'
        '6f6d652e62726f777365722e7461626d6f64656c121b4173796e63546162506172616d734d616e61'
        '676572496d706c4b7422002a00'
    )
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as jar:
        for member in sorted(KOTLIN_JARS[name], reverse=True):
            if member == omit:
                continue
            if member.endswith('.class'):
                data = empty_class('wrong/Other' if wrong_class else member.removesuffix('.class'), name.endswith('.kotlinc.jar'))
            elif member.endswith('.kotlin_module'):
                data = module
            else:
                data = b'Manifest-Version: 1.0\r\nCreated-By: JetBrains Kotlin\r\n\r\n'
            jar.writestr(member, data)


class NominalOutputTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.out = self.root / 'out/Bare'
        self.out.mkdir(parents=True)
        self.baseline = self.root / 'baseline'
        self.trial = self.root / 'trial'
        self.metrics = self.root / 'siso-metrics-restore.json'
        self.future = sg.canonical(['future'])
        self.graph = '9' * 64
        self.primary = next(iter(NOMINAL_GROUPS))
        self.initialize(self.primary)

    def initialize(self, primary):
        self.primary = primary
        rule, group = NOMINAL_GROUPS[primary]
        self.group = list(group)
        self.edge = sg.canonical(group)
        self.nominal = primary + '.md5.stamp'
        name = primary[4:].removesuffix('.kotlinc.jar').removesuffix('.stamp').replace('/', '_')
        action = '__' + name + ('__compile_kt' if rule.endswith('compile_kt') else '') + '___build_toolchain_android_android_clang_arm64__rule'
        self.rule = {self.edge: [rule, primary, action]}
        self.planned = {self.edge: self.group, self.future: ['future']}
        now = time.time_ns()
        self.began = now - 10_000_000
        group_names = [primary, *(n for n in group if n != primary), self.nominal]
        self.step = dict(step_id='fresh', rule=rule, action=action, is_local=True, outputs=group_names,
                         action_start_nanos=2_000_000, action_end_nanos=6_000_000)
        self.log = {n: f'2\t6\t{now}\t{n}\t0123456789abcdef' for n in group_names}
        for name in group:
            path = self.out / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if rule == 'android/errorprone':
                path.touch()
            else:
                write_jar(path, name)
        self.write_observations()

    def write_observations(self):
        self.metrics.write_text(json.dumps(self.step) + '\n')
        (self.out / '.ninja_log').write_text('# ninja log v5\n' + '\n'.join(self.log.values()) + '\n')

    def finish(self, parent_files=None):
        self.baseline.write_text(json.dumps(dict(format=sg.FORMAT, graph=self.graph, target=sg.TARGET,
             parent_sha256='a' * 64, files=parent_files or {}, planned_groups=self.planned,
             stamp_rules=self.rule, began_ns=self.began)))
        self.trial.write_text(json.dumps(dict(target=sg.TARGET, ready_for_restore_test=True,
              failed_step_count=0, forced_kill=False, phase='restore', reason='time-limit',
              metrics_path=str(self.metrics))))
        with patch.object(sg, 'fixed_graph', return_value=self.graph), \
             patch.object(sg, 'plan', return_value={self.future: ['future']}), \
             patch.object(sg, 'runtime_groups', return_value=({self.edge: {self.nominal}}, {self.edge: {}})), \
             patch.object(sg, 'run', return_value={}):
            sg.finish(self.out, self.baseline, self.trial, [], host_quiesced=True)
        return json.loads((self.out / sg.PROOF).read_bytes())

    def receive(self, proof):
        with patch.object(sg, 'plan', return_value={self.future: ['future']}), \
             patch.object(sg, 'runtime_groups', return_value=({self.edge: {self.nominal}}, {self.edge: {}})), \
             patch.object(sg, 'run', return_value={}):
            return sg.verify_subset(self.out, [], proof, self.graph, {})

    def test_both_rules_complete_with_only_real_outputs(self):
        for primary in (self.primary, 'obj/chrome/browser/xsurface/java__errorprone.stamp'):
            with self.subTest(primary=primary):
                self.initialize(primary)
                proof = self.finish()
                self.assertEqual(set(stamp_metadata(proof, sg.canonical)), set(self.group))
                self.assertEqual(set(self.receive(proof)), {self.future})

    def test_kotlin_crc_valid_repack_still_requires_all_classes_and_role(self):
        abi = next(n for n in self.group if n.endswith('.kt-jvm-abi.jar'))
        path = self.out / abi
        missing = next(n for n in KOTLIN_JARS[abi] if n.endswith('.class'))
        for variant in ('missing-class', 'wrong-internal-name', 'wrong-role', 'missing-index'):
            with self.subTest(variant=variant), self.assertRaisesRegex(ValueError, 'Invalid fixed Kotlin JAR'):
                if variant == 'missing-class':
                    write_jar(path, abi, omit=missing)
                elif variant == 'wrong-internal-name':
                    write_jar(path, abi, wrong_class=True)
                elif variant == 'missing-index':
                    write_jar(path, abi, omit='META-INF/main.kotlin_module')
                else:
                    write_jar(path, self.primary)
                self.finish()

    def test_same_named_real_class_from_opposite_role(self):
        abi_name = next(n for n in self.group if n.endswith('.kt-jvm-abi.jar'))
        main, abi = self.out / self.primary, self.out / abi_name
        member = next(n for n in KOTLIN_JARS[abi_name] if n.endswith('.class'))
        with zipfile.ZipFile(abi) as jar:
            contents = {name: jar.read(name) for name in jar.namelist()}
        with zipfile.ZipFile(main) as jar:
            contents[member] = jar.read(member)
        with zipfile.ZipFile(abi, 'w', zipfile.ZIP_DEFLATED) as jar:
            for name, content in contents.items():
                jar.writestr(name, content)
        with self.assertRaisesRegex(ValueError, 'implementation and ABI class are identical'):
            self.finish()

    def test_changed_or_incomplete_archive_bytes(self):
        proof = self.finish()
        # Discard the incidental generic witness to directly test this contract.
        other = self.out / 'independent.o'
        other.write_bytes(b'x')
        proof['witnesses'] = [{'independent.o': sg.file_record(self.out, 'independent.o')}]
        material = self.out / self.group[-1]
        original = material.read_bytes()
        material.write_bytes(b'x' * len(original))
        with self.assertRaisesRegex(ValueError, 'absent or changed'):
            self.receive(proof)
        material.unlink()
        with self.assertRaises((ValueError, FileNotFoundError)):
            self.receive(proof)
        with self.assertRaisesRegex(ValueError, 'Invalid material Android output'):
            self.finish()

    def test_nonempty_error_prone_marker_even_with_matching_claimed_digest(self):
        self.initialize('obj/chrome/browser/xsurface/java__errorprone.stamp')
        proof = self.finish()
        path = self.out / self.primary
        path.write_bytes(b'stale')
        record = sg.file_record(self.out, self.primary)
        proof['runtime_stamps'][self.edge]['observation']['material'][self.primary] = record
        proof['witnesses'][0][self.primary] = record
        with self.assertRaisesRegex(ValueError, 'must be an empty file'):
            self.receive(proof)
        with self.assertRaisesRegex(ValueError, 'must be an empty file'):
            self.finish()

    def test_missing_receipt_unknown_rule_and_replayed_completion(self):
        proof = self.finish()
        for change in ('missing', 'other-rule', 'wrong-action', 'pretend-restat', 'stale-window', 'extra-physical'):
            with self.subTest(change=change), self.assertRaises(ValueError):
                revised = copy.deepcopy(proof)
                row = revised['runtime_stamps'][self.edge]
                if change == 'missing':
                    revised['runtime_stamps'].clear()
                elif change == 'other-rule':
                    row['rule'] = 'android/compile_java'
                elif change == 'wrong-action':
                    row['action'] += '_other'
                elif change == 'pretend-restat':
                    row['observation']['basis'] = 'unchanged-parent'
                    for key in ('window_ns', 'ninja', 'action_ns'):
                        del row['observation'][key]
                elif change == 'stale-window':
                    row['observation']['window_ns'][0] = time.time_ns() + 1
                else:
                    row['files'][self.nominal] = [0, hashlib.sha256(b'').hexdigest()]
                self.receive(revised)
        self.log.pop(self.nominal)
        self.write_observations()
        with self.assertRaisesRegex(ValueError, 'absent or stale'):
            self.receive(proof)
        with self.assertRaisesRegex(ValueError, 'Stale or incomplete'):
            self.finish()

    def test_checksum_path_must_remain_absent_at_save_and_receive(self):
        proof = self.finish()
        (self.out / self.nominal).symlink_to('unresolved-file')
        with self.assertRaisesRegex(ValueError, 'Unexpected physical'):
            self.receive(proof)
        with self.assertRaisesRegex(ValueError, 'Unexpected physical'):
            self.finish()

    def test_missing_output_reopened_by_plan_blocks_otherwise_valid_progress(self):
        (self.out / self.group[-1]).unlink()
        other = sg.canonical(['unrelated.o'])
        with patch.object(sg, 'runtime_groups', return_value=({}, {})):
            with self.assertRaisesRegex(ValueError, 'vanished after successful'):
                sg.successful_witnesses(self.out, self.metrics, {other}, self.rule, self.planned, {}, self.began)

    def test_no_current_success_cannot_be_downgraded_to_parent_restat(self):
        self.metrics.write_text('')
        with self.assertRaisesRegex(ValueError, 'without success evidence'):
            self.finish(sg.inventory(self.out))


if __name__ == '__main__':
    unittest.main()
