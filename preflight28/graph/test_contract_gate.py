"""Keep a broken pinned Android contract out of the pre-compile baseline."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import contract_gate
from graph import canonical
from retained import ANDROID_RULES_SHA256, NOMINAL_GROUPS
import segment_graph


PRIMARY = 'obj/third_party/androidx/compose_ui_overrides_java.kotlinc.jar'
RULE, GROUP = NOMINAL_GROUPS[PRIMARY]
ACTION = '__third_party_androidx_compose_ui_overrides_java__compile_kt___build_toolchain_android_android_clang_arm64__rule'
EDGE = canonical(GROUP)


class PendingOutputContractTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.out = self.root / 'out/Bare'
        self.out.mkdir(parents=True)
        self.planned = {EDGE: list(GROUP)}
        self.rule = {EDGE: [RULE, PRIMARY, ACTION]}

    def check(self, planned, rules, parent_sha='', graph=''):
        return contract_gate.verify_pending_contract(self.out, planned, rules, parent_sha=parent_sha, graph=graph)

    def test_all_four_initial_pending_ids_bound_to_exact_s2_and_graph(self):
        planned = {edge: ['obj/example.o'] for edge in contract_gate.S2_PENDING}
        del planned[EDGE]
        with self.assertRaisesRegex(ValueError, EDGE):
            self.check(planned, {}, contract_gate.S2, contract_gate.S2_GN)
        self.assertEqual(self.check({}, {}, 'b' * 64, contract_gate.S2_GN), 0)
        self.assertEqual(self.check({}, {}, contract_gate.S2, 'c' * 64), 0)
        self.assertEqual(self.check({}, {}), 0)

    def test_unaffected_pending_group_needs_no_siso_or_sources(self):
        self.assertEqual(self.check({'other': ['obj/other.o']}, {}), 0)

    def test_known_group_without_runtime_metadata_stops(self):
        with self.assertRaisesRegex(ValueError, EDGE):
            self.check(self.planned, {})

    def test_existing_file_at_log_only_path_stops(self):
        reported = self.out / (PRIMARY + '.md5.stamp')
        reported.parent.mkdir(parents=True)
        reported.touch()
        with self.assertRaisesRegex(ValueError, 'physical file'):
            self.check(self.planned, self.rule)

    def test_touch_cannot_repair_preexisting_errorprone_marker(self):
        primary = 'obj/chrome/browser/xsurface/java__errorprone.stamp'
        rule, names = NOMINAL_GROUPS[primary]
        edge = canonical(names)
        planned, rules = {edge: list(names)}, {edge: [rule, primary, 'errorprone']}
        marker = self.out / primary
        marker.parent.mkdir(parents=True)
        # Empty and absent markers advance to the normal source/command checks.
        with patch.object(contract_gate, 'sha', side_effect=RuntimeError('source check')):
            with self.assertRaisesRegex(RuntimeError, 'source check'):
                self.check(planned, rules)
            marker.touch()
            with self.assertRaisesRegex(RuntimeError, 'source check'):
                self.check(planned, rules)
            marker.write_bytes(b'stale payload')
            with self.assertRaisesRegex(ValueError, 'empty regular file'):
                self.check(planned, rules)
            marker.unlink()
            marker.symlink_to('absent')
            with self.assertRaisesRegex(ValueError, 'empty regular file'):
                self.check(planned, rules)

    @unittest.skipUnless(os.environ.get('SISO'), 'requires the pinned Siso executable')
    def test_changed_real_rule_command_stops_before_writing_baseline(self):
        (self.root / '.gclient').touch()
        binary = self.root / 'third_party/siso/cipd/siso'
        binary.parent.mkdir(parents=True)
        binary.symlink_to(Path(os.environ['SISO']).resolve())
        (self.out / 'build.ninja').write_text(
            f'rule {ACTION}\n  command = touch $out\nbuild {" ".join(GROUP)}: {ACTION}\n')
        baseline = self.root / 'before.json'

        def plan(out, command, rules):
            rules.update(self.rule)
            return self.planned

        with (patch.object(segment_graph, 'plan', plan),
              patch.object(contract_gate, 'sha', return_value=ANDROID_RULES_SHA256),
              patch.object(contract_gate, 'verify_nominal_sources'),
              self.assertRaisesRegex(ValueError, 'GN command expansion|command differs')):
            segment_graph.begin(self.out, baseline, 'a' * 64, [], bootstrap=True)
        self.assertFalse(baseline.exists())
        self.assertFalse((self.out / PRIMARY).exists())
