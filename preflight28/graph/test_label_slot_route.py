"""Trace the actual signed run's YAML argument forwarding for every fixed slot."""
import os
from pathlib import Path
import re
import subprocess
import unittest

import yaml


DIRECTORY = Path(__file__).resolve().parents[2] / ".github/workflows"
RUN = "111222333"
SHA = "6" * 40
S1 = "fa44728d39b61c25d4116579e6da2c63ca7898cec24ada0e7ae453548bbd73bf"


def read(name):
    return yaml.safe_load((DIRECTORY / name).read_text())


class NormalSlotLabelRouteTest(unittest.TestCase):
    def test_dispatch_defaults_and_actual_guard_through_all_consumers(self):
        caller = read("bare-checkpoint-transfer.yml")
        wrapper = read("bare-r28-native-slot.yml")
        worker = read("bare-arm64-probe.yml")["jobs"]["compile-probe"]
        settings = wrapper["on"]["workflow_call"]["inputs"]
        step = next(s for s in worker["steps"] if s.get("id") == "identity")
        start = step["run"].index("if [[ $PERSONAL_LABEL_RUN == true ]]")
        end = step["run"].index("if [[ -n $R28_PARENT_RUN ]]", start)
        guard = step["run"][start:end]
        conditions = worker["env"]["PERSONAL_LABEL_RUN"]
        for term in ("github.event.inputs.mode == 'build-apk'", "github.ref == 'refs/heads/bare-coexist-v2.0.4'",
                     "inputs.probe == 'checkpoint-production'", "inputs.backend == 'draft'",
                     "inputs.segment_ordinal >= 2", "inputs.segment_ordinal <= 13"):
            self.assertIn(term, conditions)
        self.assertNotIn("inputs.parent_", conditions)  # malformed parents must not disable migration
        for n in range(2, 14):
            call = caller["jobs"][f"slot{n:02d}"]
            values = {k: field.get("default") for k, field in settings.items()}
            values.update(call["with"])
            self.assertEqual(call["uses"], "./.github/workflows/bare-r28-native-slot.yml")
            self.assertEqual(wrapper["jobs"]["arm"]["uses"], "./.github/workflows/bare-arm64-probe.yml")
            def forwarded(field):
                token = wrapper["jobs"]["arm"]["with"][field]
                name = re.fullmatch(r"\$\{\{ inputs\.(\w+) \}\}", token)[1]
                return values[name]
            previous, producer = forwarded("parent_run"), forwarded("expected_parent_producer")
            self.assertEqual(forwarded("segment_ordinal"), n)
            self.assertEqual(forwarded("verify_frontier_only"), n == 13)
            if n > 2:
                self.assertEqual(previous, "")
                self.assertEqual(producer, '$' + '{{ needs.slot%02d.outputs.producer_sha }}' % (n - 1))
                self.assertIn(f"needs.slot{n - 1:02}.outputs.producer_sha == github.sha", call["if"])
                producer = SHA
            env = dict(os.environ, GITHUB_SHA=SHA, GITHUB_RUN_ID=RUN, PERSONAL_LABEL_RUN="true",
                       SEGMENT_ORDINAL=str(n), R28_PARENT_RUN=previous, R28_PARENT_MANIFEST=forwarded("parent_manifest_id"),
                       EXPECTED_SHA=forwarded("expected_checkpoint_sha"), PARENT_PRODUCER=producer)
            self.assertEqual(subprocess.run(["bash", "-eu", "-c", guard], env=env).returncode, 0, n)
            for foreign in (RUN, "9999999"):
                self.assertNotEqual(subprocess.run(["bash", "-eu", "-c", guard],
                                        env=dict(env, R28_PARENT_RUN=foreign)).returncode, 0, n)
            if n > 2:
                self.assertNotEqual(subprocess.run(["bash", "-eu", "-c", guard],
                                       env=dict(env, PARENT_PRODUCER="f"*40)).returncode, 0, n)
