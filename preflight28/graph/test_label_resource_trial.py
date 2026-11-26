import unittest
from label_resource_trial import check_plan


class ResourceMigrationPlanTest(unittest.TestCase):
    def test_old_native_work_and_scoped_resource_addition(self):
        check_plan({"old"}, {"old", "resource"}, {"resource"})

    def test_old_work_may_not_disappear(self):
        with self.assertRaisesRegex(ValueError, "lost 1"):
            check_plan({"old"}, {"resource"}, {"resource"})

    def test_native_target_may_not_be_introduced(self):
        with self.assertRaisesRegex(ValueError, "1 unrelated"):
            check_plan({"old"}, {"old", "native"}, {"resource"})


class RelinkGateTest(unittest.TestCase):
    def test_stale_final_resources_cannot_pass_after_correct_raw_link(self):
        from unittest.mock import patch
        from label_resource_trial import OPTIMIZED, relink

        with patch("label_resource_trial.run", return_value={}) as invoke:
            with self.assertRaisesRegex(ValueError, "plan was empty"):
                relink(None, ["autoninja"], OPTIMIZED, set(), set())
            self.assertEqual(invoke.call_count, 1)

    def test_native_or_previous_pending_action_disallowed_before_running(self):
        from unittest.mock import patch
        from label_resource_trial import OPTIMIZED, canonical, relink

        native = ("obj/native.o",)
        with patch("label_resource_trial.run", return_value={native: "cxx"}) as invoke:
            with self.assertRaisesRegex(ValueError, "original APK work"):
                relink(None, ["autoninja"], OPTIMIZED, {canonical(native)}, {canonical(native)})
            self.assertEqual(invoke.call_count, 1)

    def test_restat_may_activate_a_dormant_downstream_action(self):
        from unittest.mock import patch
        from label_resource_trial import canonical, relink

        producer, target = ("ids", "values"), ("final",)
        observed = [{producer: "restat"}, {producer: "restat", target: "link"}, {}]
        with patch("label_resource_trial.run", side_effect=observed):
            self.assertEqual(set(relink(None, ["ninja"], "final", {canonical(producer), canonical(target)}, set())),
                             {producer, target})


class AuthenticatedRuntimeStampTest(unittest.TestCase):
    def setUp(self):
        from label_resource_trial import JAVAC, JAVAC_ACTION, JAVAC_GROUP, JAVAC_RULE, JAVAC_STAMP
        self.jar, self.action, self.group, self.rule = JAVAC, JAVAC_ACTION, JAVAC_GROUP, JAVAC_RULE
        self.actual = (*self.group, JAVAC_STAMP)

    def normalize(self, names, rule, primary, action):
        from label_resource_trial import canonical, declared_groups
        return declared_groups({names: action}, {canonical(names): [rule, primary, action]})

    def test_runtime_metric_identifies_exact_gn_group(self):
        from label_resource_trial import canonical
        self.assertEqual(canonical(self.actual), "215428b622e4738fd27d474de38f57822b966ef2763ac21ec2201164126e57d6")
        self.assertEqual(self.normalize(self.actual, self.rule, self.jar, self.action), {self.group})

    def test_wrong_rule_owner_action_and_extra_output_are_rejected(self):
        for names, rule, primary, action in [
            (self.actual, "android/proguard", self.jar, self.action),
            (self.actual, self.rule, self.jar + ".info", self.action),
            (self.actual, self.rule, self.jar, "unrelated"),
            (self.actual + ("unexpected",), self.rule, self.jar, self.action),
            (self.group, self.rule, self.jar, self.action),
        ]:
            with self.subTest(names=names, rule=rule, primary=primary, action=action):
                with self.assertRaisesRegex(ValueError, "Unexpected Java compiler metric"):
                    self.normalize(names, rule, primary, action)

    def test_normalized_runtime_action_still_cannot_consume_a_pending_action(self):
        from unittest.mock import patch
        from label_resource_trial import canonical, relink
        target = ("final",)
        def metrics(out, cmd, targets, *, dry, **options):
            if dry:
                return {target: "link"}
            options["plan_rules"][1][canonical(self.actual)] = [self.rule, self.jar, self.action]
            return {self.actual: self.action, target: "link"}
        with patch("label_resource_trial.run", metrics):
            with self.assertRaisesRegex(ValueError, "original_pending=1"):
                relink(None, [], "final", {canonical(self.group), canonical(target)}, {canonical(self.group)})

    def test_unexpected_bytes_still_have_label_evidence(self):
        import sys
        from pathlib import Path
        from types import SimpleNamespace
        from unittest.mock import Mock, patch
        from label_resource_trial import RAW, canonical, relink
        evidence = {}
        target = (RAW,)
        observed = {"application": ["Bare Personal"]}
        verifier = Mock(return_value=observed)
        with (patch.dict(sys.modules, launcher_labels=SimpleNamespace(verify_labels=verifier)),
              patch("label_resource_trial.sha", side_effect=["old", "different"]),
              patch("label_resource_trial.run", return_value={target: "link"})):
            with self.assertRaisesRegex(ValueError, "expected Personal SHA"):
                relink(Path("/work/src/out/Bare"), [], RAW, {canonical(target)}, set(), labels=evidence)
        self.assertEqual(evidence, {RAW: observed})
        verifier.assert_called_once()


class ResourceInventoryEvidenceTest(unittest.TestCase):
    def setUp(self):
        from label_resource_trial import RAW, OPTIMIZED
        self.before = "f:0:1:" + "1"*64
        self.after = "f:0:2:" + "2"*64
        self.parent = {RAW:self.before, OPTIMIZED:self.before}
        self.current = {RAW:self.after, OPTIMIZED:self.after}
        self.allowed = {RAW, OPTIMIZED, "permitted"}

    def check_failure(self, message):
        from contextlib import redirect_stdout
        from io import StringIO
        import json
        from label_resource_trial import verify_resource_inventory
        stream = StringIO()
        with redirect_stdout(stream), self.assertRaisesRegex(ValueError,message):
            verify_resource_inventory(self.parent,self.current,self.allowed)
        lines = stream.getvalue().splitlines()
        self.assertEqual(len(lines),1)
        self.assertTrue(lines[0].startswith("BARE_LABEL_INVENTORY_MISMATCH "))
        return json.loads(lines[0].split(" ",1)[1])

    def test_failing_gate_reports_all_classes_and_binds_unsampled_rows(self):
        from label_resource_trial import inventory_mismatch
        for i in range(6):
            self.parent[f"changed/{i}"] = self.before
            self.current[f"changed/{i}"] = self.after
        self.parent["permitted"] = self.before  # Old files, including authorized ones, cannot vanish.
        self.current["new/link"] = "l:" + "a"*64
        result = self.check_failure("Previously present payload disappeared: permitted")
        self.assertEqual(result["counts"], {"missing":1, "changed":6, "added":1})
        self.assertEqual(len(result["samples"]["changed"]),3)
        self.assertEqual(result["samples"]["changed"][0],dict(path="changed/0",old=self.before,new=self.after))
        self.assertEqual(result["samples"]["added"],[dict(path="new/link",old=None,new=self.current["new/link"])])
        self.assertEqual(inventory_mismatch(dict(reversed(list(self.parent.items()))),
                        self.current,self.allowed)["sha256"],result["sha256"])
        self.current["changed/5"] = "f:0:3:" + "3"*64
        self.assertNotEqual(self.check_failure("Previously present payload disappeared")["sha256"],result["sha256"])

    def test_existing_error_order_and_success_without_diagnostic(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from label_resource_trial import verify_resource_inventory, RAW, OPTIMIZED
        self.parent["bad"] = self.before
        self.current.update(bad=self.after, extra=self.after)
        self.check_failure("Unaccounted retained output replacement: bad")
        self.current["bad"] = self.before
        self.check_failure("Unattributed new resource files")
        self.allowed.add("extra")
        self.current[RAW] = self.before
        self.check_failure("Resource APK did not change")
        self.current[RAW] = self.after
        stream = StringIO()
        with redirect_stdout(stream):
            changed, added = verify_resource_inventory(self.parent,self.current,self.allowed)
        self.assertEqual(set(changed),{RAW,OPTIMIZED})
        self.assertEqual(added,{"extra"})
        self.assertEqual(stream.getvalue(),"")
