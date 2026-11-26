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
