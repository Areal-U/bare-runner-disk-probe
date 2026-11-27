import os
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


class PathmapMigrationTest(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("SISO"), "requires the pinned Siso executable")
    def test_live_manifest_phases_surround_one_handled_copy(self):
        import json
        from pathlib import Path
        import subprocess
        from tempfile import TemporaryDirectory
        from graph import parse_metrics
        from label_resource_trial import PATHMAP_OUTPUT

        with TemporaryDirectory() as name:
            root = Path(name)
            (root / ".gclient").touch()
            (root / "input").write_bytes(b"content")
            config = root / "build/config/siso"
            config.mkdir(parents=True)
            (config / "main.star").write_text(
                'load("@builtin//encoding.star", "json")\nload("@builtin//struct.star", "module")\n'
                'def copy(ctx, cmd):\n    ctx.actions.copy(cmd.inputs[0], cmd.outputs[0])\n'
                '    ctx.actions.exit(exit_status=0)\n'
                'def init(ctx):\n    rules = [{"name":"simple/copy","action":"copy","handler":"copy"}]\n'
                '    return module("config", filegroups={}, step_config=json.encode({"rules":rules}), '
                'handlers={"copy":copy})\n')
            out = root / "out/Bare"
            (out / "apks").mkdir(parents=True)
            (out / "build.ninja").write_text(
                "rule regen\n  command = touch build.ninja\n  generator = 1\n"
                "build build.ninja: regen ../../input\nrule copy\n  command = false\n"
                f"build {PATHMAP_OUTPUT}: copy ../../input\n")
            raw = root / "run.jsonl"
            logs = root / "logs"
            logs.mkdir()
            # Go's startup logger uses TMPDIR before Siso opens its build logs.
            subprocess.run([os.environ["SISO"], "ninja", "-C", str(out), "-metrics_json", str(raw),
                            "-log_dir", str(logs), PATHMAP_OUTPUT], cwd=root,
                           env=dict(os.environ, GOMAXPROCS="2", TMPDIR=str(logs)),
                           check=True, capture_output=True, timeout=30)
            rows = [json.loads(line) for line in raw.read_bytes().splitlines()]
            self.assertEqual(["step_id" in row for row in rows], [False, False, True, False])
            self.assertEqual(parse_metrics(raw, 1, out, actual=True, handler_copy=PATHMAP_OUTPUT),
                             {(PATHMAP_OUTPUT,):"copy"})
            self.assertEqual((out / PATHMAP_OUTPUT).read_bytes(), b"content")

    def test_dirty_and_clean_copy_with_verified_material(self):
        from unittest.mock import patch
        from pathlib import Path
        import label_resource_trial as m
        record = [m.PATHMAP_BYTES, m.PATHMAP_SHA]
        parent = {name:f"f:0:{record[0]}:{record[1]}" for name in (m.PATHMAP_SOURCE,m.PATHMAP_OUTPUT)}
        copy = {(m.PATHMAP_OUTPUT,): "copy"}
        for sequence, expected in (([copy, copy, {}],True),([{}],False)):
            with self.subTest(expected=expected), patch.object(m,"file_record",return_value=record), \
                    patch.object(m,"sha",return_value=m.COPY_HANDLER_SHA), \
                    patch.object(m,"run",side_effect=sequence) as run:
                result = m.verify_pathmap_copy(Path("."), [], parent, set())
                self.assertEqual(result["executed"], expected)
                self.assertEqual(result["group"], m.canonical((m.PATHMAP_OUTPUT,)))
                self.assertEqual([c.kwargs["dry"] for c in run.call_args_list],
                                 [True,False,True] if expected else [True])
                self.assertEqual([c.kwargs.get("handler_copy") for c in run.call_args_list],
                                 [None,m.PATHMAP_OUTPUT,None] if expected else [None])

    def test_only_the_expected_handler_can_report_a_successful_copy(self):
        import json
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from graph import parse_metrics
        from label_resource_trial import PATHMAP_OUTPUT

        row = dict(step_id="11111111-1111-1111-1111-111111111111", duration_nanos=10,
                   rule="simple/copy", action="copy", outputs=[PATHMAP_OUTPUT], inputs=1, no_exec=True)
        summary = dict(build_id="22222222-2222-2222-2222-222222222222", duration_nanos=30)
        with TemporaryDirectory() as root:
            out = Path(root)
            metrics = out / "metrics.jsonl"

            def observe(changes, scope=PATHMAP_OUTPUT):
                metrics.write_text(json.dumps(dict(row, **changes)) + "\n" + json.dumps(summary) + "\n")
                return parse_metrics(metrics, 1, out, actual=True, handler_copy=scope)

            self.assertEqual(observe({}), {(PATHMAP_OUTPUT,): "copy"})
            with self.assertRaisesRegex(ValueError, "did not execute locally"):
                observe({}, scope=None)
            for changes in (dict(outputs=["another"]), dict(outputs=[PATHMAP_OUTPUT,"extra"]),
                            dict(rule="simple/stamp"), dict(action="stamp"), dict(no_exec=False),
                            dict(no_exec=1), dict(err=True), dict(cached=True), dict(is_remote=True),
                            dict(is_local=True), dict(fallback=True), dict(racing=True), dict(two_phase_cache_hit=True),
                            dict(inputs=True), dict(inputs=2), dict(inputs="1"), dict(inputs=None)):
                with self.subTest(changes=changes), self.assertRaises(ValueError):
                    observe(changes)
            from contextlib import redirect_stdout
            from io import StringIO
            log = StringIO()
            with redirect_stdout(log), self.assertRaises(ValueError):
                observe(dict(rule="private-rule", action="private-action", outputs=["private-path"],
                             is_remote="private-value", cmdhash="private-hash", inputs="private-inputs"))
            self.assertNotIn("private", log.getvalue())
            observed = json.loads(log.getvalue().splitlines()[0].removeprefix("BARE_LABEL_COPY_METRIC "))
            self.assertEqual((observed["rule_matches"], observed["action_matches"], observed["output_matches"],
                              observed["one_input"], observed["steps"], observed["no_exec"], observed["is_remote"]),
                             (False, False, False, False, 1, True, None))
            phase1 = dict(summary,duration_nanos=10)
            phase2 = dict(summary,duration_nanos=20)
            for before in ([], [phase1], [phase1,phase2]):
                metrics.write_text("".join(json.dumps(v) + "\n" for v in [*before,row,summary]))
                self.assertEqual(parse_metrics(metrics,1,out,actual=True,handler_copy=PATHMAP_OUTPUT),
                                 {(PATHMAP_OUTPUT,):"copy"})
            for rows, count in (([],0), ([summary],1), ([row],1), ([row,summary],2),
                                ([row,row,summary],1), ([row,dict(summary,err=True)],1),
                                ([row,summary,summary],1), ([None],1), ([phase1,phase2,row],1),
                                ([dict(phase1,err=True),phase2,row,summary],1), ([phase2,phase1,row,summary],1),
                                ([dict(phase1,build_id=row["step_id"]),phase2,row,summary],1),
                                ([phase1,phase1,row,summary],1), ([phase1,phase2,row,phase2,summary],1),
                                ([dict(phase1,duration_nanos=1),phase1,phase2,row,summary],1),
                                ([dict(phase1,private_data="secret"),phase2,row,summary],1),
                                ([phase1,dict(row,action="gn"),phase2,row,summary],1)):
                with self.subTest(rows=rows,count=count), redirect_stdout(StringIO()) as log, self.assertRaises(ValueError):
                    metrics.write_text("".join(json.dumps(value) + "\n" for value in rows))
                    parse_metrics(metrics, count, out, actual=True, handler_copy=PATHMAP_OUTPUT)
                self.assertIn("BARE_LABEL_COPY_",log.getvalue())

    def test_changed_handler_and_lost_or_changed_post_copy_bytes_are_rejected(self):
        from pathlib import Path
        from unittest.mock import patch
        import label_resource_trial as m
        record = [m.PATHMAP_BYTES, m.PATHMAP_SHA]
        parent = {name:f"f:0:{record[0]}:{record[1]}" for name in (m.PATHMAP_SOURCE,m.PATHMAP_OUTPUT)}
        copy = {(m.PATHMAP_OUTPUT,):"copy"}
        with (patch.object(m,"file_record",return_value=record), patch.object(m,"sha",return_value="different"),
              patch.object(m,"run",return_value=copy) as run, self.assertRaisesRegex(ValueError, "copy handler")):
            m.verify_pathmap_copy(Path("."), [], parent, set())
        self.assertEqual(run.call_count, 1)
        for target in (0,1):
            for bad in ([m.PATHMAP_BYTES,"different"], FileNotFoundError()):
                final = [record,record]
                final[target] = bad
                with (self.subTest(target=target, bad=bad), patch.object(m,"file_record",side_effect=[record,record,*final]),
                      patch.object(m,"sha",return_value=m.COPY_HANDLER_SHA), patch.object(m,"run",side_effect=[copy,copy,{}]),
                      self.assertRaises((ValueError, FileNotFoundError))):
                    m.verify_pathmap_copy(Path("."), [], parent, set())

    def test_copy_rejects_foreign_work_or_damaged_material_before_any_real_action(self):
        from unittest.mock import patch
        from pathlib import Path
        import label_resource_trial as m
        expected = [m.PATHMAP_BYTES,m.PATHMAP_SHA]
        parent = {name:f"f:0:{expected[0]}:{expected[1]}" for name in (m.PATHMAP_SOURCE,m.PATHMAP_OUTPUT)}
        for old, disk, plan in [
            ({m.PATHMAP_GROUP_ID}, expected, {}),
            (set(), [m.PATHMAP_BYTES,"other"], {}),
            (set(), expected, {("foreign",):"copy"}),
            (set(), expected, {(m.PATHMAP_OUTPUT,):"unexpected"}),
        ]:
            with self.subTest(old=old, disk=disk, plan=plan), patch.object(m,"file_record",return_value=disk), \
                    patch.object(m,"run",return_value=plan) as run, self.assertRaises(ValueError):
                m.verify_pathmap_copy(Path("."),[],parent,old)
            self.assertTrue(all(c.kwargs["dry"] for c in run.call_args_list))

    def test_independent_gate_failures_all_observed_and_no_baseline_published(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        import label_resource_trial as m
        old = {m.canonical(("old",)):("old",)}
        after = {**old,m.canonical(("extra",)):("extra",)}
        original = {"files":{"missing":"f:0:1:"+"1"*64}, "planned_groups":old}
        log = StringIO()
        with (redirect_stdout(log), patch.object(m,"verify_pathmap_copy",side_effect=ValueError("copy cause")),
              patch.object(m,"plan",return_value=after),patch.object(m,"inventory",return_value={}) as read,
              patch.object(m,"write_record") as write, self.assertRaisesRegex(ValueError,"path-map:.*final plan:.*retained inventory:")):
            m.finish_resources(None,[],original,{})
        self.assertIn('BARE_LABEL_FINAL_PLAN',log.getvalue())
        self.assertIn('"outputs": ["extra"]',log.getvalue())
        self.assertIn('BARE_LABEL_INVENTORY_MISMATCH',log.getvalue())
        read.assert_called_once()
        write.assert_not_called()

    def test_failed_resource_check_forbids_copy_and_still_collects_plan_and_inventory(self):
        from unittest.mock import patch
        from contextlib import redirect_stdout
        from io import StringIO
        import label_resource_trial as m
        old = {m.canonical(("old",)):("old",)}
        original = {"files":{"missing":"f:0:1:"+"1"*64}, "planned_groups":old}
        log = StringIO()
        with (redirect_stdout(log),patch.object(m,"verify_pathmap_copy") as copy,
              patch.object(m,"plan",return_value=old),patch.object(m,"inventory",return_value={}) as read,
              self.assertRaisesRegex(ValueError,"bad resource.*retained inventory:")):
            m.finish_resources(None,[],original,{},resource_error="bad resource")
        copy.assert_not_called()
        read.assert_called_once()
        self.assertIn("BARE_LABEL_FINAL_PLAN",log.getvalue())
        self.assertIn("BARE_LABEL_INVENTORY_MISMATCH",log.getvalue())
