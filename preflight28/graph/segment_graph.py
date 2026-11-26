#!/usr/bin/env python3
"""Compare complete pinned APK plans at the ordinary segment boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import time
import tempfile
import zipfile

from graph import TARGET, canonical, compare, file_record, fixed_graph, output_name, run

from contract_gate import verify_pending_contract
from retained import (DEVIL_LINK, FRONTIER_FORMAT, FRONTIER_V3, check_frontier_log, devil_link_record,
                      scan_ninja_log)
from android_outputs import runtime_groups
from retained import (FILEARG_RULES, verify_kotlin_disk_pair, NOMINAL_GROUPS, STAMP_RULES, check_errorprone_marker, check_nominal_state,
                      commitment, compare_payload, digest_stream, inventory,
                      stamp_metadata, valid_completion)

FORMAT = FRONTIER_FORMAT
PROOF = "checkpoint-segment-frontier.json"
BOOTSTRAP = "cold"
LIBCHROME_PAIR = ("libchrome.so", "lib.unstripped/libchrome.so")
LIBCHROME_OUTPUTS = tuple(sorted((*LIBCHROME_PAIR, "libchrome.so.TOC", "lib.unstripped/libchrome.so.map.gz")))
LIBCHROME_EDGE = canonical(LIBCHROME_OUTPUTS)
APK_PATH = "apks/ChromePublic.apk"
APK_CORE = "lib/arm64-v8a/libchrome.so"


def verify_libchrome_pair(out):
    """The pinned linker uses --build-id=sha1. Stripping must retain that ID."""
    readelf = out.parent.parent / "third_party/llvm-build/Release+Asserts/bin/llvm-readelf"
    ids = []
    for name in LIBCHROME_PAIR:
        try:
            result = subprocess.run([str(readelf), "--notes", str(out / name)],
                                    check=True, capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError("could not verify the linked ARM64 libchrome GNU build IDs") from exc
        matches = re.findall(rb"(?m)^\s*Build ID: ([a-f0-9]{40})\s*$", result.stdout)
        if len(matches) != 1:
            raise ValueError("missing or ambiguous GNU SHA-1 build ID in a libchrome output")
        ids.append(matches[0])
    if ids[0] != ids[1]:
        raise ValueError("stripped and unstripped libchrome GNU build IDs differ")


def verify_packaged_libchrome(out, files):
    """Pinned apkbuilder stores the stripped library's bytes under its ABI path."""
    stripped = files.get("libchrome.so", "")
    if not stripped.startswith("f:") or not files.get(APK_PATH, "").startswith("f:"):
        raise ValueError("terminal APK or retained stripped libchrome is missing or irregular")
    _, _, size, digest = stripped.split(":")
    with zipfile.ZipFile(out / APK_PATH) as apk:
        members = [item for item in apk.infolist() if item.filename == APK_CORE]
        if len(members) != 1:
            raise ValueError("terminal APK must contain exactly one ARM64 libchrome")
        member, = members
        if member.file_size != int(size):
            raise ValueError("packaged libchrome length differs from retained stripped library")
        with apk.open(member) as stream:
            if digest_stream(stream) != digest:
                raise ValueError("packaged libchrome SHA-256 differs from retained stripped library")



def stage(name, **fields):
    """Keep stage starts in the job log even if the runner kills the process."""
    print('BARE_FRONTIER_PHASE ' + json.dumps(dict(stage=name, **fields), sort_keys=True), flush=True)


def write_record(path, data):
    with tempfile.NamedTemporaryFile("w", dir=path.parent, encoding="ascii", delete=False) as f:
        temp = Path(f.name)
        try:
            json.dump(data, f, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        except BaseException:
            temp.unlink()
            raise
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def load(path, limit=64 * 1024**2):
    if not path.is_file() or path.is_symlink() or path.stat().st_size > limit:
        raise ValueError("absent, invalid or oversized frontier evidence")
    return json.loads(path.read_text(encoding="ascii"))


def plan(out, command, rules=None):
    metadata = (STAMP_RULES, rules) if rules is not None else None
    return {canonical(group): group for group in run(out, command, [TARGET], dry=True, plan_rules=metadata)}


def digests(values):
    if (not isinstance(values, list) or len(values) != len(set(values))
            or any(not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v) for v in values)):
        raise ValueError("invalid or duplicate pending edge identities")
    return set(values)


def witness_record(out, name):
    return devil_link_record(out) if name == DEVIL_LINK else file_record(out, name)


def verify_subset(out, command, evidence, expected_graph, rules, *, require_current=False):
    if (evidence.get("format") not in (FORMAT, FRONTIER_V3) or evidence.get("target") != TARGET
            or evidence["graph"] != expected_graph):
        raise ValueError("segment refers to another graph or build target")
    nominal = any(row['primary'] in NOMINAL_GROUPS for row in evidence.get('runtime_stamps', {}).values())
    rows, log_identity = {}, None
    if evidence.get("format") == FORMAT or nominal:
        log = out / ".ninja_log"
        if log.is_symlink() or not log.is_file():
            raise ValueError("Missing regular Ninja completion log")
        with log.open("rb") as stream:
            rows, log_identity = scan_ninja_log(stream)
    check_frontier_log(evidence, log_identity, require_current=require_current)
    parent = digests(evidence["before"])
    recorded = digests(evidence["after"])
    witnesses = evidence["witnesses"]
    if not isinstance(witnesses, list) or not 1 <= len(witnesses) <= 3:
        raise ValueError("expected successful output witnesses")
    witness_ids = set()
    for files in witnesses:
        if not isinstance(files, dict) or not files:
            raise ValueError("empty witness")
        group = tuple(sorted(files))
        for name, value in files.items():
            if output_name(name, out) != name or witness_record(out, name) != value:
                raise ValueError("completed output did not survive restore")
        if run(out, command, list(group), dry=True):
            raise ValueError("selected whole edge became dirty after restore")
        witness_ids.add(canonical(group))
    closed = evidence["closed_groups"]
    if (not isinstance(closed, list) or len(closed) != len(parent - recorded)
            or {canonical(group) for group in closed} != parent - recorded):
        raise ValueError("stored completed groups differ from the entire frontier change")
    for group in closed:
        if (not isinstance(group, list) or not group or group != sorted(set(group)) or
                any(output_name(name, out) != name for name in group)):
            raise ValueError("missing or invalid required output of a completed edge")
    if any(DEVIL_LINK in group for group in closed):
        devil_link_record(out)
    stamps = stamp_metadata(evidence, canonical)
    claims = evidence.get('runtime_stamps', {})
    if LIBCHROME_EDGE in parent - recorded:
        stage('libchrome-build-id', group_id=LIBCHROME_EDGE)
        verify_libchrome_pair(out)
    if claims:
        rules_on_disk = {edge: [row['rule'], row['primary'], row['action']] for edge, row in claims.items()}
        declared = {canonical(g): g for g in closed}
        complete, bindings = runtime_groups(out, rules_on_disk, declared)
        if any(names != (set(claims[edge]['files']) | set(claims[edge].get('observation', {}).get('reported_only', []))) or
               bindings[edge] != claims[edge]['fileargs'] for edge, names in complete.items()):
            raise ValueError('Restored runtime outputs differ from the fixed command')
    if nominal:
        check_nominal_state(evidence, lambda n: os.path.lexists(out / n), rows)
    for name, expected in stamps.items():
        if file_record(out, name) != expected:
            raise ValueError('Restored runtime stamp is absent or changed')
    for row in claims.values():
        verify_kotlin_disk_pair(out, row['primary'])
    observed = plan(out, command, rules)
    compare(parent, set(observed), witness_ids)
    if set(observed) != recorded:
        raise ValueError("restored APK has a different full pending-edge set")
    return observed


def begin(out, baseline, parent_sha, command, *, bootstrap=False, verify_only=False, require_current=False):
    if parent_sha != BOOTSTRAP and not re.fullmatch("[0-9a-f]{64}", parent_sha):
        raise ValueError("expected exact incoming archive digest")
    if baseline.exists():
        raise ValueError("segment baseline already exists")
    graph = fixed_graph(out)
    proof = out / PROOF
    rules = {}
    if proof.exists():
        data = load(proof)
        observed = verify_subset(out, command, data, graph, rules, require_current=require_current)
        verified = True
    elif bootstrap and not verify_only:
        # Caller permits this only for cold bootstrap or a pinned original
        # archive that predates this schema and passed original provenance.
        observed = plan(out, command, rules)
        verified = False
    else:
        raise ValueError("successor lacks an independent progress receipt")
    if not verify_only:
        stage('pending-output-contract', parent_sha256=parent_sha, graph=graph)
        started = time.monotonic()
        checked = verify_pending_contract(out, observed, rules, parent_sha=parent_sha, graph=graph)
        stage('pending-output-contract-verified', groups=checked, seconds=round(time.monotonic() - started, 3))
    contents = inventory(out)
    if verified and any(name not in contents for group in data["closed_groups"] for name in group):
        raise ValueError("completed APK edge is missing a required output")
    if verified and commitment(contents) != data["child_content"]:
        raise ValueError("Independent restore changed retained output contents")
    write_record(baseline, {"files": contents, "format": FORMAT, "target": TARGET, "graph": graph,
                            "parent_sha256": parent_sha, "planned_groups": observed, "stamp_rules": rules, "began_ns": time.time_ns()})
    stage('baseline-ready', parent_sha256=parent_sha, graph=graph, pending=len(observed))
    return {"parent_frontier_verified": verified, "pending": len(observed)}


def current_completion(step, group, logged, began_ns, checked_ns):
    """Bind all persisted output rows to this invocation's measured action."""
    if not all(name in logged for name in group):
        return False
    rows = {logged[name] for name in group}
    if len(rows) != 1:
        return False
    return valid_completion(step.get('action_start_nanos'), step.get('action_end_nanos'),
                            rows.pop(), began_ns, checked_ns)


def successful_witnesses(out, metrics, removed, rules, planned, parent_files, began_ns, *, need_witness=True, private_intermediates=False, zero_witness_steps=None):
    # Compare current-invocation success with a coherent Ninja row for every output.
    # Command hashes in Ninja and Siso use different algorithms; all rows emitted by
    # one Siso action share the same start/end, wall clock and Ninja command hash.
    stage('ninja-completions')
    logged = {}
    with (out / '.ninja_log').open(encoding='utf-8') as stream:
        if stream.readline().strip() != '# ninja log v5':
            raise ValueError('missing Ninja v5 completion log')
        for line in stream:
            fields = line.rstrip('\n').split('\t')
            if len(fields) == 5:
                try:
                    name = output_name(fields[3], out)
                except ValueError:
                    continue
                logged[name] = (fields[0], fields[1], fields[2], fields[4])
    witnesses, successful, stamps = [], {}, {}
    rules = {edge: value for edge, value in rules.items() if edge in removed}
    for primary, (kind, material) in NOMINAL_GROUPS.items():
        edge = canonical(material)
        if edge in removed and rules.get(edge, [])[:2] != [kind, primary]:
            raise ValueError('Missing or mismatched fixed Android action identity: ' + edge)
    stage('runtime-ownership', rules=len(rules))
    auxiliaries, bindings = runtime_groups(out, rules, planned)
    by_primary = {value[1]: edge for edge, value in rules.items()}
    stamp_owners = {name: edge for edge, names in auxiliaries.items() for name in names}
    observed_owners = {}
    stage('invocation-metrics')
    checked_ns = time.time_ns()
    with metrics.open(encoding='utf-8') as stream:
        for line in stream:
            m = json.loads(line)
            if not m.get('step_id') or m.get('err') or not m.get('outputs'):
                continue
            names = [output_name(n, out) for n in m['outputs']]
            group = tuple(sorted(names))
            for name in group:
                if name in stamp_owners:
                    if name in observed_owners:
                        raise ValueError('Multiple current actions wrote a runtime output')
                    observed_owners[name] = m['step_id']
            edge = canonical(group)
            declared = group
            primary = names[0]
            expected = by_primary.get(primary)
            # A missing output can re-open this edge during the final dry plan.
            # Do not let progress on a different edge hide a successful local
            # action whose real output vanished before the checkpoint.
            if expected is None and primary in NOMINAL_GROUPS:
                kind, material = NOMINAL_GROUPS[primary]
                material_edge = canonical(material)
                if material_edge in planned and m.get('rule') == kind:
                    for name in material:
                        path = out / name
                        if not path.is_file() or path.is_symlink() or path.parent.resolve() != path.parent:
                            stage('reopened-missing-material', group_id=material_edge, members=len(material))
                            raise ValueError('Required Android output vanished after successful action: ' + material_edge)
                    verify_kotlin_disk_pair(out, primary)
                    if kind == 'android/errorprone':
                        check_errorprone_marker(primary, {primary: file_record(out, primary)})
                    if os.path.lexists(out / (primary + '.md5.stamp')):
                        raise ValueError('Unexpected physical file at a report-only Android output: ' + primary)
            if edge in rules and expected != edge:
                continue
            if edge not in removed and expected is None:
                continue
            if not current_completion(m, group, logged, began_ns, checked_ns):
                if primary in NOMINAL_GROUPS and expected is not None:
                    raise ValueError('Stale or incomplete current Android completion: ' + expected)
                continue
            if expected is not None and auxiliaries[expected]:
                edge = expected
                declared = tuple(planned[edge])
                extra = auxiliaries[edge]
                if (m.get('rule') != rules[edge][0] or m.get('action') != rules[edge][2] or m.get('is_local') is not True or
                        group != tuple(sorted((*declared, *extra)))):
                    if primary in NOMINAL_GROUPS:
                        raise ValueError('Unexpected reported Android output group or action: ' + edge)
                    continue
                for binding, digest in bindings[edge].items():
                    source = binding.partition(':')[0]
                    if not parent_files.get(source, '').endswith(':' + digest):
                        raise ValueError('FileArg source changed or was unavailable at segment start')
                if m['rule'] in FILEARG_RULES and any(n in parent_files for n in extra):
                    raise ValueError('FileArg output already belonged to the verified parent')
                if primary in NOMINAL_GROUPS:
                    nominal = primary + '.md5.stamp'
                    if os.path.lexists(out / nominal) or nominal in parent_files:
                        raise ValueError('Unexpected physical file at a report-only Android output: ' + nominal)
                    # Bind every real output, even when this is not one of the three
                    # ordinary witnesses. The nominal name participates only in the log.
                    try:
                        material = {n: file_record(out, n) for n in declared}
                    except (ValueError, OSError) as exc:
                        stage('missing-or-irregular-material', group_id=edge, members=len(declared))
                        raise ValueError('Invalid material Android output for completed edge: ' + edge) from exc
                    verify_kotlin_disk_pair(out, primary)
                    check_errorprone_marker(primary, material)
                    observation = dict(basis='executed', reported_only=[nominal],
                                       material=material,
                                       ninja=list(logged[primary]), window_ns=[began_ns, checked_ns],
                                       action_ns=[m['action_start_nanos'], m['action_end_nanos']])
                    stamps[edge] = dict(rule=m['rule'], primary=primary, action=m['action'],
                                        fileargs={}, files={}, observation=observation)
                    group = declared
                else:
                    stamps[edge] = dict(rule=m['rule'], primary=primary, action=m['action'], fileargs=bindings[edge],
                                        files={n: file_record(out, n) for n in sorted(extra)})
            if edge not in removed:
                continue
            if edge in successful:
                raise ValueError('duplicate successful edge in this invocation')
            successful[edge] = group
            if not need_witness or len(witnesses) >= 3:
                continue
            if 'apks/ChromePublic.apk' in declared or (not private_intermediates and any(
                    n.startswith('apks/') or n.lower().endswith(('.apk', '.ap_', '.aab', '.apks')) for n in declared)):
                continue
            try:
                files = {n: witness_record(out, n) for n in declared}
            except (FileNotFoundError, ValueError):
                continue
            if files not in witnesses:
                witnesses.append(files)
                if zero_witness_steps is not None and any(record[0] == 0 for record in files.values()):
                    zero_witness_steps[edge] = m['step_id']
    return witnesses, successful, stamps, auxiliaries, bindings


def rejected_group(out, metrics, group, parent_files, child_files):
    """Explain the first rejection without disclosing private filenames, commands or bytes."""
    wanted = set(group)
    rows = {key: 0 for key in ('exact_success', 'overlapping_success', 'exact_failed', 'overlapping_failed')}
    metric_outputs = set()
    examples = []
    with metrics.open(encoding='utf-8') as stream:
        for line in stream:
            step = json.loads(line)
            if not step.get('step_id') or not step.get('outputs'):
                continue
            try:
                reported = sorted(output_name(name, out) for name in step['outputs'])
            except (TypeError, ValueError):
                # Failed, unrelated steps can contain paths the success validator never consumes.
                continue
            overlap = wanted.intersection(reported)
            if not overlap:
                continue
            shape = 'exact' if reported == group else 'overlapping'
            status = 'failed' if step.get('err') else 'success'
            rows[shape + '_' + status] += 1
            if status == 'success':
                metric_outputs.update(overlap)
            if len(examples) < 3:
                examples.append({'step_id_hash': canonical(step['step_id']), 'output_group': canonical(reported),
                                 'members': len(reported), 'intersection': len(overlap), 'status': status})
    logged = set()
    samples = set(group[:3])
    log_rows = {}
    with (out / '.ninja_log').open(encoding='utf-8') as stream:
        for line in stream:
            fields = line.rstrip('\n').split('\t')
            if len(fields) != 5:
                continue
            try:
                name = output_name(fields[3], out)
            except ValueError:
                continue
            if name in wanted:
                logged.add(name)
                if name in samples:
                    # Bind the last observed row without logging command arguments or paths.
                    log_rows[name] = canonical(fields)
    members = [{'path_hash': canonical(n), 'parent_record': canonical(parent_files[n]) if n in parent_files else None,
                'child_record': canonical(child_files[n]), 'success_metric': n in metric_outputs,
                'ninja_record': log_rows.get(n)} for n in group[:3]]
    return {'group_id': canonical(group), 'members': len(group), 'new': sum(n not in parent_files for n in group),
            'changed': sum(n in parent_files and parent_files[n] != child_files[n] for n in group),
            'successful_metric_members': len(metric_outputs), 'ninja_members': len(logged),
            'current_metric_rows': rows, 'metric_examples': examples, 'member_examples': members}


def finish(out, baseline, trial, command, *, host_quiesced=False, terminal=False, private_intermediates=False):
    stage('read-baseline')
    base = load(baseline, 512 * 1024**2)
    parent = base.get('parent_sha256')
    if parent != BOOTSTRAP and not (isinstance(parent, str) and re.fullmatch('[0-9a-f]{64}', parent)):
        raise ValueError("invalid baseline parent")
    stage('read-controller', parent_sha256=parent)
    report = load(trial, 128 * 1024**2)
    stage('fixed-graph')
    if (base["format"] != FORMAT or base["target"] != TARGET
            or fixed_graph(out) != base["graph"]):
        raise ValueError("fixed graph changed in this segment")
    if report.get("reason") == "insufficient-terminal-retry-window":
        if (terminal or not host_quiesced or report.get("target") != TARGET or
                report.get("forced_kill") is not False or report.get("returncode") is not None or
                report.get("controller_error") or "command" in report or "metrics_path" in report or
                report.get("ready_for_restore_test") is not False or not report.get("interrupted_terminal_actions")):
            raise ValueError("ambiguous deferred terminal retry")
        before = set(base["planned_groups"])
        stage('apk-plan', pending_before=len(before))
        if set(plan(out, command)) != before:
            raise ValueError("deferred terminal retry changed the full APK frontier")
        stage('deferred-inventory-and-compare')
        compare_payload(base["files"], inventory(out), set())
        return {"frontier_status": "no-progress", "candidate_progress": False,
                "parent_dirty": len(before), "child_dirty": len(before), "reason": report["reason"]}
    if (report.get("target") != TARGET
            or not (host_quiesced or report.get("container_quiescence_verified") is True)
            or report.get("forced_kill") is not False or report.get("controller_error")
            or report.get("close", {}).get("errors") or report.get("failed_step_count") != 0
            or report.get("reason") not in ({"completed"} if terminal else {"time-limit","disk-limit","output-limit","output-entry-limit"})):
        raise ValueError("incomplete segment has no clean, quiescent controller result")
    planned = base.pop("planned_groups")
    before = set(planned)
    stage('apk-plan', pending_before=len(before))
    after = set(plan(out, command))
    stage('output-inventory', pending_after=len(after))
    new_files = inventory(out)
    if LIBCHROME_EDGE in before - after or (terminal and
            ((out / "obj/chrome/android/libchrome.ninja").is_file() or any(n in new_files for n in LIBCHROME_PAIR))):
        stage('libchrome-build-id', group_id=LIBCHROME_EDGE)
        verify_libchrome_pair(out)
    if terminal and (after or report.get("artifact_ready") is not True or report.get("returncode") != 0):
        raise ValueError("Terminal APK is not clean and complete")
    if terminal:
        stage('apk-packaged-libchrome', group_id=LIBCHROME_EDGE)
        verify_packaged_libchrome(out, new_files)
    if after == before and not terminal:
        stage('retained-comparison')
        compare_payload(base["files"], new_files, set())
        return {"frontier_status": "no-progress", "candidate_progress": False,
                "parent_dirty": len(before), "child_dirty": len(after)}
    if (not terminal and not after < before) or not after <= before:
        raise ValueError("full APK frontier regressed")
    if not terminal and report.get("ready_for_restore_test") is not True:
        raise ValueError("controller did not authorize interrupted checkpoint")
    phase = report["phase"]
    if phase not in ("seed", "restore"):
        raise ValueError("unexpected controller phase")
    metrics = trial.parent / ("siso-metrics-" + phase + ".json")
    if Path(report["metrics_path"]) != metrics.absolute():
        raise ValueError("success metrics belong to another invocation")
    rules = base.pop("stamp_rules", {})
    zero_witness_steps = {}
    witnesses, successful, stamps, auxiliaries, bindings = successful_witnesses(out, metrics, before - after, rules, planned, base["files"], base.pop("began_ns", 0), need_witness=not terminal,
                                                  private_intermediates=private_intermediates, zero_witness_steps=zero_witness_steps)
    # A restat can make a dependent edge clean without running its command.
    # Accept that only if every output of that edge was already present and
    # remains byte-for-byte unchanged. Every other retired edge must have its
    # entire group in this invocation's Siso success metrics and Ninja log.
    closed_groups = []
    unsupported = []
    stage('retired-output-groups', retired=len(before - after))
    for key in sorted(before - after):
        group = planned[key]
        closed_groups.append(group)
        if DEVIL_LINK in group:
            devil_link_record(out)
        if not all(name in new_files for name in group):
            stage('missing-output', group_id=canonical(group), members=len(group),
                  missing=sum(name not in new_files for name in group))
            raise ValueError("completed APK edge is missing a required output")
        if key in successful:
            continue
        # A restat which skipped a runtime handler needs all of its original
        # declared AND runtime files. New/changed/missing bytes require execution.
        extras = auxiliaries.get(key, set())
        sources = {loc.partition(':')[0]: digest for loc, digest in bindings.get(key, {}).items()}
        primary = rules[key][1] if key in rules else None
        nominal = primary + '.md5.stamp' if primary in NOMINAL_GROUPS else None
        # No receiver can authenticate an unchanged-parent claim for these four
        # fresh S2 edges from a child alone. Require a real, current completion,
        # even when a previous attempt left plausible bytes on disk.
        if (nominal or any(base["files"].get(name) != new_files[name] for name in group) or
                any(name not in new_files or not new_files[name].startswith("f:") or
                    base["files"].get(name) != new_files[name] for name in extras) or
                any(not base["files"].get(name, '').endswith(':' + digest) or
                    base["files"].get(name) != new_files.get(name) for name, digest in sources.items())):
            if not unsupported:
                stage('first-unproved-change', group_id=canonical(group), members=len(group))
            unsupported.append(key)
        elif extras:
            rule, primary, action = rules[key]
            stamps[key] = dict(rule=rule, primary=primary, action=action, fileargs=bindings[key],
                               files={name: file_record(out, name) for name in sorted(extras)})
    if unsupported:
        stage('rejection-detail', group_id=canonical(planned[unsupported[0]]), count=len(unsupported))
        diagnostic = {'format': 'bare-frontier-rejection-v1', 'parent_sha256': base['parent_sha256'],
                      'graph': base['graph'], 'before': len(before), 'after': len(after),
                      'removed': len(closed_groups), 'unsupported_count': len(unsupported),
                      'unsupported_commitment': canonical(unsupported),
                      'first_group': rejected_group(out, metrics, planned[unsupported[0]], base['files'], new_files)}
        extras = auxiliaries.get(unsupported[0], set())
        if unsupported[0] in rules and rules[unsupported[0]][1] in NOMINAL_GROUPS:
            extras = set()
            diagnostic['first_group']['reported_only'] = 1
        diagnostic['first_group']['runtime_files'] = {
            'required': len(extras), 'present_at_start': sum(n in base['files'] for n in extras),
            'present_at_end': sum(n in new_files for n in extras),
            'unchanged': sum(n in new_files and base['files'].get(n) == new_files[n] for n in extras)}
        print('BARE_FRONTIER_REJECTION ' + json.dumps(diagnostic, sort_keys=True), flush=True)
        raise ValueError("retired APK edge has new or changed outputs without success evidence")
    if not terminal and not witnesses:
        raise ValueError('no persistable success matches a removed APK edge')
    authorized = {name for group in successful.values() for name in group}
    stage('retained-comparison')
    replacements = compare_payload(base["files"], new_files, authorized)
    stage('content-commitments')
    parent_content = commitment(base.pop("files"))
    child_content = commitment(new_files)
    if terminal:
        return {"frontier_status": "apk-complete", "replacements": replacements,
                "parent_content": parent_content, "child_content": child_content}
    for files in witnesses:
        stage('witness-noop', group_id=canonical(sorted(files)))
        if run(out, command, sorted(files), dry=True):
            raise ValueError("completed output group is still dirty")
    evidence = {**base, "ninja_log": file_record(out, ".ninja_log"), "before": sorted(before), "after": sorted(after), "closed_groups": closed_groups,
                "witnesses": witnesses, "runtime_stamps": stamps,
                "parent_content": parent_content, "child_content": child_content,
                "replacements": replacements}
    if zero_witness_steps:
        evidence['zero_witness_steps'] = zero_witness_steps
    stage('write-proof')
    write_record(out / PROOF, evidence)
    return {"frontier_status": "candidate", "candidate_progress": True, "parent_dirty": len(before), "child_dirty": len(after),
            "advanced_edges": len(before - after), "proof_sha256": canonical(evidence)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("out/Bare"))
    sub = parser.add_subparsers(dest="operation", required=True)
    p = sub.add_parser("before")
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--parent-sha", required=True)
    p.add_argument("--bootstrap", action="store_true")
    p.add_argument("--verify-only", action="store_true")
    p.add_argument("--require-current-proof", action="store_true")
    p = sub.add_parser("after")
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--trial", type=Path, required=True)
    p.add_argument("--host-quiesced", action="store_true")
    p.add_argument("--terminal", action="store_true")
    p.add_argument("--private-intermediates", action="store_true")
    args = parser.parse_args()
    if args.operation == "before":
        result = begin(args.out.resolve(), args.baseline, args.parent_sha, ["autoninja"],
                       bootstrap=args.bootstrap, verify_only=args.verify_only, require_current=args.require_current_proof)
    else:
        result = finish(args.out.resolve(), args.baseline, args.trial, ["autoninja"],
                        host_quiesced=args.host_quiesced, terminal=args.terminal,
                        private_intermediates=args.private_intermediates)
    print(json.dumps(result, sort_keys=True))
