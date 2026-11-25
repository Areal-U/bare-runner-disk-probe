#!/usr/bin/env python3
"""Compare complete pinned APK plans at the ordinary segment boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import time
import tempfile

from graph import TARGET, canonical, compare, file_record, fixed_graph, output_name, run

from android_outputs import runtime_groups
from retained import FILEARG_RULES, STAMP_RULES, commitment, compare_payload, inventory, stamp_metadata

FORMAT = "bare-apk-segment-frontier-v3"
PROOF = "checkpoint-segment-frontier.json"
BOOTSTRAP = "cold"


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


def verify_subset(out, command, evidence, expected_graph, rules):
    if (evidence.get("format") != FORMAT or evidence.get("target") != TARGET
            or evidence["graph"] != expected_graph):
        raise ValueError("segment refers to another graph or build target")
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
            if output_name(name, out) != name or file_record(out, name) != value:
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
    stamps = stamp_metadata(evidence, canonical)
    claims = evidence.get('runtime_stamps', {})
    if claims:
        rules_on_disk = {edge: [row['rule'], row['primary'], row['action']] for edge, row in claims.items()}
        declared = {canonical(g): g for g in closed}
        complete, bindings = runtime_groups(out, rules_on_disk, declared)
        if any(names != set(claims[edge]['files']) or bindings[edge] != claims[edge]['fileargs'] for edge, names in complete.items()):
            raise ValueError('Restored runtime outputs differ from the fixed command')
    for name, expected in stamps.items():
        if file_record(out, name) != expected:
            raise ValueError('Restored runtime stamp is absent or changed')
    observed = plan(out, command, rules)
    compare(parent, set(observed), witness_ids)
    if set(observed) != recorded:
        raise ValueError("restored APK has a different full pending-edge set")
    return observed


def begin(out, baseline, parent_sha, command, *, bootstrap=False, verify_only=False):
    if parent_sha != BOOTSTRAP and not re.fullmatch("[0-9a-f]{64}", parent_sha):
        raise ValueError("expected exact incoming archive digest")
    if baseline.exists():
        raise ValueError("segment baseline already exists")
    graph = fixed_graph(out)
    proof = out / PROOF
    rules = {}
    if proof.exists():
        data = load(proof)
        observed = verify_subset(out, command, data, graph, rules)
        verified = True
    elif bootstrap and not verify_only:
        # Caller permits this only for cold bootstrap or a pinned original
        # archive that predates this schema and passed original provenance.
        observed = plan(out, command, rules)
        verified = False
    else:
        raise ValueError("successor lacks an independent progress receipt")
    contents = inventory(out)
    if verified and any(name not in contents for group in data["closed_groups"] for name in group):
        raise ValueError("completed APK edge is missing a required output")
    if verified and commitment(contents) != data["child_content"]:
        raise ValueError("Independent restore changed retained output contents")
    write_record(baseline, {"files": contents, "format": FORMAT, "target": TARGET, "graph": graph,
                            "parent_sha256": parent_sha, "planned_groups": observed, "stamp_rules": rules, "began_ns": time.time_ns()})
    return {"parent_frontier_verified": verified, "pending": len(observed)}


def successful_witnesses(out, metrics, removed, rules, planned, parent_files, began_ns, *, need_witness=True, private_intermediates=False):
    # Compare current-invocation success with a coherent Ninja row for every output.
    # Command hashes in Ninja and Siso use different algorithms; all rows emitted by
    # one Siso action share the same start/end, wall clock and Ninja command hash.
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
    auxiliaries, bindings = runtime_groups(out, rules, planned)
    by_primary = {value[1]: edge for edge, value in rules.items()}
    stamp_owners = {name: edge for edge, names in auxiliaries.items() for name in names}
    observed_owners = {}
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
            if edge in rules and expected != edge:
                continue
            if expected is not None and auxiliaries[expected]:
                edge = expected
                declared = tuple(planned[edge])
                extra = auxiliaries[edge]
                if (m.get('rule') != rules[edge][0] or m.get('action') != rules[edge][2] or m.get('is_local') is not True or
                        group != tuple(sorted((*declared, *extra))) or not all(n in logged for n in group) or
                        len({logged[n] for n in group}) != 1):
                    continue
                start, end, end_ns, _ = logged[primary]
                mstart, mend = m.get('action_start_nanos'), m.get('action_end_nanos')
                if type(mstart) is not int or type(mend) is not int or not end_ns.isdecimal():
                    continue
                ms = mstart // 1_000_000
                if (not began_ns <= int(end_ns) <= time.time_ns() or
                        (start, end) != (str(ms), str(max(ms + 1, mend // 1_000_000)))):
                    continue
                for binding, digest in bindings[edge].items():
                    source = binding.partition(':')[0]
                    if not parent_files.get(source, '').endswith(':' + digest):
                        raise ValueError('FileArg source changed or was unavailable at segment start')
                if m['rule'] in FILEARG_RULES and any(n in parent_files for n in extra):
                    raise ValueError('FileArg output already belonged to the verified parent')
                stamps[edge] = dict(rule=m['rule'], primary=primary, action=m['action'], fileargs=bindings[edge],
                                    files={n: file_record(out, n) for n in sorted(extra)})
            if edge not in removed or not all(n in logged for n in group):
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
                files = {n: file_record(out, n) for n in declared}
            except (FileNotFoundError, ValueError):
                continue
            if files not in witnesses:
                witnesses.append(files)
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
    base = load(baseline, 512 * 1024**2)
    report = load(trial, 128 * 1024**2)
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
        if set(plan(out, command)) != before:
            raise ValueError("deferred terminal retry changed the full APK frontier")
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
    after = set(plan(out, command))
    new_files = inventory(out)
    if terminal and (after or report.get("artifact_ready") is not True or report.get("returncode") != 0):
        raise ValueError("Terminal APK is not clean and complete")
    if after == before and not terminal:
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
    witnesses, successful, stamps, auxiliaries, bindings = successful_witnesses(out, metrics, before - after, rules, planned, base["files"], base.pop("began_ns", 0), need_witness=not terminal,
                                                  private_intermediates=private_intermediates)
    # A restat can make a dependent edge clean without running its command.
    # Accept that only if every output of that edge was already present and
    # remains byte-for-byte unchanged. Every other retired edge must have its
    # entire group in this invocation's Siso success metrics and Ninja log.
    closed_groups = []
    unsupported = []
    for key in sorted(before - after):
        group = planned[key]
        closed_groups.append(group)
        if not all(name in new_files for name in group):
            raise ValueError("completed APK edge is missing a required output")
        if key in successful:
            continue
        # A restat which skipped a runtime handler needs all of its original
        # declared AND runtime files. New/changed/missing bytes require execution.
        extras = auxiliaries.get(key, set())
        sources = {loc.partition(':')[0]: digest for loc, digest in bindings.get(key, {}).items()}
        if (any(base["files"].get(name) != new_files[name] for name in group) or
                any(name not in new_files or not new_files[name].startswith("f:") or
                    base["files"].get(name) != new_files[name] for name in extras) or
                any(not base["files"].get(name, '').endswith(':' + digest) or
                    base["files"].get(name) != new_files.get(name) for name, digest in sources.items())):
            unsupported.append(key)
        elif extras:
            rule, primary, action = rules[key]
            stamps[key] = dict(rule=rule, primary=primary, action=action, fileargs=bindings[key],
                               files={name: file_record(out, name) for name in sorted(extras)})
    if unsupported:
        diagnostic = {'format': 'bare-frontier-rejection-v1', 'parent_sha256': base['parent_sha256'],
                      'graph': base['graph'], 'before': len(before), 'after': len(after),
                      'removed': len(closed_groups), 'unsupported_count': len(unsupported),
                      'unsupported_commitment': canonical(unsupported),
                      'first_group': rejected_group(out, metrics, planned[unsupported[0]], base['files'], new_files)}
        extras = auxiliaries.get(unsupported[0], set())
        diagnostic['first_group']['runtime_files'] = {
            'required': len(extras), 'present_at_start': sum(n in base['files'] for n in extras),
            'present_at_end': sum(n in new_files for n in extras),
            'unchanged': sum(n in new_files and base['files'].get(n) == new_files[n] for n in extras)}
        print('BARE_FRONTIER_REJECTION ' + json.dumps(diagnostic, sort_keys=True), flush=True)
        raise ValueError("retired APK edge has new or changed outputs without success evidence")
    if not terminal and not witnesses:
        raise ValueError('no persistable success matches a removed APK edge')
    authorized = {name for group in successful.values() for name in group}
    replacements = compare_payload(base["files"], new_files, authorized)
    parent_content = commitment(base.pop("files"))
    child_content = commitment(new_files)
    if terminal:
        return {"frontier_status": "apk-complete", "replacements": replacements,
                "parent_content": parent_content, "child_content": child_content}
    for files in witnesses:
        if run(out, command, sorted(files), dry=True):
            raise ValueError("completed output group is still dirty")
    evidence = {**base, "before": sorted(before), "after": sorted(after), "closed_groups": closed_groups,
                "witnesses": witnesses, "runtime_stamps": stamps,
                "parent_content": parent_content, "child_content": child_content,
                "replacements": replacements}
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
    p = sub.add_parser("after")
    p.add_argument("--baseline", type=Path, required=True)
    p.add_argument("--trial", type=Path, required=True)
    p.add_argument("--host-quiesced", action="store_true")
    p.add_argument("--terminal", action="store_true")
    p.add_argument("--private-intermediates", action="store_true")
    args = parser.parse_args()
    if args.operation == "before":
        result = begin(args.out.resolve(), args.baseline, args.parent_sha, ["autoninja"],
                       bootstrap=args.bootstrap, verify_only=args.verify_only)
    else:
        result = finish(args.out.resolve(), args.baseline, args.trial, ["autoninja"],
                        host_quiesced=args.host_quiesced, terminal=args.terminal,
                        private_intermediates=args.private_intermediates)
    print(json.dumps(result, sort_keys=True))
