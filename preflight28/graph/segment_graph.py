#!/usr/bin/env python3
"""Compare complete pinned APK plans at the ordinary segment boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

from graph import TARGET, canonical, compare, file_record, fixed_graph, output_name, run

from retained import commitment, compare_payload, inventory

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


def plan(out, command):
    return {canonical(group): group for group in run(out, command, [TARGET], dry=True)}


def digests(values):
    if (not isinstance(values, list) or len(values) != len(set(values))
            or any(not isinstance(v, str) or not re.fullmatch("[0-9a-f]{64}", v) for v in values)):
        raise ValueError("invalid or duplicate pending edge identities")
    return set(values)


def verify_subset(out, command, evidence, expected_graph):
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
    observed = plan(out, command)
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
    if proof.exists():
        data = load(proof)
        observed = verify_subset(out, command, data, graph)
        verified = True
    elif bootstrap and not verify_only:
        # Caller permits this only for cold bootstrap or a pinned original
        # archive that predates this schema and passed original provenance.
        observed = plan(out, command)
        verified = False
    else:
        raise ValueError("successor lacks an independent progress receipt")
    contents = inventory(out)
    if verified and any(name not in contents for group in data["closed_groups"] for name in group):
        raise ValueError("completed APK edge is missing a required output")
    if verified and commitment(contents) != data["child_content"]:
        raise ValueError("Independent restore changed retained output contents")
    write_record(baseline, {"files": contents, "format": FORMAT, "target": TARGET, "graph": graph,
                            "parent_sha256": parent_sha, "planned_groups": observed})
    return {"parent_frontier_verified": verified, "pending": len(observed)}


def successful_witnesses(out, metrics, removed, *, need_witness=True, private_intermediates=False):
    # The whole-plan comparison is authoritative. These bounded byte records
    # join actual completed steps with their complete output groups and Ninja log.
    log = out / ".ninja_log"
    logged = set()
    with log.open(encoding="utf-8") as f:
        if f.readline().strip() != "# ninja log v5":
            raise ValueError("missing Ninja v5 completion log")
        for line in f:
            fields = line.rstrip("\n").split("\t")
            if len(fields) == 5:
                try:
                    logged.add(output_name(fields[3], out))
                except ValueError:
                    continue
    witnesses = []
    successful = {}
    with metrics.open(encoding="utf-8") as f:
        for line in f:
            m = json.loads(line)
            if not m.get("step_id") or m.get("err") or not m.get("outputs"):
                continue
            group = tuple(sorted(output_name(n, out) for n in m["outputs"]))
            edge = canonical(group)
            if edge not in removed or not set(group) <= logged:
                continue
            if edge in successful:
                raise ValueError("duplicate successful edge in this invocation")
            successful[edge] = group
            if not need_witness or len(witnesses) >= 3:
                continue
            # The checkpoint transport omits the APK subtree and packaged files.
            if "apks/ChromePublic.apk" in group or (not private_intermediates and any(
                    n.startswith("apks/") or n.lower().endswith((".apk", ".ap_", ".aab", ".apks"))
                    for n in group)):
                continue
            try:
                files = {n: file_record(out, n) for n in group}
            except (FileNotFoundError, ValueError):
                continue
            if files not in witnesses:
                witnesses.append(files)
    if need_witness and not witnesses:
        raise ValueError("no persistable success matches a removed APK edge")
    return witnesses, successful


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
    witnesses, successful = successful_witnesses(out, metrics, before - after, need_witness=not terminal,
                                                  private_intermediates=private_intermediates)
    # A restat can make a dependent edge clean without running its command.
    # Accept that only if every output of that edge was already present and
    # remains byte-for-byte unchanged. Every other retired edge must have its
    # entire group in this invocation's Siso success metrics and Ninja log.
    closed_groups = []
    for key in sorted(before - after):
        group = planned[key]
        closed_groups.append(group)
        if not all(name in new_files for name in group):
            raise ValueError("completed APK edge is missing a required output")
        if key not in successful and any(base["files"].get(name) != new_files[name] for name in group):
            raise ValueError("retired APK edge has new or changed outputs without success evidence")
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
                "witnesses": witnesses,
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
