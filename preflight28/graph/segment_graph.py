#!/usr/bin/env python3
"""Compare complete pinned APK plans at the ordinary segment boundaries."""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

from graph import TARGET, canonical, compare, file_record, fixed_graph, frontier, output_name, run

FORMAT = "bare-apk-segment-frontier-v1"
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
    return frontier(run(out, command, [TARGET], dry=True))


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
    observed = plan(out, command)
    compare(parent, observed, witness_ids)
    if observed != recorded:
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
        observed = verify_subset(out, command, load(proof), graph)
        verified = True
    elif bootstrap and not verify_only:
        # Caller permits this only for cold bootstrap or a pinned original
        # archive that predates this schema and passed original provenance.
        observed = plan(out, command)
        verified = False
    else:
        raise ValueError("successor lacks an independent progress receipt")
    write_record(baseline, {"format": FORMAT, "target": TARGET, "graph": graph,
                            "parent_sha256": parent_sha, "before": sorted(observed)})
    return {"parent_frontier_verified": verified, "pending": len(observed)}


def successful_witnesses(out, metrics, removed):
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
    with metrics.open(encoding="utf-8") as f:
        for line in f:
            m = json.loads(line)
            if not m.get("step_id") or m.get("err") or not m.get("outputs"):
                continue
            group = tuple(sorted(output_name(n, out) for n in m["outputs"]))
            if canonical(group) not in removed or not set(group) <= logged:
                continue
            # The checkpoint transport omits the APK subtree and packaged files.
            if any(n.startswith("apks/") or n.lower().endswith((".apk", ".ap_", ".aab", ".apks"))
                   for n in group):
                continue
            try:
                files = {n: file_record(out, n) for n in group}
            except (FileNotFoundError, ValueError):
                continue
            if files not in witnesses:
                witnesses.append(files)
            if len(witnesses) == 3:
                break
    if not witnesses:
        raise ValueError("no persistable success matches a removed APK edge")
    return witnesses


def finish(out, baseline, trial, command):
    base = load(baseline)
    report = load(trial, 128 * 1024**2)
    if (base["format"] != FORMAT or base["target"] != TARGET
            or fixed_graph(out) != base["graph"]):
        raise ValueError("fixed graph changed in this segment")
    if (report.get("target") != TARGET or report.get("container_quiescence_verified") is not True
            or report.get("ready_for_restore_test") is not True or report.get("forced_kill") is not False
            or report.get("failed_step_count") != 0):
        raise ValueError("incomplete segment has no clean, quiescent controller result")
    before = digests(base["before"])
    after = plan(out, command)
    if not after < before:
        raise ValueError("full APK frontier did not strictly advance")
    phase = report["phase"]
    if phase not in ("seed", "restore"):
        raise ValueError("unexpected controller phase")
    metrics = trial.parent / ("siso-metrics-" + phase + ".json")
    if Path(report["metrics_path"]) != metrics.absolute():
        raise ValueError("success metrics belong to another invocation")
    witnesses = successful_witnesses(out, metrics, before - after)
    for files in witnesses:
        if run(out, command, sorted(files), dry=True):
            raise ValueError("completed output group is still dirty")
    evidence = {**base, "after": sorted(after), "witnesses": witnesses}
    write_record(out / PROOF, evidence)
    return {"candidate_progress": True, "parent_dirty": len(before), "child_dirty": len(after),
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
    args = parser.parse_args()
    if args.operation == "before":
        result = begin(args.out.resolve(), args.baseline, args.parent_sha, ["autoninja"],
                       bootstrap=args.bootstrap, verify_only=args.verify_only)
    else:
        result = finish(args.out.resolve(), args.baseline, args.trial, ["autoninja"])
    print(json.dumps(result, sort_keys=True))
