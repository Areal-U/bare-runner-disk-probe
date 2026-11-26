#!/usr/bin/env python3
"""Prove forward progress for the pinned APK using the actual Siso planner."""
import argparse
import contextlib
import hashlib
import json
from itertools import islice
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time

from retained import commitment, compare_payload, inventory

TARGET = "chrome_public_apk"
FORMAT = "bare-28-apk-frontier-2"
END = re.compile(rb"Build Succeeded: (\d+) steps -")


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, separators=(",", ":"),
                                     sort_keys=True).encode("ascii")).hexdigest()


def fixed_graph(out):
    # GN may regenerate the files. Content, paths and pinned inputs must agree.
    records = [(str(p.relative_to(out)), sha(p)) for p in sorted(out.rglob("*.ninja"))
               if p.is_file()]
    if not records or not (out / "build.ninja").is_file():
        raise ValueError("missing GN manifest")
    return canonical(records)


def output_name(value, out):
    if not isinstance(value, str) or not value or any(ord(c) < 32 for c in value):
        raise ValueError("invalid Siso output")
    p = Path(value)
    if p.is_absolute():
        p = p.relative_to(out)
    elif p.parts[:2] == ("out", "Bare"):
        p = Path(*p.parts[2:])
    if not p.parts or ".." in p.parts or "\\" in value:
        raise ValueError("output outside build directory: " + value)
    return p.as_posix()


def parse_metrics(metrics, count, out, *, actual, plan_rules=None):
    edges = {}
    seen_step = set()
    summary = False
    if not metrics.exists() and count == 0:
        return edges
    with metrics.open(encoding="utf-8") as stream:
        for line in stream:
            step = json.loads(line)
            if "step_id" not in step:
                if "build_id" in step:
                    summary = True
                continue
            if step["step_id"] in seen_step or step.get("err", False):
                raise ValueError("duplicate or failed metric")
            seen_step.add(step["step_id"])
            raw = step.get("outputs")
            if not isinstance(raw, list) or not raw:
                raise ValueError("missing declared step output group")
            names = tuple(sorted(output_name(n, out) for n in raw))
            if names in edges or len(set(names)) != len(names):
                raise ValueError("ambiguous edge output group")
            if actual and not step.get("is_local", False):
                raise ValueError("small preflight edge did not execute locally")
            edges[names] = step.get("action", "")
            if plan_rules is not None and step.get('rule') in plan_rules[0]:
                plan_rules[1][canonical(names)] = [step['rule'], output_name(raw[0], out), step['action']]
    if count != len(edges) or (count and not summary):
        raise ValueError(f"incomplete Siso metrics: {len(edges)} of {count} steps")
    return edges


@contextlib.contextmanager
def preserve_ninja_log(out):
    # v1.6.5 writes .ninja_log in the output directory even on -n with an
    # isolated -state_dir/-log_dir. The runner has a single exclusive writer.
    src = out / ".ninja_log"
    with tempfile.TemporaryDirectory(prefix=".round28-plan-", dir=out) as name:
        before = Path(name) / "original"
        if src.exists() or src.is_symlink():
            if not stat.S_ISREG(src.lstat().st_mode):
                raise ValueError("unexpected Ninja log file type")
            src.rename(before)
        try:
            if before.exists():
                shutil.copy2(before, src)
            yield
        finally:
            if before.exists():
                os.replace(before, src)
            else:
                src.unlink(missing_ok=True)


def dirty_target_details(logdir, edges):
    # Keep bounded, path-only evidence. Siso's full console may contain commands.
    report = {"groups": [canonical(names) for names in islice(edges, 4)]}
    explain = logdir / "siso_explain"
    if explain.is_file():
        with explain.open("rb") as stream:
            lines = stream.read(16 * 1024).decode("utf-8", errors="replace").splitlines()
        reasons = []
        for line in lines:
            match = re.fullmatch(
                r"output ([a-zA-Z0-9_./+@=-]{1,512}) older than most recent input "
                r"([a-zA-Z0-9_./+@=-]{1,512}): out:([0-9T:+.Z-]+) in:([+0-9.hmsµn-]+)", line)
            if match:
                output, dependency, output_time, age = match.groups()
                reasons.append(dict(output=output, dependency=dependency, output_time=output_time, input_newer_by=age))
                if len(reasons) == 3:
                    break
        if reasons:
            report["mtime_reasons"] = reasons
    return report


def run(out, command, targets, *, dry, noop=False, plan_rules=None):
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="bare28-plan-") as name:
        tmp = Path(name)
        metrics = tmp / "metrics.jsonl"
        args = [*command, "-C", str(out), "-j", "2", "-metrics_json", str(metrics)]
        if dry:
            state = tmp / "state"
            state.mkdir()
            for basename in (".siso_deps", ".siso_fs_state", ".siso_fs_state.journal"):
                path = out / basename
                if path.exists():
                    if not stat.S_ISREG(path.lstat().st_mode):
                        raise ValueError("unexpected Siso state type")
                    shutil.copy2(path, state / basename)
            args.extend(["-n", "-state_dir", os.path.relpath(state, out),
                         "-log_dir", str(tmp / "logs")])
        with (tmp / "console").open("w+b") as console:
            with preserve_ninja_log(out) if (dry or noop) else contextlib.nullcontext():
                process = subprocess.run([*args, *targets], stdout=console,
                                         stderr=subprocess.STDOUT, timeout=600, check=False)
                console.seek(max(0, console.tell() - 8192))
                tail = console.read()
            counts = END.findall(tail)
            if process.returncode or len(counts) != 1 or b"Build Failed" in tail:
                raise ValueError("Siso completion/step count unavailable: "
                                 + tail[-1000:].decode(errors="replace"))
        edges = parse_metrics(metrics, int(counts[0]), out, actual=not dry, plan_rules=plan_rules)
        report = {"operation": "plan" if dry else "execute", "target": targets[0],
                  "steps": len(edges), "seconds": round(time.monotonic() - start, 2)}
        if dry and edges and targets != [TARGET]:
            report["dirty_targets"] = dirty_target_details(tmp / "logs", edges)
    print(json.dumps(report), flush=True)
    return edges


def file_record(out, name):
    path = out / name
    if path.resolve().parent != path.parent or not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError("target is not a regular file in the build tree")
    return [path.stat().st_size, sha(path)]


def frontier(edges):
    return {canonical(names) for names in edges}


def compare(parent, child, selected):
    if not child < parent or not selected <= (parent - child) or not selected:
        raise ValueError("APK frontier regressed or selected edge remains dirty")


def pick(out, command, edges):
    # A small missing object with no other dirty prerequisites. Prefer an
    # early scheduled group over an arbitrary source object from another target.
    ranked = []
    for index, group in enumerate(edges):
        for n in group:
            if n.startswith("obj/") and n.endswith(".o") and not (out / n).exists():
                ranked.append((index, n, group))
                break
    for _, target, group in sorted(ranked)[:32]:
        plan = run(out, command, [target], dry=True)
        if set(plan) == {group}:
            return target, group
    raise ValueError("no missing single-step APK ancestor found among initial objects")


def check_selected(out, command, names, expected, *, execute_check=True):
    if {n: file_record(out, n) for n in names} != expected:
        raise ValueError("selected edge bytes changed or missing")
    if run(out, command, list(names), dry=True):
        raise ValueError("restored selected edge/dependencies require work")
    if execute_check and run(out, command, list(names), dry=False, noop=True):
        raise ValueError("Siso actually executed a supposedly clean step")


def produce(out, proof, command):
    if proof.exists():
        raise ValueError("proof already exists on initial parent")
    graph_id = fixed_graph(out)
    old_files = inventory(out, proof)
    original = run(out, command, [TARGET], dry=True)
    parent = frontier(original)
    target, group = pick(out, command, original)
    executed = run(out, command, [target], dry=False)
    if set(executed) != {group}:
        raise ValueError("target executed different prerequisites or output group")
    log = (out / ".ninja_log").read_text(encoding="utf-8").splitlines()
    if not log or log[0].strip() != "# ninja log v5":
        raise ValueError("missing Ninja v5 success evidence")
    recorded = {output_name(fields[3], out) for line in log[1:]
                if len(fields := line.split("\t")) == 5}
    if not set(group) <= recorded:
        raise ValueError("Ninja and Siso disagree about executed outputs")
    records = {n: file_record(out, n) for n in group}
    check_selected(out, command, group, records)
    child = frontier(run(out, command, [TARGET], dry=True))
    compare(parent, child, {canonical(group)})
    if graph_id != fixed_graph(out):
        raise ValueError("GN graph changed while measuring")
    new_files = inventory(out, proof)
    replaced = compare_payload(old_files, new_files, set(group))
    data = {"format": FORMAT, "target": TARGET, "graph_sha256": graph_id,
            "parent_content": commitment(old_files), "child_content": commitment(new_files),
            "replacements": replaced,
            "parent_pending": sorted(parent), "successor_pending": sorted(child),
            "target_path": target, "outputs": records}
    with proof.open("x", encoding="ascii") as stream:
        json.dump(data, stream, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return {"parent_dirty": len(parent), "child_dirty": len(child), "new_target": target,
            "proof_sha256": sha(proof), "outputs": records}


def receive(out, proof, command):
    if proof.stat().st_size > 64 * 1024**2:
        raise ValueError("unbounded graph proof")
    data = json.loads(proof.read_text(encoding="ascii"))
    if (data["format"] != FORMAT or data["target"] != TARGET
            or data["graph_sha256"] != fixed_graph(out)):
        raise ValueError("graph provenance changed")
    records = data["outputs"]
    group = tuple(sorted(records))
    if not group or data["target_path"] not in group or any(output_name(n, out) != n for n in group):
        raise ValueError("invalid recorded group")
    check_selected(out, command, group, records, execute_check=False)
    observed = frontier(run(out, command, [TARGET], dry=True))
    if observed != set(data["successor_pending"]):
        raise ValueError("independent restore has a different APK plan")
    compare(set(data["parent_pending"]), observed, {canonical(group)})
    if commitment(inventory(out, proof)) != data["child_content"]:
        raise ValueError("Independent restore changed retained output contents")
    return {"parent_dirty": len(data["parent_pending"]), "restored_dirty": len(observed),
            "restored_target": data["target_path"], "proof_sha256": sha(proof)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["produce", "receive"])
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    args = parser.parse_args()
    result = {"produce": produce, "receive": receive}[args.action](
        args.out.resolve(), args.proof, ["autoninja"])
    print(json.dumps(result, sort_keys=True))
