"""Migrate the verified R30 S1 launcher resource before the remaining APK work."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import time

from graph import canonical, file_record, run, sha
from retained import ANDROID_RULES_SHA256, commitment, compare_payload, inventory
from segment_graph import load, plan, write_record
from angle_restore import GRAPH, S1_PROOF_SHA, S1_SHA

RAW = "obj/chrome/android/chrome_public_apk.ap_"
OPTIMIZED = "obj/chrome/android/chrome_public_apk.optimized.ap_"
APK = "apks/ChromePublic.apk"
OPTIMIZED_SHA = "a01ff002507636f864c6fc62b4b153f5fec8e8fa3436af79a012098b659420db"
SOURCE = "../../chrome/android/java/res_chromium_base/values/bare_launcher_label.xml"
RAW_SHA = "b319b80fae9723d99a5d3441a4e6bcb778ea35e32b63f203cb3a289aa8baa40e"
PERSONAL_RESOURCE_SHA = {
    RAW: "a664cc5b6e46e862d247e3aaf97e4a2784b8d5a2c74555c4a609d0bb4086498d",
    OPTIMIZED: "23041a04f9719bd42727b4c7a4f9c15cc011c81f5ccddb5aabc21881fa56953f",
}
JAVAC = "obj/chrome/android/chrome_public_apk.javac.jar"
JAVAC_GROUP = (JAVAC, JAVAC + ".info")
JAVAC_STAMP = JAVAC + ".md5.stamp"
JAVAC_ACTION = "__chrome_android_chrome_public_apk__compile_java___build_toolchain_android_android_clang_arm64__rule"
JAVAC_RULE = "android/compile_java"
MANIFESTS = {
    "toolchain.ninja": "02f0e819a46bd2b601d5dbb3bd15c98cf12244b6e55fe41f37c9ac0d0b4f9896",
    "build.ninja": "34759cff04ca63a00da8891250cde7aee91dcefc11bcf407c41b69d74539192e",
}


def build_edges(manifests):
    for path in manifests:
        with path.open() as stream:
            for line in stream:
                if line.startswith("build "):
                    lhs, rhs = line[6:].split(": ", 1)
                    # Only content dependencies propagate a change in this input.
                    rule, *dependencies = rhs.partition(" || ")[0].split()
                    yield tuple(sorted(lhs.split())), rule, dependencies


def closure(neighbours, start):
    pending, seen = [start], set()
    while pending:
        item = pending.pop()
        if item not in seen:
            seen.add(item)
            pending.extend(neighbours[item] - seen)
    return seen


def permitted_actions(out):
    """Compute both dependency intersections from the two byte-pinned GN manifests."""
    paths = [out / name for name in MANIFESTS]
    if any(sha(path) != MANIFESTS[path.name] for path in paths):
        raise ValueError("Unreviewed GN manifests in the R30 resource migration")
    by_output, groups, rules = {}, [], []
    for names, rule, _ in build_edges(paths):
        index = len(groups)
        groups.append(names)
        rules.append(rule)
        by_output.update((name, index) for name in names)
    forward, reverse = defaultdict(set), defaultdict(set)
    for names, _, dependencies in build_edges(paths):
        target = by_output[names[0]]
        upstream = {by_output[name] for name in dependencies if name in by_output}
        if SOURCE in dependencies:
            upstream.add(-1)
        reverse[target].update(upstream)
        for source in upstream:
            forward[source].add(target)
    changed = closure(forward, -1)

    def through(target):
        relevant = changed & closure(reverse, by_output[target])
        return {canonical(groups[i]) for i in relevant if i >= 0 and rules[i] != "phony"}

    raw, optimized, apk = through(RAW), through(OPTIMIZED), through(APK)
    if ([len(raw), len(optimized), len(apk)] != [154, 1028, 1029]
            or not raw <= optimized <= apk):
        raise ValueError("Unexpected action scope in the pinned build graph")
    return raw, optimized, apk


def check_plan(old, current, allowed):
    missing, foreign = old - current, current - old - allowed
    if missing or foreign:
        raise ValueError(f"Migration lost {len(missing)} old pending groups or added "
                         f"{len(foreign)} unrelated groups: {sorted(missing | foreign)[:8]}")


def verify_s1_javac_stamp(out, proof):
    # The incoming proof was authenticated before this call. It binds the
    # sidecar to this GN group, command and exact original bytes.
    claim = proof["runtime_stamps"][canonical(JAVAC_GROUP)]
    if (claim != dict(primary=JAVAC, rule=JAVAC_RULE, action=JAVAC_ACTION,
                      fileargs={}, files={JAVAC_STAMP: file_record(out, JAVAC_STAMP)}) or
            sha(out.parent.parent / "build/config/siso/android.star") != ANDROID_RULES_SHA256):
        raise ValueError("Missing or changed authenticated Java compiler stamp or Siso handler")


def declared_groups(executed, details):
    groups = set()
    for names, action in executed.items():
        declared = names
        if JAVAC in names or JAVAC_STAMP in names:
            if (names != (*JAVAC_GROUP, JAVAC_STAMP) or action != JAVAC_ACTION or
                    details.get(canonical(names)) != [JAVAC_RULE, JAVAC, JAVAC_ACTION]):
                raise ValueError(f"Unexpected Java compiler metric: {action}, {names!r}")
            declared = JAVAC_GROUP
        groups.add(declared)
    return groups


def relink(out, command, target, permitted, old, *, labels=None):
    expected = run(out, command, [target], dry=True)
    ids = {canonical(group) for group in expected}
    if not ids or not ids <= permitted or ids & old:
        raise ValueError(f"{target} plan was empty, unexpected or required original APK work")
    # Real old S1 timings: raw link 42.229s, R8 329.013s and optimization 5.321s.
    # Both commands are also bounded by the outer 30-minute step timeout.
    print("BARE_LABEL_RELINK " + json.dumps({"target": target, "planned": len(ids)}), flush=True)
    old_sha = sha(out / target) if target in PERSONAL_RESOURCE_SHA else None
    details = {}
    executed = run(out, command, [target], dry=False, isolated_logs=True,
                   plan_rules=({JAVAC_RULE}, details), timeout_seconds=1080 if target == OPTIMIZED else 600)
    new_sha = sha(out / target) if target in PERSONAL_RESOURCE_SHA else None
    examples = list(executed) if target == OPTIMIZED else list(executed)[:2]
    print("BARE_LABEL_EXECUTION " + json.dumps(dict(target=target, before=old_sha, after=new_sha,
          steps=len(executed), metrics=[{"action": executed[g], "outputs": g} for g in examples[:8]])), flush=True)
    if target in PERSONAL_RESOURCE_SHA:
        from launcher_labels import verify_labels
        aapt2 = out.parent.parent / "third_party/android_sdk/public/build-tools/37.0.0/aapt2"
        observed_labels = verify_labels(aapt2, out / target)
        print("BARE_LABEL_VERIFIED " + json.dumps(dict(target=target, labels=observed_labels)), flush=True)
        if labels is not None:
            labels[target] = observed_labels
        if new_sha != PERSONAL_RESOURCE_SHA[target]:
            raise ValueError(f"{target}: expected Personal SHA {PERSONAL_RESOURCE_SHA[target]}, got {new_sha}")
    declared = declared_groups(executed, details)
    actual = {canonical(group) for group in declared}
    # Siso -n cannot foresee a restat producer changing one of several outputs.
    # A downstream action may run only after that producer has actually finished.
    outside = actual - permitted
    overlap = actual & old
    linked = any(target in group for group in declared)
    if not actual or outside or overlap or not linked:
        samples = [group for group in sorted(declared) if canonical(group) in outside | overlap][:5]
        raise ValueError(f"{target}: executed={len(actual)}, outside={len(outside)}, "
                         f"original_pending={len(overlap)}, linked={linked}, unexpected={samples!r}")
    if any(JAVAC_STAMP in group for group in executed):
        stamp = file_record(out, JAVAC_STAMP)
        if not stamp[0]:
            raise ValueError("Java compiler reported an empty stamp")
        print("BARE_LABEL_JAVAC_STAMP " + json.dumps(dict(bytes=stamp[0], sha256=stamp[1])), flush=True)
    if run(out, command, [target], dry=True):
        raise ValueError(f"{target} remained dirty after execution")
    return executed


def inventory_mismatch(parent, current, authorized):
    # Commit every discrepancy in path order, but keep only three sample paths
    # per class in the public log. A symlink record stores no length.
    counts = {"missing": 0, "changed": 0, "added": 0}
    samples = {kind: [] for kind in counts}
    digest = hashlib.sha256()
    for name in sorted(parent.keys() | current.keys()):
        before, after = parent.get(name), current.get(name)
        if before == after or (after is not None and name in authorized):
            continue
        kind = "missing" if after is None else "added" if before is None else "changed"
        counts[kind] += 1
        row = json.dumps([kind, name, before, after], ensure_ascii=True, separators=(",", ":"))
        digest.update(row.encode("ascii") + b"\n")
        if len(samples[kind]) < 3:
            display = name if len(name) <= 240 else name[:118] + "..." + name[-118:]
            # f:<execute bits>:<bytes>:<SHA256>, l:<target SHA256>, or null.
            samples[kind].append(dict(path=display, old=before, new=after))
    return dict(counts=counts, sha256=digest.hexdigest(), samples=samples)


def verify_resource_inventory(parent, current, authorized):
    try:
        replacements = compare_payload(parent, current, authorized)
        if RAW not in replacements or OPTIMIZED not in replacements:
            raise ValueError("Resource APK did not change")
        added_files = current.keys() - parent.keys()
        if not added_files <= authorized:
            raise ValueError("Unattributed new resource files: " + str(sorted(added_files - authorized)[:8]))
    except ValueError:
        print("BARE_LABEL_INVENTORY_MISMATCH " + json.dumps(inventory_mismatch(parent, current, authorized),
                                                          sort_keys=True), flush=True)
        raise
    return replacements, added_files


def migrate(out, baseline, mode):
    from personal_label import prepare, UPSTREAM_SHA, PERSONAL_SHA
    from contract_gate import verify_pending_contract

    src = out.parent.parent
    parent_proof = out / "checkpoint-segment-frontier.json"
    original = load(baseline, 512 * 1024**2)
    if (sha(parent_proof) != S1_PROOF_SHA or original["parent_sha256"] != S1_SHA
            or original["graph"] != GRAPH or original["target"] != "chrome_public_apk"):
        raise ValueError("Only the positively verified R30 S1 can enter the label migration")
    proof = load(parent_proof)
    old = set(original["planned_groups"])
    if (len(old) != 1911 or old != set(proof["after"]) or
            commitment(original["files"]) != proof["child_content"] or sha(out / RAW) != RAW_SHA
            or sha(out / OPTIMIZED) != OPTIMIZED_SHA):
        raise ValueError("The R30 S1 baseline or its linked resources differ")
    verify_s1_javac_stamp(out, proof)
    raw_scope, optimized_scope, apk_scope = permitted_actions(out)
    command = ["autoninja"]
    if run(out, command, [RAW, OPTIMIZED], dry=True):
        raise ValueError("The original S1 resource target was already dirty")
    transition = prepare(src, apply=True)
    if (transition["before"], transition["after"]) != (UPSTREAM_SHA, PERSONAL_SHA):
        raise ValueError("Did not apply the exact old-to-new source bytes")

    changed_plan = set(plan(out, command))
    check_plan(old, changed_plan, apk_scope)
    labels = {}
    executed = relink(out, command, RAW, raw_scope, old, labels=labels)
    # The final apkbuilder consumes optimized.ap_, not the intermediate raw file.
    optimized_work = relink(out, command, OPTIMIZED, optimized_scope, old, labels=labels)
    if set(executed) & set(optimized_work):
        raise ValueError("Optimizing resources repeated a previously finished raw action")
    executed.update(optimized_work)
    rules = {}
    remaining = plan(out, command, rules)
    check_plan(old, set(remaining), apk_scope)
    if set(remaining) != old:
        raise ValueError("Final resource migration left additional or missing APK work: " +
                         str(sorted(set(remaining) ^ old)[:8]))

    # The real generators account for every replacement. Chromium prepare_resources
    # stores MD5 input-state sidecars beside its declared resource ZIP outputs.
    authorized = {name for group in executed for name in group}
    authorized.update(name + ".md5.stamp" for name in tuple(authorized) if name.endswith(".resources.zip"))
    current = inventory(out)
    replacements, added_files = verify_resource_inventory(original["files"], current, authorized)

    verify_pending_contract(out, remaining, rules, parent_sha=S1_SHA, graph=GRAPH)
    report = {"mode": mode, "parent_sha256": S1_SHA, "old_pending": len(old),
              "before_resource_rebuild": len(changed_plan), "remaining": len(remaining),
              "resource_executed": len(executed), "replacements": replacements, "new_files": sorted(added_files),
              "source": transition, "resource_sha256": sha(out / RAW), "raw_labels": labels[RAW],
              "optimized_sha256": sha(out / OPTIMIZED), "optimized_labels": labels[OPTIMIZED],
              "additional_pending": sorted(set(remaining) - old), "retained": commitment(current)}
    write_record(baseline.with_name("label-resource-migration.json"), report)
    if mode == "prepare":
        # Publish the new baseline only after complete validation. The original S1
        # proof stays unchanged; future retirements use new invocation's metrics.
        original.update(files=current, planned_groups=remaining, stamp_rules=rules, began_ns=time.time_ns())
        write_record(baseline.with_name("segment-after-label.json"), original)
    print("BARE_LABEL_MIGRATION " + json.dumps({k: v for k, v in report.items()
          if k != "additional_pending"}, sort_keys=True), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--mode", choices=("trial", "prepare"), required=True)
    args = parser.parse_args()
    migrate(args.out.resolve(), args.baseline.resolve(), args.mode)
