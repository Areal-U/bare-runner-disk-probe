"""Carry the reviewed launcher migration across this one production run's checkpoints."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re

from angle_restore import S1_SHA, S1_PROOF_SHA
from graph import sha
from label_resource_trial import (OPTIMIZED, RAW, OPTIMIZED_SHA, RAW_SHA, PATHMAP_BYTES,
                                 PATHMAP_GROUP_ID, PATHMAP_OUTPUT, PATHMAP_SHA, PATHMAP_SOURCE)
from launcher_labels import verify_labels
from personal_label import LABEL, PERSONAL_SHA, UPSTREAM_SHA, prepare
from retained import commitment
from segment_graph import load, write_record


ORIGINAL_CONTENT = {"files": 324262, "sha256": "b0806c54059d411288cd9c33ae68547be38758277f55552899630ed47528d992"}
PENDING_SHA = "0f475e82f12516553f7e6d7278be9fcca3a5a5b87cbc7ab2ad5689faa1dcd5fd"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def valid_pathmap(record):
    return (isinstance(record, dict) and type(record.get("executed")) is bool and
            type(record.get("bytes")) is int and
            record == dict(group=PATHMAP_GROUP_ID, source=PATHMAP_SOURCE, output=PATHMAP_OUTPUT,
                           bytes=PATHMAP_BYTES, sha256=PATHMAP_SHA, executed=record["executed"]))


def certificate(directory):
    path = directory / "label_trial_certificate.json"
    cert = load(path)
    require(cert.get("status") == "accepted" and cert.get("source_sha256") == S1_SHA and
            cert.get("pending_sha256") == PENDING_SHA and valid_pathmap(cert.get("pathmap_copy")) and
            type(cert.get("trial_run_id")) is int and cert["trial_run_id"] > 0 and
            cert["trial_run_id"] not in (45771045621, 45841492691) and
            cert.get("trial_attempt") == 1 and re.fullmatch("[0-9a-f]{40}", cert.get("trial_head", "")) and
            all(re.fullmatch("[0-9a-f]{64}", cert.get(k, "")) for k in ("raw_sha256", "optimized_sha256")) and
            cert["raw_sha256"] != RAW_SHA and cert["optimized_sha256"] != OPTIMIZED_SHA,
            "The independent resource trial has no reviewed acceptance for this production version")
    helpers = ("graph.py", "launcher_labels.py", "label_resource_trial.py", "personal_label.py")
    require(cert.get("helpers") == {name: sha(directory / name) for name in helpers},
            "Loaded label verifier code differs from the reviewed independent trial")
    return cert, sha(path)


def job_identity(env):
    run_id, slot = int(env["GITHUB_RUN_ID"]), int(env["SEGMENT_ORDINAL"])
    require(run_id > 0 and run_id not in (45771045621, 45841492691) and
            2 <= slot <= 13 and re.fullmatch("[0-9a-f]{40}", env["GITHUB_SHA"]),
            "Unexpected production build lineage")
    return run_id, slot, env["GITHUB_SHA"]


def check_material(out, cert):
    require(sha(out / RAW) == cert["raw_sha256"] and sha(out / OPTIMIZED) == cert["optimized_sha256"],
            "Restored resource APKs differ from the independently accepted migration")
    for name in (PATHMAP_SOURCE, PATHMAP_OUTPUT):
        path = out / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == PATHMAP_BYTES and
                sha(path) == PATHMAP_SHA, "Restored resource path map differs from the fixed S1 bytes")
    aapt2 = out.parent.parent / "third_party/android_sdk/public/build-tools/37.0.0/aapt2"
    for target in (RAW, OPTIMIZED):
        verify_labels(aapt2, out / target)


def manifest_entry(out, expected):
    # General input timestamp restore deliberately skips changed members. Require
    # this one material source entry to agree and be unique for Personal.
    source = str(LABEL)
    matches = []
    with gzip.open(out / "checkpoint-inputs.jsonl.gz", "rb") as stream:
        header = json.loads(next(stream))
        require(header.get("roots", {}).get("src") == "/work/chromium/src", "Different checkpoint input roots")
        for line in stream:
            item = json.loads(line)
            if item.get("root") == "src" and item.get("path") == source:
                matches.append(item)
    require(len(matches) == 1 and matches[0].get("type") == "file" and
            matches[0].get("sha256") == expected and type(matches[0].get("mtime_ns")) is int,
            "Stored input manifest does not attest the corrected source")
    return matches[0]


def verify_source_mtime(out):
    entry = manifest_entry(out, PERSONAL_SHA)
    material = out.parent.parent / LABEL
    require(sha(material) == PERSONAL_SHA and material.stat().st_mtime_ns == entry["mtime_ns"],
            "Personal source timestamp/content was skipped or changed during input restoration")


def activate(out, exchange, cert, cert_sha, run, head):
    """Atomically select the checked new baseline; preserve original bytes by hard link."""
    check_material(out, cert)
    folder = exchange / "checkpoint"
    current = folder / "segment-before.json"
    pending = folder / "segment-after-label.json"
    source = load(current, 512 * 1024**2)
    proposed = load(pending, 512 * 1024**2)
    result = load(folder / "label-resource-migration.json")
    origin = out / "checkpoint-segment-frontier.json"
    recorded = load(origin)
    unchanged_keys = ("parent_sha256", "format", "graph", "target", "planned_groups")
    require(all(source[k] == proposed[k] for k in unchanged_keys) and
            source["parent_sha256"] == S1_SHA and sha(origin) == S1_PROOF_SHA and
            set(source["planned_groups"]) == set(recorded["after"]) and len(recorded["after"]) == 1911 and
            result.get("mode") == "prepare" and result["parent_sha256"] == S1_SHA and
            result["remaining"] == result["old_pending"] == 1911 and result["additional_pending"] == [] and
            result["source"]["before"] == UPSTREAM_SHA and result["source"]["after"] == PERSONAL_SHA and
            result["resource_sha256"] == cert["raw_sha256"] and result["optimized_sha256"] == cert["optimized_sha256"] and
            commitment(source["files"]) == recorded["child_content"] and
            commitment(proposed["files"]) == result["retained"], "Unverified migration baseline")
    lineage = dict(version=1, run=run, head=head, original=S1_SHA, certificate_sha256=cert_sha,
                   trial=cert["trial_run_id"], old_content=recorded["child_content"], new_content=result["retained"],
                   original_baseline_sha256=sha(current), new_baseline_sha256=sha(pending),
                   evidence_sha256=sha(folder / "label-resource-migration.json"), evidence=result)
    match_lineage(lineage, cert, cert_sha, run, head)
    write_record(folder / "label-lineage.json", lineage)
    (folder / "segment-before-original-s1.json").hardlink_to(current)
    os.replace(pending, current)


def match_lineage(lineage, cert, cert_sha, run, head):
    expected = dict(version=1, run=run, head=head, original=S1_SHA, certificate_sha256=cert_sha,
                    trial=cert["trial_run_id"])
    evidence = lineage.get("evidence", {}) if isinstance(lineage, dict) else {}
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("ascii")
    require(isinstance(lineage, dict) and type(evidence) is dict and
            hashlib.sha256(encoded).hexdigest() == lineage.get("evidence_sha256") and
            evidence.get("parent_sha256") == S1_SHA and evidence.get("old_pending") == evidence.get("remaining") == 1911 and
            evidence.get("pending_sha256") == cert.get("pending_sha256") == PENDING_SHA and
            valid_pathmap(cert.get("pathmap_copy")) and valid_pathmap(evidence.get("pathmap_copy")) and
            evidence.get("resource_sha256") == cert["raw_sha256"] and
            evidence.get("optimized_sha256") == cert["optimized_sha256"] and
            evidence.get("retained") == lineage.get("new_content") and lineage.get("old_content") == ORIGINAL_CONTENT and
            all(lineage.get(k) == v for k, v in expected.items()) and
            lineage["old_content"] != lineage["new_content"] and
            all(re.fullmatch("[0-9a-f]{64}", lineage.get(k, "")) for k in
                ("original_baseline_sha256", "new_baseline_sha256", "evidence_sha256")),
            "Wrong or absent migration lineage in the authenticated parent")


def restore_source(out, exchange, cert, cert_sha, run, slot, head):
    # Runner already authenticated the full parent archive by its exact manifest and SHA.
    seal = load(out / "checkpoint-source-verification.json").get("personal_label", {})
    require(seal.get("producer_slot") == slot - 1 and slot > 2, "Wrong producer slot for corrected source")
    lineage = seal.get("lineage")
    match_lineage(lineage, cert, cert_sha, run, head)
    check_material(out, cert)
    manifest_entry(out, PERSONAL_SHA)
    value = prepare(out.parent.parent, apply=True)
    require((value["before"], value["after"]) == (UPSTREAM_SHA, PERSONAL_SHA),
            "New receiver checkout did not make the pinned source transition")
    write_record(exchange / "checkpoint/label-lineage.json", lineage)


def record_successor(exchange, cert, cert_sha, run, slot, head):
    folder = exchange / "checkpoint"
    lineage = load(folder / "label-lineage.json")
    match_lineage(lineage, cert, cert_sha, run, head)
    receipt = folder / "provenance-check.json"
    existing = load(receipt)
    existing["personal_label"] = {"producer_slot": slot, "lineage": lineage}
    write_record(receipt, existing)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["gate", "activate", "restore-source", "record-successor", "check-source-manifest"])
    parser.add_argument("--out", type=Path, default=Path("out/Bare"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    run, slot, head = job_identity(os.environ)
    accepted, digest = certificate(root)
    if args.operation == "activate":
        require(slot == 2, "Only the fixed first resumed slot changes the baseline")
        activate(args.out.resolve(), root, accepted, digest, run, head)
    elif args.operation == "restore-source":
        restore_source(args.out.resolve(), root, accepted, digest, run, slot, head)
    elif args.operation == "check-source-manifest":
        verify_source_mtime(args.out.resolve())
    elif args.operation == "record-successor":
        record_successor(root, accepted, digest, run, slot, head)
