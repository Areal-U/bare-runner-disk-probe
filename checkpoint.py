#!/usr/bin/env python3
"""Validate, identify and verify the bounded Bare build checkpoint."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile


ROOTS = {
    "src": Path("/work/chromium/src"),
    "depot_tools": Path("/home/builder/depot_tools"),
}
FORMAT = "bare-input-mtimes"
VERSION = 1
CHECKPOINT_VERSION = 2
EVIDENCE_FORMAT = "bare-completed-objects"
CONTINUATION_FORMAT = "bare-checkpoint-continuation"
PROVENANCE_FORMAT = "bare-checkpoint-provenance"
CITY_OBJECT = "out/Bare/obj/base/third_party/cityhash/cityhash/city.o"
CONTINUATION_RECORD = "out/Bare/checkpoint-continuation.json"
CONTINUATION_TRIAL = "out/Bare/checkpoint-trial-restore.json"
PROVENANCE_RECORD = "out/Bare/checkpoint-provenance.json"
APK_PATH = "out/Bare/apks/ChromePublic.apk"
CONTINUATION_TRIAL_LIMIT = 16 * 1024 ** 2
SCALE_CONTINUATION_TRIAL_LIMIT = 64 * 1024 ** 2
LARGE_CONTINUATION_TRIAL_LIMIT = 128 * 1024 ** 2
SCALE_ARCHIVE_BYTES = 11 * 1024 ** 3 // 4
SCALE_UNPACKED_BYTES = 3 * 1024 ** 3
SCALE_ARCHIVE_MEMBERS = 150_000
LARGE_UNPACKED_BYTES = 7 * 1024 ** 3
LARGE_ARCHIVE_MEMBERS = 320_000
CI_FILES = ("checkpoint.py", "build_trial.py", "bare-arm64-probe.yml",
            "bare-checkpoint-transfer.yml")
TOOL_FILES = (
    "third_party/llvm-build/Release+Asserts/bin/clang",
    "third_party/llvm-build/Release+Asserts/bin/ld.lld",
    "third_party/llvm-build/Release+Asserts/bin/llvm-ar",
    "buildtools/linux64/gn",
    "third_party/siso/cipd/siso",
    "third_party/siso/siso",
    "buildtools/linux64/siso",
    "third_party/rust-toolchain/bin/rustc",
)
SYSTEM_PACKAGES = ("libc6", "libc6-dev", "libstdc++6", "libgcc-s1",
                   "python3", "python3-minimal", "binutils")
LEGACY_INPUT_PATH_REPAIR = {
    "ci_revision": "e1c837e3456e9ee5d9957eebefb6309f44b90670",
    "identity_sha256": "fc3b4584696b8239bfc3b04db9490e3c0b722b62b81c54c772b96f27543a8896",
    "ci_files": {
        "checkpoint.py": "294daf9bb7af482ee46b0775012b479cc2724f9ae18b179bfbcda75ba0df0cb7",
        "build_trial.py": "fea6686cee8017b319b2874ee0eec8051b09ea9cf1c6a9ba06178f5403e32d34",
        "bare-arm64-probe.yml": "c2e0026278400d5399e29390eafdbc7790c19a155a27a106dc569cc5e1fe128e",
        "bare-checkpoint-transfer.yml": "d56a0ade1158469032f839b185c4dbb69fbd124fde10aa0980ba147e31056ec9",
    },
}
SCALE_PREDECESSOR = {
    "ci_revision": "40b60fcac3b34d96a3e450848d2374d3b921bf5f",
    "identity_sha256": "87c8946d20f1f0f97d494c21291b1bb1865772084f0e1a09577414007c3ae170",
    "ci_files": {
        "checkpoint.py": "caf87200558fc833cc80f6372524f2881d74ee0a0a9309a710e9fd06ef780687",
        "build_trial.py": "aea2624bcb392f52241e4c9afb179f87268fa3f4e064a519f9f64fe08813f2fc",
        "bare-arm64-probe.yml": "7bccd928b2730cd9de020ff41424b8c488b40f0ea9388c07068b6c8ba28f9dd4",
        "bare-checkpoint-transfer.yml": "a1c5de31084e0f420ea02cbbb85a03e9ac832f0a0e05e2cf375e27e3c93f25f2",
    },
}
LARGER_PREDECESSOR = {
    "ci_revision": "5d3f7993c975630d4abf3efe2925aee79e51dc39",
    "identity_sha256": "5a1826fb351f149a8a4132fb21d80acba90d937131ce211c8c0b13d79970a966",
    "ci_files": {
        "checkpoint.py": "fd46f6a6ca05625e24ea4d6d8e4477a98c92e98e0c37ba28417a2e14907dfeb1",
        "build_trial.py": "24220044336f7770234b6af7d957b5e8ce08a8deb9b6b87445c335686067fd04",
        "bare-arm64-probe.yml": "c632f5ee7e99a6ebf078b593d32c875dcf0b118e93a0433213314bb27a85df5d",
        "bare-checkpoint-transfer.yml": "8ef66d0965fa6880b60dce6c8eeeab36df3035867768ffae5665607f73c57fc5",
    },
}


def kind(info):
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISLNK(info.st_mode):
        return "symlink"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    raise ValueError("An input has an unsupported file type")


def ignored(name, relative, root_name):
    return (name in {".git", "__pycache__"} or name.endswith(".pyc")
            or (root_name == "src" and relative == PurePosixPath("out")))


def child_entries(path, relative, root_name):
    with os.scandir(path) as entries:
        children = [(entry.name, kind(entry.stat(follow_symlinks=False)))
                    for entry in entries
                    if not ignored(entry.name, relative / entry.name, root_name)]
    return sorted(children)


def directory_hash(path, relative, root_name):
    data = json.dumps(child_entries(path, relative, root_name), ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Expected a regular input file")
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_mode) != (
            after.st_size, after.st_mtime_ns, after.st_mode):
        raise ValueError("An input changed while its content was being read")
    return digest.hexdigest()


def check_roots(roots):
    for root in roots.values():
        if not root.is_dir() or root.resolve() != root:
            raise ValueError("Expected the fixed, non-symlink input roots")


def describe(path, root_name, relative):
    before = path.lstat()
    entry = {"root": root_name, "path": relative.as_posix(),
             "type": kind(before), "mode": stat.S_IMODE(before.st_mode),
             "mtime_ns": before.st_mtime_ns}
    if entry["type"] == "file":
        entry.update(size=before.st_size, sha256=file_hash(path))
    elif entry["type"] == "symlink":
        entry["target"] = os.readlink(path)
    else:
        entry["children_sha256"] = directory_hash(path, relative, root_name)
    after = path.lstat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_mode) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_mode):
        raise ValueError("An input changed while its metadata was being recorded")
    return entry


def walk_inputs(root_name, root):
    pending = [PurePosixPath(".")]
    while pending:
        relative = pending.pop()
        path = root / relative
        entry = describe(path, root_name, relative)
        yield entry
        if entry["type"] == "directory":
            for name, _ in reversed(child_entries(path, relative, root_name)):
                pending.append(relative / name)


def record_inputs(manifest, roots=ROOTS):
    check_roots(roots)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=manifest.name + ".", dir=manifest.parent)
    os.close(descriptor)
    count = 0
    try:
        with gzip.open(temporary, "wt", encoding="utf-8") as stream:
            header = {"format": FORMAT, "version": VERSION,
                      "roots": {name: str(path) for name, path in roots.items()}}
            stream.write(json.dumps(header) + "\n")
            for root_name, root in roots.items():
                for entry in walk_inputs(root_name, root):
                    stream.write(json.dumps(entry, separators=(",", ":")) + "\n")
                    count += 1
        os.replace(temporary, manifest)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"recorded": count, "manifest_bytes": manifest.stat().st_size}


def safe_relative(value):
    if (not isinstance(value, str) or not value or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)):
        raise ValueError("Invalid checkpoint-relative path")
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != value:
        raise ValueError("Unsafe checkpoint-relative path")
    return relative


def input_relative(value):
    """A canonical POSIX source name, never a shell target or archive member.

    Linux input trees may contain literal backslashes and control characters.
    They are ordinary filename characters here; only '/' separates components.
    Keep the stricter safe_relative policy for command targets and archives.
    """
    diagnostic = repr(value)[:160]
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("Invalid checkpoint input path: " + diagnostic)
    relative = PurePosixPath(value)
    if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != value:
        raise ValueError("Unsafe checkpoint input path: " + diagnostic)
    return relative


def validate_entry(entry, roots):
    if not isinstance(entry, dict) or entry.get("root") not in roots:
        raise ValueError("Unknown checkpoint input root")
    relative = input_relative(entry.get("path"))
    if any(part in {".git", "__pycache__"} for part in relative.parts):
        raise ValueError("Excluded directory in checkpoint input")
    if relative.parts and ((entry["root"] == "src" and relative.parts[0] == "out")
                           or relative.name.endswith(".pyc")):
        raise ValueError("Excluded path in checkpoint input")
    if entry.get("type") not in {"file", "symlink", "directory"}:
        raise ValueError("Invalid checkpoint input type")
    for field in ("mode", "mtime_ns"):
        if type(entry.get(field)) is not int or entry[field] < 0:
            raise ValueError("Invalid checkpoint input metadata")
    if entry["mode"] > 0o7777:
        raise ValueError("Invalid checkpoint input mode")
    if entry["type"] == "file":
        if type(entry.get("size")) is not int or entry["size"] < 0:
            raise ValueError("Invalid checkpoint file size")
        if not re.fullmatch("[0-9a-f]{64}", str(entry.get("sha256", ""))):
            raise ValueError("Invalid checkpoint content hash")
    elif entry["type"] == "symlink":
        if not isinstance(entry.get("target"), str) or "\x00" in entry["target"]:
            raise ValueError("Invalid checkpoint symlink target")
    elif not re.fullmatch("[0-9a-f]{64}", str(entry.get("children_sha256", ""))):
        raise ValueError("Invalid checkpoint directory hash")
    return relative


def read_entries(manifest, roots):
    with gzip.open(manifest, "rt", encoding="utf-8") as stream:
        header = json.loads(next(stream))
        expected = {"format": FORMAT, "version": VERSION,
                    "roots": {name: str(path) for name, path in roots.items()}}
        if header != expected:
            raise ValueError("Checkpoint format or input roots differ")
        for line in stream:
            entry = json.loads(line)
            validate_entry(entry, roots)
            yield entry


def inspect_input_paths(archive_path, max_records=2_000_000,
                        max_line_bytes=64 * 1024, max_decompressed_bytes=1024 ** 3,
                        *, max_archive_bytes=1024 ** 3,
                        max_unpacked_bytes=2 * 1024 ** 3, max_members=100_000):
    """Read bounded input-path diagnostics without extracting or changing files.

    The workflow separately validates the complete archive first. This command
    also bounds its own outer scan and the nested compressed JSONL manifest.
    """
    if min(max_records, max_line_bytes, max_decompressed_bytes,
           max_archive_bytes, max_unpacked_bytes, max_members) <= 0:
        raise ValueError("Input inspection limits must be positive")
    if archive_path.stat().st_size > max_archive_bytes:
        raise ValueError("Checkpoint archive exceeds the bounded transfer limit")
    expected_header = {"format": FORMAT, "version": VERSION,
                       "roots": {name: str(path) for name, path in ROOTS.items()}}
    expected_name = "out/Bare/checkpoint-inputs.jsonl.gz"
    result = None
    members = 0
    unpacked_bytes = 0
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            members += 1
            unpacked_bytes += member.size
            if members > max_members or member.size < 0 or unpacked_bytes > max_unpacked_bytes:
                raise ValueError("Checkpoint archive exceeds the bounded extraction limit")
            if archive_relative(member.name).as_posix() != expected_name:
                continue
            if result is not None or not member.isfile():
                raise ValueError("Expected one regular checkpoint input manifest")
            count = 0
            unusual = 0
            total = 0
            examples = []
            with archive.extractfile(member) as compressed, gzip.GzipFile(fileobj=compressed) as stream:
                while True:
                    line = stream.readline(max_line_bytes + 1)
                    if not line:
                        break
                    total += len(line)
                    if len(line) > max_line_bytes or total > max_decompressed_bytes:
                        raise ValueError("Checkpoint input manifest exceeds the bounded inspection limit")
                    entry = json.loads(line)
                    if count == 0:
                        if entry != expected_header:
                            raise ValueError("Checkpoint format or input roots differ")
                    else:
                        if count > max_records:
                            raise ValueError("Checkpoint input manifest has too many records")
                        validate_entry(entry, ROOTS)
                        try:
                            safe_relative(entry["path"])
                        except ValueError:
                            unusual += 1
                            if len(examples) < 10:
                                examples.append({"root": entry["root"], "path": entry["path"]})
                    count += 1
            if count == 0:
                raise ValueError("Checkpoint input manifest is empty")
            result = {"records": count - 1, "manifest_uncompressed_bytes": total,
                      "paths_rejected_by_strict_validator": unusual, "examples": examples}
    if result is None:
        raise ValueError("Checkpoint input manifest is missing")
    return result


def path_without_symlink_parents(root, relative):
    path = root
    for part in relative.parts[:-1]:
        path /= part
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError("Checkpoint input parent is not a regular directory")
    return root / relative


def restore_inputs(manifest, roots=ROOTS):
    check_roots(roots)
    # Validate every record before changing any timestamps.
    for _ in read_entries(manifest, roots):
        pass
    restored = 0
    skipped = 0
    skipped_examples = []
    directories = []
    blocked = set()
    for entry in read_entries(manifest, roots):
        relative = input_relative(entry["path"])
        if entry["type"] == "directory":
            directories.append(entry)
            continue
        try:
            path = path_without_symlink_parents(roots[entry["root"]], relative)
            current = describe(path, entry["root"], relative)
            if {key: value for key, value in current.items() if key != "mtime_ns"} != {
                    key: value for key, value in entry.items() if key != "mtime_ns"}:
                raise ValueError("Checkpoint input content or mode differs")
            info = path.lstat()
            os.utime(path, ns=(info.st_atime_ns, entry["mtime_ns"]), follow_symlinks=False)
            restored += 1
        except (OSError, ValueError) as error:
            skipped += 1
            if len(skipped_examples) < 10:
                reason = error.strerror if isinstance(error, OSError) else str(error)
                skipped_examples.append({"root": entry["root"], "path": entry["path"], "reason": reason})
            blocked.update((entry["root"], parent.as_posix()) for parent in relative.parents)
    # Set directory times last so restoring a child cannot change them again.
    for entry in sorted(directories, key=lambda item: len(PurePosixPath(item["path"]).parts), reverse=True):
        relative = input_relative(entry["path"])
        try:
            if (entry["root"], relative.as_posix()) in blocked:
                raise ValueError("A directory contains an unmatched checkpoint input")
            path = path_without_symlink_parents(roots[entry["root"]], relative)
            info = path.lstat()
            if kind(info) != "directory" or stat.S_IMODE(info.st_mode) != entry["mode"]:
                raise ValueError("Checkpoint directory type or mode differs")
            if directory_hash(path, relative, entry["root"]) != entry["children_sha256"]:
                raise ValueError("Checkpoint directory entries differ")
            os.utime(path, ns=(info.st_atime_ns, entry["mtime_ns"]), follow_symlinks=False)
            restored += 1
        except (OSError, ValueError) as error:
            skipped += 1
            if len(skipped_examples) < 10:
                reason = error.strerror if isinstance(error, OSError) else str(error)
                skipped_examples.append({"root": entry["root"], "path": entry["path"], "reason": reason})
            blocked.update((entry["root"], parent.as_posix()) for parent in relative.parents)
    return {"restored": restored, "skipped": skipped, "skipped_examples": skipped_examples}


def object_metadata(path, source_root):
    relative = path.relative_to(source_root)
    safe_relative(relative.as_posix())
    if relative.parts[:2] != ("out", "Bare"):
        raise ValueError("Expected an object inside the Bare output directory")
    path_without_symlink_parents(source_root, PurePosixPath(relative.as_posix()))
    entry = describe(path, "src", PurePosixPath(relative.as_posix()))
    if entry["type"] != "file":
        raise ValueError("Expected a regular compiled object")
    return {key: entry[key] for key in ("path", "sha256", "size", "mtime_ns", "mode")}


def write_json(path, value):
    """Publish a complete record rather than an interrupted partial JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def canonical_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode("utf-8")).hexdigest()


def checked_command(arguments):
    process = subprocess.run(arguments, capture_output=True, text=True, timeout=30,
                             check=False)
    if process.returncode:
        raise ValueError(f"Identity command failed: {arguments[0]}: {process.stderr.strip()[:200]}")
    return process.stdout.strip()


def provenance_identity(ci_revision, base_image, source_root=ROOTS["src"],
                        depot_root=ROOTS["depot_tools"], exchange=Path("/exchange")):
    if not re.fullmatch(r"[0-9a-f]{40}", ci_revision):
        raise ValueError("Expected the exact CI commit SHA")
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", base_image):
        raise ValueError("Expected the immutable base image reference")
    revisions = {}
    for name, root in (("chromium", source_root), ("depot_tools", depot_root),
                       ("v8", source_root / "v8")):
        revision = checked_command(["git", "-C", str(root), "rev-parse", "HEAD"])
        if not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("An input checkout has no exact revision")
        revisions[name] = revision
    patches = sorted((exchange / "patches").glob("*.patch"))
    if not patches:
        raise ValueError("The official Bare patch series is missing")
    # The consumer has already unpacked out/Bare. Compare its restored GN file
    # with the freshly prepared desired settings so restoration cannot hide a
    # change to the build configuration.
    if file_hash(exchange / "args.gn") != file_hash(source_root / "out/Bare/args.gn"):
        raise ValueError("Restored and freshly prepared GN arguments differ")
    fixed_files = {"args.gn": exchange / "args.gn",
                   "ublock_origin.crx": source_root / "chrome/browser/resources/bare/ublock_origin.crx",
                   "v8-x64.profile": source_root / "v8/tools/builtins-pgo/profiles/x64.profile"}
    tools = {name: file_hash((source_root / name).resolve())
             for name in TOOL_FILES if (source_root / name).is_file()}
    if TOOL_FILES[0] not in tools or TOOL_FILES[1] not in tools:
        raise ValueError("The pinned compiler and linker are missing")
    packages = checked_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\n",
                                *SYSTEM_PACKAGES])
    identity = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "input_manifest_version": VERSION,
        "ci_revision": ci_revision,
        "base_image": base_image,
        "bare_revision": os.environ.get("BARE_REV", ""),
        "revisions": revisions,
        "ci_files": {name: file_hash(exchange / name) for name in CI_FILES},
        "fixed_files": {name: file_hash(path) for name, path in fixed_files.items()},
        "patches": {path.name: file_hash(path) for path in patches},
        "tools": tools,
        "system_packages": dict(line.split("\t", 1) for line in packages.splitlines()),
        "os_release_sha256": file_hash(Path("/etc/os-release").resolve()),
    }
    if not re.fullmatch(r"[0-9a-f]{40}", identity["bare_revision"]):
        raise ValueError("The fixed Bare revision was not passed to the container")
    return identity


def record_provenance(path, ci_revision, base_image, **roots):
    identity = provenance_identity(ci_revision, base_image, **roots)
    record = {"format": PROVENANCE_FORMAT, "version": CHECKPOINT_VERSION,
              "identity": identity, "identity_sha256": canonical_hash(identity)}
    write_json(path, record)
    return {"identity_sha256": record["identity_sha256"], "version": CHECKPOINT_VERSION}


def verify_provenance(path, ci_revision, base_image,
                      repair_legacy_input_paths=False, allow_scale_predecessor=False,
                      allow_larger_predecessor=False, **roots):
    if sum((repair_legacy_input_paths, allow_scale_predecessor, allow_larger_predecessor)) > 1:
        raise ValueError("Select only one checkpoint CI migration")
    record = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or record.get("format") != PROVENANCE_FORMAT
            or record.get("version") != CHECKPOINT_VERSION
            or not isinstance(record.get("identity"), dict)
            or record.get("identity_sha256") != canonical_hash(record["identity"])):
        raise ValueError("The checkpoint identity record is invalid or incompatible")
    expected = None
    if repair_legacy_input_paths:
        expected = LEGACY_INPUT_PATH_REPAIR
        mismatch = "The input-path repair permits only the exact recorded legacy producer"
    elif allow_scale_predecessor:
        expected = SCALE_PREDECESSOR
        mismatch = "The scale probe permits only the exact recorded successor as predecessor"
    elif allow_larger_predecessor:
        expected = LARGER_PREDECESSOR
        mismatch = "The larger probe permits only the exact recorded scale predecessor"
    if expected is not None:
        if (record["identity_sha256"] != expected["identity_sha256"]
                or record["identity"].get("ci_revision") != expected["ci_revision"]
                or record["identity"].get("ci_files") != expected["ci_files"]):
            raise ValueError(mismatch)
    current = provenance_identity(ci_revision, base_image, **roots)
    if expected is not None:
        # A pinned predecessor may use an earlier CI implementation. Every
        # build input other than that implementation must still match.
        excluded = {"ci_revision", "ci_files"}
        producer_inputs = {key: value for key, value in record["identity"].items()
                           if key not in excluded}
        current_inputs = {key: value for key, value in current.items()
                          if key not in excluded}
        if producer_inputs != current_inputs:
            differences = sorted(name for name in set(current_inputs) | set(producer_inputs)
                                 if current_inputs.get(name) != producer_inputs.get(name))
            raise ValueError("Checkpoint build inputs differ: " + ", ".join(differences))
        return {"matched": False, "matched_build_inputs": True,
                "explicit_ci_migration": True,
                "producer_ci_revision": record["identity"]["ci_revision"],
                "validator_ci_revision": current["ci_revision"],
                "producer_identity_sha256": record["identity_sha256"],
                "validator_identity_sha256": canonical_hash(current)}
    if record["identity"] != current:
        differences = sorted(name for name in set(current) | set(record["identity"])
                             if current.get(name) != record["identity"].get(name))
        raise ValueError("Checkpoint build inputs differ: " + ", ".join(differences))
    return {"identity_sha256": record["identity_sha256"], "matched": True}


def collect_evidence(trial_path, record_path, source_root=ROOTS["src"], limit=3):
    """Select stable objects only from controller-verified successful APK edges."""
    trial = json.loads(trial_path.read_text(encoding="utf-8"))
    if (not isinstance(trial, dict) or trial.get("format") != "bare-apk-trial"
            or trial.get("version") != 1 or trial.get("phase") != "seed"
            or trial.get("target") != "chrome_public_apk"
            or trial.get("build_dir") != "out/Bare"
            or not isinstance(trial.get("new_completed_outputs"), list)):
        raise ValueError("Expected the seed APK trial completion record")
    records = []
    selected = set()
    for edge in trial["new_completed_outputs"]:
        if not isinstance(edge, dict):
            raise ValueError("Invalid completed edge")
        relative = safe_relative(edge.get("path"))
        if (edge.get("success") is not True
                or edge.get("success_source") != "siso_metrics+ninja_log-v5"
                or not isinstance(edge.get("step_id"), str) or not edge["step_id"]):
            raise ValueError("The APK edge has no successful-completion evidence")
        if (not relative.parts or relative.parts[0] != "obj" or relative.suffix != ".o"
                or relative.as_posix() in selected
                or "out/Bare/" + relative.as_posix() == CITY_OBJECT):
            continue
        item = object_metadata(source_root / "out/Bare" / relative, source_root)
        if item["size"] == 0:
            continue
        selected.add(relative.as_posix())
        records.append({"target": relative.as_posix(), "object": item,
                        "success_source": edge["success_source"], "step_id": edge["step_id"]})
        if len(records) == limit:
            break
    if not records:
        raise ValueError("The short APK trial completed no additional verifiable object")
    record = {"format": EVIDENCE_FORMAT, "version": CHECKPOINT_VERSION,
              "objects": records}
    write_json(record_path, record)
    return {"objects": len(records), "targets": [item["target"] for item in records]}


def evidence_records(record_path):
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or record.get("format") != EVIDENCE_FORMAT
            or record.get("version") != CHECKPOINT_VERSION
            or not isinstance(record.get("objects"), list)
            or not 1 <= len(record["objects"]) <= 3):
        raise ValueError("Invalid completed-object evidence record")
    seen = set()
    for item in record["objects"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid completed-object evidence")
        target = safe_relative(item.get("target"))
        if (not target.parts or target.parts[0] != "obj" or target.suffix != ".o"
                or target.as_posix() in seen or not isinstance(item.get("object"), dict)
                or item["object"].get("path") != "out/Bare/" + target.as_posix()
                or item.get("success_source") != "siso_metrics+ninja_log-v5"
                or not isinstance(item.get("step_id"), str) or not item["step_id"]):
            raise ValueError("Unsafe or duplicated completed-object target")
        seen.add(target.as_posix())
        yield item


def verify_evidence(record_path, source_root=ROOTS["src"]):
    records = list(evidence_records(record_path))
    for item in records:
        current = object_metadata(source_root / item["object"]["path"], source_root)
        if current != item["object"]:
            raise ValueError("An APK trial object changed: " + item["target"])
    return {"verified": len(records)}


def successful_continuation_edges(trial):
    if (not isinstance(trial, dict) or trial.get("format") != "bare-apk-trial"
            or trial.get("version") != 1 or trial.get("phase") != "restore"
            or trial.get("target") != "chrome_public_apk" or trial.get("build_dir") != "out/Bare"
            or trial.get("ready_for_restore_test") is not True
            or trial.get("container_quiescence_verified") is not True
            or not isinstance(trial.get("new_completed_outputs"), list)):
        raise ValueError("Expected a verified, quiescent APK continuation trial")
    edges = {}
    for edge in trial["new_completed_outputs"]:
        if (not isinstance(edge, dict) or edge.get("success") is not True
                or edge.get("success_source") != "siso_metrics+ninja_log-v5"
                or not isinstance(edge.get("step_id"), str) or not edge["step_id"]):
            raise ValueError("The continuation edge has no successful-completion evidence")
        relative = safe_relative(edge.get("path"))
        name = (PurePosixPath("out/Bare") / relative).as_posix()
        if not relative.parts or name in edges:
            raise ValueError("Invalid or duplicated continuation output")
        edges[name] = edge["step_id"]
    return edges


def continuation_trial_limit(scale, large):
    if scale and large:
        raise ValueError("Select only one continuation size profile")
    if large:
        return LARGE_CONTINUATION_TRIAL_LIMIT
    return SCALE_CONTINUATION_TRIAL_LIMIT if scale else CONTINUATION_TRIAL_LIMIT


def record_continuation(trial_path, record_path, source_root=ROOTS["src"], *,
                        scale=False, large=False):
    trial_limit = continuation_trial_limit(scale, large)
    with trial_path.open("rb") as stream:
        payload = stream.read(trial_limit + 1)
    if len(payload) > trial_limit:
        raise ValueError("Continuation trial JSON exceeds its size limit")
    edges = successful_continuation_edges(json.loads(payload))
    def output_priority(name):
        is_object = name.endswith(".o")
        target_object = large and is_object and name.startswith("out/Bare/obj/")
        return (not target_object, not is_object, name)

    outputs = []
    for name in sorted(edges, key=output_priority):
        try:
            path = path_without_symlink_parents(source_root, PurePosixPath(name))
            info = path.lstat()
        except FileNotFoundError:
            continue
        # The readback checks regular archive members directly. GNU tar can
        # represent multiply linked filesystem files as hardlink members.
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not info.st_size:
            continue
        if large and info.st_size > 2 * 1024 ** 3:
            continue
        metadata = object_metadata(path, source_root)
        outputs.append({"path": name, "step_id": edges[name], "size": metadata["size"],
                        "sha256": metadata["sha256"]})
        if len(outputs) == 3:
            break
    if not outputs:
        raise ValueError("The continuation produced no verifiable new regular output")
    write_json(record_path, {"format": CONTINUATION_FORMAT, "version": 1,
                             "trial_sha256": hashlib.sha256(payload).hexdigest(),
                             "outputs": outputs})
    return {"recorded": len(outputs), "paths": [item["path"] for item in outputs]}


def continuation_archive_records(archive_path, trial_limit=CONTINUATION_TRIAL_LIMIT):
    limits = {CONTINUATION_RECORD: 32 * 1024, CONTINUATION_TRIAL: trial_limit,
              PROVENANCE_RECORD: 1024 ** 2}
    records = {}
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            name = member.name
            if name not in limits:
                continue
            if name in records or not member.isfile() or not 0 < member.size <= limits[name]:
                raise ValueError("Invalid continuation archive record: " + name)
            with archive.extractfile(member) as stream:
                records[name] = stream.read(member.size)
            if len(records[name]) != member.size:
                raise ValueError("Truncated continuation archive record: " + name)
    if records.keys() != limits.keys():
        raise ValueError("Missing continuation archive record: " + ", ".join(sorted(limits.keys() - records.keys())))
    return records


def verify_continuation(archive_path, expected_identity, ci_revision, *, scale=False, large=False):
    if (not re.fullmatch(r"[0-9a-f]{64}", expected_identity)
            or not re.fullmatch(r"[0-9a-f]{40}", ci_revision)):
        raise ValueError("Expected the exact successor identity and CI revision")
    trial_limit = continuation_trial_limit(scale, large)
    records = continuation_archive_records(archive_path, trial_limit)
    provenance = json.loads(records[PROVENANCE_RECORD])
    if (not isinstance(provenance, dict) or provenance.get("format") != PROVENANCE_FORMAT
            or provenance.get("version") != CHECKPOINT_VERSION
            or not isinstance(provenance.get("identity"), dict)
            or provenance["identity"].get("ci_revision") != ci_revision
            or provenance.get("identity_sha256") != expected_identity
            or canonical_hash(provenance["identity"]) != expected_identity):
        raise ValueError("The archived successor provenance does not match")
    trial_payload = records[CONTINUATION_TRIAL]
    trial = json.loads(trial_payload)
    edges = successful_continuation_edges(trial)
    record = json.loads(records[CONTINUATION_RECORD])
    if (not isinstance(record, dict) or record.get("format") != CONTINUATION_FORMAT
            or record.get("version") != 1
            or record.get("trial_sha256") != hashlib.sha256(trial_payload).hexdigest()
            or not isinstance(record.get("outputs"), list) or not 1 <= len(record["outputs"]) <= 3):
        raise ValueError("Invalid continuation evidence or trial binding")
    expected = {}
    for item in record["outputs"]:
        if not isinstance(item, dict):
            raise ValueError("Invalid continuation output evidence")
        name = safe_relative(item.get("path")).as_posix()
        if (name in expected or name not in edges or item.get("step_id") != edges[name]
                or type(item.get("size")) is not int or not 0 < item["size"] <= 2 * 1024 ** 3
                or not isinstance(item.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
            raise ValueError("Invalid continuation output evidence")
        expected[name] = item

    sample_paths = sorted(expected)
    apk = None
    if large and trial.get("reason") == "completed":
        apk = trial.get("apk")
        if (not isinstance(apk, dict) or apk.get("path") != APK_PATH
                or type(apk.get("size")) is not int or not 0 < apk["size"] <= LARGE_UNPACKED_BYTES
                or not isinstance(apk.get("sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", apk["sha256"])):
            raise ValueError("The completed trial has no valid APK metadata")
        member = safe_relative(apk.get("arm64_member"))
        if member.parts[:2] != ("lib", "arm64-v8a") or member.suffix != ".so":
            raise ValueError("The completed trial has no verified ARM64 library")
        if APK_PATH in expected and any(expected[APK_PATH][field] != apk[field]
                                        for field in ("size", "sha256")):
            raise ValueError("Completed APK and continuation sample metadata differ")
        expected[APK_PATH] = apk

    verified = set()
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            name = member.name
            if name not in expected:
                continue
            item = expected[name]
            if name in verified or not member.isfile() or member.size != item["size"]:
                raise ValueError("Invalid archived continuation output: " + name)
            digest = hashlib.sha256()
            with archive.extractfile(member) as stream:
                for block in iter(lambda: stream.read(4 * 1024 ** 2), b""):
                    digest.update(block)
            if digest.hexdigest() != item["sha256"]:
                raise ValueError("Archived continuation output content differs: " + name)
            verified.add(name)
    if verified != expected.keys():
        raise ValueError("Missing archived continuation output: " + ", ".join(sorted(expected.keys() - verified)))
    result = {"verified": len(sample_paths), "paths": sample_paths}
    if apk is not None:
        result["apk"] = {name: apk[name] for name in ("path", "size", "sha256", "arm64_member")}
    return result


def canonicalize_logs(source_root=ROOTS["src"], max_file_bytes=32 * 1024 * 1024,
                      max_total_bytes=128 * 1024 * 1024, *, scale=False):
    """After Siso stops, copy short-probe diagnostics or omit scale log links."""
    output = source_root / "out/Bare"
    pattern = (r"siso(?:\.[0-9]+)?\.(INFO|WARNING|ERROR)" if scale
               else r"siso(?:\.[0-9])?\.(INFO|WARNING|ERROR)")
    converted = []
    omitted = []
    total = 0
    for link in sorted(output.iterdir()):
        match = re.fullmatch(pattern, link.name)
        if not match or not link.is_symlink():
            continue
        target = link.resolve(strict=True)
        level = match.group(1)
        if not target.name.startswith("siso.") or f".log.{level}." not in target.name:
            raise ValueError("Unexpected Siso diagnostic link target")
        if scale:
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise ValueError("Siso diagnostic link must target an owned regular log")
            link.unlink()
            omitted.append(link.name)
            continue
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        temporary = None
        try:
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                        or before.st_size > max_file_bytes
                        or total + before.st_size > max_total_bytes):
                    raise ValueError("Siso diagnostic log is not a bounded owned regular file")
                fd, temporary = tempfile.mkstemp(prefix=link.name + ".", dir=output)
                with os.fdopen(fd, "wb") as copy:
                    remaining = before.st_size
                    while remaining:
                        block = stream.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ValueError("A Siso diagnostic log was truncated during copying")
                        copy.write(block)
                        remaining -= len(block)
                    if stream.read(1):
                        raise ValueError("A Siso diagnostic log grew during copying")
                after = os.fstat(stream.fileno())
                if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns):
                    raise ValueError("A Siso diagnostic log changed during checkpoint creation")
            os.chmod(temporary, stat.S_IMODE(before.st_mode) & 0o666)
            os.utime(temporary, ns=(before.st_atime_ns, before.st_mtime_ns))
            os.replace(temporary, link)
            total += before.st_size
            converted.append({"name": link.name, "size": before.st_size})
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
    if scale:
        return {"omitted_logs": omitted}
    return {"converted_logs": converted, "converted_bytes": total}


def archive_relative(name):
    while name.startswith("./"):
        name = name[2:]
    relative = safe_relative(name.rstrip("/"))
    if relative.parts[:2] != ("out", "Bare"):
        raise ValueError("Checkpoint archive member is outside out/Bare")
    return relative


def validate_archive(archive_path, max_archive_bytes=1024 ** 3,
                     max_unpacked_bytes=2 * 1024 ** 3, max_members=100_000):
    if archive_path.stat().st_size > max_archive_bytes:
        raise ValueError("Checkpoint archive exceeds the bounded transfer limit")
    members = {}
    symlinks = {}
    hardlinks = {}
    unpacked_bytes = 0
    with tarfile.open(archive_path, mode="r|gz") as archive:
        for member in archive:
            relative = archive_relative(member.name)
            name = relative.as_posix()
            if name in members:
                raise ValueError("Checkpoint archive contains a duplicate member")
            if not (member.isdir() or member.isfile() or member.issym() or member.islnk()):
                raise ValueError("Checkpoint archive contains a special file")
            if member.size < 0:
                raise ValueError("Checkpoint archive contains an invalid member size")
            if relative == PurePosixPath("out/Bare") and not member.isdir():
                raise ValueError("Checkpoint archive root must be a directory")
            members[name] = member.type
            unpacked_bytes += member.size
            if len(members) > max_members or unpacked_bytes > max_unpacked_bytes:
                raise ValueError("Checkpoint archive exceeds the bounded extraction limit")
            if member.issym() or member.islnk():
                target = member.linkname
                if not target or "\x00" in target or "\\" in target or target.startswith("/"):
                    raise ValueError("Unsafe checkpoint archive link target")
                if member.issym():
                    target = posixpath.join(relative.parent.as_posix(), target)
                    symlinks[name] = member.linkname
                else:
                    hardlinks[name] = posixpath.normpath(target)
                archive_relative(posixpath.normpath(target))
    if "out/Bare" not in members:
        raise ValueError("Checkpoint archive root is missing")
    for name in members:
        if any(parent.as_posix() in symlinks or parent.as_posix() in hardlinks
               for parent in PurePosixPath(name).parents):
            raise ValueError("Checkpoint archive member has a link parent")
    # Resolve symlink components as the filesystem would, including '..' after
    # an earlier symlink. Lexical normalization alone misses those escapes.
    for name, target in symlinks.items():
        resolved = list(PurePosixPath(name).parent.parts)
        pending = target.split("/")
        links_followed = 0
        while pending:
            component = pending.pop(0)
            if component in {"", "."}:
                continue
            if component == "..":
                if len(resolved) <= 2:
                    raise ValueError("Checkpoint archive symlink resolves outside out/Bare")
                resolved.pop()
                continue
            resolved.append(component)
            current = "/".join(resolved)
            if current in symlinks:
                links_followed += 1
                if links_followed > 40:
                    raise ValueError("Checkpoint archive contains a symlink loop")
                resolved.pop()
                pending = symlinks[current].split("/") + pending
    for target in hardlinks.values():
        followed = set()
        while target in hardlinks:
            if target in followed:
                raise ValueError("Checkpoint archive contains a hardlink loop")
            followed.add(target)
            target = hardlinks[target]
        if members.get(target) not in tarfile.REGULAR_TYPES:
            raise ValueError("Checkpoint archive hardlink must refer to a regular member")
    return {"members": len(members), "unpacked_bytes": unpacked_bytes,
            "archive_bytes": archive_path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("record-inputs", "restore-inputs"):
        command = commands.add_parser(name)
        command.add_argument("manifest", type=Path)
    for name in ("object-info", "verify-object"):
        command = commands.add_parser(name)
        command.add_argument("object", type=Path)
        command.add_argument("record", type=Path)
    for name in ("validate-archive", "inspect-input-paths"):
        command = commands.add_parser(name)
        command.add_argument("archive", type=Path)
        if name == "validate-archive":
            command.add_argument("--max-archive-bytes", type=int)
            command.add_argument("--max-unpacked-bytes", type=int)
        profile = command.add_mutually_exclusive_group()
        profile.add_argument("--scale", action="store_true")
        profile.add_argument("--large", action="store_true")
    for name in ("record-provenance", "verify-provenance"):
        command = commands.add_parser(name)
        command.add_argument("record", type=Path)
        command.add_argument("--ci-revision", required=True)
        command.add_argument("--base-image", required=True)
        if name == "verify-provenance":
            migration = command.add_mutually_exclusive_group()
            migration.add_argument("--repair-legacy-input-paths", action="store_true")
            migration.add_argument("--allow-scale-predecessor", action="store_true")
            migration.add_argument("--allow-larger-predecessor", action="store_true")
    command = commands.add_parser("collect-evidence")
    command.add_argument("trial", type=Path)
    command.add_argument("record", type=Path)
    for name in ("record-continuation", "verify-continuation"):
        command = commands.add_parser(name)
        if name == "record-continuation":
            command.add_argument("trial", type=Path)
            command.add_argument("record", type=Path)
        else:
            command.add_argument("archive", type=Path)
            command.add_argument("--expected-identity", required=True)
            command.add_argument("--ci-revision", required=True)
        profile = command.add_mutually_exclusive_group()
        profile.add_argument("--scale", action="store_true")
        profile.add_argument("--large", action="store_true")
    for name in ("verify-evidence", "evidence-targets"):
        command = commands.add_parser(name)
        command.add_argument("record", type=Path)
    command = commands.add_parser("canonicalize-logs")
    command.add_argument("--scale", action="store_true")
    args = parser.parse_args()
    if args.command == "record-inputs":
        result = record_inputs(args.manifest)
    elif args.command == "restore-inputs":
        result = restore_inputs(args.manifest)
    elif args.command in {"validate-archive", "inspect-input-paths"}:
        limits = {}
        if args.command == "validate-archive":
            for name in ("max_archive_bytes", "max_unpacked_bytes"):
                value = getattr(args, name)
                if value is not None:
                    if value <= 0:
                        raise ValueError("Archive size limits must be positive")
                    limits[name] = value
        if args.scale or args.large:
            if limits:
                profile = "large" if args.large else "scale"
                raise ValueError(f"The {profile} archive limits are fixed")
            limits = {"max_archive_bytes": SCALE_ARCHIVE_BYTES,
                      "max_unpacked_bytes": LARGE_UNPACKED_BYTES if args.large else SCALE_UNPACKED_BYTES,
                      "max_members": LARGE_ARCHIVE_MEMBERS if args.large else SCALE_ARCHIVE_MEMBERS}
        operation = validate_archive if args.command == "validate-archive" else inspect_input_paths
        result = operation(args.archive, **limits)
    elif args.command in {"record-provenance", "verify-provenance"}:
        operation = record_provenance if args.command == "record-provenance" else verify_provenance
        options = ({"repair_legacy_input_paths": args.repair_legacy_input_paths,
                    "allow_scale_predecessor": args.allow_scale_predecessor,
                    "allow_larger_predecessor": args.allow_larger_predecessor}
                   if args.command == "verify-provenance" else {})
        result = operation(args.record, args.ci_revision, args.base_image, **options)
    elif args.command == "collect-evidence":
        result = collect_evidence(args.trial, args.record)
    elif args.command == "record-continuation":
        result = record_continuation(args.trial, args.record, scale=args.scale, large=args.large)
    elif args.command == "verify-continuation":
        result = verify_continuation(args.archive, args.expected_identity, args.ci_revision,
                                     scale=args.scale, large=args.large)
    elif args.command == "verify-evidence":
        result = verify_evidence(args.record)
    elif args.command == "evidence-targets":
        for item in list(evidence_records(args.record)):
            print(item["target"])
        return 0
    elif args.command == "canonicalize-logs":
        result = canonicalize_logs(scale=args.scale)
    else:
        path = args.object.absolute()
        result = object_metadata(path, ROOTS["src"])
        if args.command == "object-info":
            write_json(args.record, result)
        elif result != json.loads(args.record.read_text(encoding="utf-8")):
            raise ValueError("Compiled object content, mode, size or mtime differs")
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, TypeError, KeyError, StopIteration, EOFError, tarfile.TarError,
            subprocess.SubprocessError) as error:
        print(f"Checkpoint validation failed: {error}", file=sys.stderr)
        sys.exit(2)
