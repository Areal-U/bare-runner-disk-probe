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
PROVENANCE_FORMAT = "bare-checkpoint-provenance"
CITY_OBJECT = "out/Bare/obj/base/third_party/cityhash/cityhash/city.o"
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


def validate_entry(entry, roots):
    if not isinstance(entry, dict) or entry.get("root") not in roots:
        raise ValueError("Unknown checkpoint input root")
    relative = safe_relative(entry.get("path"))
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
        relative = safe_relative(entry["path"])
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
        relative = safe_relative(entry["path"])
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


def verify_provenance(path, ci_revision, base_image, **roots):
    record = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or record.get("format") != PROVENANCE_FORMAT
            or record.get("version") != CHECKPOINT_VERSION
            or not isinstance(record.get("identity"), dict)
            or record.get("identity_sha256") != canonical_hash(record["identity"])):
        raise ValueError("The checkpoint identity record is invalid or incompatible")
    current = provenance_identity(ci_revision, base_image, **roots)
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


def canonicalize_logs(source_root=ROOTS["src"], max_file_bytes=32 * 1024 * 1024,
                      max_total_bytes=128 * 1024 * 1024):
    """Make known Siso diagnostic links portable; never alter incremental state."""
    output = source_root / "out/Bare"
    converted = []
    total = 0
    for link in sorted(output.iterdir()):
        match = re.fullmatch(r"siso(?:\.[0-9])?\.(INFO|WARNING|ERROR)", link.name)
        if not match or not link.is_symlink():
            continue
        target = link.resolve(strict=True)
        level = match.group(1)
        if not target.name.startswith("siso.") or f".log.{level}." not in target.name:
            raise ValueError("Unexpected Siso diagnostic link target")
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
    command = commands.add_parser("validate-archive")
    command.add_argument("archive", type=Path)
    command.add_argument("--max-archive-bytes", type=int, default=1024 ** 3)
    command.add_argument("--max-unpacked-bytes", type=int, default=2 * 1024 ** 3)
    for name in ("record-provenance", "verify-provenance"):
        command = commands.add_parser(name)
        command.add_argument("record", type=Path)
        command.add_argument("--ci-revision", required=True)
        command.add_argument("--base-image", required=True)
    command = commands.add_parser("collect-evidence")
    command.add_argument("trial", type=Path)
    command.add_argument("record", type=Path)
    for name in ("verify-evidence", "evidence-targets"):
        command = commands.add_parser(name)
        command.add_argument("record", type=Path)
    commands.add_parser("canonicalize-logs")
    args = parser.parse_args()
    if args.command == "record-inputs":
        result = record_inputs(args.manifest)
    elif args.command == "restore-inputs":
        result = restore_inputs(args.manifest)
    elif args.command == "validate-archive":
        if args.max_archive_bytes <= 0 or args.max_unpacked_bytes <= 0:
            raise ValueError("Archive size limits must be positive")
        result = validate_archive(args.archive, args.max_archive_bytes, args.max_unpacked_bytes)
    elif args.command in {"record-provenance", "verify-provenance"}:
        operation = record_provenance if args.command == "record-provenance" else verify_provenance
        result = operation(args.record, args.ci_revision, args.base_image)
    elif args.command == "collect-evidence":
        result = collect_evidence(args.trial, args.record)
    elif args.command == "verify-evidence":
        result = verify_evidence(args.record)
    elif args.command == "evidence-targets":
        for item in list(evidence_records(args.record)):
            print(item["target"])
        return 0
    elif args.command == "canonicalize-logs":
        result = canonicalize_logs()
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
    except (OSError, ValueError, TypeError, KeyError, StopIteration, tarfile.TarError,
            subprocess.SubprocessError) as error:
        print(f"Checkpoint validation failed: {error}", file=sys.stderr)
        sys.exit(2)
