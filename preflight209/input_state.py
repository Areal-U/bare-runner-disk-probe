"""Bind the source and tools across fresh VMs, including CIPD's deployed files.

CIPD allocates numeric directories in installation order. Identify those slots
by their package names. Every package, version, link, file and directory still
participates in the comparison. Source timestamps are restored only after the
matching file or directory contents have been checked.
"""
import gzip
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
import tempfile
from itertools import zip_longest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import checkpoint

FORMAT = "bare-personal-209-source-tools-1"
STORES = {"src": "third_party/depot_tools/.cipd_bin/.cipd/pkgs",
          "depot_tools": ".cipd_bin/.cipd/pkgs"}
REQUIRED = {("src", "."), ("depot_tools", "."), ("src", "DEPS"), ("depot_tools", "autoninja"),
            ("src", "third_party/siso/cipd/siso"), ("src", "third_party/llvm-build/Release+Asserts/bin/clang"),
            ("src", "chrome/android/java/res_chromium_base/values/bare_launcher_label.xml")}


def require(value, msg):
    if not value:
        raise ValueError(msg)


def slots(directory):
    mapping = {}
    if directory.is_dir():
        for entry in directory.iterdir():
            if entry.name.isdecimal():
                require(entry.is_dir() and not entry.is_symlink(), "Invalid CIPD package slot")
                desc = entry / "description.json"
                require(desc.is_file() and not desc.is_symlink() and desc.stat().st_size < 65536,
                        "Missing CIPD package description")
                name = json.loads(desc.read_bytes())["package_name"]
                require(isinstance(name, str) and re.fullmatch(r"[a-zA-Z0-9._/-]+", name), "Invalid CIPD package name")
                key = "package-" + sha256(name.encode()).hexdigest()
                require(key not in mapping.values(), "Ambiguous CIPD package identity")
                mapping[entry.name] = key
    return mapping


def canonical_link(path, target, store, mapping):
    if ".cipd/pkgs/" not in target:
        return ["literal", target]
    absolute = Path(os.path.normpath(path.parent / target))
    if not absolute.is_relative_to(store):
        return ["literal", target]
    parts = absolute.relative_to(store).parts
    if not parts or parts[0] not in mapping:
        return ["literal", target]
    old = ".cipd/pkgs/" + parts[0]
    end = "" if target.endswith(old) else "/"
    require(target.count(old + end) == 1, "Ambiguous CIPD link")
    return ["cipd-slot", target.replace(old + end, ".cipd/pkgs/" + mapping[parts[0]] + end, 1)]


def walk(root_name, root):
    store = root / STORES[root_name]
    mapping = slots(store)

    def visit(path, logical):
        info = path.lstat()
        kind = checkpoint.kind(info)
        value = None
        if kind == "directory":
            entries = []
            renamed = mapping if path == store else {}
            for name in os.listdir(path):
                rel = logical / name
                if not checkpoint.ignored(name, rel, root_name):
                    entries.append((renamed.get(name, name), name))
            require(len({label for label, _ in entries}) == len(entries), "Repeated logical input")
            for label, name in sorted(entries):
                yield from visit(path / name, logical / label)
        elif kind == "file":
            value = [info.st_size, checkpoint.file_hash(path)]
        else:
            value = canonical_link(path, os.readlink(path), store, mapping)
        final = path.lstat()
        require((info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns) ==
                (final.st_ino, final.st_mode, final.st_size, final.st_mtime_ns),
                f"Input changed while scanning {path}")
        yield [root_name, logical.as_posix(), kind, info.st_mode & 0o7777, info.st_mtime_ns, value], path

    yield from visit(root, PurePosixPath("."))


def inputs(roots):
    checkpoint.check_roots(roots)
    for name, root in sorted(roots.items()):
        yield from walk(name, root)


def record(path, roots=checkpoint.ROOTS):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as tmp:
        temporary = Path(tmp.name)
    try:
        with gzip.open(temporary, "wt", compresslevel=2, encoding="utf-8") as output:
            output.write(json.dumps(FORMAT) + "\n")
            count = 0
            for row, _ in inputs(roots):
                output.write(json.dumps(row, separators=(",", ":")) + "\n")
                count += 1
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return {"recorded": count, "manifest_bytes": path.stat().st_size}


def rows(path):
    previous, seen_required, pending_dirs = None, set(), set()
    count = total = 0
    with gzip.open(path, "rb") as stream:
        require(stream.readline(128) == (json.dumps(FORMAT) + "\n").encode(), "Unknown input record format")
        while line := stream.readline(65537):
            total += len(line)
            count += 1
            require(len(line) <= 65536 and total <= 1024**3 and count <= 2_000_000, "Unbounded source manifest")
            row = json.loads(line)
            require(isinstance(row, list) and len(row) == 6, "Malformed source row")
            name, value, kind, mode, mtime, contents = row
            require(name in STORES and type(mode) is int and 0 <= mode <= 0o7777 and
                    type(mtime) is int and mtime >= 0, "Invalid source metadata")
            rel = checkpoint.input_relative(value)
            require(not any(checkpoint.ignored(p, PurePosixPath(*rel.parts[:i+1]), name)
                            for i, p in enumerate(rel.parts)), "Excluded source in manifest")
            # Children sort before their own directory, in the walk's exact order.
            key = (name, tuple((0, p) for p in rel.parts) + ((1, ""),))
            require(previous is None or previous < key, "Duplicate or out-of-order source")
            previous = key
            if kind == "file":
                require(isinstance(contents, list) and len(contents) == 2 and type(contents[0]) is int and
                        contents[0] >= 0 and isinstance(contents[1], str) and
                        re.fullmatch("[0-9a-f]{64}", contents[1]), "Invalid source file binding")
            elif kind == "symlink":
                require(isinstance(contents, list) and len(contents) == 2 and
                        contents[0] in ("literal", "cipd-slot") and isinstance(contents[1], str) and
                        contents[1] and "\0" not in contents[1], "Invalid source symlink")
            else:
                require(kind == "directory" and contents is None, "Invalid source type")
                pending_dirs.discard((name, value))
            if rel.parts:
                pending_dirs.add((name, rel.parent.as_posix()))
            if (name, value) in REQUIRED:
                require((kind == "directory") == (value == "."), "Required input has the wrong type")
                seen_required.add((name, value))
            yield row
    require(seen_required == REQUIRED and not pending_dirs, "Incomplete source or tool inventory")


def validate(path):
    return sum(1 for _ in rows(path))


def restore(path, roots=checkpoint.ROOTS):
    count = 0
    for old, pair in zip_longest(rows(path), inputs(roots)):
        require(old is not None and pair is not None, "Source inventory length changed")
        actual, physical = pair
        require(old[:4] == actual[:4] and old[5] == actual[5],
                f"Source input differs at {old[:2]!r} vs {actual[:2]!r}")
        info = physical.lstat()
        os.utime(physical, ns=(info.st_atime_ns, old[4]), follow_symlinks=False)
        count += 1
    return {"restored": count, "skipped": 0}
