"""Content continuity of quiescent build outputs, including outputs outside the witness sample."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile

MAX_ENTRIES = 550_000
MAX_RAW = 21 * 1024**3
PROOF = "checkpoint-round28-graph.json"
S2 = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
# Only internal bookkeeping at the build root. Dependency state is also tested by
# the fresh Siso planner. A real output at a nested path with this name is protected.
RECEIPTS = {
    "checkpoint-inputs.jsonl.gz", "checkpoint-provenance.json", "checkpoint-object.json",
    "checkpoint-evidence.json", "checkpoint-continuation.json", "checkpoint-trial-seed.json",
    "checkpoint-trial-restore.json", "checkpoint-producer-provenance.json",
    "checkpoint-source-verification.json", "checkpoint-round28-parent-provenance.json",
    PROOF, "checkpoint-segment-frontier.json",
}
STATE = re.compile(
    r"(?:\.ninja_(?:deps|log)(?:\.(?:old|recompact|restat))?"
    r"|\.siso_(?:deps|fs_state|filegroups|config|lock|port)(?:\.journal)?(?:\.[0-9]+)?"
    r"|siso(?:\.[0-9]+)?\.(?:INFO|WARNING|ERROR)"
    r"|siso_(?:build|trace|metadata|result)(?:\.[0-9]+)?\.(?:json|pprof)"
    r"|siso_(?:explain|crash|localexec|output|spawn_helper)(?:\.[0-9]+)?)"
)


def meta(name):
    return name in RECEIPTS or bool(STATE.fullmatch(name))


def digest_stream(stream):
    h = hashlib.sha256()
    for b in iter(lambda: stream.read(1024 * 1024), b""):
        h.update(b)
    return h.hexdigest()


def record(mode, size, digest):
    return f"f:{mode & 0o111}:{size}:{digest}"


def link_record(target):
    return "l:" + hashlib.sha256(os.fsencode(target)).hexdigest()


def inventory(out, exclude=None):
    rows = {}
    def fail_scan(error):
        raise error

    for root, dirs, files in os.walk(out, followlinks=False, onerror=fail_scan):
        for name in list(dirs):
            if (Path(root) / name).is_symlink():
                dirs.remove(name)
                files.append(name)
        for name in files:
            p = Path(root) / name
            rel = p.relative_to(out).as_posix()
            if meta(rel) or p == exclude:
                continue
            st = p.lstat()
            if stat.S_ISLNK(st.st_mode):
                rows[rel] = link_record(os.readlink(p))
            elif stat.S_ISREG(st.st_mode):
                with p.open("rb") as stream:
                    rows[rel] = record(st.st_mode, st.st_size, digest_stream(stream))
            else:
                raise ValueError("Unexpected output type: " + rel)
            if len(rows) > MAX_ENTRIES:
                raise ValueError("Output content inventory exceeded checkpoint entry quota")
    return rows


def commitment(rows):
    h = hashlib.sha256()
    for k in sorted(rows):
        h.update(json.dumps([k, rows[k]], ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
    return {"files": len(rows), "sha256": h.hexdigest()}


def compare_payload(parent, child, successful):
    if missing := parent.keys() - child.keys():
        raise ValueError("Previously present payload disappeared: " + min(missing))
    changed = {name for name, rec in parent.items() if rec != child[name]}
    if unknown := changed - successful:
        raise ValueError("Unaccounted retained output replacement: " + min(unknown))
    return sorted(changed)


def archive_path(raw):
    name = PurePosixPath(raw)
    if name.parts[:2] != ("out", "Bare") or ".." in name.parts or "\\" in raw:
        raise ValueError("Unexpected archive path")
    return "/".join(name.parts[2:])


@contextlib.contextmanager
def decode(path, codec):
    # These archives are already byte-identified. Never unpack onto the runner.
    with subprocess.Popen([codec, "-dc", "--", str(path)], stdout=subprocess.PIPE) as p:
        try:
            yield p.stdout
            # Include the archive trailer in the decoder's integrity checks.
            while p.stdout.read(1024 * 1024):
                pass
            if p.wait():
                raise ValueError("Checkpoint decompression failed")
        finally:
            p.stdout.close()
            if p.poll() is None:
                p.kill()


def archived(path, codec, expected, *, load_original_proof=False):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid archive identity")
    with path.open("rb") as src:
        if digest_stream(src) != expected:
            raise ValueError("Encoded checkpoint SHA mismatch")
    rows, links, proof, used = {}, {}, None, 0
    names = set()
    with decode(path, codec) as raw, tarfile.open(fileobj=raw, mode="r|") as tar:
        for entry in tar:
            name = archive_path(entry.name)
            used += entry.size
            if name in names or len(names) >= MAX_ENTRIES or used > MAX_RAW:
                raise ValueError("Duplicate member or checkpoint quota exceeded")
            names.add(name)
            if name == PROOF and load_original_proof:
                if not entry.isfile() or entry.size > 64*1024**2:
                    raise ValueError("Invalid historical graph proof")
                proof = json.load(tar.extractfile(entry))
            if entry.isdir() or meta(name):
                continue
            if entry.isfile():
                rows[name] = record(entry.mode, entry.size, digest_stream(tar.extractfile(entry)))
            elif entry.issym():
                rows[name] = link_record(entry.linkname)
            elif entry.islnk():
                links[name] = archive_path(entry.linkname)
            else:
                raise ValueError("Unexpected checkpoint type: " + name)
    for name in links:
        key = name
        visited = set()
        while key in links and key not in rows:
            if key in visited:
                raise ValueError("Cyclic hardlink")
            visited.add(key)
            key = links[key]
        if key not in rows or not rows[key].startswith("f:"):
            raise ValueError("Hardlink does not resolve to an authenticated regular output")
        for key2 in visited:
            rows[key2] = rows[key]
    return rows, proof


def archives(parent_path, child_path, parent_sha, child_sha):
    if parent_sha != S2:
        raise ValueError("The historical continuity check requires the fixed S2 parent")
    parent, _ = archived(parent_path, "gzip", parent_sha)
    child, proof = archived(child_path, "zstd", child_sha, load_original_proof=True)
    # The previously accepted one-edge trial selects a missing .o, so no existing
    # file is authorized to change except another declared output of its same edge.
    if (not isinstance(proof, dict) or proof.get("format") != "bare-28-apk-frontier-1"
            or proof.get("target") != "chrome_public_apk" or not isinstance(proof.get("outputs"), dict)):
        raise ValueError("No accepted v1 single-edge proof")
    target = proof["target_path"]
    if target not in proof["outputs"] or target in parent or not target.endswith(".o"):
        raise ValueError("Historical trial did not select a missing object")
    for name, item in proof["outputs"].items():
        if (not isinstance(item,list) or len(item) != 2 or name not in child
                or not child[name].startswith("f:") or child[name].split(":")[2:] != [str(item[0]), item[1]]):
            raise ValueError("Historical output group does not match archived bytes")
    replacements = compare_payload(parent, child, set(proof["outputs"]))
    return {"parent_sha":parent_sha, "child_sha":child_sha, "parent_content":commitment(parent),
            "child_content":commitment(child), "matched_before":len(parent)-len(replacements),
            "replaced":replacements, "new_files":len(child)-len(parent)}


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    p=parser.add_subparsers(dest="mode",required=True).add_parser("archives")
    p.add_argument("--parent",type=Path,required=True)
    p.add_argument("--child",type=Path,required=True)
    p.add_argument("--parent-sha",required=True)
    p.add_argument("--child-sha",required=True)
    args=parser.parse_args()
    print(json.dumps(archives(args.parent,args.child,args.parent_sha,args.child_sha),sort_keys=True))
