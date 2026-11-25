"""Content continuity of quiescent build outputs, including outputs outside the witness sample."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
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
    PROOF, "checkpoint-segment-frontier.json", "checkpoint-round28-trial-provenance.json",
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


DIAGNOSTIC = "gn_logs.txt"
DIAGNOSTIC_PRODUCER = "//BUILD.gn:1662-1672"
CHROMIUM = "800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6"
GN_BUILD_SHA = "31f8205fe64264c5b4f9638eb6552e558ccf78a4839413a7c1a194116f26e72e"
GN_HEADER = "Generated during 'gn gen' by //BUILD.gn."
TOKEN = DIAGNOSTIC.encode()
MAX_LOG = 256 * 1024


def graph_input(name):
    return (name.endswith((".ninja", ".ninja.d", ".dd", ".d", ".rsp", ".depfile", ".params"))
            or re.fullmatch(r"\.(?:ninja_deps|siso_deps)(?:\.[\w.-]+)?", name) is not None)


class ArchiveEvidence:
    def __init__(self, root):
        self.root = root
        self.members = {}
        self.references = set()
        self.unreadable_graph = set()
        self.aliases = set()
        self.log = None
        self.manifests = {}
        self.proof = None

    def read(self, name, entry, source, capture_proof):
        h = hashlib.sha256()
        is_graph = graph_input(name)
        stage = name.endswith(".ninja")
        capture = (name == DIAGNOSTIC and entry.size <= MAX_LOG) or capture_proof
        captured = bytearray()
        overlap = b""
        with contextlib.ExitStack() as stack:
            if stage:
                target = self.root / name
                target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                writer = stack.enter_context(target.open("xb"))
            for block in iter(lambda: source.read(1024 * 1024), b""):
                h.update(block)
                if stage:
                    writer.write(block)
                if capture:
                    captured.extend(block)
                if is_graph:
                    if TOKEN in overlap + block:
                        self.references.add(name)
                    overlap = block[-(len(TOKEN)-1):]
        identity = record(entry.mode, entry.size, h.hexdigest())
        if stage:
            self.manifests[name] = identity
        if name == DIAGNOSTIC and capture and not entry.mode & 0o111:
            self.log = bytes(captured)
        if capture_proof:
            self.proof = json.loads(captured)
        return identity

    def prove_diagnostic(self):
        if self.log is None or self.aliases or self.references or self.unreadable_graph:
            raise ValueError("unable to demonstrate isolated regular GN diagnostic: "
                             + repr(sorted(self.aliases | self.references | self.unreadable_graph)[:8]))
        try:
            lines = self.log.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError("GN log is not UTF-8") from exc
        if (not lines or lines[0] != GN_HEADER or "\x00" in self.log.decode()
                or not any("get_concurrent_links.py" in line and line.startswith("#") for line in lines)):
            raise ValueError("GN log lacks fixed producer markers")
        if "build.ninja" not in self.manifests:
            raise ValueError("no root manifest to demonstrate GN diagnostic independence")
        cmd = [os.environ.get("NINJA", "ninja"), "-C", str(self.root), "-t", "query"]
        try:
            apk = subprocess.run(cmd+["chrome_public_apk"], capture_output=True, timeout=150)
            log = subprocess.run(cmd+[DIAGNOSTIC], capture_output=True, timeout=150)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("failed to parse complete Ninja graph with the read-only query tool") from exc
        if (apk.returncode != 0 or not re.search(rb"(?m)^chrome_public_apk:$", apk.stdout)
                or log.returncode != 1 or not re.fullmatch(
                    rb"ninja: error: unknown target 'gn_logs\.txt'(?:, did you mean '[^\r\n]+'\?)?",
                    log.stderr.strip())):
            raise ValueError("Ninja graph did not confirm the APK target and unknown GN diagnostic")
        sections = {}
        section = "<header>"
        for line in lines:
            if re.fullmatch(r"#{2,}\s*[^#]+?\s*#{2,}", line):
                section = line.strip("# ").strip()
            sections.setdefault(section, []).append(line)
        return {"chromium":CHROMIUM, "build_gn_sha256":GN_BUILD_SHA,
                "target":"chrome_public_apk", "diagnostic_query":"unknown target",
                "manifest_content":commitment(self.manifests), "graph_references":0, "aliases":0,
                "sections":{k:{"lines":len(v),"sha256":hashlib.sha256(
                    json.dumps(v, ensure_ascii=True,separators=(",",":")).encode("ascii")).hexdigest()}
                    for k,v in sections.items()}}


def archived(path, codec, expected, evidence, *, load_original_proof=False):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid archive identity")
    with path.open("rb") as src:
        if digest_stream(src) != expected:
            raise ValueError("Encoded checkpoint SHA mismatch")
    rows, links, used = {}, {}, 0
    members = evidence.members
    with decode(path, codec) as raw, tarfile.open(fileobj=raw, mode="r|") as tar:
        for entry in tar:
            name = archive_path(entry.name)
            used += entry.size
            if name in members or len(members) >= MAX_ENTRIES or used > MAX_RAW:
                raise ValueError("Duplicate member or checkpoint quota exceeded")
            capture = name == PROOF and load_original_proof
            if capture and (not entry.isfile() or entry.size > 64*1024**2):
                raise ValueError("Invalid historical graph proof")
            if entry.isdir():
                members[name] = "d"
                continue
            if entry.isfile():
                identity = evidence.read(name, entry, tar.extractfile(entry), capture)
            elif entry.issym() or entry.islnk():
                if DIAGNOSTIC in PurePosixPath(entry.linkname).parts or name == DIAGNOSTIC:
                    evidence.aliases.add(name)
                if graph_input(name):
                    evidence.unreadable_graph.add(name)
                if entry.issym():
                    identity = link_record(entry.linkname)
                else:
                    links[name] = archive_path(entry.linkname)
                    identity = "h:" + links[name]
            else:
                raise ValueError("Unexpected checkpoint type: " + name)
            members[name] = identity
            if not meta(name):
                rows[name] = identity
    for name in links:
        key = name
        visited = set()
        while key in links:
            if key in visited:
                raise ValueError("Cyclic hardlink")
            visited.add(key)
            key = links[key]
        if key not in members or not members[key].startswith("f:"):
            raise ValueError("Hardlink does not resolve to an authenticated regular output")
        for item in visited:
            if not meta(item):
                if meta(key):
                    raise ValueError("Payload hardlink resolves only to bookkeeping")
                rows[item] = members[key]
    return rows, evidence.proof


def archives(parent_path, child_path, parent_sha, child_sha, *, report_path=None):
    if parent_sha != S2:
        raise ValueError("The historical continuity check requires the fixed S2 parent")
    with tempfile.TemporaryDirectory(prefix="r28-graph-") as a, tempfile.TemporaryDirectory(prefix="r28-graph-") as b:
        pe, ce = ArchiveEvidence(Path(a)), ArchiveEvidence(Path(b))
        parent, _ = archived(parent_path, "gzip", parent_sha, pe)
        child, proof = archived(child_path, "zstd", child_sha, ce, load_original_proof=True)
        if (not isinstance(proof, dict) or proof.get("format") not in {"bare-28-apk-frontier-1", "bare-28-apk-frontier-2"}
                or proof.get("target") != "chrome_public_apk" or not isinstance(proof.get("outputs"), dict)):
            raise ValueError("No accepted versioned single-edge proof")
        target = proof["target_path"]
        if target not in proof["outputs"] or target in parent or not target.endswith(".o"):
            raise ValueError("Historical trial did not select a missing object")
        issues = []
        approved = set()
        for name, item in proof["outputs"].items():
            if (not isinstance(item,list) or len(item) != 2 or name not in child
                    or not child[name].startswith("f:") or child[name].split(":")[2:] != [str(item[0]), item[1]]):
                issues.append("Historical output group does not match archived bytes: " + name)
            else:
                approved.add(name)
        child_content = commitment(child)
        if proof["format"] == "bare-28-apk-frontier-2" and proof.get("child_content") != child_content:
            issues.append("Archive differs from complete producer quiescent content commitment")
        counts = dict.fromkeys(("unchanged", "added", "removed", "completed_replacement", "gn_diagnostic",
                                "unclassified", "bookkeeping", "directory"), 0)
        differences, diagnostics, replacements = [], [], []
        for name in sorted(pe.members.keys() | ce.members.keys()):
            old, new = pe.members.get(name), ce.members.get(name)
            if meta(name):
                category = "bookkeeping"
            elif old in {"d", None} and new in {"d", None}:
                category = "directory"
            elif name in parent and name not in child:
                category = "removed"
            elif name in child and name not in parent:
                category = "added"
            elif parent[name] == child[name]:
                # Classify a hardlink representation change separately in the detailed diff.
                category = "unchanged"
            elif name == DIAGNOSTIC:
                category = "unclassified"
                try:
                    if proof["format"] != "bare-28-apk-frontier-2":
                        raise ValueError("GN migration requires original v2 commitment")
                    before, after = pe.prove_diagnostic(), ce.prove_diagnostic()
                    changed = sorted(k for k in before["sections"].keys() | after["sections"].keys()
                                     if before["sections"].get(k) != after["sections"].get(k))
                    diagnostics.append({"path":name, "parent":old, "child":new, "producer":DIAGNOSTIC_PRODUCER,
                                        "evidence":{"parent":before, "child":after, "changed_sections":changed}})
                    category = "gn_diagnostic"
                except ValueError as exc:
                    issues.append(str(exc))
            elif name in approved:
                category = "completed_replacement"
                replacements.append(name)
            else:
                category = "unclassified"
            if category not in {"bookkeeping", "directory"} or old != new:
                counts[category] += 1
            if old != new or category in {"removed", "unclassified", "completed_replacement", "gn_diagnostic"}:
                row = {"path":name,"classification":category,"parent":old,"child":new}
                if old and old.startswith("h:"):
                    row["parent_resolved"] = parent.get(name)
                if new and new.startswith("h:"):
                    row["child_resolved"] = child.get(name)
                differences.append(row)
        if counts["unclassified"] or counts["removed"]:
            names = [x["path"] for x in differences if x["classification"] in {"unclassified","removed"}]
            issues.append("Unaccounted retained replacement or disappearance: " + repr(names[:8]))
        report = {"schema":"bare-r28-archive-continuity-v3", "status":"rejected" if issues else "passed",
                  "parent_sha":parent_sha, "child_sha":child_sha, "parent_content":commitment(parent),
                  "child_content":child_content, "matched_before":counts["unchanged"], "replaced":replacements,
                  "new_files":counts["added"], "counts":counts, "diagnostics":diagnostics,
                  "differences":differences, "issues":issues}
        if report_path is not None:
            with open(report_path, "w", encoding="utf-8") as stream:
                json.dump(report,stream,sort_keys=True)
        if issues:
            raise ValueError(" | ".join(issues) + " counts=" + json.dumps(counts,sort_keys=True))
        return report


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    p=parser.add_subparsers(dest="mode",required=True).add_parser("archives")
    p.add_argument("--parent",type=Path,required=True)
    p.add_argument("--child",type=Path,required=True)
    p.add_argument("--parent-sha",required=True)
    p.add_argument("--child-sha",required=True)
    p.add_argument("--report",type=Path)
    args=parser.parse_args()
    result = archives(args.parent,args.child,args.parent_sha,args.child_sha,report_path=args.report)
    print(json.dumps({k:v for k,v in result.items() if k not in {"differences","diagnostics"}},sort_keys=True))
