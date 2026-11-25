"""Content continuity of quiescent build outputs, including outputs outside the witness sample."""
import argparse
import contextlib
import hashlib
import base64
import io
import importlib.util
from functools import lru_cache
import posixpath
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


METRICS = ["siso_metrics.json"] + [f"siso_metrics.{i}.json" for i in range(10)]
METRIC_TOKEN = re.compile(rb"siso_metrics(?:\.[0-9])?\.json")
DESCRIPTORS = {"apks/ChromeAndWebView32.ssargs", "apks/ChromeAndWebView64.ssargs"}
GN_DEPFILE_LIMIT = 8 * 1024**2
GN_REVISION = "0035961837fbcfe875d855744b3eda4fd2eefb43"


@lru_cache(maxsize=1)
def metric_reader():
    # Isolated Python does not add the script directory to its import path.
    path = Path(__file__).resolve().with_name("metrics_evidence.py")
    spec = importlib.util.spec_from_file_location("r28_fixed_metric_schema", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.inspect_metrics


def regeneration_inputs(data):
    # Match the one make-style statement emitted by the fixed GN writer.
    lines = data.decode("utf-8").replace("\\\n", "").strip().splitlines()
    if len(lines) != 1 or not lines[0].startswith("build.ninja.stamp: "):
        raise ValueError("Unexpected GN regeneration depfile target or multiple rules")
    rhs = lines[0].split(":", 1)[1]
    words = re.findall(r"(?:\\.|[^\\\s])+", rhs)
    root = "/work/chromium/src/out/Bare"
    return [posixpath.relpath(posixpath.normpath(posixpath.join(root,
                re.sub(r"\\(.)", r"\1", w))),root) for w in words]


class ArchiveEvidence:
    def __init__(self, root):
        self.root = root
        self.members = {}
        self.references = set()
        self.metric_references = {}
        self.unreadable_graph = set()
        self.aliases = set()
        self.metric_aliases = set()
        self.log = None
        self.samples = {}
        self.gn_depfile = None
        self.manifests = {}
        self.proof = None
        self.query_cache = set()
        self.native_queries = {}

    def read(self, name, entry, source, capture_proof):
        h = hashlib.sha256()
        is_graph = graph_input(name)
        stage = name.endswith(".ninja")
        tiny = name in [DIAGNOSTIC, *METRICS] and entry.size <= MAX_LOG
        capture = tiny or (name == "build.ninja.d" and entry.size <= GN_DEPFILE_LIMIT) or capture_proof
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
                    chunk = overlap + block
                    if TOKEN in chunk:
                        self.references.add(name)
                    if b"siso_metrics" in chunk:
                        for token in METRIC_TOKEN.findall(chunk):
                            self.metric_references.setdefault(token.decode("ascii"), set()).add(name)
                    overlap = chunk[-32:]
        identity = record(entry.mode, entry.size, h.hexdigest())
        if stage:
            self.manifests[name] = identity
        if name == DIAGNOSTIC and capture and not entry.mode & 0o111:
            self.log = bytes(captured)
        if tiny:
            self.samples[name] = (entry.mode, bytes(captured))
        if name == "build.ninja.d" and capture:
            self.gn_depfile = bytes(captured)
        if capture_proof:
            self.proof = json.loads(captured)
        return identity

    def unknown(self, name):
        if name in self.query_cache:
            return
        cmd = [os.environ.get("NINJA", "ninja"), "-C", str(self.root), "-t", "query"]
        if "build.ninja" not in self.manifests:
            raise ValueError("no root Ninja manifest")
        try:
            if "chrome_public_apk" not in self.query_cache:
                apk = subprocess.run(cmd+["chrome_public_apk"], capture_output=True, timeout=150)
                self.native_queries["chrome_public_apk"]=self.query_sample(apk)
                if apk.returncode or not re.search(rb"(?m)^chrome_public_apk:$", apk.stdout):
                    raise ValueError("Ninja query could not resolve the pinned APK target")
                self.query_cache.add("chrome_public_apk")
            q = subprocess.run(cmd+[name], capture_output=True, timeout=150)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError("could not run native read-only Ninja query") from exc
        self.native_queries[name]=self.query_sample(q)
        expected = rb"ninja: error: unknown target '" + re.escape(name.encode("ascii")) + rb"'(?:, did you mean '[^\r\n]+'\?)?"
        if q.returncode != 1 or not re.fullmatch(expected,q.stderr.strip()):
            raise ValueError("File is declared in Ninja graph or query failed: " + name)
        self.query_cache.add(name)

    @staticmethod
    def query_sample(q):
        return {"returncode":q.returncode, "stdout":q.stdout[:768].decode("utf-8","replace"),
                "stderr":q.stderr[:1536].decode("utf-8","replace")}

    def generator_input(self, name):
        if self.gn_depfile is None:
            raise ValueError("GN regeneration depfile missing or too large")
        graph = (self.root / "build.ninja").read_bytes()
        rule = b"build build.ninja.stamp: gn\n  generator = 1\n  depfile = build.ninja.d\n"
        phony = b"build build.ninja: phony build.ninja.stamp\n  generator = 1\n"
        inputs = regeneration_inputs(self.gn_depfile)
        if (inputs.count(name) != 1 or graph.count(rule) != 1 or graph.count(phony) != 1
                or self.gn_depfile.count(name.encode("ascii")) != 1):
            raise ValueError("Input is not the exact sole normalized RHS entry of the fixed GN regeneration rule: " + name)
        return {"path":"build.ninja.d","target":"build.ninja.stamp","role":"regeneration-input",
                "references":1,"generator":"gn","token":name,"gn_revision":GN_REVISION,
                "sha256":hashlib.sha256(self.gn_depfile).hexdigest()}

    def prove_metric(self, name):
        if (name not in self.samples or self.metric_aliases or self.metric_references.get(name)
                or self.unreadable_graph):
            raise ValueError("Missing regular metrics bytes or declared metrics dependency: "+name)
        self.unknown(name)
        mode, data = self.samples[name]
        result = metric_reader()(name,mode,len(data),io.BytesIO(data),regular=True)
        return {**result, "graph_references":0, "diagnostic_query":"unknown target"}

    def forensic(self):
        # Included only in the restricted report on rejection; it never goes to stdout.
        dep=self.gn_depfile or b""
        manifest=self.root/"build.ninja"
        head=""
        if manifest.is_file():
            with manifest.open("rb") as f:
                head=f.read(3200).decode("utf-8","replace")
        try:
            version=self.query_sample(subprocess.run([os.environ.get("NINJA","ninja"),"--version"],
                                                      capture_output=True,timeout=8))
        except (OSError,subprocess.TimeoutExpired) as exc:
            version={"unavailable":str(exc)}
        return {"regular_samples":{name:{"mode":mode,"size":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                    "base64":base64.b64encode(raw).decode("ascii") if len(raw)<=4096 else None}
                    for name,(mode,raw) in self.samples.items()},
                "gn_depfile":{"sha256":hashlib.sha256(dep).hexdigest(),"size":len(dep),
                    "lhs":dep.split(b":",1)[0][:100].decode("utf-8","replace"),
                    "near_tokens":[dep[max(0,m.start()-72):m.end()+72].decode("utf-8","replace")
                                   for m in list(re.finditer(rb"gn_logs\.txt|ChromeAndWebView(?:32|64)\.ssargs",dep))[:8]]},
                "ninja_references": sorted(self.references),"metrics_references":{
                    k:sorted(v)[:30] for k,v in self.metric_references.items()},
                "root_manifest_header":head,"native_queries":self.native_queries,"native_version":version, "ninja_rules_sha256":self.manifests.get("build.ninja"),"links":sorted(self.aliases|self.metric_aliases)[:30]}

    def prove_diagnostic(self):
        if self.log is None or self.aliases or (self.references - {"build.ninja.d"}) or self.unreadable_graph:
            raise ValueError("unable to demonstrate isolated regular GN diagnostic: "
                             + repr(sorted(self.aliases | self.references | self.unreadable_graph)[:8]))
        matches = self.generator_input(DIAGNOSTIC) if "build.ninja.d" in self.references else None
        try:
            lines = self.log.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise ValueError("GN log is not UTF-8") from exc
        if (not lines or lines[0] != GN_HEADER or "\x00" in self.log.decode()
                or not any("get_concurrent_links.py" in line and line.startswith("#") for line in lines)):
            raise ValueError("GN log lacks fixed producer markers")
        self.unknown(DIAGNOSTIC)
        sections = {}
        section = "<header>"
        for line in lines:
            if re.fullmatch(r"#{2,}\s*[^#]+?\s*#{2,}", line):
                section = line.strip("# ").strip()
            sections.setdefault(section, []).append(line)
        return {"chromium":CHROMIUM, "build_gn_sha256":GN_BUILD_SHA,
                "target":"chrome_public_apk", "diagnostic_query":"unknown target",
                "manifest_content":commitment(self.manifests), "graph_references":0, "aliases":0,
                "regeneration_dependency":matches, "sections":{k:{"lines":len(v),"sha256":hashlib.sha256(
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
                if name in METRICS or set(METRICS).intersection(PurePosixPath(entry.linkname).parts):
                    evidence.metric_aliases.add(name)
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
        differences, diagnostics, replacements, metrics = [], [], [], []
        counts["siso_metrics"] = 0
        metric_rotation = None
        metric_change = any(parent.get(k) != child.get(k) for k in METRICS)
        if metric_change:
            try:
                if (proof["format"] != "bare-28-apk-frontier-2" or not all(k in parent and k in child for k in METRICS)
                        or not all(parent[a]==child[b] for a,b in zip(METRICS, METRICS[3:]))):
                    raise ValueError("Required original byte-for-byte three-step Siso rotation is missing")
                for k in METRICS:
                    metrics.append({"path":k,"parent":parent[k],"child":child[k],
                                    "evidence":{"parent":pe.prove_metric(k),"child":ce.prove_metric(k)}})
                metric_rotation={"steps":3,"matched":8,"bounded_files":11}
            except ValueError as exc:
                metrics=[]
                issues.append(str(exc))
        descriptors={}
        for name in DESCRIPTORS & (child.keys()-parent.keys()):
            try:
                if (not child[name].startswith("f:0:") or not 0<int(child[name].split(":")[2])<=4096
                        or pe.generator_input(name)!=ce.generator_input(name)):
                    raise ValueError("Invalid or changed GN descriptor dependency: "+name)
                descriptors[name]=ce.generator_input(name)
            except (ValueError, OSError) as exc:
                issues.append(str(exc))
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
            elif name in METRICS and metric_rotation:
                category = "siso_metrics"
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
                if name in descriptors:
                    row["role"]="gn-generated-packaging-descriptor"
                    row["regeneration_dependency"]=descriptors[name]
                differences.append(row)
        if counts["unclassified"] or counts["removed"]:
            names = [x["path"] for x in differences if x["classification"] in {"unclassified","removed"}]
            issues.append("Unaccounted retained replacement or disappearance: " + repr(names[:8]))
        report = {"schema":"bare-r28-archive-continuity-v4", "status":"rejected" if issues else "passed",
                  "parent_sha":parent_sha, "child_sha":child_sha, "parent_content":commitment(parent),
                  "child_content":child_content, "matched_before":counts["unchanged"], "replaced":replacements,
                  "new_files":counts["added"], "counts":counts, "diagnostics":diagnostics,
                  "differences":differences, "issues":issues,"metrics":metrics,"metric_rotation":metric_rotation}
        if issues:
            report["forensic"]={"parent":pe.forensic(),"child":ce.forensic()}
        if report_path is not None:
            with open(report_path, "w", encoding="utf-8") as stream:
                json.dump(report,stream,sort_keys=True)
        if issues:
            raise ValueError(" | ".join(issues) + " counts=" + json.dumps(counts,sort_keys=True))
        return report


# Only deterministic extra outputs of this exact Chromium Android handler revision.
FILEARG_RULES = {'android/trace_event_bytecode_rewriter': 'trace_event_bytecode_rewriter.py', 'android/proguard': 'proguard.py'}
STAMP_RULES = {'android/compile_java', 'android/compile_kt', 'android/errorprone', 'android/dex'} | FILEARG_RULES.keys()
ANDROID_RULES_SHA256 = 'ebfbb8b3524aff976c0f9336d53f2efe4eb45ca2874ecf06226a75b0c225b18c'


def stamp_metadata(proof, canonical):
    """Map each evidenced auxiliary output to its ordinary-file size and digest."""
    records = proof.get('runtime_stamps', {})
    if not isinstance(records, dict):
        raise ValueError('Invalid runtime output records')
    closed = {canonical(g): g for g in proof['closed_groups']}
    declared = {name for group in closed.values() for name in group}
    result = {}
    for edge, row in records.items():
        if not isinstance(row, dict) or set(row) != {'rule', 'primary', 'action', 'files', 'fileargs'}:
            raise ValueError('Incomplete runtime output record')
        primary = row['primary']
        if not isinstance(row['action'], str) or not 0 < len(row['action']) <= 512 or row['rule'] not in STAMP_RULES or edge not in closed or primary not in closed[edge]:
            raise ValueError('Unbound runtime output record')
        fileargs = row['fileargs']
        if not isinstance(fileargs, dict) or (fileargs and row['rule'] not in FILEARG_RULES) or len(fileargs) > 64:
            raise ValueError('Unexpected runtime output bindings')
        for loc, digest in fileargs.items():
            name, sep, selector = loc.partition(':')
            if (not sep or not selector or not name.endswith('.json') or not name.startswith(('gen/', 'obj/')) or
                    not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}',digest)):
                raise ValueError('Unbound FileArg selector')
        files = row['files']
        if not isinstance(files, dict) or not (1 <= len(files) <= (1024 if row['rule'] in FILEARG_RULES else 2)):
            raise ValueError('Missing or invalid runtime outputs')
        for name, rec in files.items():
            if row['rule'] in FILEARG_RULES:
                safe = (name.startswith(('gen/', 'obj/')) and name.endswith(('.jar','.dex','.zip')) and
                        PurePosixPath(name).as_posix() == name and '..' not in PurePosixPath(name).parts)
            else:
                safe = name == primary + '.md5.stamp' or (row['rule'] == 'android/dex' and name.endswith('.desugardeps'))
            if not safe:
                raise ValueError('Unexpected runtime output')
            if (name in result or name in declared or not isinstance(rec, list) or len(rec) != 2 or
                    type(rec[0]) is not int or rec[0] < 0 or not re.fullmatch('[0-9a-f]{64}', rec[1])):
                raise ValueError('Ambiguous or invalid runtime output')
            result[name] = rec
    return result


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
    print(json.dumps({k:v for k,v in result.items() if k not in {"differences","diagnostics","metrics","forensic"}},sort_keys=True))
