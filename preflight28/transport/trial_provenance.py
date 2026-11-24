"""Bind the actual PR executable recipe to the fixed S2 producer, and export only its receipt."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

FORMAT = "bare-r28-trial-provenance-v1"
WORKFLOW = ".github/workflows/bare-r28-s2-recovery.yml"
OLD = "bf70ddbf474f3390a62220a076b8c43347fecc64"
S2 = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
FILE = "checkpoint-round28-trial-provenance.json"
LEGACY = {
    "checkpoint.py": "20ca6c2f1ac6862e730ec06575e3cd009673e34a833610b1b7bc9c10fca4683d",
    "build_trial.py": "5102b18404ccdfe8071549f411e28f75f1b10dec7d0f6007056339dc8e94094a",
    "coexist_inputs.py": "0ca8a1136dbe23c3f4c70c1e2f47ddd7ce1b3f19b57ccbd6f0e33d00dc18f183",
    "bare-arm64-probe.yml": "7f4ba3e8ff94e91777a4bf0b400bfc0e4250cafaa485ad43b050818ea565911b",
    "bare-checkpoint-transfer.yml": "5cfc45c4033c052330ff00247ccde69f800828539df879f9eddd04800b039407",
}
CORE = ("preflight28/graph/graph.py", "preflight28/graph/retained.py","preflight28/limits/guard.py",
        "preflight28/transport/trial_provenance.py", "preflight28/transport/prepare.py",
        "preflight28/transport/build-tail.sh", "preflight28/bridge/check_archive.py")
EXPORTS = {"child-provenance.json", "graph-sha.txt", "trial-provenance-sha.txt"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(row):
    return json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"


def checked(ok, why):
    if not ok:
        raise ValueError(why)


def expected(root, head, script, document, pinned):
    checked(re.fullmatch("[0-9a-f]{40}",head) and subprocess.check_output(
        ["git","-C",str(root),"rev-parse","HEAD"],text=True).strip()==head, "Unexpected PR checkout")
    def blob(path):
        return subprocess.check_output(["git","-C",str(root),"show",head+":"+path])
    workflow = blob(WORKFLOW)
    checked(workflow == (root/WORKFLOW).read_bytes(), "Workflow differs from immutable head")
    inputs = {}
    # Independently parse the exact heredoc program literals of the committed
    # workflow, including the separate reader/writer when only a subset is staged.
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            lines = step.get("run","").splitlines()
            for i,line in enumerate(lines):
                m = re.fullmatch(r"cat > (preflight28/[a-zA-Z0-9_./-]+) <<'([A-Za-z0-9_]+)'", line)
                if not m:
                    continue
                name, marker = m.groups()
                checked(".." not in Path(name).parts, "Invalid staged source path")
                end = lines.index(marker, i+1)
                raw = ("\n".join(lines[i+1:end])+"\n").encode()
                h = sha(raw)
                checked(inputs.setdefault(name,h)==h, "Different staged bytes at " + name)
                if (root/name).exists():
                    checked((root/name).read_bytes()==raw, "Executing helper differs from immutable workflow: "+name)
    # The recovery entry checks out its exact head rather than embedding all
    # sources. Include the implementation set for all three roles (incl. the
    # transfer/fallback helpers that run after the compiler VM has stopped).
    names = subprocess.check_output(["git","-C",str(root),"ls-tree","-r","--name-only",head,"--","preflight28"],text=True).splitlines()
    for name in names:
        path = Path(name)
        if path.suffix not in (".sh",".py") or path.name.startswith("test_"):
            continue
        raw = blob(name)
        checked((root/name).is_file() and (root/name).read_bytes()==raw, "Staged implementation differs: "+name)
        checked(inputs.setdefault(name,sha(raw))==sha(raw), "Embedded and tracked implementations differ: "+name)
    for name in CORE:
        checked((root/name).is_file(), "Missing required trial helper: " + name)
        if name not in inputs:
            raw = blob(name)
            checked(raw == (root/name).read_bytes(), "Local helper differs from immutable commit: " + name)
            inputs[name] = sha(raw)
    for filename, digest in pinned:
        name = ".github/workflows/" + filename
        checked(sha(blob(name)) == digest == sha((root/name).read_bytes()), "Pinned environment recipe mismatch")
        inputs[name] = digest
    return {"format":FORMAT,"source_revision":head,"s2_producer_revision":OLD,"s2_archive_sha256":S2,
            "trial_workflow":{"path":WORKFLOW,"sha256":sha(workflow)}, "inputs":inputs,"legacy_ci":LEGACY,
            "effective_script_sha256":sha(script.encode()),"graph_format":"bare-28-apk-frontier-2"}


def write_private(path, payload):
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(payload)


def export(path, payload):
    checked(path.name in EXPORTS, "Refused non-receipt export")
    fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd,"wb") as f:
        f.write(payload)
        f.flush()
        os.fchmod(f.fileno(),0o644)


def finish(out, exchange, mode):
    checked(mode in ("produce","receive"), "Invalid trial provenance operation")
    base = json.loads((exchange / "trial-inputs.json").read_bytes())
    checked(base["source_revision"]==os.environ["TRIAL_SHA"] and base["legacy_ci"]==LEGACY
            and base["format"]==FORMAT, "Unbound trial inputs")
    for name, val in LEGACY.items():
        checked(sha((exchange/name).read_bytes())==val,"Effective legacy helper differs: "+name)
    for name in CORE[:4]:
        checked(sha((exchange/Path(name).name).read_bytes())==base["inputs"][name],
                "Effective builder helper differs: "+name)
    graph = (out/"checkpoint-round28-graph.json").read_bytes()
    checked(json.loads(graph)["format"]==base["graph_format"], "Incorrect APK graph proof version")
    prov = json.loads((out/"checkpoint-provenance.json").read_bytes())
    ci = prov["identity"]["ci_revision"]; ident=prov["identity_sha256"]
    checked(ci==base["source_revision"] and re.fullmatch(r"[0-9a-f]{64}",ident)
            and sha(encoded(prov["identity"]).rstrip(b"\n"))==ident, "Invalid child effective identity")
    payload = encoded({**base,"graph_sha256":sha(graph),"child_identity":ident})
    if mode == "produce":
        write_private(out/FILE,payload)
    else:
        checked((out/FILE).read_bytes()==payload, "Archived trial provenance differs from executing receipt")
    dest = exchange/"checkpoint"
    # Only non-secret scalar receipts cross UID. The archived raw identity and graph stay private.
    export(dest/"child-provenance.json",encoded({"identity_sha256":ident,"identity":{"ci_revision":ci}}))
    export(dest/"graph-sha.txt",(sha(graph)+"\n").encode())
    export(dest/"trial-provenance-sha.txt",(sha(payload)+"\n").encode())


def fixture_write(folder):
    # Reproduce checkpoint.py's 0600 writes under the strictest actor umask.
    os.umask(0o077)
    write_private(folder/"private-source",b"private fixture only")
    write_private(folder/"private-data",b"private synthetic metadata")
    for name in EXPORTS:
        export(folder/name, encoded({"fixture": True}))
    try:
        export(folder/"other.json", b"not approved")
    except ValueError:
        pass
    else:
        raise ValueError("Unknown receipt unexpectedly exportable")


def fixture_read(folder):
    for name in EXPORTS:
        p=folder/name
        checked(p.read_bytes()==encoded({"fixture":True}) and stat.S_IMODE(p.stat().st_mode)==0o644,
                "Cross-UID allowed receipt was not readable")
        try:
            p.open("ab").close()
        except PermissionError:
            pass
        else:
            raise ValueError("Reader can write builder receipt")
    for name in ("private-source", "private-data"):
        try:
            (folder/name).open("rb").close()
        except PermissionError:
            continue
        raise ValueError("Reader can access private builder file")
    checked(not (folder/"other.json").exists(), "Unapproved export exists")
    print(f"uid_boundary=passed reader_uid={os.getuid()} builder_uid={(folder/'private-source').stat().st_uid} public_receipts=3 private_controls=2")


if __name__=="__main__":
    if len(sys.argv)==3 and sys.argv[1] in ("fixture-write","fixture-read"):
        {"fixture-write":fixture_write,"fixture-read":fixture_read}[sys.argv[1]](Path(sys.argv[2]))
    else:
        phase, = sys.argv[1:]
        finish(Path("out/Bare"),Path("/exchange"),phase)
