"""Bind each quiescent output tree and the retired Siso output groups to its transfer."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat


CLOSED = ".r209/closed.json"
PROOF = ".r209/proof.json"
MAX_GROUPS = 525_000
PREFIX = "out/Bare"
GN_SHA = json.loads(Path(__file__).with_name("upstream-lock.json").read_text())["personal_gn_sha256"]


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def digest_stream(source):
    result = hashlib.sha256()
    for block in iter(lambda: source.read(1024 * 1024), b""):
        result.update(block)
    return result.hexdigest()


def add(rows, member, mode, kind, size, value):
    """Called once per validated tar member with its uncompressed file SHA or link text."""
    require(member == PREFIX or member.startswith(PREFIX + "/"), "Wrong output root")
    name = member[len(PREFIX):].lstrip("/")
    # This seal carries its own content commitment; its bytes are bound separately.
    if name == PROOF:
        return
    require(name not in rows and kind in ("dir", "file", "link"), "Invalid output inventory row")
    rows[name] = [kind, mode & 0o7777, size if kind == "file" else 0, value]


def source_rows(out):
    rows = {}

    def visit(path, name):
        s = path.lstat()
        if stat.S_ISREG(s.st_mode):
            with path.open("rb") as f:
                value = digest_stream(f)
            size = s.st_size
            kind = "file"
        elif stat.S_ISLNK(s.st_mode):
            value, size, kind = os.readlink(path), 0, "link"
        elif stat.S_ISDIR(s.st_mode):
            value, size, kind = None, 0, "dir"
        else:
            raise ValueError("Unsupported checkpoint output: " + name)
        add(rows, name, s.st_mode, kind, size, value)
        if kind == "dir":
            for child in path.iterdir():
                if child != out / PROOF:
                    visit(child, name + "/" + child.name)

    visit(out, PREFIX)
    return rows


def content(rows):
    h = hashlib.sha256()
    for name in sorted(rows):
        h.update(canonical([name, *rows[name]]) + b"\n")
    return {"entries": len(rows), "sha256": h.hexdigest()}


def group_map(groups):
    require(isinstance(groups, list) and len(groups) <= MAX_GROUPS, "Invalid Siso edge list")
    edges = {}
    for row in groups:
        require(isinstance(row, list) and len(row) == 2, "Malformed Siso edge")
        names, action = row
        require(isinstance(names, list) and names and all(isinstance(n, str) and n for n in names)
                and names == sorted(set(names)) and isinstance(action, str), "Invalid Siso edge outputs")
        for name in names:
            path = PurePosixPath(name)
            require(path.parts and not path.is_absolute() and path.as_posix() == name
                    and ".." not in path.parts and "\\" not in name and not name.startswith(".r209/")
                    and not any(ord(c) < 32 for c in name), "Invalid Siso output path")
        key = tuple(names)
        require(key not in edges, "Duplicate Siso output group")
        edges[key] = action
    return edges


def as_list(edges):
    return [[list(names), edges[names]] for names in sorted(edges)]


def partitions(closed, pending):
    require(isinstance(closed, dict) and set(closed) == {"previous", "now"}, "Invalid completed groups")
    previous, now, pending = group_map(closed["previous"]), group_map(closed["now"]), group_map(pending)
    require(now and not (previous.keys() & now.keys() or previous.keys() & pending.keys()
                         or now.keys() & pending.keys()), "Inconsistent retired or pending groups")
    return previous, now, pending


def require_outputs(rows, groups):
    for group in groups:
        for name in group:
            row = rows.get(name)
            if name == "devil_util_host":
                target = rows.get("clang_x64/devil_util_bin")
                require(row and row[0] == "link" and row[3] == "clang_x64/devil_util_bin"
                        and target and target[0] == "file" and target[1] & 0o111 and target[2] > 0,
                        "Invalid completed devil_util_host link")
            else:
                require(row and row[0] == "file", "Missing completed Siso output: " + name)


def create(out, before, after, trial):
    """After the trial, git heads and frontier have been written, before writing proof.json."""
    before_map, after_map = group_map(before), group_map(after)
    require(0 < len(after_map) < len(before_map)
            and all(before_map.get(k) == v for k, v in after_map.items()), "Not a strict graph advance")
    closed_file = out / CLOSED
    if trial["phase"] == "restore":
        inherited = json.loads(closed_file.read_bytes())
        previous, latest, _ = partitions(inherited, before)
        inherited_edges = previous | latest
    else:
        require(trial["phase"] == "seed" and not os.path.lexists(closed_file), "Unexpected cold proof")
        inherited_edges = {}
    now = {k: v for k, v in before_map.items() if k not in after_map}
    closed = {"previous": as_list(inherited_edges), "now": as_list(now)}
    closed_file.write_bytes(canonical(closed))
    rows = source_rows(out)
    seal = {"tree": content(rows), "closed": digest(closed), "start_plan": digest(as_list(before_map)),
            "previous": len(inherited_edges), "retired": len(now)}
    verify(rows, {"retained": seal, "graph": graph_id(rows), "before": len(before_map),
                  "remaining": len(after_map), "ordinal": 1 if trial["phase"] == "seed" else 2},
           closed, after, trial, measured=seal["tree"])
    return seal


def graph_id(rows):
    names = sorted((n for n, r in rows.items() if n.endswith(".ninja") and r[0] == "file"),
                   key=PurePosixPath)
    require("build.ninja" in names, "Missing GN graph")
    return digest([[name, rows[name][3]] for name in names])


def regular(rows, name):
    row = rows.get(name)
    require(row and row[0] == "file" and row[2] > 0, "Missing checkpoint state: " + name)
    return row


def verify(rows, proof, closed, frontier, trial, *, measured=None):
    previous, now, pending = partitions(closed, frontier)
    seal = proof["retained"]
    require(len(now) + len(pending) == proof["before"] and len(pending) == proof["remaining"]
            and (proof["ordinal"] != 1 or not previous) and bool(previous) == (proof["ordinal"] > 1)
            and seal["retired"] == len(now) and seal["previous"] == len(previous)
            and seal["start_plan"] == digest(as_list(pending | now)) and seal["closed"] == digest(closed)
            and regular(rows, CLOSED)[3] == seal["closed"], "Unbound completed groups")
    require(seal["tree"] == (measured if measured is not None else content(rows)), "Retained tree differs")
    require(graph_id(rows) == proof["graph"] and regular(rows, "args.gn")[3] == GN_SHA,
            "GN or Personal arguments differ")
    require(regular(rows, ".r209/frontier.json")[3] == digest(frontier)
            and regular(rows, "checkpoint-trial-restore.json")[3] == digest(trial),
            "Archived frontier or trial differs from verification input")
    require_outputs(rows, previous)
    require_outputs(rows, now)
    phase = "seed" if proof["ordinal"] == 1 else "restore"
    command = ["autoninja", "-C", "out/Bare", "-j", "2", "-metrics_json",
               "/exchange/slot209/siso-metrics-" + phase + ".json", "chrome_public_apk"]
    require(trial["format"] == "bare-apk-trial" and trial["version"] == 1 and trial["phase"] == phase
            and trial["target"] == "chrome_public_apk" and trial["command"] == command
            and trial["ready_for_restore_test"] is True and trial["artifact_ready"] is False
            and trial["forced_kill"] is False and trial.get("oom_kill_count", 0) == 0
            and trial["container_quiescence_verified"] is True and not trial.get("controller_error")
            and trial["failed_steps"] == [] and trial["failed_step_count"] == 0
            and trial["reason"] in ("time-limit", "output-limit", "output-entry-limit", "disk-limit")
            and trial["close"]["errors"] == []
            and (trial["close"]["saved"] is True or trial["close"]["journal_ready"] is True),
            "Invalid interrupted target or Siso close evidence")
    regular(rows, ".ninja_log")
    regular(rows, ".siso_deps")
    names = [(".siso_fs_state", "state")]
    if trial["close"]["journal_ready"]:
        names.append((".siso_fs_state.journal", "journal"))
    for name, key in names:
        evidence = trial["close"][key]
        row = regular(rows, name)
        require(evidence and row[2:] == [evidence["size"], evidence["sha256"]], "Siso state differs: " + name)
