"""Recognize bounded JSONL diagnostics from Chromium's pinned Siso v1.6.5."""
import hashlib
import json
import re
import stat

REVISION = "b521b230cb7c56c821235e498285cf8e548a73ee"
# siso/subcmd/ninja/{config.go,log.go}: rotateFiles inserts 0..9 before ".json".
NAME = re.compile(r"siso_metrics(?:\.[0-9])?\.json", re.ASCII)
ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.ASCII)
# A header, an unbounded allocation, or an oversized file cannot get an exception
# to ordinary archived-output equality. Read one bounded row at a time.
MAX_BYTES = 128 * 1024**2
MAX_ROW = 2 * 1024**2

# StepMetric and MetricSpan in siso/build/metrics.go at REVISION.
STRINGS = set("step_id rule action gn_target prev cmdhash digest racing_winner worker_pool "
              "two_phase_caching_key".split())
FLAGS = set("scandeps_err clang_scandeps no_exec is_remote is_local sandbox fast_local "
            "start_local cache_write cache_write_err cached fallback racing err two_phase_cache_hit".split())
NUMBERS = set("ready_nanos start_nanos duration_nanos weighted_duration_nanos remote_retry "
              "depsscan_nanos action_start_nanos scandeps_start_nanos scandeps_nanos "
              "cache_start_nanos cache_nanos materialize_inputs_nanos materialize_outputs_nanos "
              "two_phase_caching_actions run_nanos queue_nanos exec_start_nanos input_fetch_nanos "
              "exec_nanos worker_nanos output_upload_nanos action_end_nanos inputs max_rss "
              "majflt inblock oublock utime_nanos stime_nanos".split())
STEP = STRINGS | FLAGS | NUMBERS | {"outputs", "spans"}
SUMMARY = {"build_id", "duration_nanos", "err"}


def metrics_name(name):
    return isinstance(name, str) and NAME.fullmatch(name) is not None


def _object(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate Siso metrics field")
    return obj


def _text(value):
    return isinstance(value, str) and bool(value) and not any(ord(c) < 32 for c in value)


def _int(value):
    return type(value) is int and -(2**63) <= value < 2**63


def _kind(row):
    if not isinstance(row, dict):
        raise ValueError("Siso metric row is not an object")
    if "build_id" in row:
        if (not row.keys() <= SUMMARY or not isinstance(row["build_id"], str)
                or not ID.fullmatch(row["build_id"])
                or not _int(row.get("duration_nanos")) or row["duration_nanos"] < 0
                or ("err" in row and type(row["err"]) is not bool)):
            raise ValueError("unknown Siso build-summary schema")
        return "summary"
    if (not row.keys() <= STEP or not isinstance(row.get("step_id"), str)
            or not ID.fullmatch(row["step_id"]) or not _text(row.get("action"))
            or not _int(row.get("duration_nanos")) or row["duration_nanos"] < 0):
        raise ValueError("unknown Siso step schema")
    for key, value in row.items():
        if ((key in STRINGS and not _text(value)) or (key in FLAGS and type(value) is not bool)
                or (key in NUMBERS and not _int(value))):
            raise ValueError("incorrect Siso step metric type: " + key)
        if key == "outputs" and (not isinstance(value, list) or not value or not all(map(_text, value))):
            raise ValueError("invalid Siso metric outputs")
        if key == "spans":
            if not isinstance(value, list) or not value:
                raise ValueError("invalid Siso span list")
            for span in value:
                if (not isinstance(span, dict) or span.keys() != {"name", "start_ns", "duration_ns"}
                        or not _text(span["name"]) or not _int(span["start_ns"])
                        or not _int(span["duration_ns"])):
                    raise ValueError("invalid Siso metric span")
    return "step"


def inspect_metrics(name, mode, size, stream, *, regular=True, observe=None):
    """Read the original regular archive member, returning its identity and typed facts."""
    if (not metrics_name(name) or not regular or type(mode) is not int
            or stat.S_IFMT(mode) not in (0, stat.S_IFREG) or mode & 0o7111
            or type(size) is not int or size < 0 or size > MAX_BYTES):
        raise ValueError("unexpected Siso metric member name, type, mode or size")
    h = hashlib.sha256()
    steps = summaries = error_steps = used = 0
    build_id = first_id = last_id = None
    build_error = None
    elapsed = -1
    while line := stream.readline(MAX_ROW + 1):
        used += len(line)
        if (used > size or len(line) > MAX_ROW or not line.endswith(b"\n")
                or not line.startswith(b"{") or not line.endswith(b"}\n")):
            raise ValueError("invalid Siso JSONL frame")
        h.update(line)
        try:
            row = json.loads(line.decode("utf-8"), object_pairs_hook=_object)
        except (UnicodeError, RecursionError, ValueError) as exc:
            raise ValueError("invalid Siso JSONL row") from exc
        if observe is not None:
            observe(row)  # An optional caller can inspect a decoded row before schema rejection.
        if _kind(row) == "summary":
            # A generator edge for build.ninja adds manifest build phases in the
            # SAME invocation. Each records its own time.Since(buildStart).
            if ((build_id is not None and row["build_id"] != build_id)
                    or row["duration_nanos"] <= elapsed):
                raise ValueError("unrelated or reordered Siso build phases")
            elapsed = row["duration_nanos"]
            summaries += 1
            build_id = row["build_id"]
            build_error = row.get("err", False)
        else:
            steps += 1
            error_steps += int(row.get("err", False))
            last_id = row["step_id"]
            if first_id is None:
                first_id = last_id
    if used != size:
        raise ValueError("Siso metric member shorter than authenticated size")
    return {"producer_revision": REVISION, "version": "1.6.5", "schema": "siso.StepMetric.jsonl",
            "name": name, "mode": stat.S_IMODE(mode), "size": used, "sha256": h.hexdigest(),
            "step_rows": steps, "summary_rows": summaries, "error_steps": error_steps,
            "first_step_id": first_id, "last_step_id": last_id, "build_id": build_id,
            "build_error": build_error, "last_summary_nanos": elapsed if summaries else None}
