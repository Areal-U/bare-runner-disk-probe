#!/usr/bin/env python3
"""Run a bounded APK trial and record evidence without treating a stop as success.

The caller must stop the dedicated container before packing its output volume.
This controller only waits for its own process group and records Siso's close;
it does not claim that every possible writer has exited.
"""

import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from zipfile import BadZipFile, ZipFile


FORMAT = "bare-apk-trial"
VERSION = 1
BUILD_DIR = PurePosixPath("out/Bare")
TARGET = "chrome_public_apk"
SUCCESS_SOURCE = "siso_metrics+ninja_log-v5"
# GN's initial output already occupies about 1.3 GB on this pinned build.
# This is an uncompressed working-set guard, not the 1 GiB upload limit.
# Leave 256 MiB below the separate 2 GiB archive extraction limit.
OUTPUT_LIMIT = 1792 * 1024 * 1024
# Keep room below the archive validator's 100,000-member limit for metadata
# and outputs created between samples. The final archive check is still required.
OUTPUT_ENTRY_LIMIT = 98_000
SMALL_MIN_FREE_BYTES = 10_000_000_000
SCALE_TIME_LIMIT = 3600
SCALE_OUTPUT_LIMIT = 5 * 1024 ** 3 // 2
SCALE_OUTPUT_ENTRY_LIMIT = 140_000
SCALE_MIN_FREE_BYTES = 20 * 1024 ** 3
LARGE_TIME_LIMIT = 5400
LARGE_OUTPUT_LIMIT = 6 * 1024 ** 3
LARGE_OUTPUT_ENTRY_LIMIT = 300_000
LARGE_MIN_FREE_BYTES = 20 * 1024 ** 3
PRODUCTION_TIME_LIMIT = 180 * 60
PRODUCTION_DEFAULT_OUTPUT_LIMIT = 11 * 1024 ** 3
PRODUCTION_OUTPUT_LIMIT = 14 * 1024 ** 3
PRODUCTION_OUTPUT_ENTRY_LIMIT = 525_000
PRODUCTION_MIN_FREE_BYTES = 20 * 1024 ** 3
PRODUCTION_MIN_FREE_INODES = 20_000
LARGE_SAMPLE_SECONDS = 5
LARGE_CONSOLE_PREFIX_BYTES = 2 * 1024 ** 2
LARGE_CONSOLE_TAIL_BYTES = 32 * 1024
LARGE_CONSOLE_PROGRESS_SECONDS = 60
# Two evidence arrays leave 16 MiB for diagnostics and the workflow's final
# metadata within the checkpoint verifier's 128 MiB large-report limit.
LARGE_EVIDENCE_ARRAY_BYTES = 56 * 1024 ** 2
SOURCE_ROOT = Path("/work/chromium/src")
CGROUP_ROOT = Path("/sys/fs/cgroup")
SISO_STATUS = re.compile(rb"(?:^|[\r\n])\[(\d+)/(\d+)\] [^\r\n]{1,64}? ([SF]) ([^\r\n]{1,400})(?=[\r\n]|$)")


def trial_limits(scale, large, production=False):
    if production:
        return (PRODUCTION_TIME_LIMIT, PRODUCTION_OUTPUT_LIMIT,
                PRODUCTION_OUTPUT_ENTRY_LIMIT, PRODUCTION_MIN_FREE_BYTES)
    if large:
        return LARGE_TIME_LIMIT, LARGE_OUTPUT_LIMIT, LARGE_OUTPUT_ENTRY_LIMIT, LARGE_MIN_FREE_BYTES
    if scale:
        return SCALE_TIME_LIMIT, SCALE_OUTPUT_LIMIT, SCALE_OUTPUT_ENTRY_LIMIT, SCALE_MIN_FREE_BYTES
    return 600, OUTPUT_LIMIT, OUTPUT_ENTRY_LIMIT, SMALL_MIN_FREE_BYTES


def atomic_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def output_path(value, source_root):
    """Normalize supported Siso paths to paths relative to out/Bare."""
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("Invalid build output path")
    path = PurePosixPath(value)
    if path.is_absolute():
        path = path.relative_to(PurePosixPath(str(source_root)) / BUILD_DIR)
    elif path.parts[:2] == BUILD_DIR.parts:
        path = path.relative_to(BUILD_DIR)
    if not path.parts or any(part in {"..", "."} for part in path.parts):
        raise ValueError("Build output is outside out/Bare")
    return path.as_posix()


def tree_snapshot(directory, *, include_paths=True):
    """Return existing files and a conservative archive-input size estimate."""
    files = set()
    logical = allocated = entries = 0
    for root, directories, names in os.walk(directory, followlinks=False):
        for name in directories + names:
            path = Path(root) / name
            try:
                info = path.lstat()
            except FileNotFoundError:
                # Generators may atomically rename temporary outputs while a
                # running trial is sampled. A vanished entry consumes no space.
                continue
            entries += 1
            allocated += info.st_blocks * 512
            if stat.S_ISREG(info.st_mode):
                logical += info.st_size
                if include_paths:
                    files.add(path.relative_to(directory).as_posix())
    # PAX/tar metadata and directory entries also need space. Count both logical
    # and allocated bytes so sparse files cannot evade the small trial's guard.
    estimate = max(logical, allocated) + entries * 2048
    return {"paths": files, "logical_bytes": logical, "allocated_bytes": allocated,
            "entries": entries, "archive_input_estimate_bytes": estimate}


def record_sample(measurements, sample, free_bytes):
    measurements["sample_count"] += 1
    prior_free = measurements["min_free_bytes"]
    measurements["min_free_bytes"] = free_bytes if prior_free is None else min(prior_free, free_bytes)
    peak = measurements["peak_output"]
    for name in ("logical_bytes", "allocated_bytes", "entries", "archive_input_estimate_bytes"):
        peak[name] = max(peak.get(name, 0), sample[name])


def resource_status(source_root):
    filesystem = os.statvfs(source_root)
    result = {"free_inodes": filesystem.f_favail}
    for name in ("memory.current", "memory.peak", "memory.swap.current", "memory.events"):
        try:
            value = (CGROUP_ROOT / name).read_text().strip()
            result[name] = (dict((key, int(count)) for key, count in
                                 (line.split() for line in value.splitlines()))
                            if name == "memory.events" else int(value))
        except (OSError, ValueError):
            continue
    return result


def update_siso_status(progress, chunk):
    # Preserve a possible split line between pipe reads. Very long output lines
    # are diagnostic output and are not needed for the bounded heartbeat.
    data = progress.pop("partial", b"") + chunk
    split = max(data.rfind(b"\r"), data.rfind(b"\n"))
    if split < 0:
        progress["partial"] = data[-1024:]
        return
    progress["partial"] = data[split + 1:][-1024:]
    for match in SISO_STATUS.finditer(data[:split + 1]):
        progress["step_counter"] = int(match[1])
        progress["graph_total"] = int(match[2])
        description = match[4].decode("utf-8", errors="replace")
        if match[3] == b"S" and description.startswith(("LINK ", "SOLINK ")):
            progress["link_action"] = description
            progress["link_started"] = time.monotonic()
        elif match[3] == b"F" and description == progress.get("link_action"):
            progress.pop("link_action", None)
            progress.pop("link_started", None)


def bounded_output_evidence(outputs, max_bytes):
    """Keep complete evidence records within one JSON array's byte budget."""
    def priority(item):
        path = item["path"]
        object_file = path.endswith(".o")
        return (not (object_file and path.startswith("obj/")), not object_file, path)

    used = 2  # The array brackets.
    selected = []
    for item in sorted(outputs, key=priority):
        # atomic_json uses ASCII escaping and default separators. Allow a
        # separator even for the first item to keep this estimate conservative.
        size = len(json.dumps(item, sort_keys=True)) + 2
        if used + size <= max_bytes:
            selected.append(item)
            used += size
    return selected


def log_snapshot(path):
    try:
        with path.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode):
                return None
            head = stream.read(min(info.st_size, 4096))
            stream.seek(max(0, info.st_size - 4096))
            tail = stream.read()
        return {"dev": info.st_dev, "ino": info.st_ino, "size": info.st_size,
                "head": head, "tail": tail}
    except FileNotFoundError:
        return None


def current_log_markers(path, before):
    """Scan this invocation after append, truncation, or log rotation."""
    phrases = ("Saved fs state in ", "Failed to save fs state", "close journal",
               "Failed to remove stale fs state", "not save state", "close hashfs:")
    encoded = tuple(phrase.encode("ascii") for phrase in phrases)
    with path.open("rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("Siso close log is not a regular file")
        offset = 0
        if before and (info.st_dev, info.st_ino) == (before["dev"], before["ino"]):
            if info.st_size >= before["size"]:
                head = stream.read(len(before["head"]))
                stream.seek(max(0, before["size"] - len(before["tail"])))
                tail = stream.read(len(before["tail"]))
                if head == before["head"] and tail == before["tail"]:
                    offset = before["size"]
        stream.seek(offset)
        markers = []
        for line in stream:
            if any(phrase in line for phrase in encoded):
                markers.extend(part for part in line.decode("utf-8", errors="replace").splitlines()
                               if any(phrase in part for phrase in phrases))
        return markers, {"path": str(path), "offset": offset, "bytes": info.st_size - offset}


def regular_file_identity(path):
    """Identify nonempty state files without following links."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size == 0:
                return None
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        if (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns):
            return None
        return {"sha256": digest.hexdigest(), "size": before.st_size,
                "mtime_ns": before.st_mtime_ns}
    except OSError:
        return None


def close_evidence(path, before, output, journal_before):
    try:
        markers, source = current_log_markers(path, before)
    except (OSError, ValueError) as error:
        return {"saved": False, "journal_closed": False, "journal_ready": False,
                "notes": [], "errors": [str(error)], "source_files": [], "markers": []}
    errors = [line for line in markers if any(phrase in line for phrase in (
        "Failed to save fs state", "Failed to close journal",
        "Failed to remove stale fs state", "close hashfs:"))]
    closed = any("close journal" in line and "Failed to close journal" not in line
                 for line in markers)
    notes = [line for line in markers if "not save state" in line]
    skip = None
    for line in notes:
        match = re.search(r"not save state clean=(true|false) loaded=(true|false) journal:(\d+) tainted:(\d+)", line)
        if match:
            skip = {"clean": match[1] == "true", "loaded": match[2] == "true",
                    "journal_entries": int(match[3]), "tainted": int(match[4])}
    state = regular_file_identity(output / ".siso_fs_state")
    journal = regular_file_identity(output / ".siso_fs_state.journal")
    journal_updated = bool(journal and (not journal_before
                                       or journal["sha256"] != journal_before["sha256"]))
    journal_ready = bool(closed and not errors and skip and skip["loaded"]
                         and skip["journal_entries"] > 0 and skip["tainted"] == 0
                         and state and journal and journal_updated)
    return {"saved": any("Saved fs state in " in line for line in markers),
            "journal_closed": closed, "journal_ready": journal_ready,
            "journal_updated": journal_updated, "state": state, "journal": journal,
            "skip_save": skip, "notes": notes,
            "errors": errors, "source_files": [source], "markers": markers[-20:]}


def ninja_records(path, source_root):
    records = {}
    with path.open(encoding="utf-8") as stream:
        if stream.readline().rstrip("\n") != "# ninja log v5":
            raise ValueError("Expected the pinned Siso ninja log v5")
        for line in stream:
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 5:
                raise ValueError("Malformed ninja log record")
            start, end, mtime = map(int, fields[:3])
            # The third field is Siso's recorded step-end UnixNano, not the
            # object's mtime. Keep it as diagnostic data, not a validity gate
            # or proof of the output file's actual timestamp.
            if start < 0 or end < start:
                raise ValueError("Invalid ninja log timing")
            if not re.fullmatch(r"[0-9a-fA-F]{16}", fields[4]):
                raise ValueError("Invalid pinned Siso command hash")
            try:
                output = output_path(fields[3], source_root)
            except ValueError:
                continue
            records[output] = {"path": output, "start_ms": start, "end_ms": end,
                               "mtime": mtime, "command_hash": fields[4]}
    return records


def read_step_metrics(metrics_path, source_root):
    metrics = {}
    failed_steps = {}
    with metrics_path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError("Malformed Siso metrics item")
            step = item.get("step_id")
            outputs = item.get("outputs")
            if not step:
                continue  # Aggregate metrics are not a completed build edge.
            if not isinstance(step, str) or (outputs is not None and not isinstance(outputs, list)):
                raise ValueError("Malformed Siso step metrics")
            if "err" in item and type(item["err"]) is not bool:
                raise ValueError("Malformed Siso error flag")
            if item.get("err", False):
                failed_steps[step] = {"step_id": step, "outputs": outputs or []}
            for value in outputs or []:
                try:
                    output = output_path(value, source_root)
                except ValueError:
                    continue
                metrics[output] = {"success": not item.get("err", False), "step_id": step}
    return metrics, list(failed_steps.values())


def completed_outputs(metrics_path, ninja_path, source_root, metrics=None):
    """A ninja record alone can describe a failure; join successful metrics."""
    if metrics is None:
        metrics, _ = read_step_metrics(metrics_path, source_root)
    records = ninja_records(ninja_path, source_root)
    result = []
    for name, metric in metrics.items():
        if not metric["success"] or name not in records:
            continue
        path = source_root / BUILD_DIR / name
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                continue
        except FileNotFoundError:
            continue
        result.append({**records[name], **metric, "success_source": SUCCESS_SOURCE})
    return sorted(result, key=lambda item: item["path"])


def previous_paths(path):
    if path is None:
        return set()
    item = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(item, dict) or item.get("format") != FORMAT
            or item.get("version") != VERSION or item.get("target") != TARGET
            or item.get("phase") != "seed"):
        raise ValueError("Incompatible seed trial result")
    values = item.get("completed_outputs")
    if not isinstance(values, list):
        raise ValueError("Missing successful seed outputs")
    paths = set()
    for record in values:
        if (not isinstance(record, dict) or record.get("success") is not True
                or record.get("success_source") != SUCCESS_SOURCE):
            raise ValueError("Unverified seed output")
        name = record.get("path")
        if not isinstance(name, str) or not name or "\\" in name or "\x00" in name:
            raise ValueError("Invalid seed output path")
        relative = PurePosixPath(name)
        if (relative.is_absolute() or not relative.parts or ".." in relative.parts
                or relative.as_posix() != name):
            raise ValueError("Unsafe seed output path")
        paths.add(name)
    return paths


def apk_metadata(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    with ZipFile(path) as archive:
        invalid = archive.testzip()
        if invalid is not None:
            raise ValueError(f"APK ZIP integrity failed: {invalid}")
        arm64_member = None
        for name in archive.namelist():
            if name.startswith("lib/arm64-v8a/") and name.endswith(".so"):
                with archive.open(name) as member:
                    header = member.read(20)
                if header[:6] == b"\x7fELF\x02\x01" and header[18:20] == b"\xb7\x00":
                    arm64_member = name
                    break
        if arm64_member is None:
            raise ValueError("APK contains no verified AArch64 ELF library")
    return {"path": "out/Bare/apks/ChromePublic.apk", "sha256": digest.hexdigest(),
            "size": path.stat().st_size, "arm64_member": arm64_member}


def run_trial(source_root, phase, result_path, log_path, seconds=180,
              max_output_bytes=OUTPUT_LIMIT, min_free_bytes=SMALL_MIN_FREE_BYTES,
              previous_result=None, command=None, stop_grace_seconds=120,
              sample_seconds=None, output_stream=None, max_output_entries=OUTPUT_ENTRY_LIMIT,
              *, scale=False, large=False, production=False, jobs=2):
    """Run a bounded trial. Only local callers can substitute the build command."""
    source_root = source_root.absolute()
    output = source_root / BUILD_DIR
    metrics_path = log_path.with_name(f"siso-metrics-{phase}.json")
    info_path = output / "siso.INFO"
    measured = large or production
    expanded = scale or measured
    if sample_seconds is None:
        sample_seconds = LARGE_SAMPLE_SECONDS if measured else 2
    result = {"format": FORMAT, "version": VERSION, "phase": phase,
              "target": TARGET, "build_dir": str(BUILD_DIR), "reason": "controller-error",
              "returncode": None, "forced_kill": False, "interrupt_sent": False,
              "ready_for_restore_test": False, "completed_outputs": [],
              "new_completed_outputs": [], "failed_steps": [], "apk": None,
              "container_quiescence_verified": False, "max_output_entries": max_output_entries}
    if scale:
        result["scale_limits"] = {"seconds": seconds, "max_output_bytes": max_output_bytes,
                                  "max_output_entries": max_output_entries,
                                  "min_free_bytes": min_free_bytes}
    if measured:
        result["production_limits" if production else "large_limits"] = {
            "seconds": seconds, "max_output_bytes": max_output_bytes,
            "max_output_entries": max_output_entries, "min_free_bytes": min_free_bytes}
        result["measurements"] = {"sample_interval_seconds": sample_seconds, "sample_count": 0,
                                  "min_free_bytes": None, "peak_output": {}}
    if production:
        result["artifact_ready"] = False
        result["rebuilt_completed_output_count"] = 0
        result["resources_before"] = resource_status(source_root)
    process = None
    selector = selectors.DefaultSelector()
    old_handlers = {}
    received_signals = []
    started = time.monotonic()
    sink = output_stream if output_stream is not None else sys.stdout.buffer
    console = {"prefix_bytes": 0, "tail_bytes": 0, "truncated": False}
    last_console_progress = started
    progress = {}
    try:
        if phase not in {"seed", "restore"} or seconds <= 0 or sample_seconds <= 0:
            raise ValueError("Invalid trial phase or time budget")
        if sum((scale, large, production)) > 1:
            raise ValueError("Choose only one restore trial mode")
        if type(jobs) is not int or jobs not in (1, 2) or (jobs == 1 and not production):
            raise ValueError("Use two build jobs, or one in production")
        time_limit, output_limit, entry_limit, disk_floor = trial_limits(scale, large, production)
        if type(max_output_entries) is not int or not 1 <= max_output_entries <= entry_limit:
            raise ValueError(f"The output entry guard must be between 1 and {entry_limit}")
        if expanded and (phase != "restore" or seconds > time_limit
                                 or not 1 <= max_output_bytes <= output_limit
                                 or min_free_bytes < disk_floor):
            raise ValueError("Expanded trials require restore and bounded time, output bytes, and free disk")
        if phase == "restore" and previous_result is None and not expanded:
            raise ValueError("Restore requires the saved seed trial result")
        if metrics_path.exists() or metrics_path.is_symlink():
            raise ValueError("Metrics path must be new for this trial")
        baseline = previous_paths(previous_result)
        snapshot = tree_snapshot(output)
        # A restored tree contains outputs from earlier generations. Even
        # without a seed result, their paths cannot count as new work.
        baseline.update(snapshot.pop("paths"))
        result["output_before"] = snapshot
        close_before = log_snapshot(info_path)
        journal_before = regular_file_identity(output / ".siso_fs_state.journal")
        free_before = shutil.disk_usage(source_root).free if measured else None
        if measured:
            record_sample(result["measurements"], snapshot, free_before)
        if snapshot["archive_input_estimate_bytes"] >= max_output_bytes:
            result["reason"] = "preflight-output-limit"
            return result
        if snapshot["entries"] >= max_output_entries:
            result["reason"] = "preflight-output-entry-limit"
            return result
        if free_before is None:
            free_before = shutil.disk_usage(source_root).free
        if free_before < min_free_bytes or (production and
                result["resources_before"]["free_inodes"] < PRODUCTION_MIN_FREE_INODES):
            result["reason"] = "preflight-disk-limit"
            return result
        log_path.parent.mkdir(parents=True, exist_ok=True)
        arguments = command if command is not None else [
            "autoninja", "-C", str(BUILD_DIR), "-j", str(jobs),
            "-metrics_json", str(metrics_path.absolute()), TARGET]
        result["metrics_path"] = str(metrics_path)
        result["command"] = arguments
        for name in (signal.SIGINT, signal.SIGTERM):
            old_handlers[name] = signal.signal(name, lambda signum, frame: received_signals.append(signum))
        with log_path.open("wb") as log:
            process = subprocess.Popen(arguments, cwd=source_root, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            os.set_blocking(process.stdout.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ)
            interrupted_at = None
            last_sample = 0
            leader_exited_at = None
            while True:
                now = time.monotonic()
                running = process.poll() is None
                if running and interrupted_at is None:
                    reason = None
                    if received_signals:
                        reason = "controller-interrupted"
                    elif now - started >= seconds:
                        reason = "time-limit"
                    elif now - last_sample >= sample_seconds:
                        sample = tree_snapshot(output, include_paths=False)
                        sample.pop("paths")
                        free = shutil.disk_usage(source_root).free
                        result["last_sample"] = {**sample, "free_bytes": free}
                        if production:
                            result["last_sample"]["free_inodes"] = os.statvfs(source_root).f_favail
                        if measured:
                            record_sample(result["measurements"], sample, free)
                            if (production or console["truncated"]) and now - last_console_progress >= LARGE_CONSOLE_PROGRESS_SECONDS:
                                status = (f"[APK trial: {now - started:.0f}s, {sample['entries']} entries, "
                                          f"{sample['archive_input_estimate_bytes']} estimated output bytes, "
                                          f"{free} free bytes]")
                                if production:
                                    resources = resource_status(source_root)
                                    counts = {key: progress[key] for key in ("step_counter", "graph_total")
                                              if key in progress}
                                    if "link_started" in progress:
                                        counts["link_action"] = progress["link_action"]
                                        counts["link_elapsed_seconds"] = round(now - progress["link_started"])
                                    status += " " + json.dumps({**counts, **resources}, sort_keys=True)
                                sink.write((status + "\n").encode("ascii"))
                                sink.flush()
                                last_console_progress = now
                        last_sample = now
                        if sample["archive_input_estimate_bytes"] >= max_output_bytes:
                            reason = "output-limit"
                        elif sample["entries"] >= max_output_entries:
                            reason = "output-entry-limit"
                        elif free < min_free_bytes or (production and
                                result["last_sample"]["free_inodes"] < PRODUCTION_MIN_FREE_INODES):
                            reason = "disk-limit"
                    if reason:
                        result["reason"] = reason
                        with contextlib.suppress(ProcessLookupError):
                            os.killpg(process.pid, signal.SIGINT)
                        result["interrupt_sent"] = True
                        interrupted_at = now
                if running and interrupted_at is not None and now - interrupted_at >= stop_grace_seconds:
                    with contextlib.suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    result["forced_kill"] = True
                    process.wait(timeout=10)
                for key, _ in selector.select(timeout=0.2):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        log.write(chunk)
                        log.flush()
                        if production:
                            update_siso_status(progress, chunk)
                        if measured:
                            remaining = LARGE_CONSOLE_PREFIX_BYTES - console["prefix_bytes"]
                            shown = chunk[:remaining]
                            if shown:
                                sink.write(shown)
                                sink.flush()
                                console["prefix_bytes"] += len(shown)
                            if len(shown) < len(chunk) and not console["truncated"]:
                                sink.write(b"\n[APK trial console capped; full output continues in the runner log.]\n")
                                sink.flush()
                                console["truncated"] = True
                                if not production:
                                    last_console_progress = time.monotonic()
                        else:
                            sink.write(chunk)
                            sink.flush()
                if process.poll() is not None:
                    leader_exited_at = leader_exited_at or time.monotonic()
                    if not selector.get_map() or time.monotonic() - leader_exited_at > 1:
                        break
            result["returncode"] = process.returncode
            result["stdout_drain_complete"] = not bool(selector.get_map())
            if interrupted_at is None:
                result["reason"] = "completed" if process.returncode == 0 else "compile-error"
        result["close"] = close_evidence(info_path, close_before, output, journal_before)
        if production:
            result["resources_after"] = resource_status(source_root)
            start_oom = result["resources_before"].get("memory.events", {}).get("oom_kill", 0)
            end_oom = result["resources_after"].get("memory.events", {}).get("oom_kill", 0)
            if end_oom > start_oom:
                result["oom_kill_count"] = end_oom - start_oom
                result["stop_reason"] = result["reason"]
                result["reason"] = "oom-kill"
        if not result["forced_kill"]:
            metrics, failed = read_step_metrics(metrics_path, source_root)
            result["failed_step_count"] = len(failed)
            result["failed_steps"] = failed[:20]
            if failed and result["reason"] != "oom-kill":
                result["stop_reason"] = result["reason"]
                result["reason"] = "compile-error"
            result["completed_outputs"] = completed_outputs(metrics_path, output / ".ninja_log", source_root, metrics)
            result["new_completed_outputs"] = [item for item in result["completed_outputs"]
                                                if item["path"] not in baseline]
        if result["reason"] == "completed":
            result["apk"] = apk_metadata(output / "apks/ChromePublic.apk")
        no_failure = not result["forced_kill"] and not result["close"]["errors"] and not result["failed_steps"]
        complete = result["reason"] == "completed" and result["returncode"] == 0 and result["apk"] is not None
        usable_outputs = result["completed_outputs"] if production else result["new_completed_outputs"]
        interrupted = (result["reason"] in {"time-limit", "output-limit", "output-entry-limit", "disk-limit"}
                       and bool(usable_outputs)
                       and (result["close"]["saved"] or result["close"]["journal_ready"]))
        # This only permits the next VM's validation. No state is "verified"
        # until the caller proves reuse and continuation after restoration.
        result["ready_for_restore_test"] = bool(no_failure and (interrupted or (complete and not production)))
        if production:
            result["artifact_ready"] = bool(no_failure and complete)
    except (OSError, ValueError, subprocess.SubprocessError, BadZipFile) as error:
        result["controller_error"] = str(error)
        result["ready_for_restore_test"] = False
        # A validation error does not erase the actual stop/compile result.
        if result["returncode"] is None:
            result["reason"] = "controller-error"
    finally:
        if process is not None and process.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            result["forced_kill"] = True
            process.wait(timeout=10)
            result["returncode"] = process.returncode
        selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        for name, old in old_handlers.items():
            signal.signal(name, old)
        if measured:
            if console["truncated"]:
                # Exclude the already displayed prefix even if the full log
                # ends less than one tail-length beyond it.
                with contextlib.suppress(OSError):
                    with log_path.open("rb") as stream:
                        size = os.fstat(stream.fileno()).st_size
                        stream.seek(max(console["prefix_bytes"], size - LARGE_CONSOLE_TAIL_BYTES))
                        tail = stream.read(LARGE_CONSOLE_TAIL_BYTES)
                    if tail:
                        sink.write(b"\n[Final APK trial output]\n")
                        sink.write(tail)
                        sink.write(b"\n")
                        sink.flush()
                        console["tail_bytes"] = len(tail)
            result["console"] = console
            result["completed_output_count"] = len(result["completed_outputs"])
            result["new_completed_output_count"] = len(result["new_completed_outputs"])
            if production:
                result["rebuilt_completed_output_count"] = (
                    result["completed_output_count"] - result["new_completed_output_count"])
                if "resources_after" not in result:
                    result["resources_after"] = resource_status(source_root)
            for name in ("completed_outputs", "new_completed_outputs"):
                result[name] = bounded_output_evidence(result[name], LARGE_EVIDENCE_ARRAY_BYTES)
            result["evidence_truncated"] = (
                len(result["completed_outputs"]) != result["completed_output_count"]
                or len(result["new_completed_outputs"]) != result["new_completed_output_count"])
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        atomic_json(result_path, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("seed", "restore"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--previous-result", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--scale", action="store_true", help="Use the bounded scale restore limits")
    mode.add_argument("--large", action="store_true", help="Use the larger restore trial limits")
    mode.add_argument("--production", action="store_true", help="Use the APK production restore limits")
    parser.add_argument("--jobs", type=int, choices=(1, 2), default=2)
    parser.add_argument("--seconds", type=int)
    parser.add_argument("--max-output-bytes", type=int)
    parser.add_argument("--max-output-entries", type=int)
    parser.add_argument("--min-free-bytes", type=int)
    args = parser.parse_args()
    if Path.cwd() != SOURCE_ROOT:
        parser.error("Run only from the fixed /work/chromium/src directory")
    expanded = args.scale or args.large or args.production
    if expanded and args.phase != "restore":
        parser.error("--scale, --large, and --production require --phase restore")
    if args.jobs == 1 and not args.production:
        parser.error("--jobs 1 requires --production")
    time_limit, output_limit, entry_limit, disk_floor = trial_limits(args.scale, args.large, args.production)
    seconds = args.seconds if args.seconds is not None else (time_limit if expanded else 180)
    default_output = PRODUCTION_DEFAULT_OUTPUT_LIMIT if args.production else output_limit
    max_output_bytes = args.max_output_bytes if args.max_output_bytes is not None else default_output
    max_output_entries = args.max_output_entries if args.max_output_entries is not None else entry_limit
    min_free_bytes = args.min_free_bytes if args.min_free_bytes is not None else disk_floor
    if not 1 <= seconds <= time_limit:
        parser.error(f"--seconds must be between 1 and {time_limit}")
    if not 1 <= max_output_bytes <= output_limit or min_free_bytes < disk_floor:
        parser.error(f"Expected output bytes at most {output_limit} and free bytes at least {disk_floor}")
    if not 1 <= max_output_entries <= entry_limit:
        parser.error(f"--max-output-entries must be between 1 and {entry_limit}")
    result = run_trial(SOURCE_ROOT, args.phase, args.result, args.log, seconds,
                       max_output_bytes, min_free_bytes, args.previous_result,
                       max_output_entries=max_output_entries, scale=args.scale, large=args.large,
                       production=args.production, jobs=args.jobs)
    summary = {key: result[key] for key in ("phase", "reason", "returncode",
                                           "forced_kill", "ready_for_restore_test", "max_output_entries")}
    for key in ("scale_limits", "large_limits", "production_limits", "output_before", "last_sample",
                "measurements", "completed_output_count", "new_completed_output_count",
                "rebuilt_completed_output_count", "evidence_truncated", "console", "artifact_ready",
                "resources_before", "resources_after", "oom_kill_count"):
        if key in result:
            summary[key] = result[key]
    print(json.dumps(summary))
    # The workflow must inspect the result after its unconditional stop/save.
    # A planned stop or a failed build must not skip preservation steps.
    return 0


if __name__ == "__main__":
    sys.exit(main())
