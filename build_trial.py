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
SOURCE_ROOT = Path("/work/chromium/src")


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


def tree_snapshot(directory):
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
                files.add(path.relative_to(directory).as_posix())
    # PAX/tar metadata and directory entries also need space. Count both logical
    # and allocated bytes so sparse files cannot evade the small trial's guard.
    estimate = max(logical, allocated) + entries * 2048
    return {"paths": files, "logical_bytes": logical, "allocated_bytes": allocated,
            "entries": entries, "archive_input_estimate_bytes": estimate}


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


def current_log_bytes(path, before):
    """Read only this invocation after append, truncation, or log rotation."""
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
        return stream.read(), {"path": str(path), "offset": offset,
                               "bytes": info.st_size - offset}


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
        data, source = current_log_bytes(path, before)
    except (OSError, ValueError) as error:
        return {"saved": False, "journal_closed": False, "journal_ready": False,
                "notes": [], "errors": [str(error)], "source_files": [], "markers": []}
    text = data.decode("utf-8", errors="replace")
    markers = [line for line in text.splitlines() if any(phrase in line for phrase in (
        "Saved fs state in ", "Failed to save fs state", "close journal",
        "Failed to remove stale fs state", "not save state", "close hashfs:"))]
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
              max_output_bytes=OUTPUT_LIMIT, min_free_bytes=10_000_000_000,
              previous_result=None, command=None, stop_grace_seconds=120,
              sample_seconds=2, output_stream=None, max_output_entries=OUTPUT_ENTRY_LIMIT):
    """Run a short trial. command injection is exposed to local tests, not CLI."""
    source_root = source_root.absolute()
    output = source_root / BUILD_DIR
    metrics_path = log_path.with_name(f"siso-metrics-{phase}.json")
    info_path = output / "siso.INFO"
    result = {"format": FORMAT, "version": VERSION, "phase": phase,
              "target": TARGET, "build_dir": str(BUILD_DIR), "reason": "controller-error",
              "returncode": None, "forced_kill": False, "interrupt_sent": False,
              "ready_for_restore_test": False, "completed_outputs": [],
              "new_completed_outputs": [], "failed_steps": [], "apk": None,
              "container_quiescence_verified": False, "max_output_entries": max_output_entries}
    process = None
    selector = selectors.DefaultSelector()
    old_handlers = {}
    received_signals = []
    started = time.monotonic()
    sink = output_stream if output_stream is not None else sys.stdout.buffer
    try:
        if phase not in {"seed", "restore"} or seconds <= 0:
            raise ValueError("Invalid trial phase or time budget")
        if type(max_output_entries) is not int or not 1 <= max_output_entries <= OUTPUT_ENTRY_LIMIT:
            raise ValueError("The output entry guard must be between 1 and 98000")
        if phase == "restore" and previous_result is None:
            raise ValueError("Restore requires the saved seed trial result")
        if metrics_path.exists() or metrics_path.is_symlink():
            raise ValueError("Metrics path must be new for this trial")
        baseline = previous_paths(previous_result)
        snapshot = tree_snapshot(output)
        baseline.update(snapshot.pop("paths"))
        result["output_before"] = snapshot
        close_before = log_snapshot(info_path)
        journal_before = regular_file_identity(output / ".siso_fs_state.journal")
        if snapshot["archive_input_estimate_bytes"] >= max_output_bytes:
            result["reason"] = "preflight-output-limit"
            return result
        if snapshot["entries"] >= max_output_entries:
            result["reason"] = "preflight-output-entry-limit"
            return result
        if shutil.disk_usage(source_root).free < min_free_bytes:
            result["reason"] = "preflight-disk-limit"
            return result
        log_path.parent.mkdir(parents=True, exist_ok=True)
        arguments = command if command is not None else [
            "autoninja", "-C", str(BUILD_DIR), "-j", "2",
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
                        sample = tree_snapshot(output)
                        sample.pop("paths")
                        free = shutil.disk_usage(source_root).free
                        result["last_sample"] = {**sample, "free_bytes": free}
                        last_sample = now
                        if sample["archive_input_estimate_bytes"] >= max_output_bytes:
                            reason = "output-limit"
                        elif sample["entries"] >= max_output_entries:
                            reason = "output-entry-limit"
                        elif free < min_free_bytes:
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
        if not result["forced_kill"]:
            metrics, failed = read_step_metrics(metrics_path, source_root)
            result["failed_step_count"] = len(failed)
            result["failed_steps"] = failed[:20]
            if failed:
                result["stop_reason"] = result["reason"]
                result["reason"] = "compile-error"
            result["completed_outputs"] = completed_outputs(metrics_path, output / ".ninja_log", source_root, metrics)
            result["new_completed_outputs"] = [item for item in result["completed_outputs"]
                                                if item["path"] not in baseline]
        if result["reason"] == "completed":
            result["apk"] = apk_metadata(output / "apks/ChromePublic.apk")
        no_failure = not result["forced_kill"] and not result["close"]["errors"] and not result["failed_steps"]
        complete = result["reason"] == "completed" and result["returncode"] == 0 and result["apk"] is not None
        interrupted = (result["reason"] in {"time-limit", "output-limit", "output-entry-limit", "disk-limit"}
                       and bool(result["new_completed_outputs"])
                       and (result["close"]["saved"] or result["close"]["journal_ready"]))
        # This only permits the next VM's validation. No state is "verified"
        # until the caller proves reuse and continuation after restoration.
        result["ready_for_restore_test"] = bool(no_failure and (complete or interrupted))
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
        result["elapsed_seconds"] = round(time.monotonic() - started, 3)
        atomic_json(result_path, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("seed", "restore"), required=True)
    parser.add_argument("--result", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--previous-result", type=Path)
    parser.add_argument("--seconds", type=int, default=180)
    parser.add_argument("--max-output-bytes", type=int, default=OUTPUT_LIMIT)
    parser.add_argument("--max-output-entries", type=int, default=OUTPUT_ENTRY_LIMIT)
    parser.add_argument("--min-free-bytes", type=int, default=10_000_000_000)
    args = parser.parse_args()
    if Path.cwd() != SOURCE_ROOT:
        parser.error("Run only from the fixed /work/chromium/src directory")
    if not 1 <= args.seconds <= 600:
        parser.error("This is a short probe: --seconds must be between 1 and 600")
    if not 1 <= args.max_output_bytes <= OUTPUT_LIMIT or args.min_free_bytes < 10_000_000_000:
        parser.error("The small-trial output and free-disk guards cannot be relaxed")
    if not 1 <= args.max_output_entries <= OUTPUT_ENTRY_LIMIT:
        parser.error("The small-trial entry guard must be between 1 and 98000")
    result = run_trial(SOURCE_ROOT, args.phase, args.result, args.log, args.seconds,
                       args.max_output_bytes, args.min_free_bytes, args.previous_result,
                       max_output_entries=args.max_output_entries)
    summary = {key: result[key] for key in ("phase", "reason", "returncode",
                                           "forced_kill", "ready_for_restore_test", "max_output_entries")}
    for key in ("output_before", "last_sample"):
        if key in result:
            summary[key] = result[key]
    print(json.dumps(summary))
    # The workflow must inspect the result after its unconditional stop/save.
    # A planned stop or a failed build must not skip preservation steps.
    return 0


if __name__ == "__main__":
    sys.exit(main())
