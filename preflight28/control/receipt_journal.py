"""Verify an immutable first-attempt receipt against Actions' own job and Artifact records."""
from datetime import datetime, timezone
from hashlib import sha256
from io import BytesIO
import json
import re
from zipfile import ZipFile

SLOT_STEP = "Persist the original verified segment receipt"
SEAL_STEP = "Persist the original sealed APK receipt"
RESULT_JOB = "Record the independently verified segment outcome"
MAX_ZIP = 16 * 1024
MAX_NOTE = 8 * 1024
SCHEMA = "bare-r28-segment-receipt-v1"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def timestamp(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(dt.tzinfo is not None, "Missing provider timezone")
    return dt.timestamp()


def upload_step(job, step):
    steps = [item for item in job["steps"] if item["name"] == step]
    require(len(steps) <= 1, "Ambiguous original job step")
    if not steps or steps[0].get("conclusion") not in {"success", "failure", "cancelled"}:
        return None
    return steps[0]


def original_job(jobs, run, head, n, suffix):
    prefix = f"Bounded build segment {n}" if n <= 12 else "Independently receive checkpoint at the 12-segment limit"
    matches = [job for job in jobs if job["name"].startswith(prefix + " / ") and
               job["name"].endswith(" / " + suffix) and job.get("conclusion") != "skipped"]
    require(len(matches) <= 1, "Ambiguous original attestor job")
    if matches:
        job = matches[0]
        require(job["run_id"] == run and job["run_attempt"] == 1 and job["head_sha"] == head and
                job["status"] == "completed", "Job is not the completed original attestor")
        return job
    return None


def matches_artifact(row, run, head):
    owner = row["workflow_run"]
    require(owner["id"] == run and owner["head_sha"] == head and type(row["id"]) is int and row["id"] > 0 and
            re.fullmatch(r"sha256:[0-9a-f]{64}", row.get("digest") or ""), "Artifact belongs to another operation")


def one_artifact(artifacts, name):
    matches = [row for row in artifacts if row["name"] == name]
    require(len(matches) <= 1, "Conflicting physical Artifacts with the same receipt name")
    return matches[0] if matches else None


def checked_artifact(row, run, head, job, step_name, metadata):
    """An acknowledged upload, or a committed upload whose reply was lost, must fall inside the original step."""
    matches_artifact(row, run, head)
    require(job is not None, "No physical first-attempt upload job for this Artifact")
    step = upload_step(job, step_name)
    require(step is not None and step["started_at"] and job["completed_at"], "No physical first-attempt upload step")
    created = timestamp(row["created_at"])
    # The provider timestamps Actions steps to whole seconds.
    require(int(timestamp(step["started_at"])) <= created < int(timestamp(step.get("completed_at") or job["completed_at"])) + 1,
            "Artifact created outside its original upload step")
    direct = metadata(row["id"])
    if direct.get("workflow_run"):
        matches_artifact(direct, run, head)
    keys = ("id", "name", "size_in_bytes", "digest", "expired", "expires_at", "created_at")
    require(all(direct[k] == row[k] for k in keys), "Artifact listing and immutable ID disagree")


def decode(raw, row, member):
    require(0 < len(raw) == row["size_in_bytes"] <= MAX_ZIP and "sha256:" + sha256(raw).hexdigest() == row["digest"],
            "Receipt ZIP no longer matches the provider's immutable digest")
    with ZipFile(BytesIO(raw)) as z:
        files = z.infolist()
        require(len(files) == 1 and files[0].filename == member and 0 < files[0].file_size <= MAX_NOTE,
                "Wrong or oversized receipt ZIP member")
        return json.loads(z.read(files[0]))


def result_fields(result):
    """Admit only scalar fields actually written by the bounded native slot."""
    usual = {"status","ordinal","producer_sha","accepted_parent"}
    groups = {
        "apk": {"cipher_id","cipher_cache","cipher_sha","cipher_bytes"},
        "limit-verified": {"sha"},
        "candidate": {"key","sha","identity"},
        "manifest_present_visibility_pending": {"key","sha","identity"},
        **{k:set() for k in ("no-progress","apk-size-exceeded","cipher-size-exceeded","relay-quota-denied",
                             "relay-capacity-exceeded","relay-deadline","relay-missing","relay-ambiguous")}
    }
    state = result.get("status")
    require(state in groups, "Unknown journal result")
    allowed = usual | groups[state]
    private = {"manifest_id","manifest_sha","archive_bytes"}
    if state == "manifest_present_visibility_pending" or (state == "candidate" and private.intersection(result)):
        allowed |= private
        require(re.fullmatch(r"[1-9][0-9]*", result["manifest_id"]) and
                re.fullmatch(r"[a-f0-9]{64}", result["manifest_sha"]) and
                str(result["archive_bytes"]).isdecimal() and 0 < int(result["archive_bytes"]) <= 7*1024**3//2,
                "Invalid private receipt")
    require(result.keys()==allowed and all(k=="ordinal" or (isinstance(v,str) and len(v)<=384 and
            "\r" not in v and "\n" not in v) for k,v in result.items()), "Unexpected slot journal fields")


def read_note(artifacts, run, head, n, job, purpose, metadata, download, *, terminal_salvage=False):
    slot = purpose == "slot"
    name = f"r28-{run}-a1-s{n:02}-" + ("receipt" if slot else "apk-seal")
    row = one_artifact(artifacts, name)
    step_name = SLOT_STEP if slot else SEAL_STEP
    if row is None:
        # A missing committed slot forbids choosing any older parent. A missing seal
        # has the exact embedded counterpart in the independently downloaded APK.
        if slot and job is not None and not terminal_salvage:
            step = upload_step(job, step_name)
            require(job.get("conclusion") != "success" and not (step and step["conclusion"] == "success"),
                    "Committed slot receipt is missing; refuse rollback")
        return None
    checked_artifact(row, run, head, job, step_name, metadata)
    if row["expired"] or timestamp(row["expires_at"]) <= datetime.now(timezone.utc).timestamp():
        require(not slot or terminal_salvage, "Original committed slot receipt expired; refuse rollback")
        return None
    require(type(row["size_in_bytes"]) is int and 0 < row["size_in_bytes"] <= MAX_ZIP, "Oversized receipt")
    note = decode(download(row["id"]), row, "receipt.json" if slot else "seal.json")
    if not slot:
        return note
    require(type(note) is dict and set(note) == {"schema", "run", "attempt", "head", "result"} and
            note["schema"] == SCHEMA and type(note["run"]) is int and type(note["attempt"]) is int and
            note["run"] == run and note["attempt"] == 1 and note["head"] == head and
            type(note["result"]["ordinal"]) is int and note["result"]["ordinal"] == n and
            note["result"]["producer_sha"] == head, "Slot receipt is outside the original lineage")
    result_fields(note["result"])
    return note["result"]
