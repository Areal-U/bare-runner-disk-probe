"""Read the immutable receipts of the first attempt of a build or one-slot replacement."""
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryFile
from zipfile import ZipFile
from urllib.parse import urlencode

from admission import REPO, REPO_ID, BASE_REF, S2_SHA
import apk_seal
import receipt_journal as journal

HEX = re.compile(r"[a-f0-9]{64}")
WORKFLOW = ".github/workflows/bare-checkpoint-transfer.yml"


def require(ok, why):
    if not ok:
        raise ValueError(why)


def get(path):
    return subprocess.check_output(["gh", "api", "--method", "GET", "repos/" + REPO + "/" + path],
                                   timeout=90).decode("utf-8-sig")


R30_S1_SHA = "fa44728d39b61c25d4116579e6da2c63ca7898cec24ada0e7ae453548bbd73bf"
R30_S1_IDENTITY = "8f6e0fc60ac76d6558ff3f7f593a8db5a3a5c2da523b251b3847fb594fa2e3be"
S2_IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"


@dataclass(frozen=True)
class ChainStart:
    ordinal: int = 1
    sha: str = S2_SHA
    identity: str = S2_IDENTITY
    replacement: bool = False

    @property
    def last(self):
        return self.ordinal + 1 if self.replacement else 13

    @classmethod
    def from_admission(cls, env):
        mode = env.get("R28_REPLAY_MODE", "build-apk")
        values = tuple(env.get(k,"") for k in ("R28_REPLAY_ORDINAL","R28_REPLAY_PARENT","R28_REPLAY_IDENTITY"))
        if mode == "build-apk":
            require(not any(values), "Unexpected replacement credentials for a normal run")
            if env.get("R30_RESUME_S1") == "1":
                return cls(2, R30_S1_SHA, R30_S1_IDENTITY)
            return cls()
        ordinal, parent, identity = values
        require(mode == "recover-lost-slot" and re.fullmatch("[1-9]|1[0-2]",ordinal) and
                HEX.fullmatch(parent) and HEX.fullmatch(identity), "Missing authenticated replacement admission")
        require(ordinal != "1" or (parent, identity) == (S2_SHA, S2_IDENTITY), "Different initial replacement input")
        return cls(int(ordinal), parent, identity, True)


def follow(receipts, run, sha, scope=ChainStart()):
    current = scope.sha
    confirmed = scope.sha
    seen = {current, S2_SHA}
    terminal = None
    for n, r in enumerate(sorted(receipts, key=lambda x: int(x["ordinal"])), scope.ordinal):
        require(terminal is None and r["ordinal"] == n and n <= scope.last and r["producer_sha"] == sha
                and r["accepted_parent"] == current, "Stale, duplicate or incomplete slot chain")
        state = r["status"]
        # Each non-initial segment must have passed the frontier gate before its
        # own success receipt. A final candidate without the next gate is pending.
        if n > scope.ordinal:
            confirmed = current
        require(n != scope.last or state == "limit-verified", "Expected independent verification only")
        if state == "candidate":
            require(n <= 12 and r["key"] == f"bare-coexist-204-{run}-1-checkpoint-production-s{n}"
                    and HEX.fullmatch(r["sha"]) and HEX.fullmatch(r["identity"])
                    and r["sha"] not in seen, "Conflicting successor")
            current = r["sha"]
            seen.add(current)
        elif state == "apk":
            require(HEX.fullmatch(r["cipher_sha"]) and 0 < int(r["cipher_bytes"]) <= 451 * 1024**2,
                    "Invalid ciphertext receipt")
            aid, cache = r["cipher_id"], r["cipher_cache"]
            require((not aid or re.fullmatch(r"[1-9]\d*", aid)) and
                    (not cache or cache == f"bare-coexist-204-apk-v1-{run}-1-s{n}")
                    and (aid or cache), "Invalid archived APK location")
            terminal = r
        elif state == "manifest_present_visibility_pending":
            require(n <= 12 and r['key'] == f"bare-coexist-204-{run}-1-checkpoint-production-s{n}"
                    and re.fullmatch(r"[1-9][0-9]*",r["manifest_id"]) and HEX.fullmatch(r["manifest_sha"])
                    and HEX.fullmatch(r["sha"]) and HEX.fullmatch(r["identity"]) and r["sha"] not in seen and
                    0 < int(r["archive_bytes"]) <= 7*1024**3//2,"Invalid pending private manifest receipt")
            terminal = r
        elif state in {"no-progress", "apk-size-exceeded", "cipher-size-exceeded",
                       "relay-quota-denied","relay-capacity-exceeded","relay-deadline","relay-missing","relay-ambiguous"}:
            terminal = r
        elif state == "limit-verified":
            require(n == scope.last and r["sha"] == current, "Unverified last parent")
            terminal = r
        else:
            raise ValueError("Unknown accepted state")
    return terminal or {"status":"recovery-no-terminal", "accepted_parent":confirmed, "pending":current}


def inventory(path, collection):
    rows = []
    for page in range(1, 101):
        response = json.loads(get(f"{path}?per_page=100&page={page}"))
        added = response[collection]
        rows.extend(added)
        if len(rows) == response["total_count"]:
            require(len({x["id"] for x in rows}) == len(rows), "Duplicate inventory records")
            return rows
        require(len(added) == 100 and len(rows) < response["total_count"], "Incomplete inventory")
    raise ValueError("Unbounded inventory")


def last_private_slot(jobs, receipts, run, sha, artifacts, scope=ChainStart()):
    # A partial publication can only belong to a producer that actually started.
    # Slot 13 verifies a parent only and has no publishable next generation.
    pattern = re.compile(r"^Bounded build segment ([1-9]|1[0-2]) /")
    candidates = [int(m[1]) for j in jobs if (m := pattern.match(j["name"])) and scope.ordinal <= int(m[1]) < scope.last and j["run_id"] == run and
                  j["run_attempt"] == 1 and j.get("conclusion") != "skipped" and any(
                      s.get("name") == "Issue time-limited parent read descriptors bound to the peer" and
                      s.get("conclusion") == "success" for s in j.get("steps", []))]
    if not candidates:
        return {}
    n = max(candidates)
    if n == scope.ordinal:
        parent, identity = scope.sha, scope.identity
    else:
        previous = [r for r in receipts if r["ordinal"] == n-1 and r["status"]=="candidate" and r["producer_sha"]==sha]
        require(len(previous)==1, "Unconfirmed predecessor for private recovery")
        parent,identity=previous[0]["sha"],previous[0]["identity"]
    found = [a for a in artifacts if a["name"] == f"r28-{run}-a1-s{n:02}-outcome"]
    require(len(found)<=1, "Conflicting encrypted candidate artifacts")
    result = {"private_ordinal": n, "private_parent": parent, "private_identity": identity}
    if found:
        a,=found
        require(a["workflow_run"]["id"] == run and a["workflow_run"]["head_sha"] == sha and
                re.fullmatch(r"sha256:[a-f0-9]{64}", a.get("digest") or ""), "Unbound private trial envelope")
        result.update(private_outcome_asset_id=a["id"], private_outcome_expires_at=a["expires_at"],
                      private_outcome_expired=a["expired"], private_outcome_outer_digest=a["digest"])
    return result


def download_note(aid):
    # Only after read_note has checked the immutable provider ID, type and small ZIP size.
    return subprocess.check_output(["gh", "api", "--method", "GET", f"repos/{REPO}/actions/artifacts/{aid}/zip"],
                                   timeout=45)


CIPHER_UPLOAD = "Upload the encrypted APK bundle"
CIPHER_CACHE = "Save only the encrypted APK for retrieval retry"


def attempted_seal(job):
    return job and any(journal.upload_step(job, step) for step in (CIPHER_UPLOAD, CIPHER_CACHE, journal.SEAL_STEP))


def slot_chain(jobs, artifacts, run, head, metadata, download, scope=ChainStart(), *, terminal_salvage=False):
    receipts = []
    for ordinal in range(1, 14):
        job = journal.original_job(jobs, run, head, ordinal, journal.RESULT_JOB)
        # Only the GET-only terminal reader may salvage a missing receipt from
        # its exact physical APK producer. Loss admission keeps the strict fence.
        salvage = terminal_salvage and attempted_seal(journal.original_job(
            jobs, run, head, ordinal, f"Compile or verify authenticated APK slot {ordinal}"))
        row = journal.read_note(artifacts, run, head, ordinal, job, "slot", metadata, download,
                                terminal_salvage=salvage)
        if row is not None:
            receipts.append(row)
    follow(receipts, run, head, scope)  # Reject holes, delayed duplicates, rollback and post-terminal work.
    terminal = bool(receipts and receipts[-1]["status"] != "candidate")
    last_allowed = min(scope.last, scope.ordinal + len(receipts) - int(terminal))
    for j in jobs:
        m = re.match(r"^(?:Bounded build segment ([1-9]|1[0-2])|Independently receive checkpoint at the 12-segment limit) /", j["name"])
        if m and any(s.get("conclusion") in {"success","failure"} for s in j.get("steps", [])):
            require(scope.ordinal <= int(m[1] or 13) <= last_allowed, "Physical work ran after a terminal or missing receipt")
    return receipts


def same_time_as_upload(row, job, step_name):
    step = journal.upload_step(job, step_name)
    require(step is not None and step["started_at"], "Terminal cache lacks an original save step")
    created = journal.timestamp(row["created_at"])
    require(int(journal.timestamp(step["started_at"])) <= created <
            int(journal.timestamp(step.get("completed_at") or job["completed_at"]))+1,
            "Terminal cache was created outside the original save")


def current_caches(key, ref):
    page = json.loads(get("actions/caches?"+urlencode({"key":key,"ref":ref,"per_page":100})))
    require(page["total_count"] == len(page["actions_caches"]), "Incomplete exact cache inventory")
    return page["actions_caches"]


def terminal_source(receipts, jobs, artifacts, run, head, metadata, download, caches, scope=ChainStart()):
    """Reconcile original receipts and currently recoverable bytes, even if upload replies were lost."""
    outcome = follow(receipts, run, head, scope)
    origins = []
    for n in range(1, 13):
        job = journal.original_job(jobs,run,head,n,f"Compile or verify authenticated APK slot {n}")
        cipher = journal.one_artifact(artifacts, f"bare-personal-204-encrypted-{run}-1-s{n}")
        separate = journal.one_artifact(artifacts, f"r28-{run}-a1-s{n:02}-apk-seal")
        attempted = attempted_seal(job)
        if cipher or separate or attempted or (outcome["status"] == "apk" and outcome["ordinal"] == n):
            require(job is not None and attempted, "Terminal object lacks its first-attempt producer")
            origins.append((n,job,cipher))
    if not origins:
        return outcome
    require(len(origins)==1, "Multiple terminal APK producers")
    n,job,cipher = origins[0]
    terminal = outcome["status"] == "apk"
    require((terminal and outcome["ordinal"] == n) or
            (outcome["status"] == "recovery-no-terminal" and n == scope.ordinal + len(receipts) and n < scope.last),
            "Original ciphertext conflicts with the latest logical receipt")
    parent = scope.sha if n == scope.ordinal else receipts[n-scope.ordinal-1]["sha"]
    if terminal:
        require(outcome["accepted_parent"] == parent, "Terminal ancestry changed")
    note = journal.read_note(artifacts,run,head,n,job,"seal",metadata,download)
    if note:
        apk_seal.validate(note,run=run,ordinal=n,head=head,parent=parent)
        if terminal:
            require(outcome["cipher_sha"] == note["sha"] and int(outcome["cipher_bytes"]) == note["bytes"],
                    "Sealed and accepted APK receipts disagree")
    artifact_id = ""
    if cipher is not None:
        journal.checked_artifact(cipher,run,head,job,CIPHER_UPLOAD,metadata)
        require(0 < cipher["size_in_bytes"] <= apk_seal.CIPHER_CAP+2*1024**2, "Ciphertext ZIP exceeds transport cap")
        require(not terminal or outcome["cipher_id"] in ("", str(cipher["id"])), "Replaced terminal Artifact")
        if not cipher["expired"] and journal.timestamp(cipher["expires_at"]) > datetime.now(timezone.utc).timestamp():
            artifact_id = str(cipher["id"])
    cache_key, cache_id = "", ""
    if journal.upload_step(job,CIPHER_CACHE):
        key=f"bare-coexist-204-apk-v1-{run}-1-s{n}"
        ref="refs/heads/"+BASE_REF
        current = [row for row in caches(key,ref) if row["key"] == key and row["ref"] == ref]
        require(len(current)<=1, "Ambiguous terminal cache identity")
        if current:
            row, = current
            same_time_as_upload(row,job,CIPHER_CACHE)
            require(type(row["id"]) is int and row["id"]>0 and 0<row["size_in_bytes"]<=apk_seal.CIPHER_CAP+2*1024**2,
                    "Unexpected terminal cache metadata")
            cache_key, cache_id = key, str(row["id"])
    if not artifact_id and not cache_key:
        raise ValueError("Sealed terminal output currently unavailable: consult the registered owner's durable copy")
    return dict(outcome, status="inspect-terminal", ordinal=n, accepted_parent=parent, cipher_cache=cache_key, cipher_cache_id=cache_id,
                cipher_id=artifact_id, cipher_outer_digest=cipher["digest"] if artifact_id else "",
                cipher_zip_bytes=cipher["size_in_bytes"] if artifact_id else "", cipher_sha=outcome.get("cipher_sha", "") if not note else note["sha"],
                cipher_bytes=outcome.get("cipher_bytes", "") if not note else note["bytes"])


def receive_terminal_zip(stream, directory, expected_length, expected_digest):
    require(0 < expected_length <= apk_seal.CIPHER_CAP + 2*1024**2 and
            re.fullmatch("sha256:[a-f0-9]{64}", expected_digest), "Invalid original terminal ZIP bounds")
    digest = sha256()
    count = 0
    with TemporaryFile(dir=directory.parent) as raw:
        for block in iter(lambda: stream.read(1024**2), b""):
            count += len(block)
            require(count <= expected_length, "Terminal ZIP exceeds immutable provider size")
            raw.write(block)
            digest.update(block)
        require(count == expected_length and "sha256:" + digest.hexdigest() == expected_digest,
                "Terminal ZIP differs from the immutable provider digest")
        raw.seek(0)
        with ZipFile(raw) as bundle:
            parts = bundle.infolist()
            require(len(parts) == 2 and {p.filename for p in parts} == {"seal.json", apk_seal.CIPHER_FILE},
                    "Unexpected members in terminal ZIP")
            directory.mkdir()
            for part in parts:
                limit = 4096 if part.filename == "seal.json" else apk_seal.CIPHER_CAP
                require(0 < part.file_size <= limit, "Oversized member in terminal ZIP")
                with bundle.open(part) as source, (directory/part.filename).open("xb") as dest:
                    shutil.copyfileobj(source, dest, length=1024**2)
                    require(dest.tell() == part.file_size, "Incomplete terminal ZIP member")


def fetch_terminal(env):
    aid = env["ARTIFACT_ID"]
    require(re.fullmatch("[1-9][0-9]*", aid), "Invalid terminal artifact ID")
    target = Path(env["RUNNER_TEMP"]) / "bare-apk-artifact"
    with subprocess.Popen(["gh","api","--method","GET",f"repos/{REPO}/actions/artifacts/{aid}/zip"],
                          stdout=subprocess.PIPE) as proc:
        try:
            receive_terminal_zip(proc.stdout,target,int(env["ARCHIVE_BYTES"]),env["ARCHIVE_DIGEST"])
        finally:
            proc.stdout.close()
        require(proc.wait(timeout=15) == 0, "Terminal Artifact download did not complete")


def verify_terminal(env, list_caches=current_caches):
    """Only a complete physical byte read of a matching embedded seal produces an APK recovery receipt."""
    root=Path(env["RUNNER_TEMP"])
    run=int(env["GITHUB_RUN_ID"])
    n=int(env["ORDINAL"])
    parent,head=env["ACCEPTED_PARENT"],env["GITHUB_SHA"]
    locations=[]
    if env.get("ARTIFACT_ID") and env.get("ARTIFACT_OK")=="success":
        locations.append(root/"bare-apk-artifact")
    if env.get("EXPECTED_CACHE") and env.get("CACHE_HIT")=="true" and env.get("CACHE_MATCH")==env["EXPECTED_CACHE"]:
        # restore addresses the cache by key. Re-read its immutable ID after
        # restore before trusting an embedded seal in a cache-only bundle.
        key = env["EXPECTED_CACHE"]
        ref = "refs/heads/"+BASE_REF
        rows = [r for r in list_caches(key,ref) if r["key"] == key and r["ref"] == ref]
        require(len(rows)==1 and type(rows[0]["id"]) is int and str(rows[0]["id"])==env["CACHE_ID"],
                "Original terminal cache was replaced or expired during readback")
        locations.append(root/"bare-apk-delivery")
    require(locations, "No terminal source was independently restored")
    accepted=None
    for directory in locations:
        require(not directory.is_symlink() and {p.name for p in directory.iterdir()}=={"seal.json",apk_seal.CIPHER_FILE},
                "Unexpected contents of terminal bundle")
        record=directory/"seal.json"
        cipher=directory/apk_seal.CIPHER_FILE
        require(record.is_file() and not record.is_symlink() and 0<record.stat().st_size<=4096 and
                cipher.is_file() and not cipher.is_symlink(),"Unexpected terminal file type")
        note=apk_seal.validate(json.loads(record.read_bytes()),run=run,ordinal=n,head=head,parent=parent)
        require(not accepted or accepted==note,"Conflicting terminal sources")
        expected_sha, expected_bytes=env.get("EXPECTED_SHA",""),env.get("EXPECTED_BYTES","")
        require((not expected_sha and not expected_bytes) or
                (note["sha"]==expected_sha and str(note["bytes"])==expected_bytes),"Original terminal receipts disagree")
        require(cipher.stat().st_size==note["bytes"],"Ciphertext length changed")
        digest=sha256()
        with cipher.open("rb") as stream:
            require(stream.readline(40)==b"age-encryption.org/v1\n", "Invalid terminal ciphertext")
            stream.seek(0)
            for block in iter(lambda: stream.read(1024**2), b""):
                digest.update(block)
        require(digest.hexdigest()==note["sha"],"Original encrypted APK bytes changed")
        accepted=note
    print("R28_VERIFIED_TERMINAL_BYTES " + json.dumps(accepted,sort_keys=True))
    return accepted


def main():
    run, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    sha = os.environ["GITHUB_SHA"]
    require(attempt > 1 and run > 0 and re.fullmatch("[0-9a-f]{40}", sha), "Expected a manual rerun")
    base = f"actions/runs/{run}/attempts/1"
    origin = json.loads(get(base))
    require(origin["id"] == run and origin["head_sha"] == sha and origin["path"] == WORKFLOW and
            origin["event"] == "workflow_dispatch" and origin["run_attempt"] == 1 and origin["status"] == "completed" and
            origin["head_branch"] == BASE_REF and origin["repository"]["id"] == origin["head_repository"]["id"] == REPO_ID,
            "Incorrect original producing run")
    jobs = inventory(base + "/jobs", "jobs")
    artifacts = inventory(f"actions/runs/{run}/artifacts", "artifacts")
    def metadata(aid):
        return json.loads(get(f"actions/artifacts/{aid}"))
    scope = ChainStart.from_admission(os.environ)
    if scope.ordinal == 2 and scope.sha == R30_S1_SHA and not scope.replacement:
        binder = [job for job in jobs if job["name"] == "Bind the prior private collection registration to this originating run"]
        require(len(binder) == 1 and binder[0]["conclusion"] == "success" and binder[0]["run_id"] == run
                and binder[0]["run_attempt"] == 1 and binder[0]["head_sha"] == sha,
                "No successful first-attempt admission for the fixed S1 continuation")
    receipts = slot_chain(jobs, artifacts, run, sha, metadata, download_note, scope, terminal_salvage=True)
    outcome = terminal_source(receipts, jobs, artifacts, run, sha, metadata, download_note, current_caches, scope)
    if outcome["status"] in ("recovery-no-terminal","manifest_present_visibility_pending") or outcome["status"].startswith("relay-"):
        outcome.update(last_private_slot(jobs, receipts, run, sha, artifacts, scope))
    if outcome["status"] == "manifest_present_visibility_pending":
        require(outcome.get("private_ordinal") == outcome["ordinal"],"No physical original publisher for pending manifest")
    print("R28_READ_ONLY_RECOVERY " + json.dumps(outcome, sort_keys=True))
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        for k in ("status", "ordinal", "accepted_parent", "cipher_id", "cipher_cache", "cipher_sha", "cipher_bytes",
                  "cipher_zip_bytes", "cipher_outer_digest", "cipher_cache_id", "private_ordinal", "private_parent", "private_identity", "manifest_id", "manifest_sha"):
            print(f"{k}={outcome.get(k,'')}",file=f)


if __name__ == "__main__":
    import sys
    if sys.argv[1:]==["verify-terminal"]:
        verify_terminal(os.environ)
    elif sys.argv[1:]==["fetch-terminal"]:
        fetch_terminal(os.environ)
    elif not sys.argv[1:]:
        main()
    else:
        raise SystemExit("Unexpected receipt operation")
