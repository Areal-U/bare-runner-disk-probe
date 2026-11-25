"""Identify a terminal APK control Artifact which cannot contain a checkpoint."""
import receipt_journal as journal

STOP = "Emit terminal peer outcome for this exact slot"
PACK = "Pack the completed intermediate outputs"
CANDIDATE = "Certify an advanced checkpoint exists before transfer"
UPLOADS = ("Deposit outcome in this run", "Retry the same sealed files at the same immutable name once")


def verified(artifacts, job, run, head, k, parent, now, metadata, download):
    """Caller has independently read the original APK seal for this parent."""
    row = journal.one_artifact(artifacts, f"r28-{run}-a1-s{k:02}-outcome")
    if row is None:
        return False
    for name, expected in ((STOP, "success"), (PACK, "skipped"), (CANDIDATE, "skipped")):
        states = [s.get("conclusion") for s in job["steps"] if s["name"] == name]
        journal.require(states == [expected], "Original control Artifact might contain a checkpoint")
    journal.require(type(row["size_in_bytes"]) is int and 0 < row["size_in_bytes"] <= journal.MAX_ZIP,
                    "Original APK control marker exceeds its ZIP bound")
    created = journal.timestamp(row["created_at"])
    upload = []
    for name in UPLOADS:
        step = journal.upload_step(job, name)
        if step and int(journal.timestamp(step["started_at"])) <= created < int(
                journal.timestamp(step.get("completed_at") or job["completed_at"])) + 1:
            upload.append(name)
    journal.require(len(upload) == 1, "No unique original APK marker upload")
    journal.checked_artifact(row, run, head, job, upload[0], metadata)
    expiration = journal.timestamp(row["expires_at"])
    if row["expired"] is True and expiration <= now.timestamp():
        # The API no longer returns ZIP bytes. The immutable original job
        # uploaded only outcome.json: packing and candidate certification were
        # skipped, the terminal marker writer succeeded, and the APK seal was
        # verified separately. No such upload could include checkpoint.cms.
        return True
    journal.require(row["expired"] is False and expiration > now.timestamp(), "Unsettled control marker expiration")
    note = journal.decode(download(row["id"]), row, "outcome.json")
    expected = dict(schema="bare-r28-checkpoint-private-v1", key=f"bare-coexist-204-{run}-1-checkpoint-production-s{k}",
                    run=run, attempt=1, ordinal=k, producer_sha=head, parent_sha=parent["parent_sha"],
                    parent_identity=parent["parent_identity"])
    journal.require(type(note) is dict and note.keys() == expected.keys() | {"status"} and
                    all(type(note[key]) is type(value) and note[key] == value for key, value in expected.items()) and
                    note["status"] in {"apk", "failed"}, "Unexpected terminal control marker binding")
    return True
