"""Verify the single encrypted terminal APK Artifact before recording its ID."""
from datetime import datetime, timezone
import os
from pathlib import Path
import re
import signal
import time

import artifact_poll
import bridge as b


def receipt(run, attempt, suffix, head, size, sdk_id, sdk_digest, *, get, sleep):
    b.require(re.fullmatch(r"(?:-s(?:[1-9]|1[0-3]))?",suffix) and
              type(attempt) is int and attempt>0 and 0<size<=451*1024**2 and
              (not sdk_id or re.fullmatch("[1-9][0-9]*",sdk_id)) and
              (not sdk_digest or b.sha(sdk_digest)), "Invalid sealed APK or upload receipt")
    name=f"bare-personal-204-encrypted-{run}-{attempt}{suffix}"
    for delay in (0, 3, 8, 12):
        if delay:
            sleep(delay)
        try:
            row=artifact_poll.lookup(run, name, get, repo=b.REPO, head=head)
        except (artifact_poll.UnstableInventory, b.TransientReadError):
            continue
        if row:
            b.require((not sdk_id or sdk_id==str(row["id"])) and
                      (not sdk_digest or row["digest"]=="sha256:"+sdk_digest) and
                      size <= row["size_in_bytes"] <= size+2*1024**2 and
                      datetime.fromisoformat(row["expires_at"].replace("Z","+00:00"))>datetime.now(timezone.utc),
                      "Terminal APK Artifact size, immutable ID, digest or expiry changed")
            return row
    # The caller preserves the same sealed bytes in the existing capacity-checked
    # recovery cache when GitHub has not provided a confirmed receipt in this job.
    return None


if __name__=="__main__":
    size=b.env_int("ENCRYPTED_BYTES")
    checksum=os.environ["ENCRYPTED_SHA"]
    b.require(os.environ["GITHUB_REPOSITORY"]==b.REPO and b.sha(checksum), "Invalid terminal ciphertext scope")
    # Leave time for this job to hand off a preserved ciphertext if the API stalls.
    class ReceiptDeadline(Exception):
        pass
    def stop_lookup(*_):
        raise ReceiptDeadline()
    signal.signal(signal.SIGALRM,stop_lookup)
    signal.alarm(85)
    try:
        row=receipt(b.env_int("GITHUB_RUN_ID"), b.env_int("GITHUB_RUN_ATTEMPT"), os.environ["SEGMENT_SUFFIX"],
                    os.environ["GITHUB_SHA"], size, os.environ["RETURNED_ID"], os.environ["RETURNED_DIGEST"],
                    get=b.api_json, sleep=time.sleep)
    except ReceiptDeadline:
        row=None
    finally:
        signal.alarm(0)
    if row:
        b.output(id=row["id"])
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as out:
            print(f"Confirmed Artifact {row['id']} (outer {row['digest']}), ciphertext {checksum} ({size} B).",file=out)
    else:
        print("Terminal receipt unconfirmed; preserving the same ciphertext via the recovery cache admission.")
