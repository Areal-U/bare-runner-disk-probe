"""Render only the independent read of the already accepted original private S2 checkpoint."""
import argparse
import hashlib
from pathlib import Path
import re
import yaml

import thaw_workflow as original

PUBLISHED_RUN = 45522666298
MANIFEST_ID = 789542812
MANIFEST_SHA = "2bf4a5a4516e5c5609d151a26436a7e4a0f04f067079796880333cdb32329267"


def steps_named(job, label):
    return [step for step in job["steps"] if step["name"]==label]


def single(job, label):
    result, = steps_named(job,label)
    return result


def render(before):
    if not re.fullmatch("[0-9a-f]{40}",before):
        raise ValueError("Invalid exact PR predecessor")
    doc = original.render(before)
    old = doc["jobs"].pop("recover")
    # All execution is readback. A manual request for the same checked PR head
    # can reissue the two short-lived peer keys and restore these same bytes.
    first_only = " && github.run_attempt == '1' }}"
    if not old["if"].endswith(first_only):
        raise ValueError("Unexpected original validation expression")
    roles = old["if"].removesuffix(first_only) + " }}"
    doc["name"] = "Bare R28 independently read the accepted original S2"
    doc["run-name"] = "r28-preflight-s2-20261125 / read private manifest 789542812"
    doc["concurrency"] = {"group":"r28-read-original-789542812","cancel-in-progress":False}
    doc["env"]["R28_RESUME_PUBLISHED"] = str(PUBLISHED_RUN)
    issue, receive = doc["jobs"]["issue"], doc["jobs"]["receive"]
    for job in (issue, receive):
        if job.pop("needs")!="recover":
            raise ValueError("Unexpected dependency on the original recovery job")
        job["if"] = roles
        job["env"] = {"MANIFEST_ID":str(MANIFEST_ID),"MANIFEST_SHA":MANIFEST_SHA}
    issue["timeout-minutes"]=110
    check=single(issue,"Read the exact original successful recovery claim before granting asset access")
    check["name"]="Confirm the immutable private generation and original completed audit"
    check["run"]="python3 preflight28/transport/published_reader.py verify"
    check["timeout-minutes"]=8
    wait_key=single(issue,"Locate authenticated key Artifact")
    wait_key["timeout-minutes"]=20
    issuer=single(issue,"Issue fresh part-scoped GET redirects encrypted to the separate runner")
    issuer["timeout-minutes"]=80
    # The prior authenticated 1.7 GB archive is never reacquired or republished
    # by the issuer. Provider public-rate resets can precede issue by an hour.
    receive["timeout-minutes"]=300
    wait_descriptor=single(receive,"Locate authenticated descriptor Artifact")
    wait_descriptor["timeout-minutes"]=88
    return doc


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("before")
    p.add_argument("output",type=Path)
    args=p.parse_args()
    body=yaml.dump(render(args.before),Dumper=original.orig.Readable,sort_keys=False,width=120)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(body)
    print("workflow_bytes",len(body.encode()),"sha256",hashlib.sha256(body.encode()).hexdigest())
