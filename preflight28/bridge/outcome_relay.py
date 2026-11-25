"""Resolve the canonical original-attempt outcome before permitting one same-name retry."""
import argparse
from datetime import datetime
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import time
import artifact_poll

import normal as n

STOPS = {"relay-quota-denied","relay-capacity-exceeded","relay-deadline","relay-missing","relay-ambiguous"}
SDK = {"uploaded", "quota-denied", "transfer-unknown"}


def payload():
    record = json.loads((n.ROOT/"outcome.json").read_text())
    n.b.require(n.b.env_int("GITHUB_RUN_ATTEMPT")==1 and os.environ["GITHUB_JOB"]=="compile-probe"
                and n.same(record), "Relay requires this ordinary initial-attempt slot")
    length=(n.ROOT/"outcome.json").stat().st_size
    if record["status"]=="candidate":
        size = (n.ROOT/"checkpoint.cms").stat().st_size
        n.b.require(size == record["sealed_bytes"] and n.b.sha(record["sealed_sha"]), "Local sealed checkpoint changed")
        length += size
    else:
        n.b.require(record["status"] in n.STOPS, "Unexpected transfer outcome")
    return record, length


def upload_minutes(record):
    return n.UPLOAD_MINUTES if record['status'] == 'candidate' else 2


def can_upload(record, cutoff, now):
    return now+(upload_minutes(record)+n.VISIBILITY_MINUTES)*60 <= cutoff


def deadline():
    epoch=int((Path(os.environ["RUNNER_TEMP"])/"bare-probe-start").read_text())
    return min(n.sender_deadline(n.info()),epoch+n.JOB_MINUTES*60)


def locate(name, raw_size, returned_id, returned_digest, *, api, now):
    run=n.b.env_int("GITHUB_RUN_ID")
    a = artifact_poll.lookup(run, name, api, repo=n.b.REPO, head=os.environ["R28_HEAD_SHA"])
    if a is None:
        return None
    digest=a.get("digest") or ""
    n.b.require(a["name"]==name and type(a["id"]) is int and a["id"]>0 and
                a["workflow_run"]["id"]==run and a["workflow_run"]["head_sha"]==os.environ["R28_HEAD_SHA"] and
                not a["expired"] and datetime.fromisoformat(a["expires_at"].replace("Z","+00:00")).timestamp()>now and
                re.fullmatch(r"sha256:[0-9a-f]{64}",digest) and raw_size <= a["size_in_bytes"] <= raw_size+2*1024**2 and
                (not returned_id or str(a["id"])==returned_id) and (not returned_digest or digest=="sha256:"+returned_digest),
                "Wrong physical Artifact, digest, expiry or byte envelope")
    return a


def settled(name, size, returned_id, returned_digest, *, api, sleep, clock, absence_samples=3):
    # Stable absence matters after an upload with a lost acknowledgement.
    empty = 0
    for delay in (0, 4, 8, 12, 12):
        if delay:
            sleep(delay)
        try:
            row = locate(name, size, returned_id, returned_digest, api=api, now=clock())
        except (artifact_poll.UnstableInventory, n.b.TransientReadError):
            empty = 0
            continue
        if row is not None:
            return row
        empty += 1
        if empty == absence_samples:
            return None
    raise artifact_poll.UnstableInventory("Timed out waiting for a settled outcome inventory")


def resolve(round_no, sdk, returned_id, returned_digest, *, api, sleep, clock):
    try:
        record, size=payload()
        name=n.stem()+"-outcome"
        if (returned_id and not re.fullmatch("[1-9][0-9]*",returned_id)) or (
                returned_digest and not n.b.sha(returned_digest)):
            return {"decision":"relay-ambiguous"}
        cutoff=deadline()
        a = settled(name,size,returned_id,returned_digest,api=api,sleep=sleep,clock=clock)
        if a:
            return {"decision":"present","id":str(a["id"]),"digest":a["digest"],"expires_at":a["expires_at"]}
        if sdk not in SDK or returned_id or returned_digest or sdk=="uploaded":
            return {"decision":"relay-ambiguous"}
        if sdk=="quota-denied":
            return {"decision":"relay-quota-denied"}
        if round_no==2:
            return {"decision":"relay-missing"}
        if not can_upload(record,cutoff,clock()):
            return {"decision":"relay-deadline"}
        # Fail closed if bytes, ownership or expected metadata differ from the first upload.
        snapshot=json.loads((n.ROOT/"first-upload.json").read_text())
        if snapshot != {"outcome_sha":n.b.digest(n.ROOT/"outcome.json"),"sealed_sha":record.get("sealed_sha"),
                        "total_bytes":size}:
            return {"decision":"relay-ambiguous"}
        if record["status"]=="candidate" and n.b.digest(n.ROOT/"checkpoint.cms")!=record["sealed_sha"]:
            return {"decision":"relay-ambiguous"}
        if not can_upload(record,cutoff,clock()):
            return {"decision":"relay-deadline"}
        return {"decision":"retry"}
    except (KeyError,TypeError,ValueError,OSError,HTTPException) as error:
        print("Canonical Artifact lookup could not be confirmed:",type(error).__name__)
        return {"decision":"relay-ambiguous"}


def plan():
    try:
        record,size=payload()
        # capacity() is the existing normal-path simultaneity/inode/time gate.
        if record["status"]=="candidate":
            n.capacity()
        # Even a zero-byte-status relay needs a checked first admission. A repo-wide
        # capacity listing cannot establish canonical absence for this run and name.
        existing = settled(n.stem()+"-outcome",size,"","",api=n.b.api_json,sleep=time.sleep,clock=time.time,absence_samples=1)
        if existing is not None:
            return {"decision":"present","id":str(existing["id"]),"digest":existing["digest"],"expires_at":existing["expires_at"]}
        if not can_upload(record,deadline(),time.time()):
            return {"decision":"relay-deadline"}
    except n.RelayPriorExists:
        try:
            original = settled(n.stem()+'-outcome',size,'','',api=n.b.api_json,sleep=time.sleep,clock=time.time)
            if original:
                return {'decision':'present','id':str(original['id']),'digest':original['digest'],
                        'expires_at':original['expires_at']}
        except (KeyError,TypeError,ValueError,OSError,HTTPException):
            pass
        return {'decision':'relay-ambiguous'}
    except n.RelayCapacityExceeded:
        return {"decision":"relay-capacity-exceeded"}
    except n.RelayTimeExpired:
        return {"decision":"relay-deadline"}
    except (KeyError,TypeError,ValueError,OSError,HTTPException) as error:
        print("Could not confirm the upload preconditions:",type(error).__name__)
        return {"decision":"relay-ambiguous"}
    with (n.ROOT/"first-upload.json").open("x") as f:
        json.dump({"outcome_sha":n.b.digest(n.ROOT/"outcome.json"), "sealed_sha":record.get("sealed_sha"),
                   "total_bytes":size},f)
    return {"decision":"upload","upload_minutes":upload_minutes(record)}


def finish(state, asset_id):
    if state=="present":
        n.b.require(re.fullmatch(r"[1-9][0-9]*",asset_id), "No physical receipt after transfer")
    else:
        n.b.require(state in STOPS and not asset_id,"Unrecognized or ambiguous final relay decision")
    if state in STOPS:
        candidate=None
        try:
            rec,_=payload()
            candidate=rec.get("sha256")
        except (KeyError,TypeError,ValueError,OSError):
            n.b.require(state=="relay-ambiguous","Sealed metadata unavailable for this stop")
        print("R28_RELAY_STOP "+json.dumps({"reason":state,"ordinal":n.slot(),"run":n.b.env_int("GITHUB_RUN_ID"),
              "attempt":1,"parent":n.context()["parent_sha"],"candidate":candidate,"recompile":False,
              "fallback":"retained-parent"},sort_keys=True))
        n.b.output(stop=state)
    n.b.output(decision=state,artifact_id=asset_id)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation",choices=("plan","resolve","finish"))
    parser.add_argument("--round",type=int,choices=(1,2))
    args=parser.parse_args()
    if args.operation=="finish": finish(os.environ["RELAY_STATE"],os.environ.get("RELAY_ID",""))
    else:
        if args.operation=="plan": result=plan()
        else:
            if args.round is None: parser.error("resolve requires a round")
            result=resolve(args.round,os.environ.get("SDK_STATUS",""),os.environ.get("RETURNED_ID",""),
                           os.environ.get("RETURNED_DIGEST",""),api=n.b.api_json,sleep=time.sleep,clock=time.time)
        n.b.output(**result)
        print("R28_RELAY_DECISION "+json.dumps(result,sort_keys=True))
