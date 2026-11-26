"""Attest only the private object identities that this specific originating job actually validated."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import sys
import time

from admission import BASE_REF, PagedOwnerDraft, RELEASE_ID, REPO, require
from registration import CAMPAIGN, CLAIM, TICKET_NAME, OWNER
import apk_seal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "collector"))
import production as owner

SCHEMA = "bare-r28-owner-witness-v1"


def row_info(row, *, owner_issued):
    name = row["name"]
    require(row["state"] == "uploaded" and type(row["id"]) is int and row["id"] > 0 and
            type(row["size"]) is int and row["size"] > 0 and re.fullmatch("sha256:[a-f0-9]{64}",row["digest"]),
            "Incomplete immutable object identity")
    if owner_issued:
        require(all(row["uploader"].get(k) == v for k,v in OWNER.items()), "Unconfirmed owner issuer")
    return dict(name=name,id=row["id"],bytes=row["size"],sha256=row["digest"][7:],owner_issued=owner_issued)


def claim_items(api, rows, run, head, job, expected_id):
    gate = owner.s1_resume if any(row["name"] == owner.s1_resume.CLAIM and row["id"] == expected_id
                                  for row in rows) else owner.handoff
    initial = owner.private_row(rows,gate.TICKET_NAME)
    ticket = owner.private_document(api,initial,owner=True)
    locator = dict(head=head,ticket_asset_id=initial["id"],ticket_sha=initial["digest"][7:],
                   owner_destination_id=ticket["owner_destination_id"],registration_id=ticket["collector_registration_id"])
    origin, physical, cid, scope = owner.bind(api,rows,locator)
    require(physical == run and cid == expected_id and
            (job == "loss-admission") == scope.replacement, "Wrong physical claim or replacement")
    result = [row_info(initial,owner_issued=True), row_info(owner.private_row(rows,gate.CLAIM),owner_issued=False)]
    if scope.replacement:
        result += [row_info(owner.private_row(rows,f"{CAMPAIGN}-loss-{origin}.json"),owner_issued=True),
                   row_info(owner.private_row(rows,f"{CAMPAIGN}-loss-evidence-{origin}.json"),owner_issued=True),
                   row_info(owner.private_row(rows,owner.REPLACEMENT),owner_issued=False)]
    return result


def terminal_items(api, rows, env, run, head):
    n = int(env["R28_SLOT"])
    source = int(env.get("R28_SOURCE_RUN") or run)
    require(1 <= n <= 12 and source>0 and (env["GITHUB_JOB"] == "deliver-recovered-cached-apk") == (source!=run),
            "Unbound terminal witness source")
    base = f"r28-{source}-a1-s{n:02}"
    part = owner.private_row(rows,base+owner.CIPHER_SUFFIX,retry=True)
    receipt = owner.private_row(rows,base+owner.RECEIPT_SUFFIX,retry=True)
    require(receipt["id"] == int(env["WITNESS_RECEIPT_ID"]) and receipt["digest"] == "sha256:"+env["WITNESS_RECEIPT_SHA"],
            "Different terminal receipt after original private deposit")
    record = owner.private_document(api,receipt)
    seal=apk_seal.validate(record["seal"],run=source,ordinal=n,head=head,parent=env["R28_PARENT_SHA"])
    require(record["schema"]=="bare-r28-private-apk-v1" and record["collection_claim_id"]==int(env["R28_COLLECTION_CLAIM"])
            and record["source_cache_key"]==f"bare-coexist-204-apk-v1-{source}-1-s{n}" and type(record["depositor_run"]) is int
            and record["depositor_run"]>0 and seal["sha"]==part["digest"][7:] and seal["bytes"]==part["size"] and
            record["cipher"]==dict(id=part["id"],name=part["name"],bytes=part["size"],sha256=seal["sha"]),
            "Private receipt conflicts with the read-back ciphertext")
    return [row_info(part,owner_issued=False),row_info(receipt,owner_issued=False)]


class NotYetVisible(OSError):
    pass


def verified_rows(read, *, pause=time.sleep):
    # This entire retry is GET-only; the private claim has already been committed.
    def deadline(*_):
        raise TimeoutError("Private witness GET deadline")
    previous=signal.signal(signal.SIGALRM,deadline)
    try:
        for attempt in range(2):
            signal.alarm(45)
            try:
                return read()
            except Exception as error:
                transient = (isinstance(error,(OSError,http.client.HTTPException)) or
                             any(str(error).endswith("returned "+str(code)) for code in (408,429,500,502,503,504)))
                if attempt or not transient:
                    raise
            finally:
                signal.alarm(0)
            pause(2)
    finally:
        signal.signal(signal.SIGALRM,previous)


def write_witness(api, env, kind):
    run, job, head = int(env["GITHUB_RUN_ID"]), env["GITHUB_JOB"], env["GITHUB_SHA"]
    jobs = {"claim":{"bind-private-receiver","loss-admission"}, "terminal":{"deliver-cached-apk","deliver-recovered-cached-apk"}}
    require(kind in jobs and job in jobs[kind] and re.fullmatch("[a-f0-9]{40}",head) and run>0 and
            env["GITHUB_REPOSITORY"]==REPO and env["GITHUB_REF"]=="refs/heads/"+BASE_REF and
            env["GITHUB_RUN_ATTEMPT"]=="1" and env["GITHUB_ACTOR"]=="Areal-U" and env["GITHUB_EVENT_NAME"]=="workflow_dispatch",
            "Unexpected provenance witness issuer")
    if kind == "claim":
        ident=int(env["WITNESS_CLAIM_ID"])
        label = f"r28-{run}-a1-owner-claim"
    else:
        ident=int(env["WITNESS_RECEIPT_ID"])
        label = f"r28-{run}-a1-s{int(env['R28_SLOT']):02}-owner-terminal"
    def read():
        rows=PagedOwnerDraft(api).draft(RELEASE_ID)["assets"]
        if not any(r["id"]==ident for r in rows):
            raise NotYetVisible("Previously acknowledged immutable ID not yet visible in this complete GET")
        if kind=="claim":
            return claim_items(api,rows,run,head,job,ident)
        return terminal_items(api,rows,env,run,head)
    entries=verified_rows(read)
    entries.sort(key=lambda row:row["name"])
    require(len({r["id"] for r in entries}) == len(entries), "Reused private object identity")
    note=dict(schema=SCHEMA,run=run,attempt=1,head=head,release_id=RELEASE_ID,kind=kind,rows=entries)
    data=json.dumps(note,sort_keys=True,separators=(",",":")).encode("ascii")+b"\n"
    require(len(data)<=8192,"Owner witness exceeds its small fixed envelope")
    with (Path(env["RUNNER_TEMP"])/"witness.json").open("xb") as file:
        file.write(data)
    return label, hashlib.sha256(data).hexdigest()


def local_attestation(env, kind):
    """Only the already verified row IDs and the canonical digest enter Actions metadata."""
    path = Path(env["RUNNER_TEMP"])/"witness.json"
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 8192, "Missing bounded witness")
    data = path.read_bytes()
    note = json.loads(data)
    require(note["schema"] == SCHEMA and note["kind"] == kind and note["run"] == int(env["GITHUB_RUN_ID"]) and
            note["attempt"] == 1 and note["head"] == env["GITHUB_SHA"] and note["release_id"] == RELEASE_ID and
            (json.dumps(note,sort_keys=True,separators=(",",":"))+"\n").encode("ascii") == data,
            "Changed physical witness before provider attestation")
    rows = note["rows"]
    require(len(rows) in ((2,5) if kind == "claim" else (2,)) and
            [r["name"] for r in rows] == sorted({r["name"] for r in rows}) and
            all(type(r["id"]) is int and 0 < r["id"] < 10**19 for r in rows) and
            len({r["id"] for r in rows}) == len(rows), "Invalid fixed-order witness IDs")
    return ",".join(str(r["id"]) for r in rows), hashlib.sha256(data).hexdigest()


def preserve(api, env, kind):
    # No user-selected object name or request body can enter the limited writer.
    from admission import admit, encode
    run=int(env["GITHUB_RUN_ID"])
    if kind=="claim":
        require(env["GITHUB_JOB"] in ("bind-private-receiver","loss-admission"),"Unbound private claim issuer")
        name=f"r28-{run}-a1-owner-claim"
    else:
        n=int(env["R28_SLOT"])
        require(kind=="terminal" and env["GITHUB_JOB"] in ("deliver-cached-apk","deliver-recovered-cached-apk")
                and 1<=n<=12,"Unbound private terminal issuer")
        name=f"r28-{run}-a1-s{n:02}-owner-terminal"
    require(env["GITHUB_RUN_ATTEMPT"]=="1" and env["GITHUB_ACTOR"]=="Areal-U" and env["GITHUB_REPOSITORY"]==REPO
            and env["GITHUB_REF"]=="refs/heads/"+BASE_REF and env["GITHUB_EVENT_NAME"]=="workflow_dispatch" and
            env["WITNESS_NAME"]==name,"Unbound original physical witness")
    path=Path(env["RUNNER_TEMP"])/"witness.json"
    require(not path.is_symlink() and path.is_file() and 0<path.stat().st_size<=8192,"Unexpected local witness")
    data=path.read_bytes()
    note=json.loads(data)
    require(encode(note)==data and note["schema"]==SCHEMA and note["head"]==env["GITHUB_SHA"] and
            note["release_id"]==RELEASE_ID and note["run"]==run and note["attempt"]==1 and note["kind"]==kind and
            hashlib.sha256(data).hexdigest()==env["WITNESS_SHA"],"Witness changed after verification")
    return admit("compute",note,PagedOwnerDraft(api),name=name+".json")


if __name__ == "__main__":
    if len(sys.argv)==3 and sys.argv[1]=="attest":
        ids, digest = local_attestation(os.environ,sys.argv[2])
        require(ids == os.environ["WITNESS_IDS"] and digest == os.environ["WITNESS_SHA"],
                "Actual fixed-order object IDs or witness digest changed")
        sys.exit(0)
    from recover_private import read_only
    sys.path.insert(0,os.environ["RUNNER_TEMP"])
    import transfer
    if len(sys.argv)==3 and sys.argv[1]=="preserve":
        print("Confirmed private owner witness ID", preserve(transfer,os.environ,sys.argv[2]))
    else:
        kind,=sys.argv[1:]
        transfer.request=read_only(transfer.request)
        name,sha=write_witness(transfer,os.environ,kind)
        ids, digest = local_attestation(os.environ,kind)
        require(digest==sha, "Cannot attest changed witness bytes")
        with open(os.environ["GITHUB_OUTPUT"],"a") as output:
            print(f"name={name}\nsha={sha}\nids={ids}",file=output)
