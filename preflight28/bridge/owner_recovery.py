"""Recover an exact sealed normal checkpoint on the owner's machine without launching CI."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import time
import zipfile

if __name__ == "__main__":
    # Offline owner recovery also runs on machines without the Actions environment.
    os.environ.setdefault("RUNNER_TEMP",tempfile.gettempdir())

import artifact_poll
import bridge as b
import frames
from verify_payload import check as verify_payload

RECIPIENT = "age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx"
SCHEMA = "bare-r28-owner-key-v1"
FIELDS = ("schema","key","run","attempt","ordinal","producer_sha","parent_sha","parent_identity")


def data(row):
    return json.dumps(row,sort_keys=True,separators=(",",":")).encode("ascii")


def bounded(path, limit):
    st=path.lstat()
    b.require(stat.S_ISREG(st.st_mode) and 0<st.st_size<=limit, "Unexpected local file type or size")
    return path.read_bytes()


def bind(ctx, recipient, claim):
    b.require(recipient == RECIPIENT and type(claim) is int and claim > 0, "Unknown owner or collection claim")
    return {"format":SCHEMA,"context":{k:ctx[k] for k in FIELDS},"owner":recipient,"claim_id":claim}


def wrap(root, ctx, recipient, claim):
    record=bind(ctx,recipient,claim)
    record["writer_fpr"]=b.fingerprint(root/"public.pem")
    plain=data({**record,"cert":bounded(root/"public.pem",8192).decode("ascii"),
                "private":bounded(root/"key.pem",8192).decode("ascii")})
    # No plaintext key is carried in an argument, log, descriptor or outcome.
    encrypted=subprocess.run(["age","-r",recipient],input=plain,stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,check=True,timeout=20).stdout
    b.require(encrypted.startswith(b"age-encryption.org/v1\n") and len(encrypted)<16384, "Invalid key wrapper")
    return {**record,"sha256":hashlib.sha256(encrypted).hexdigest(),"age":base64.b64encode(encrypted).decode("ascii")}


def checked(wrapper, ctx, recipient, claim, writer):
    expected={**bind(ctx,recipient,claim),"writer_fpr":writer}
    b.require(isinstance(wrapper,dict) and all(wrapper.get(k)==v for k,v in expected.items())
              and isinstance(wrapper.get("age"),str) and 0<len(wrapper["age"])<=24576,
              "Stale or mismatched owner recovery binding")
    encrypted=base64.b64decode(wrapper["age"],validate=True)
    b.require(encrypted.startswith(b"age-encryption.org/v1\n") and len(encrypted)<16384
              and hashlib.sha256(encrypted).hexdigest()==wrapper["sha256"], "Damaged owner key wrapper")
    return expected,encrypted


def expected_name(run,ordinal):
    return f"r28-{run}-a1-s{ordinal:02}-outcome"


def service_record(row, run, ordinal, head, parent, claim, *, expect_id=None):
    digest=row.get("digest","")
    b.require(row.get("name")==expected_name(run,ordinal) and row["workflow_run"]["id"]==run
              and row["workflow_run"]["head_sha"]==head and row.get("expired") is False
              and type(row["id"]) is int and row["id"]>0 and (expect_id is None or row["id"]==expect_id)
              and isinstance(digest,str) and re.fullmatch(r"sha256:[0-9a-f]{64}",digest)
              and 0<row["size_in_bytes"]<=b.CAP+32*1024**2 and type(claim) is int and claim>0
              and isinstance(row.get("expires_at"),str)
              and datetime.fromisoformat(row["expires_at"].replace("Z","+00:00"))>datetime.now(timezone.utc),
              "Unconfirmed immutable owner-recovery Artifact")
    return {"artifact_id":row["id"],"run":run,"ordinal":ordinal,"producer_sha":head,"parent_sha":parent,
            "claim_id":claim,"zip_sha256":digest[7:],"name":row["name"],"expires_at":row["expires_at"]}


def locate(run, ordinal, head, parent, claim, expect_id=None):
    name=expected_name(run,ordinal)
    for delay in (0, 2, 5, 10, 20):
        if delay:
            time.sleep(delay)
        try:
            row = artifact_poll.lookup(run, name, b.api_json, repo=b.REPO, head=head)
        except (artifact_poll.UnstableInventory, b.TransientReadError):
            continue
        if row is not None:
            break
    else:
        raise ValueError("Missing or unsettled owner-recovery outcome Artifact")
    rec=service_record(row,run,ordinal,head,parent,claim,expect_id=expect_id)
    # This line is printable; it contains no wrapped key, signed URL or unencrypted metadata payload.
    print("R28_OWNER_CHECKPOINT_ARTIFACT "+data(rec).decode("ascii"),flush=True)
    return rec


def read_claim(api, release, name):
    rows = [r for r in release["assets"] if r["name"] == name]
    if not rows:
        return None
    b.require(len(rows) == 1, "Ambiguous owner collection claim")
    r, = rows
    digest = (r.get("digest") or "").removeprefix("sha256:")
    b.require(b.sha(digest) and r["digest"] == "sha256:" + digest and 0 < r["size"] <= 4096,
              "Invalid owner collection claim metadata")
    api.asset_info(release, name, r["size"], digest, r["id"])
    raw = io.BytesIO()
    api.download(r["id"], r["size"], digest, raw)
    b.require(hashlib.sha256(raw.getvalue()).hexdigest() == digest, "Owner claim changed during retrieval")
    return r["id"], json.loads(raw.getvalue())


def collection_claim(api,release,ctx):
    genesis = read_claim(api,release,"bare-personal-204-r29-production-run-claim.json")
    if not genesis:
        return None
    original_id, original = genesis
    binding = {"schema":1,"campaign":"bare-personal-204-r29","repository_id":1450926240,
               "workflow":".github/workflows/bare-checkpoint-transfer.yml","branch":"bare-coexist-v2.0.4",
               "head":ctx["producer_sha"],"release_id":b.RELEASE,"recipient":RECIPIENT,"producer_attempt":1}
    b.require(original.get("initial_parent") == b.PARENT_SHA and
              all(original.get(k) == v for k,v in binding.items()), "Wrong original collection claim")
    if original["run_id"] == ctx["run"]:
        return original_id
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    event = json.loads(Path(event_path).read_text()) if event_path else {}
    inputs = event.get("inputs") or {}
    b.require(inputs.get("mode") == "recover-lost-slot" and inputs.get("loss_origin_run") == str(original["run_id"]) and
              (event.get("sender") or {}).get("id") == 292261483 and
              (event.get("repository") or {}).get("id") == binding["repository_id"],
              "Owner collection claim is for a different operation")
    replacement = read_claim(api,release,"bare-personal-204-r29-loss-replacement-claim.json")
    b.require(replacement is not None, "No immutable replacement collection claim")
    claim_id, claim = replacement
    expected = dict(binding,run_id=ctx["run"],original_claim_id=original_id,origin_run=original["run_id"],
                    registration_id=original["registration_id"],ordinal=ctx["ordinal"],
                    initial_parent=ctx["parent_sha"],parent_sha=ctx["parent_sha"],parent_identity=ctx["parent_identity"])
    b.require(all(claim.get(k) == v for k,v in expected.items()), "Unbound replacement collection claim")
    return claim_id


def open_saved(zip_path, service_receipt, age_identity_path, dest, *, artifact_id, run, ordinal, head, parent_sha, claim_id):
    exp={"artifact_id":artifact_id,"run":run,"ordinal":ordinal,"producer_sha":head,"parent_sha":parent_sha,
         "claim_id":claim_id,"name":expected_name(run,ordinal)}
    b.require(1<=ordinal<=12 and artifact_id>0 and run>0 and claim_id>0 and b.sha(parent_sha)
              and re.fullmatch("[0-9a-f]{40}",head) and all(service_receipt.get(k)==v for k,v in exp.items())
              and b.sha(service_receipt.get("zip_sha256","")), "Wrong service receipt or recovery attempt")
    zst=zip_path.lstat()
    b.require(stat.S_ISREG(zst.st_mode) and 0<zst.st_size<=b.CAP+32*1024**2
              and b.digest(zip_path)==service_receipt["zip_sha256"], "Wrong immutable Artifact ZIP")
    # Opening an already rescued Artifact is permitted after expiry. The trusted
    # service's ZIP digest and generation binding still apply to the local copy.
    with tempfile.TemporaryDirectory(prefix=".r28-owner-",dir=dest.parent) as scratch, zipfile.ZipFile(zip_path) as z:
        work=Path(scratch)
        files=z.infolist()
        b.require(len(files)==2 and {e.filename for e in files}=={"outcome.json","checkpoint.cms"},
                  "Unexpected owner Artifact members")
        meta=z.getinfo("outcome.json")
        b.require(0<meta.file_size<=65536,"Unbounded outcome receipt")
        outcome=json.loads(z.read(meta))
        n=outcome
        b.require(n["schema"]=="bare-r28-checkpoint-private-v1" and n["attempt"]==1 and n["run"]==run
                  and n["ordinal"]==ordinal and n["producer_sha"]==head and n["parent_sha"]==parent_sha
                  and n["key"]==f"bare-coexist-204-{run}-1-checkpoint-production-s{ordinal}" and n["status"]=="candidate"
                  and all(b.sha(n[k]) for k in ("sha256","sealed_sha","proof_sha","identity","parent_identity","recipient_fpr"))
                  and n["sha256"]!=parent_sha and type(n["bytes"]) is int and 0<n["bytes"]<=b.CAP
                  and n["bytes"]<n["sealed_bytes"]<=n["bytes"]+16*1024**2, "Invalid normal outcome")
        expected,encrypted=checked(n["owner_recovery"],n,RECIPIENT,claim_id,n["recipient_fpr"])
        private=subprocess.run(["age","-d","-i",str(age_identity_path)],input=encrypted,stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,timeout=20,check=True).stdout
        row=json.loads(private)
        b.require(all(row.get(k)==v for k,v in expected.items()),"Decrypted wrapper belongs to another generation")
        for name,field in (("key.pem","private"),("public.pem","cert")):
            raw=row[field].encode("ascii")
            b.require(0<len(raw)<8192,"Invalid recovery key length")
            fd=os.open(work/name,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,"wb") as f:f.write(raw)
        b.require(b.fingerprint(work/"public.pem")==n["recipient_fpr"],"Certificate differs from original recipient")
        ct=z.getinfo("checkpoint.cms")
        b.require(ct.file_size==n["sealed_bytes"],"Wrong sealed content length")
        cipher=work/"checkpoint.cms"
        with z.open(ct) as src,cipher.open("xb") as target:
            shutil.copyfileobj(src,target,length=1024**2)
        b.require(b.digest(cipher)==n["sealed_sha"],"Sealed content SHA differs")
        candidate=work/"verified.tar.zst"
        original=b.ROOT
        try:
            b.ROOT=work
            frames.receive(cipher,candidate,n["bytes"],n["sha256"])
        finally:b.ROOT=original
        verify_payload(candidate,n)
        try:
            os.link(candidate,dest)
        except FileExistsError:
            st = dest.lstat()
            b.require(stat.S_ISREG(st.st_mode) and st.st_uid==os.getuid() and not st.st_mode & 0o077
                      and b.digest(dest)==n["sha256"],
                      "Recovery destination contains a different object")
        print(f"verified_owner_checkpoint artifact_id={artifact_id} sha256={n['sha256']} bytes={n['bytes']}")
        return n["sha256"]


if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="action",required=True)
    for mode in ("locate","open"):
        args=sub.add_parser(mode)
        for key in ("run","ordinal","claim-id"):
            args.add_argument("--"+key,type=int,required=True)
        for key in ("head","parent-sha"):args.add_argument("--"+key,required=True)
        args.add_argument("--artifact-id",type=int,required=(mode=="open"))
        if mode=="locate":args.add_argument("--save-receipt",type=Path)
        if mode=="open":
            for key in ("zip","receipt","age-identity","output"):args.add_argument("--"+key,type=Path,required=True)
    v=p.parse_args()
    if v.action=="locate":
        r = locate(v.run,v.ordinal,v.head,v.parent_sha,v.claim_id,v.artifact_id)
        if v.save_receipt:
            with v.save_receipt.open("xb") as f:f.write(data(r)+b"\n")
    else:
        open_saved(v.zip,json.loads(bounded(v.receipt,8192)),v.age_identity,v.output,artifact_id=v.artifact_id,
                   run=v.run,ordinal=v.ordinal,head=v.head,parent_sha=v.parent_sha,claim_id=v.claim_id)
