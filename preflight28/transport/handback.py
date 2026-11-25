"""Recover only the fixed test writer into a separately identified, live restricted runner."""
import argparse
import base64
import binascii
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE/"control"))
from admission import BRANCH, PagedOwnerDraft, RELEASE_ID, REPO, REPO_ID

WORKFLOW = ".github/workflows/bare-r28-s2-thaw.yml"
SCHEMA = "bare-r28-private-test-key-recovery-v1"
SOURCE = {
    "run":45513782890, "attempt":1, "writer_job":138867986660,
    "head":"81105d5f7b9ba994034753ce4fbd65d9b981dde3",
    "writer_artifact":14976353454, "writer_bytes":4443,
    "writer_sha":"0cf210a57eb60e904189e1259ff55d077f6159c09d872c9e0545dcf2aa411c79",
    "original_recipient":"56735d206310a24314a8b6ddf5d97ccac73843d4e7fd4e2901708add49dc84dd",
    "cipher_artifact":14978478511, "cipher_zip_bytes":1747040746,
    "cipher_zip_sha":"b7d84d5399d6bce27424370573375a965fabe568a97e0b8a16b1faa421daaa21",
    "sealed_sha":"f11d6b4cb5cc22c8bac45a6443a96e2613fd33a59df68d7de208ff7fdab6aa27",
    "candidate_sha":"532ca75915583a89e2830d062076e3d7130f1edabbe5c03159ce6b1e3c76c1ba",
    "candidate_bytes":1745316602}
AGE_SHA = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c"
MAX_PACKET = 65536
JOB_LABEL = "Recover original sealed candidate and audit before immutable private publication"


class Rejected(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise Rejected(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(record):
    return (json.dumps(record,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")


def bounded(path, limit):
    st=path.lstat()
    require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= limit,"Unexpected file type or size")
    return path.read_bytes()


def record(path, raw):
    try:
        with path.open("xb") as f:
            os.fchmod(f.fileno(),0o600)
            f.write(raw)
    except FileExistsError:
        require(bounded(path,MAX_PACKET)==raw,"A conflicting local receipt already exists")


def command(args, raw=None):
    result=subprocess.run(args,input=raw,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=25)
    require(result.returncode==0,"Key operation failed")
    return result.stdout


def cert_fpr(pem):
    require(pem.startswith(b"-----BEGIN CERTIFICATE-----") and pem.count(b"BEGIN CERTIFICATE")==1 and
            b"PRIVATE" not in pem and len(pem)<8192,"Expected one public certificate")
    return sha(command(["openssl","x509","-outform","DER"],pem))


def check_pair(private, public):
    expected=command(["openssl","x509","-pubkey","-noout"],public)
    actual=command(["openssl","pkey","-pubout"],private)
    require(expected == actual,"Recovered test key differs from the original public certificate")


def public_context(run,head,job,check):
    require(all(type(x) is int and x>0 for x in (run,job,check)) and run!=SOURCE["run"] and
            re.fullmatch("[a-f0-9]{40}",head),"Invalid replacement worker")
    return dict(schema=SCHEMA,repository=REPO,workflow=WORKFLOW,run=run,attempt=1,job=job,
                check_run=check,role="recover",head=head,source=SOURCE)


def context():
    require(os.environ["GITHUB_REPOSITORY"]==REPO and os.environ["GITHUB_RUN_ATTEMPT"]=="1" and
            os.environ["GITHUB_JOB"]=="recover","Restricted recovery job required")
    return int(os.environ["GITHUB_RUN_ID"]),os.environ["TRIAL_SHA"]


def helper():
    sys.path.insert(0,os.environ["RUNNER_TEMP"])
    import transfer
    return PagedOwnerDraft(transfer)


def physical(api,run,head,check):
    base=f"{api.BASE}/actions/runs/{run}/attempts/1"
    detail=api.metadata(base)
    require(detail["id"]==run and detail["run_attempt"]==1 and detail["path"]==WORKFLOW and
            detail["event"]=="pull_request" and detail["head_sha"]==head and detail["head_branch"]==BRANCH and
            detail["repository"]["id"]==REPO_ID and detail["status"]=="in_progress","Unexpected physical workflow")
    listing=api.metadata(base+"/jobs?per_page=100");jobs=listing["jobs"]
    require(len(jobs)==listing["total_count"]<=100,"Incomplete recovery jobs listing")
    selected=[j for j in jobs if j["run_id"]==run and j["run_attempt"]==1 and j["head_sha"]==head and
              j["status"]=="in_progress" and j["name"]==JOB_LABEL and
              j["check_run_url"]==f"https://api.github.com/repos/{REPO}/check-runs/{check}"]
    require(len(selected)==1,"No unique current restricted recipient")
    return selected[0]["id"]


def request(folder, ctx):
    folder.mkdir(mode=0o700,exist_ok=True)
    require(not folder.is_symlink() and not (folder/"private.pem").exists(),"Recipient already initialized")
    private,public=folder/"private.pem",folder/"public.pem"
    command(["openssl","req","-new","-x509","-newkey","rsa:3072","-nodes","-sha256","-days","1",
             "-subj",f"/CN=Bare R28 thaw {ctx['run']} {ctx['job']}","-keyout",private,"-out",public])
    os.chmod(private,0o600)
    commitment=dict(ctx,nonce=secrets.token_hex(32),recipient_fpr=cert_fpr(bounded(public,8192)))
    record(folder/"request.json",encode(commitment))
    return commitment


def members(path, digest, size, expected):
    raw=bounded(path,MAX_PACKET)
    require(len(raw)==size and sha(raw)==digest,"Artifact ZIP digest or size changed")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        items=z.infolist()
        require(len(items)==len(expected) and {x.filename for x in items}==set(expected) and
                all(not x.is_dir() and not (x.flag_bits&1) and 0<x.file_size<=expected[x.filename] for x in items),
                "Unexpected bounded Artifact ZIP contents")
        return {k:z.read(k) for k in expected}


def validate_request(req,cert,run,head,job):
    ctx=public_context(run,head,job,req["check_run"])
    require(req==dict(ctx,nonce=req["nonce"],recipient_fpr=cert_fpr(cert)) and
            re.fullmatch("[a-f0-9]{64}",req["nonce"]) and
            req["recipient_fpr"] != SOURCE["original_recipient"],"Unexpected recovery challenge")
    subject=command(["openssl","x509","-subject","-noout","-nameopt","RFC2253"],cert).decode().strip()
    require(subject==f"subject=CN=Bare R28 thaw {run} {job}","Replacement recipient subject differs")
    command(["openssl","x509","-checkend","0","-noout"],cert)


def original(source_zip,kit):
    files=members(source_zip,SOURCE["writer_sha"],SOURCE["writer_bytes"],{"public.pem":8192,"writer-key.age":8192})
    public=files["public.pem"]
    require(cert_fpr(public)==SOURCE["original_recipient"],"Original writer certificate differs")
    age=kit/"age";key=kit/"test-recipient.agekey"
    require(sha(bounded(age,8*1024**2))==AGE_SHA and key.is_file() and not key.is_symlink() and
            key.stat().st_mode & 0o077 == 0 and key.stat().st_size <= 1024,"Registered test kit unavailable")
    private=command([age,"-d","-i",key],files["writer-key.age"])
    check_pair(private,public)
    return private,public


def response_name(run): return f"r28-thaw-{run}-a1-response.json"


def artifact_ref(aid,archive_sha,size):
    require(type(aid) is int and aid>0 and aid not in (SOURCE["writer_artifact"],SOURCE["cipher_artifact"]) and
            re.fullmatch("[a-f0-9]{64}",archive_sha) and 0<size<=MAX_PACKET,"Invalid request Artifact identity")
    return dict(id=aid,sha256=archive_sha,bytes=size)


def respond(source_zip,kit,request_zip,artifact,run,head,job,outdir):
    files=members(request_zip,artifact["sha256"],artifact["bytes"],{"public.pem":8192,"request.json":8192})
    req=json.loads(files["request.json"]);cert=files["public.pem"]
    validate_request(req,cert,run,head,job)
    require(files["request.json"]==encode(req),"Noncanonical recipient request")
    binding=dict(schema=SCHEMA,request_sha=sha(encode(req)),request_artifact=artifact)
    path=outdir/response_name(run)
    if path.exists():
        saved=json.loads(bounded(path,MAX_PACKET))
        require({k:saved[k] for k in binding}==binding,"Existing response is for another request")
        checked_envelope(saved,binding)
        return path
    private,public=original(source_zip,kit)
    plain=encode(dict(binding,original_private=base64.b64encode(private).decode(),original_public=public.decode("ascii")))
    # Only the recipient certificate is materialized; the old key remains in process memory.
    with tempfile.NamedTemporaryFile() as f:
        f.write(cert);f.flush()
        cipher=command(["openssl","cms","-encrypt","-binary","-outform","DER","-aes-256-gcm",
                        "-recip",f.name,"-keyopt","rsa_padding_mode:oaep","-keyopt","rsa_oaep_md:sha256"],plain)
    envelope=dict(binding,cipher_sha=sha(cipher),cms=base64.b64encode(cipher).decode("ascii"))
    record(path,encode(envelope))
    return path


def checked_envelope(envelope,binding):
    require(set(envelope)==set(binding)|{"cipher_sha","cms"} and all(envelope[k]==v for k,v in binding.items()),
            "Encrypted response addresses another request")
    cipher=base64.b64decode(envelope["cms"],validate=True)
    require(0<len(cipher)<32768 and sha(cipher)==envelope["cipher_sha"],"Response ciphertext digest differs")
    return cipher


def request_receipt(api,run,head):
    name=f"r28-thaw-{run}-request"
    reply=api.metadata(f"{api.BASE}/actions/runs/{run}/artifacts?name={name}&per_page=100")
    rows=reply["artifacts"]
    require(len(rows)==reply["total_count"]<=1,"Could not confirm one original challenge Artifact")
    if not rows:
        return None
    a=rows[0]; w=a["workflow_run"]
    require(not a["expired"] and a["name"]==name and w["id"]==run and w["head_sha"]==head and
            w["repository_id"]==REPO_ID and a["digest"].startswith("sha256:"),"Unbound challenge Artifact")
    return artifact_ref(a["id"],a["digest"][7:],a["size_in_bytes"])


def wait(folder,api,run,head,seconds=26*60):
    until=time.monotonic()+seconds
    request_id=None
    name=response_name(run)
    while time.monotonic()<until:
        try:
            if not request_id:
                request_id=request_receipt(api,run,head)
                if not request_id:
                    time.sleep(min(5,max(0,until-time.monotonic())))
                    continue
                record(folder/"request-artifact.json",encode(request_id))
            release=api.draft(RELEASE_ID)
        except (OSError,http.client.HTTPException):
            time.sleep(min(5,max(0,until-time.monotonic())))
            continue
        found=[a for a in release["assets"] if a["name"]==name]
        require(len(found)<=1,"Conflicting private recovery responses")
        if found:
            a=found[0]
            require(api.is_owner(a.get("uploader") or {}),"Only the registered owner may deliver a test response")
            if a["state"]=="starter" or (a["state"]=="uploaded" and not a.get("digest")):
                time.sleep(min(5,max(0,until-time.monotonic())))
                continue
            require(a["state"]=="uploaded" and a["size"]>0 and a["size"]<=MAX_PACKET and
                    re.fullmatch("sha256:[a-f0-9]{64}",a.get("digest") or ""),"Invalid private response receipt")
            digest=a["digest"][7:]; api.asset_info(release,name,a["size"],digest,a["id"])
            sink=io.BytesIO();api.download(a["id"],a["size"],digest,sink)
            require(len(sink.getvalue())==a["size"] and sha(sink.getvalue())==digest,"Private response changed on read")
            record(folder/"response.json",sink.getvalue())
            print(f"Recovered encrypted response asset={a['id']} bytes={a['size']} sha256={digest}")
            return
        time.sleep(min(12,max(0,until-time.monotonic())))
    raise ValueError("Owner response was not present before the collection deadline")


def consume(folder,response,run,head):
    req=json.loads(bounded(folder/"request.json",8192))
    pub=bounded(folder/"public.pem",8192)
    validate_request(req,pub,run,head,req["job"])
    ref=json.loads(bounded(folder/"request-artifact.json",2048))
    binding=dict(schema=SCHEMA,request_sha=sha(encode(req)),request_artifact=artifact_ref(ref["id"],ref["sha256"],ref["bytes"]))
    cipher=checked_envelope(json.loads(bounded(response,MAX_PACKET)),binding)
    recovered=command(["openssl","cms","-decrypt","-binary","-inform","DER","-recip",folder/"public.pem",
                       "-inkey",folder/"private.pem"],cipher)
    plain=json.loads(recovered)
    require(set(plain)==set(binding)|{"original_public","original_private"} and
            all(plain[k]==v for k,v in binding.items()),"Recovery envelope scope mismatch")
    original_public=plain["original_public"].encode("ascii")
    private=base64.b64decode(plain["original_private"],validate=True)
    require(cert_fpr(original_public)==SOURCE["original_recipient"],"Decrypted writer certificate differs")
    check_pair(private,original_public)
    record(folder/"original-public.pem",original_public)
    record(folder/"original-private.pem",private)
    print("Original disposable RSA key matched its recorded public certificate")


def main():
    os.umask(0o077)
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="op",required=True)
    sub.add_parser("request");sub.add_parser("wait")
    sub.add_parser("consume").add_argument("response",type=Path)
    for name in ("verify-original","respond"):
        parser=sub.add_parser(name)
        parser.add_argument("--source-zip",required=True,type=Path)
        parser.add_argument("--test-kit",required=True,type=Path)
        if name=="respond":
            parser.add_argument("--request-zip",required=True,type=Path)
            parser.add_argument("--request-id",required=True,type=int)
            parser.add_argument("--request-sha",required=True)
            parser.add_argument("--request-bytes",required=True,type=int)
            parser.add_argument("--run",required=True,type=int)
            parser.add_argument("--head",required=True)
            parser.add_argument("--job",required=True,type=int)
            parser.add_argument("--out-dir",required=True,type=Path)
    args=p.parse_args()
    if args.op=="verify-original":
        original(args.source_zip,args.test_kit)
        print("Verified original registered test recipient and matching disposable RSA pair")
    elif args.op=="respond":
        result=respond(args.source_zip,args.test_kit,args.request_zip,
            artifact_ref(args.request_id,args.request_sha,args.request_bytes),
            args.run,args.head,args.job,args.out_dir)
        print(f"{result.name} bytes={result.stat().st_size} sha256={sha(bounded(result,MAX_PACKET))}")
    else:
        run,head=context()
        folder=Path(os.environ["RUNNER_TEMP"])/"r28-thaw"
        if args.op=="request":
            api=helper();check=int(os.environ["R28_CHECK_RUN"])
            ctx=public_context(run,head,physical(api,run,head,check),check)
            result=request(folder,ctx);print(f"challenge run={run} job={ctx['job']} recipient_sha256={result['recipient_fpr']}")
        elif args.op=="wait":wait(folder,helper(),run,head)
        else:consume(folder,args.response,run,head)


if __name__=="__main__":
    try:main()
    except (OSError,ValueError,KeyError,binascii.Error,subprocess.SubprocessError,http.client.HTTPException,zipfile.BadZipFile) as error:
        # Do not print buffers, subprocess invocations, raw API responses, or decrypted field values.
        sys.exit("Test-key handback failed: "+(str(error) if isinstance(error,Rejected) else type(error).__name__))
