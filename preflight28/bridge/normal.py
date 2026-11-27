"""Per-slot checkpoint transport for the bounded Bare Personal Actions chain."""
import argparse
from datetime import datetime, timezone
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import time
from urllib.parse import quote, urlsplit
import artifact_poll
import bridge as b
import frames
import storage_admission as storage
import r30_parent
import owner_recovery
from verify_payload import check as verify_payload

ROOT = Path(os.environ["RUNNER_TEMP"]) / "r28-normal"
b.ROOT = ROOT
PARENT = {"sha": b.PARENT_SHA, "identity": b.PARENT_IDENTITY}
PART = 2_000_000_000
R209 = os.environ.get("BARE_GENERATION") == "2.0.9"
SCHEMA = "bare-personal-209-checkpoint-v1" if R209 else "bare-r28-checkpoint-private-v1"
STOPS = {"apk", "no-progress", "verify-only", "size-exceeded", "failed", "cancelled"}
JOB_MINUTES = 350
DOWNLOAD_MINUTES = 10
PUBLISH_MINUTES = 20
SENDER_MARGIN_MINUTES = 5
UPLOAD_MINUTES = 4
VISIBILITY_MINUTES = 2
# Pinned GitHub HTTP client uses a 150s socket timeout per anonymous GET.
VISIBILITY_REQUEST_SECONDS = 150


def slot():
    n = int(os.environ["R28_SLOT"])
    b.require(1 <= n <= (99 if R209 else 13), "Unbounded segment")
    return n


def logical(number, *, run_id=None):
    run = b.env_int("GITHUB_RUN_ID") if run_id is None else run_id
    if R209:
        return f"bare-personal-209-{run}-1-checkpoint-s{number}"
    return f"bare-coexist-204-{run}-1-checkpoint-production-s{number}"


def stem(number=None, *, run_id=None):
    run = b.env_int("GITHUB_RUN_ID") if run_id is None else run_id
    prefix = "r209" if R209 else "r28"
    return f"{prefix}-{run}-a1-s{slot() if number is None else number:02}"


def parent_read_run():
    """A replacement may read its admitted predecessor. All output names stay local."""
    current = b.env_int("GITHUB_RUN_ID")
    origin = os.environ.get("R28_PARENT_RUN", "")
    if not origin:
        return current
    if R209:
        b.require(re.fullmatch("[1-9][0-9]{0,18}", origin) and int(origin) != current and slot() > 1,
                  "Invalid new-generation recovery origin")
        # lease/bind additionally validates the new ticket/claim; the manifest
        # must independently match this exact old run, slot, CI SHA and schema.
        result = b.api_json(f"/repos/{b.REPO}/actions/runs/{origin}")
        b.require(result["status"] == "completed" and result["head_sha"] == os.environ["GITHUB_SHA"]
                  and result["head_branch"] == "bare-coexist-v2.0.9" and result["run_attempt"] == 1
                  and result["path"] == ".github/workflows/bare-checkpoint-transfer.yml"
                  and result["event"] == "workflow_dispatch", "Recovery origin is active or mismatched")
        return int(origin)
    if r30_parent.authorized(os.environ):
        return r30_parent.RUN
    b.require(re.fullmatch("[1-9][0-9]{0,18}", origin) and int(origin) != current and
              2 <= slot() <= 12 and os.environ.get("R28_PARENT_BACKEND") == "draft" and
              os.environ.get("R28_PARENT_READBACK_ONLY") == "false" and
              os.environ.get("GITHUB_RUN_ATTEMPT") == "1" and
              os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
              os.environ.get("GITHUB_REF") == "refs/heads/bare-coexist-v2.0.4" and
              os.environ.get("GITHUB_ACTOR") == "Areal-U" and
              os.environ.get("GITHUB_SHA") == os.environ["R28_HEAD_SHA"] and
              os.environ.get("R28_EXPECTED_PARENT_KEY") == logical(slot()-1, run_id=int(origin)),
              "Unbound replacement predecessor")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    inputs = event.get("inputs") or {}
    b.require(inputs.get("mode") == "recover-lost-slot" and inputs.get("loss_origin_run") == origin and
              event.get("repository", {}).get("id") == 1450926240 and
              event.get("sender", {}).get("id") == 292261483,
              "Cross-run parent requires an admitted owner replacement")
    return int(origin)


def context():
    n = slot()
    head = os.environ["R28_HEAD_SHA"]
    parent, identity = os.environ["R28_PARENT_SHA"], os.environ["R28_PARENT_IDENTITY"]
    b.require(os.environ["GITHUB_REPOSITORY"] == b.REPO and re.fullmatch("[0-9a-f]{40}", head)
              and b.sha(parent) and b.sha(identity), "Invalid immutable generation")
    if R209:
        lock = Path(__file__).resolve().parents[2] / "preflight209/upstream-lock.json"
        genesis = b.digest(lock)
        b.require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                  and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                  and os.environ.get("GITHUB_REF") == "refs/heads/bare-coexist-v2.0.9"
                  and os.environ.get("GITHUB_SHA") == head and os.environ.get("R209_GENESIS") == genesis
                  and ((n == 1 and (parent, identity) == (genesis, genesis)) or
                       (n > 1 and genesis not in (parent, identity))), "Invalid 2.0.9 production generation")
    elif n == 1:
        b.require((parent,identity) == (PARENT["sha"],PARENT["identity"]), "Initial parent differs from S2")
    return {"schema":SCHEMA, "key":logical(n), "run":b.env_int("GITHUB_RUN_ID"), "attempt":1,
            "ordinal":n,"producer_sha":head, "parent_sha":parent, "parent_identity":identity}


def same(binding):
    return all(binding.get(k) == v for k,v in context().items())


def names():
    b.output(key_name=stem()+"-key",descriptor_name=stem()+"-descriptor",outcome_name=stem()+"-outcome")


def sender_times(job_start, check_run):
    b.require(type(job_start) is int and 0 < job_start <= time.time() and
              type(check_run) is int and check_run > 0, "Invalid hosted sender job clock")
    tail = DOWNLOAD_MINUTES + PUBLISH_MINUTES + SENDER_MARGIN_MINUTES
    return {"sender_job_start":job_start, "sender_check_run":check_run,
            "sender_accept_until":job_start+(JOB_MINUTES-tail)*60}


def sender_deadline(record):
    expected = sender_times(record["sender_job_start"], record["sender_check_run"])
    b.require(all(record.get(k) == v for k,v in expected.items()), "Changed hosted sender cutoff")
    return expected["sender_accept_until"]


class RelayTimeExpired(ValueError):
    pass


RelayCapacityExceeded = storage.StorageFull


class RelayPriorExists(ValueError):
    pass


def time_left(deadline, required_seconds, stage):
    if time.time() + required_seconds > deadline:
        raise RelayTimeExpired("Sender time budget exhausted before " + stage)


def keygen(role,check_run,job_start=None):
    b.require(b.env_int("GITHUB_RUN_ATTEMPT")==1,"Retry is read-only; ephemeral work is initial-attempt only")
    b.require(role in ("ordinary","limited") and check_run > 0,"Invalid slot key owner")
    clock = sender_times(job_start, check_run) if role == "limited" else {}
    ROOT.mkdir(mode=0o700)
    b.keygen()
    (ROOT/"holder.json").write_text(json.dumps({**context(),**clock,"role":role,"check_run":check_run,
       "fingerprint":b.fingerprint(ROOT/"public.pem")},sort_keys=True))


def ordinary_job(run, get):
    check=json.loads((ROOT/"peer.json").read_text())["check_run"]
    for page in range(1, 11):
        jobs=get(f"/repos/{b.REPO}/actions/runs/{run}/attempts/1/jobs?per_page=100&page={page}")["jobs"]
        mine=[job for job in jobs if str(job["check_run_url"]).endswith("/"+str(check))]
        b.require(len(mine)<=1,"Ambiguous ordinary job identity")
        if mine:
            return mine[0]
        if len(jobs)<100:
            return None
    raise ValueError("Unbounded run jobs query")


def wait(kind):
    require_kind = {"key":"-key","descriptor":"-descriptor","outcome":"-outcome"}
    b.require(kind in require_kind,"Unrecognized peer artifact")
    tag = stem()+require_kind[kind]
    run=b.env_int("GITHUB_RUN_ID")
    start=time.monotonic()
    cutoff = sender_deadline(info()) if kind == "outcome" else None
    deadline=start+(cutoff-time.time() if cutoff is not None else 20*60)
    get=b.api_before(deadline)
    observed_done=None
    stable_absence = False
    polls = 0
    next_log = start
    while time.monotonic()<deadline:
        try:
            a = artifact_poll.lookup(run, tag, get, repo=b.REPO, head=os.environ["R28_HEAD_SHA"])
            peer = ordinary_job(run, get) if a is None and kind=="outcome" else None
            if time.monotonic()>=deadline:
                stable_absence=False
                break
            stable_absence = a is None
        except (artifact_poll.UnstableInventory, b.TransientReadError):
            a = None
            peer = None
            stable_absence = False
            observed_done = None
        if a:
            if cutoff is not None:
                time_left(cutoff, 0, "outcome download")
            bound=b.CAP+32*1024**2 if kind=="outcome" else 256*1024
            b.require(a["workflow_run"]["id"]==run and not a["expired"] and 0<a["size_in_bytes"]<=bound
                      and datetime.fromisoformat(a["expires_at"].replace("Z","+00:00"))>datetime.now(timezone.utc),
                      "Mismatched or expired peer artifact")
            b.output(id=a["id"])
            print(f"found {tag} artifact={a['id']} bytes={a['size_in_bytes']} expires_at={a['expires_at']}",flush=True)
            return
        if peer and peer["status"]=="completed":
            if observed_done is None:
                observed_done=time.monotonic()
            if time.monotonic()-observed_done>=75 and peer["conclusion"]=="success":
                b.output(outcome_absent="true")
                return
            b.require(time.monotonic()-observed_done<75,"Ordinary job terminated without a durable outcome")
        else:
            observed_done=None
        pause = min(artifact_poll.backoff(polls), max(0,deadline-time.monotonic()))
        now = time.monotonic()
        if now >= next_log:
            print(f"waiting for {tag} inventory={'absent' if stable_absence else 'unsettled'}"
                  f" next_poll_seconds={int(pause)} remaining_seconds={max(0,int(deadline-now))}", flush=True)
            next_log = now + 300
        polls += 1
        time.sleep(pause)
    if kind=="outcome" and stable_absence:
        # Only an explicit, matching ordinary stop is accepted by the caller.
        # Absence here never creates a readable checkpoint or triggers another slot.
        b.output(outcome_absent="true")
        return
    raise ValueError("Peer receipt unavailable before bounded deadline")


def info():
    p=ROOT/"input.json"
    rec=json.loads(p.read_text())
    b.require(same(rec),"Input descriptor not bound to this segment")
    return rec


def list_private(api):
    # Release metadata may include only the first page. Reuse the fixed client's
    # release/sentinel validation and enumerate immutable assets for long chains.
    release=api.draft(b.RELEASE)
    if len(release["assets"])<30:
        return release
    assets=[]
    for page in range(1,12):
        batch=api.metadata(f"{api.BASE}/releases/{b.RELEASE}/assets?per_page=100&page={page}")
        b.require(isinstance(batch,list),"Malformed private release asset listing")
        assets.extend(batch)
        if len(batch)<100:
            break
    else:
        raise ValueError("Unbounded private release")
    by_id={asset["id"]:asset for asset in assets}
    b.require(len(by_id)==len(assets) and all(a["id"] in by_id and by_id[a["id"]]["name"]==a["name"]
              for a in release["assets"]), "Inconsistent private asset listing")
    return {**release,"assets":assets}


def get_manifest(mid, expected_sha, number, *, run_id=None):
    run = b.env_int("GITHUB_RUN_ID") if run_id is None else run_id
    expected_key = logical(number, run_id=run)
    migrated = run_id == r30_parent.RUN and number == 1 and r30_parent.authorized(os.environ)
    api=b.auth_api()
    rel=list_private(api)
    row,=[r for r in rel["assets"] if r["id"]==mid]
    b.require(row["name"] in (stem(number, run_id=run)+"-manifest.json",stem(number, run_id=run)+"-manifest.json-retry1")
              and sha_check(expected_sha) and 0<row["size"]<32768,"Unrecognized private manifest")
    api.asset_info(rel,row["name"],row["size"],expected_sha,mid)
    buf=io.BytesIO()
    api.download(mid,row["size"],expected_sha,buf)
    m=json.loads(buf.getvalue())
    b.require(m["schema"]==SCHEMA and m["key"]==expected_key and m["ordinal"]==number
              and m["run"]==run and m["attempt"]==1 and
              m["producer_sha"]==(r30_parent.PRODUCER if migrated else os.environ["R28_HEAD_SHA"]) and sha_check(m["sha256"]) and
              sha_check(m["identity"]) and sha_check(m["proof_sha"]) and 0<m["bytes"]<=b.CAP
              and 0<len(m["parts"])<=2 and sum(p["bytes"] for p in m["parts"])==m["bytes"],
              "Invalid generation receipt")
    if migrated:
        b.require(mid == r30_parent.MANIFEST and expected_sha == r30_parent.MANIFEST_SHA and
                  (m["sha256"], m["identity"], m["proof_sha"], m["bytes"], m["parent_sha"]) ==
                  (r30_parent.SHA, r30_parent.IDENTITY, r30_parent.PROOF, r30_parent.SIZE, r30_parent.S2),
                  "Pinned S1 manifest disagrees with the validated checkpoint")
    for i,p in enumerate(m["parts"]):
        name=stem(number, run_id=run)+f"-p{i:02}"
        b.require(p["name"] in (name,name+"-retry1") and p["bytes"]==min(PART,m["bytes"]-i*PART)
                  and sha_check(p["sha256"]),"Unbound checkpoint part")
        api.asset_info(rel,p["name"],p["bytes"],p["sha256"],p["id"])
    return m


def sha_check(value):
    return bool(b.sha(value))


def issue():
    parent_run = parent_read_run()
    api=b.auth_api()
    peer=json.loads((ROOT/"incoming/holder.json").read_text())
    b.require(same(peer) and peer["role"]=="ordinary" and type(peer["check_run"]) is int
              and peer["check_run"]>0 and peer["fingerprint"]==b.fingerprint(ROOT/"incoming/public.pem"),
              "Invalid ordinary job certificate")
    (ROOT/"peer.json").write_text(json.dumps(peer))
    holder = json.loads((ROOT/"holder.json").read_text())
    b.require(same(holder) and holder["role"] == "limited" and holder["check_run"] == holder["sender_check_run"],
              "Unbound private writer clock")
    clock = sender_times(holder["sender_job_start"], holder["check_run"])
    time_left(sender_deadline(holder), (UPLOAD_MINUTES + VISIBILITY_MINUTES)*60, "descriptor")
    record={**context(),**clock,"worker_fpr":peer["fingerprint"],"writer_pem":(ROOT/"public.pem").read_text(),
            "lease_ends":int(time.time())+20*60,"source":None,"endpoints":[]}
    # Registration checked this recipient and its claim against the owner ticket
    # and the independent collector ACK before starting this physical slot.
    if not (r30_parent.authorized(os.environ) and os.environ["R28_PARENT_READBACK_ONLY"] == "true"):
        record["owner_recovery"] = owner_recovery.wrap(ROOT,context(),os.environ["R28_OWNER_RECIPIENT"],
                                                       b.env_int("R28_COLLECTION_CLAIM"))
    if slot()>1:
        mid=b.env_int("R28_PARENT_MANIFEST")
        digest=os.environ["R28_PARENT_MANIFEST_SHA"]
        manifest=get_manifest(mid,digest,slot()-1,run_id=parent_run)
        b.require((manifest["sha256"],manifest["identity"])==(record["parent_sha"],record["parent_identity"]),
                  "Previous manifest conflicts with independently selected parent")
        record.update(source=manifest, source_manifest_id=mid, source_manifest_sha=digest)
        for part in manifest["parts"]:
            conn,res=api.request(api.API,"GET",f"{api.BASE}/releases/assets/{part['id']}",auth=True,accept="application/octet-stream")
            try:
                b.require(res.status==302,"Part-scoped read is unavailable")
                url=res.getheader("Location","")
                b.endpoint(url)
                record["endpoints"].append(url)
            finally:conn.close()
    tmp=ROOT/"input.json"
    tmp.write_text(json.dumps(record))
    b.encrypt(ROOT/"incoming/public.pem",tmp,ROOT/"input.cms")
    print("Issued recipient-bound descriptor for",record["key"])


def acquire():
    parent_run = parent_read_run()
    b.decrypt(ROOT/"incoming/input.cms",ROOT/"input.json")
    rec=info()
    b.require(rec["worker_fpr"]==b.fingerprint(ROOT/"public.pem") and time.time()<rec["lease_ends"],
              "Input read lease invalid")
    cutoff = sender_deadline(rec)
    time_left(cutoff, (UPLOAD_MINUTES + VISIBILITY_MINUTES)*60, "peer acquisition")
    b.output(sender_outcome_deadline=cutoff)
    pub=ROOT/"writer.pem";pub.write_text(rec["writer_pem"]);b.fingerprint(pub)
    m=rec["source"]
    if slot()==1:
        b.require(m is None and not rec["endpoints"],"First slot can use only pinned S2")
        return
    b.require(m["run"]==parent_run and m["attempt"]==1 and m["ordinal"]==slot()-1 and
              m["key"]==logical(slot()-1,run_id=parent_run) and
              m["producer_sha"]==(r30_parent.PRODUCER if r30_parent.authorized(os.environ) else os.environ["R28_HEAD_SHA"]) and
              m["sha256"]==rec["parent_sha"] and m["identity"]==rec["parent_identity"] and
              rec["source_manifest_id"]==b.env_int("R28_PARENT_MANIFEST") and
              rec["source_manifest_sha"]==os.environ["R28_PARENT_MANIFEST_SHA"] and
              0<m["bytes"]<=b.CAP,"Wrong pending private parent")
    file=ROOT/"checkpoint.tar.zst"
    full=hashlib.sha256()
    b.disk("before-private-parent",m["bytes"])
    with file.open("xb") as out:
        for url,part in zip(rec["endpoints"],m["parts"],strict=True):
            u=b.endpoint(url)
            conn=http.client.HTTPSConnection(u.netloc,timeout=120)
            try:
                conn.request("GET",u.path+"?"+u.query,headers={"User-Agent":"bare-private-generation-receiver"})
                res=conn.getresponse()
                b.require(res.status==200,"Scoped read failed")
                h=hashlib.sha256();n=0
                while block:=res.read(1024**2):
                    n+=len(block)
                    b.require(n<=part["bytes"],"Part grew")
                    h.update(block);full.update(block);out.write(block)
                b.require(n==part["bytes"] and h.hexdigest()==part["sha256"],"Private part changed")
            finally:conn.close()
    b.require(file.stat().st_size==m["bytes"] and full.hexdigest()==m["sha256"],"Private checkpoint changed")
    print(f"input={m['key']} bytes={m['bytes']} sha256={m['sha256']}")


def seal(file,identity,proof_sha):
    rec=info()
    b.require(file.resolve()==file and file.is_file() and not file.is_symlink() and
              0<file.stat().st_size<=b.CAP and sha_check(identity) and sha_check(proof_sha) and slot()<=(99 if R209 else 12),
              "Unsafe checkpoint candidate")
    plain_hash=b.digest(file)
    b.require(plain_hash!=rec["parent_sha"],"Exact parent replay")
    sealed=ROOT/"checkpoint.cms"
    b.disk("before-checkpoint-encryption",file.stat().st_size+160*1024**2)
    frames.seal(ROOT/"writer.pem",file,sealed,plain_hash)
    b.require(0<sealed.stat().st_size<=file.stat().st_size+16*1024**2,"Unbounded ciphertext")
    evidence={**context(),"status":"candidate","bytes":file.stat().st_size,"sha256":plain_hash,"identity":identity,
              "proof_sha":proof_sha,"sealed_bytes":sealed.stat().st_size,"sealed_sha":b.digest(sealed),
              "recipient_fpr":b.fingerprint(ROOT/"writer.pem")}
    wrapper = rec["owner_recovery"]
    owner_recovery.checked(wrapper,context(),os.environ["R28_OWNER_RECIPIENT"],b.env_int("R28_COLLECTION_CLAIM"),
                           evidence["recipient_fpr"])
    evidence["owner_recovery"] = wrapper
    (ROOT/"outcome.json").write_text(json.dumps(evidence,sort_keys=True))
    logged={k:v for k,v in evidence.items() if k!="owner_recovery"}
    print("sealed_checkpoint="+json.dumps(logged,sort_keys=True))


def capacity():
    record=json.loads((ROOT/"outcome.json").read_text())
    b.require(same(record), "Wrong slot before peak measurement")
    size = (ROOT/"outcome.json").stat().st_size
    candidate = record["status"] == "candidate"
    if candidate:
        sealed = (ROOT/"checkpoint.cms").stat().st_size
        b.require(sealed == record["sealed_bytes"], "Checkpoint changed since seal")
        size += sealed
    envelope = size + (2*1024**2 if candidate else 8*1024)
    b.require(candidate or envelope <= 16*1024, "Oversized control-only outcome")
    answer = storage.admit(b.api_json, os.environ, envelope, 1, stage="outcome", exact_name=stem()+"-outcome")
    if answer == "existing":
        raise RelayPriorExists("Existing exact outcome must be reconciled")
    time_left(sender_deadline(info()), ((UPLOAD_MINUTES if candidate else 2)+VISIBILITY_MINUTES)*60, "outcome upload")


def stop(reason):
    b.require(reason in STOPS,"Unknown terminal state")
    with (ROOT/"outcome.json").open("x") as f:
        json.dump({**context(),"status":reason},f,sort_keys=True)


class Section:
    def __init__(self,file,length):self.file=file;self.left=length
    def read(self,n):
        block=self.file.read(min(self.left,n));self.left-=len(block)
        return block


def put(suffix,file,offset,length,digest,*,origin_prefix=None):
    api=b.auth_api();base=(origin_prefix or stem())+"-"+suffix
    def find(name, *, before_write=False):
        assets=list_private(api)["assets"]
        rows=[r for r in assets if r["name"]==name]
        if before_write and not rows:
            b.require(len(assets) < 1000, "Private Release has no remaining asset slot")
        b.require(len(rows)<=1,"Asset name collision")
        return rows[0] if rows else None
    for name in (base,base+"-retry1"):
        row=find(name,before_write=True)
        if not row:
            file.seek(offset)
            try:
                conn,res=api.request(api.UPLOAD,"POST",f"{api.BASE}/releases/{b.RELEASE}/assets?name="+quote(name),
                    auth=True,body=Section(file,length),length=length,content_type="application/octet-stream")
                try:
                    b.require(res.status in (201,422,502),f"Private write returned {res.status}")
                    res.read(65536)
                finally:conn.close()
            except (OSError,http.client.HTTPException):pass
            for delay in (0,2,4):
                if delay:time.sleep(delay)
                row=find(name)
                if row:break
            b.require(row,"Private write unresolved. Retry receipt reconciliation without propagating.")
        if row["state"]=="starter" and row["size"]==0:continue
        obj=api.asset_info(list_private(api),name,length,digest,row["id"])
        return {"id":obj["id"],"name":name,"bytes":length,"sha256":digest}
    raise ValueError("Empty residue on both permitted write attempts")


def visibility(api, rows, deadline):
    """Probe all direct URLs first, then the per-asset API sharing one anonymous quota."""
    b.require(isinstance(deadline,(int,float)) and deadline>0,
              "Visibility needs the absolute current hosted-job deadline")
    stop=time.monotonic()+max(0,deadline-time.time())
    checks=[]
    for row in rows:
        url=urlsplit(row["browser_download_url"])
        b.require(url.scheme=="https" and url.netloc=="github.com" and not url.query and not url.fragment and
                  url.path.startswith("/"+b.REPO+"/releases/download/"),"Unexpected direct asset URI")
        checks.append((row,"direct","github.com",url.path))
    checks.extend((row,"api",api.API,f"{api.BASE}/releases/assets/{row['id']}") for row in rows)
    state={row["id"]:{"id":row["id"],"bytes":row["size"],"sha256":row["digest"].removeprefix("sha256:"),
                       "authenticated":"verified","direct":"not_probed","api":"not_probed"} for row in rows}
    for row,label,host,path in checks:
        while time.monotonic()+VISIBILITY_REQUEST_SECONDS<=stop:
            # None means a genuine nonredirecting 404. Recognized API 403/429
            # supply an absolute provider deadline. Public or ambiguous replies raise.
            retry_at=api.anonymous_status(host,path,label)
            if retry_at is None:
                state[row["id"]][label]="404"
                break
            b.require(type(retry_at) is int and retry_at>0 and host==api.API,
                      "Unrecognized anonymous-service retry response")
            state[row["id"]][label]="rate_limited"
            state[row["id"]]["retry_at"]=retry_at
            delay=max(1,retry_at-time.time())
            if time.monotonic()+delay+VISIBILITY_REQUEST_SECONDS>stop:
                return False,state
            print(f"private_checkpoint_rate_wait asset_id={row['id']} endpoint={label} "
                  f"provider_retry_epoch={retry_at} remaining_seconds={max(0,int(stop-time.monotonic()))}",flush=True)
            time.sleep(delay)
        else:
            return False,state
    return True,state


def verify_outputs(mid,sha_manifest,deadline):
    m=get_manifest(mid,sha_manifest,slot())
    b.require(same(m),"Accepted manifest no longer corresponds to selected parent")
    api=b.auth_api()
    full=hashlib.sha256()
    existing=list_private(api)
    ids=[mid,*[p["id"] for p in m["parts"]]]
    by_id={r["id"]:r for r in existing["assets"] if r["id"] in ids}
    b.require(len(by_id)==len(ids),"Private generation lost assets before readback")
    class Sink:
        def write(self,block):full.update(block)
    for part in m["parts"]:
        api.download(part["id"],part["bytes"],part["sha256"],Sink())
    b.require(full.hexdigest()==m["sha256"],"Independent private GET mismatch")
    verified,observations=visibility(api,[by_id[i] for i in ids],deadline)
    status="verified" if verified else "manifest_present_visibility_pending"
    print("private_checkpoint_readback="+json.dumps({"status":status,"manifest_id":mid,
          "manifest_sha256":sha_manifest,"archive_bytes":m["bytes"],"archive_sha256":m["sha256"],
          "deadline_epoch":int(deadline),"assets":list(observations.values())},sort_keys=True),flush=True)
    flag=str(verified).lower()
    b.output(checkpoint_manifest_id=mid,checkpoint_manifest_sha=sha_manifest,checkpoint_sha=m["sha256"],
             checkpoint_bytes=m["bytes"],checkpoint_identity=m["identity"],checkpoint_key=m["key"],
             checkpoint_ordinal=m["ordinal"],producer_sha=m["producer_sha"],private_readback_verified=flag,
             checkpoint_advanced=flag,recovery_status=status)


def put_json(suffix, record, *, origin_prefix=None):
    raw=json.dumps(record,sort_keys=True,separators=(",",":")).encode("ascii")
    return put(suffix,io.BytesIO(raw),0,len(raw),hashlib.sha256(raw).hexdigest(), **({"origin_prefix":origin_prefix} if origin_prefix else {}))


def existing(rel, suffix, *, origin_prefix=None):
    base=(origin_prefix or stem())+"-"+suffix
    found=[row for row in rel["assets"] if row["name"] in (base,base+"-retry1") and row["state"]=="uploaded"]
    b.require(len(found)<=1,"Ambiguous private generation intent or committed object")
    return found[0] if found else None


def recovered_intent(rel):
    row=existing(rel,"intent.json")
    if not row:
        return False
    api=b.auth_api()
    b.require(0<row["size"]<32768 and row["digest"].startswith("sha256:"),"Invalid immutable intent")
    digest=row["digest"].removeprefix("sha256:")
    api.asset_info(rel,row["name"],row["size"],digest,row["id"])
    f=io.BytesIO()
    api.download(row["id"],row["size"],digest,f)
    intent=json.loads(f.getvalue())
    b.require(same(intent) and intent["format"]=="tar.zst" and sha_check(intent["sha256"]) and
              sha_check(intent["identity"]) and sha_check(intent["proof_sha"]) and 0<intent["bytes"]<=b.CAP and
              0<len(intent["parts"])<=2 and sum(p["bytes"] for p in intent["parts"])==intent["bytes"],
              "Unbound partial generation intent")
    total=hashlib.sha256()
    class Sink:
        def write(self, block): total.update(block)
    found=[]
    for i,part in enumerate(intent["parts"]):
        b.require(part["bytes"]==min(PART,intent["bytes"]-i*PART) and sha_check(part["sha256"]),
                  "Invalid part in private intent")
        obj=existing(rel,f"p{i:02}")
        if obj:
            api.asset_info(rel,obj["name"],part["bytes"],part["sha256"],obj["id"])
            api.download(obj["id"],part["bytes"],part["sha256"],Sink())
            found.append(obj["id"])
    status="partial_private_parts"
    if len(found)==len(intent["parts"]):
        b.require(total.hexdigest()==intent["sha256"],"Recovered all private parts but recombined bytes differ")
        status="all_private_bytes_verified_manifest_absent"
    print("uncommitted_private_evidence="+json.dumps({"status":status,"intent_id":row["id"],
          "sha256":intent["sha256"],"expected_bytes":intent["bytes"],"verified_part_ids":found},sort_keys=True))
    b.output(recovery_status=status,checkpoint_advanced="false",private_readback_verified="false")
    return True


def publish():
    b.require(b.env_int("GITHUB_RUN_ATTEMPT")==1,"Rerun may only reconcile existing receipts")
    cutoff = sender_deadline(info())
    physical_deadline = cutoff + (DOWNLOAD_MINUTES + PUBLISH_MINUTES) * 60
    time_left(physical_deadline, PUBLISH_MINUTES*60, "Draft publication")
    # Even an early finish hands long provider rate-limit waits to GET-only confirmation.
    deadline = min(physical_deadline, time.time() + PUBLISH_MINUTES * 60)
    r=json.loads((ROOT/"incoming/outcome.json").read_text())
    b.require(same(r),"Stale user, version, segment or candidate")
    if r30_parent.authorized(os.environ) and os.environ["R28_PARENT_READBACK_ONLY"] == "true":
        b.require(r["status"] in {"verify-only", "failed", "cancelled"}, "Read-only restore cannot publish")
    if r["status"]!="candidate":
        b.require(r["status"] in STOPS,"Unknown result")
        b.output(private_readback_verified="false",checkpoint_advanced="false",peer_status=r["status"])
        return
    file=ROOT/"incoming/checkpoint.cms"
    b.require(0<r["bytes"]<=b.CAP and r["bytes"]<r["sealed_bytes"]<=r["bytes"]+16*1024**2
              and sha_check(r["sha256"]) and sha_check(r["identity"]) and sha_check(r["proof_sha"])
              and slot()<=(99 if R209 else 12) and file.stat().st_size==r["sealed_bytes"] and b.digest(file)==r["sealed_sha"]
              and b.fingerprint(ROOT/"public.pem")==r["recipient_fpr"],"Sealed checkpoint mismatch")
    owner_recovery.checked(r["owner_recovery"],context(),os.environ["R28_OWNER_RECIPIENT"],
                           b.env_int("R28_COLLECTION_CLAIM"),r["recipient_fpr"])
    plain=ROOT/"candidate.tar.zst"
    b.disk("before-private-writer-decryption",r["bytes"]+144*1024**2)
    frames.receive(file,plain,r["bytes"],r["sha256"])
    b.require(plain.stat().st_size==r["bytes"] and b.digest(plain)==r["sha256"],"Checkpoint content changed")
    if R209:
        sys_path = Path(__file__).resolve().parents[2] / "preflight209"
        import sys
        sys.path.insert(0, str(sys_path))
        from checkpoint209 import check_archive
        proof = check_archive(plain, r)
    else:
        verify_payload(plain,r,require_current=True)
    if R209:
        b.output(peer_status="candidate")
    m={**context(),**{k:r[k] for k in ("bytes","sha256","identity","proof_sha")},"format":"tar.zst","parts":[]}
    if R209:
        m["next_has_headroom"] = proof["next_has_headroom"]
    # A small immutable intent permits GET-only recovery of all or some already
    # uploaded plaintext parts, even if the final manifest write never ran.
    expected=[]
    with plain.open("rb") as source:
        for off in range(0,m["bytes"],PART):
            n=min(PART,m["bytes"]-off);h=hashlib.sha256()
            remaining=Section(source,n)
            while block:=remaining.read(1024**2):h.update(block)
            b.require(remaining.left==0,"Short local candidate")
            expected.append({"bytes":n,"sha256":h.hexdigest()})
        put_json("intent.json",{**m,"parts":expected})
        for i,part in enumerate(expected):
            m["parts"].append(put(f"p{i:02}",source,i*PART,part["bytes"],part["sha256"]))
    receipt=put_json("manifest.json",m)
    # This bound is derived from the authenticated physical job start, shared
    # by all assets; the transfer reserve is not a visibility wall.
    verify_outputs(receipt["id"],receipt["sha256"],deadline)


def recover(deadline=None):
    # Only an independently readable Draft manifest admits further compilation.
    # An uncommitted encrypted Artifact has a separate offline owner-recovery path.
    api=b.auth_api()
    release=list_private(api)
    row=existing(release,"manifest.json")
    expected=os.environ.get("R28_EXPECTED_RECOVERY_MANIFEST","")
    digest=os.environ.get("R28_EXPECTED_RECOVERY_MANIFEST_SHA","")
    if expected or digest:
        b.require(expected.isdecimal() and int(expected)>0 and sha_check(digest) and row is not None
                  and row["id"]==int(expected) and row["digest"]=="sha256:"+digest,
                  "Original independently observed private manifest changed")
    if not row:
        if recovered_intent(release):
            return
        ctx=context()
        claim=owner_recovery.collection_claim(api,release,ctx)
        if claim:
            # Service metadata is observable without giving CI access to the
            # owner's identity. Only the offline owner opens and verifies bytes.
            rec=owner_recovery.locate(ctx["run"],ctx["ordinal"],ctx["producer_sha"],ctx["parent_sha"],claim)
            b.output(recovery_status="owner_outcome_artifact_available",private_readback_verified="false",
                     checkpoint_advanced="false",owner_outcome_artifact_id=rec["artifact_id"])
            return
        raise ValueError("No unique committed generation; inspect exact ciphertext and owner-wrapped recovery receipt before any reissue; no automatic recomputation")
    b.require(deadline is not None and deadline>0,"Committed manifest needs the live recovery job deadline")
    verify_outputs(row["id"],row["digest"].removeprefix("sha256:"),deadline)


if __name__=="__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="mode",required=True)
    for mode in ("names","issue","acquire","publish","capacity"):sub.add_parser(mode)
    a=sub.add_parser("recover");a.add_argument("--deadline",type=int,required=True)
    a=sub.add_parser("keygen");a.add_argument("role",choices=["ordinary","limited"]);a.add_argument("--check-run",type=int,required=True);a.add_argument("--job-start",type=int)
    a=sub.add_parser("wait");a.add_argument("kind",choices=["key","descriptor","outcome"])
    a=sub.add_parser("seal");a.add_argument("file",type=Path);a.add_argument("--identity",required=True);a.add_argument("--proof-sha",required=True)
    sub.add_parser("stop").add_argument("--reason",required=True)
    a=vars(parser.parse_args());op=a.pop("mode")
    globals()[op](**a)
