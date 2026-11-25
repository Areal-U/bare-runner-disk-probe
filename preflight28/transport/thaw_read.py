"""Restore the complete original private S2 child using a short-lived, asset-specific grant."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import parse_qs, quote, urlsplit

import thaw
import artifact_poll

b, frames = thaw.b, thaw.frames
ROOT = thaw.TEMP / "r28-thaw"
WORKFLOW = ".github/workflows/bare-r28-s2-thaw.yml"
CHUNK = 1024**2


class Rejected(ValueError):
    """An error safe to print; callers pass only fixed, non-sensitive explanations."""


def need(valid, message):
    if not valid:
        raise Rejected(message)


def scope():
    rid, attempt = b.env_int("GITHUB_RUN_ID"), b.env_int("GITHUB_RUN_ATTEMPT")
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    pr = event["pull_request"]
    head = os.environ["TRIAL_SHA"]
    need(os.environ["GITHUB_REPOSITORY"] == b.REPO and rid > thaw.ORIGINAL_RUN and
         os.environ["GITHUB_ACTOR"] == os.environ["GITHUB_TRIGGERING_ACTOR"] == "Areal-U" and
         event["action"] == "synchronize" and event["number"] == pr["number"] == 9 and
         event["sender"]["id"] == 292261483 and event["repository"]["id"] == 1450926240 and
         pr["head"]["repo"]["id"] == pr["base"]["repo"]["id"] == 1450926240 and
         pr["head"]["ref"] == "work-bare-27-storage-check" and pr["base"]["ref"] == "bare-coexist-v2.0.4" and
         pr["base"]["sha"] == "bf70ddbf474f3390a62220a076b8c43347fecc64" and
         event["after"] == head == pr["head"]["sha"] and len(head) == 40, "Unbound receiver workflow")
    return {"schema":"bare-r28-thaw-grant-v1","run":rid,"attempt":attempt,"head":head,
            "source_run":thaw.ORIGINAL_RUN,"source_head":thaw.ORIGINAL_HEAD,"release":b.RELEASE}


def service():
    c = scope()
    data = b.api_json(f"/repos/{b.REPO}/actions/runs/{c['run']}/attempts/{c['attempt']}")
    need(data["id"] == c["run"] and data["run_attempt"] == c["attempt"] and
         data["head_sha"] == c["head"] and data["path"] == WORKFLOW and data["status"] == "in_progress" and
         data["repository"]["id"] == 1450926240 and data["actor"]["id"] == 292261483, "Wrong active service run")
    return c


def manifest_inputs(ref, attempt):
    mid = os.environ.get("MANIFEST_ID","")
    sha = os.environ.get("MANIFEST_SHA","")
    if mid or sha or attempt == 1:
        need(mid == str(ref["id"]) and sha == ref["sha256"], "Different issued manifest")


def key():
    thaw.check_role("receive")
    c = service()
    b.api_json(f"/repos/{b.REPO}/releases/{b.RELEASE}",expected="denied")
    ROOT.mkdir(mode=0o700)
    previous=b.ROOT
    try:
        b.ROOT=ROOT
        b.keygen()
    finally:
        b.ROOT=previous
    holder={**c,"fingerprint":b.fingerprint(ROOT/"public.pem")}
    if resumed():
        import anon_peer
        holder["anonymous_api"]=anon_peer.sample(c)
    (ROOT/"holder.json").write_text(json.dumps(holder,sort_keys=True))


def label(c, kind):
    return f"r28-thaw-{c['run']}-a{c['attempt']}-" + {"key":"receiver-key","descriptor":"descriptor"}[kind]


ISSUER = "Grant only a short-lived read of original private checkpoint parts"
READER = "Ordinary runner reads and verifies the private generation from the original recipe"


def resumed():
    value=os.environ.get("R28_RESUME_PUBLISHED")
    need(value in (None, "45522666298"), "Unknown published checkpoint")
    return value is not None


def check_peer(scope, job_name, delivered=None):
    page=b.api_json(f"/repos/{b.REPO}/actions/runs/{scope['run']}/attempts/{scope['attempt']}/jobs?per_page=100")
    need(type(page["total_count"]) is int and 0<=page["total_count"]<=3 and len(page["jobs"])<=3, "Unbound peer inventory")
    if page["total_count"]!=len(page["jobs"]):
        return False
    found=[j for j in page["jobs"] if j["name"]==job_name]
    need(len(found)<=1,"Ambiguous physical peer")
    if not found:
        return
    item,=found
    need(item["run_id"]==scope["run"] and item.get("run_attempt",scope["attempt"])==scope["attempt"] and
         item.get("head_sha",scope["head"])==scope["head"], "Wrong peer incarnation")
    if item["status"]=="completed" and item["conclusion"]!="success":
        raise Rejected("Original peer terminated without its specific read grant")
    if delivered:
        rows=[s for s in (item.get("steps") or []) if s["name"]==delivered]
        need(len(rows)<=1, "Ambiguous peer upload step")
        if rows and rows[0]["status"]=="completed":
            need(rows[0]["conclusion"]=="success","Bound peer upload failed")
            return True
        return False
    return True


def wait(kind):
    thaw.check_role("issue" if kind=="key" else "receive")
    c=service()
    name=label(c,kind)
    extended=resumed()
    end=time.monotonic()+(84 if extended and kind=="descriptor" else 15)*60
    next_peer=0
    polls=0
    while time.monotonic()<end:
        try:
            a=artifact_poll.lookup(c["run"],name,b.api_json,repo=b.REPO,head=c["head"])
        except artifact_poll.UnstableInventory as exc:
            print("pending_stable_artifact="+str(exc),flush=True)
            a=None
        peer = ISSUER if kind=="descriptor" else READER
        label_step = "Deposit "+("descriptor" if kind=="descriptor" else "receiver-key")+" for this exact recovery"
        if a and (not extended or check_peer(c,peer,label_step)):
            need(a["size_in_bytes"]<=131072,"Oversized grant Artifact")
            b.output(id=a["id"])
            print(f"thaw_peer={kind} artifact_id={a['id']} expires_at={a['expires_at']}",flush=True)
            return
        if extended and time.monotonic()>=next_peer:
            check_peer(c,ISSUER if kind=="descriptor" else READER)
            next_peer=time.monotonic()+45
        pause=artifact_poll.backoff(polls) if extended else 8
        polls+=1
        time.sleep(max(0,min(pause,end-time.monotonic())))
    raise Rejected("Peer grant was not received before its deadline")


def expires(url):
    need(len(url)<=16384,"Oversized asset URL")
    q=parse_qs(b.endpoint(url).query,max_num_fields=100)
    limits=[]
    if "se" in q:
        need(len(q["se"])==1,"Duplicate asset expiry")
        ts=datetime.fromisoformat(q["se"][0].replace("Z","+00:00"))
        need(ts.tzinfo is not None,"Missing asset expiry zone")
        limits.append(ts.timestamp())
    if "X-Amz-Date" in q or "X-Amz-Expires" in q:
        need(len(q.get("X-Amz-Date",()))==len(q.get("X-Amz-Expires",()))==1,"Invalid AWS expiry")
        issued=datetime.strptime(q["X-Amz-Date"][0],"%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
        limits.append(issued.timestamp()+int(q["X-Amz-Expires"][0]))
    if "jwt" in q:
        need(len(q["jwt"])==1,"Duplicate grant")
        token=q["jwt"][0].split(".")
        need(len(token)==3 and len(token[1])<=8192,"Invalid token expiry")
        claims=json.loads(base64.urlsafe_b64decode(token[1]+"="*(-len(token[1])%4)))
        need(type(claims.get("exp")) is int,"Invalid token expiry")
        limits.append(claims["exp"])
    need(limits and time.time()<min(limits)<=time.time()+86400,"Expired or missing service URL lifetime")
    return int(min(limits))


def private_visibility(api, obj, deadline, scope, peer_evidence):
    release=api.draft(b.RELEASE)
    row=api.asset_info(release,obj["name"],obj["bytes"],obj["sha256"],obj["id"])
    parsed=urlsplit(row["browser_download_url"])
    need(parsed.scheme=="https" and parsed.netloc=="github.com" and not parsed.query and not parsed.fragment and
         parsed.path.startswith("/"+b.REPO+"/releases/download/"),"Unexpected private direct link")
    for host,path,label in (("github.com",parsed.path,"direct"),(api.API,f"{api.BASE}/releases/assets/{row['id']}","api")):
        for attempt in range(4):
            retry_at=api.anonymous_status(host,path,label)
            if retry_at is None:
                break
            need(label=="api" and type(retry_at) is int, "Ambiguous private visibility")
            if peer_evidence is not None:
                import anon_peer
                if anon_peer.valid(peer_evidence,row["id"],scope):
                    print(f"anonymous_api=404 origin=bound-ordinary asset_id={row['id']}",flush=True)
                    break
            remaining=retry_at-int(time.time())
            need(attempt<3 and remaining<=3900 and retry_at<=deadline,
                 "Provider reset exceeds remaining private visibility window")
            print(f"anonymous_reset_at={retry_at} wait_seconds={max(0,remaining)} asset_id={row['id']}",flush=True)
            while time.time()<retry_at:
                need(time.time()<deadline, "Private visibility deadline exhausted")
                check_peer(scope,READER)
                time.sleep(min(55,max(0,retry_at-time.time())))
        else:
            raise Rejected("No completed nonredirecting anonymous 404")


def published_gate():
    subprocess.run([sys.executable, str(Path(__file__).with_name("published_reader.py")), "verify"],check=True)


def issue():
    thaw.check_role("issue")
    c=service()
    replay=resumed()
    if replay:
        published_gate()
    else:
        thaw.gate("verify")
    pub=ROOT/"incoming/public.pem"
    fingerprint=b.fingerprint(pub)
    holder=json.loads(thaw.small(ROOT/"incoming/holder.json",8192))
    peer_evidence=holder.pop("anonymous_api",None) if replay else None
    need(holder=={**c,"fingerprint":fingerprint},
         "Receiver identity does not match the current run and attempt")
    api=thaw.private()
    part=thaw.saved(api,"p00",thaw.SIZE,thaw.SHA)
    need(part,"Original private part missing")
    ref=thaw.manifest_ref(api,part)
    need(ref,"Original completed manifest missing")
    manifest_inputs(ref,c["attempt"])
    thaw.verify_manifest(api,part,ref)
    deadline=int(time.time())+65*60
    for obj in (ref,part):
        if replay:
            private_visibility(api,obj,deadline,c,peer_evidence)
        else:
            thaw.invisible(api,obj)
    conn,res=api.request(api.API,"GET",f"{api.BASE}/releases/assets/{part['id']}",auth=True,accept="application/octet-stream")
    try:
        need(res.status==302,"No private part redirect")
        url=res.getheader("Location","")
        expiry=expires(url)
    finally:
        conn.close()
    raw=thaw.manifest(part)
    payload={**c,"recipient":fingerprint,"ref":ref,"manifest":base64.b64encode(raw).decode("ascii"),
             "url":url,"url_expiry":expiry,"until":min(expiry,int(time.time())+25*60)}
    need(not (ROOT/"descriptor.cms").exists(),"Grant already issued")
    subprocess.run(["openssl","cms","-encrypt","-binary","-stream","-outform","DER","-aes-256-gcm",
                    "-recip",str(pub),"-keyopt","rsa_padding_mode:oaep","-keyopt","rsa_oaep_md:sha256",
                    "-out",str(ROOT/"descriptor.cms")],input=json.dumps(payload).encode(),stderr=subprocess.PIPE,
                   check=True,timeout=30)
    print(f"thaw_grant run={c['run']} attempt={c['attempt']} manifest_id={ref['id']} part_id={part['id']} expiry={expiry}",flush=True)


def download(url, until, size, sha, dest):
    u=b.endpoint(url)
    whole=hashlib.sha256()
    offset=0
    for tries in range(3):
        need(time.time()<until,"Asset grant expired before read")
        conn=http.client.HTTPSConnection(u.netloc,timeout=60)
        try:
            conn.request("GET",u.path+"?"+u.query,headers={"User-Agent":"bare-private-thaw-reader",
                         "Accept-Encoding":"identity","Range":f"bytes={offset}-{size-1}"})
            response=conn.getresponse()
            if response.status in (429,500,502,503,504):
                raise OSError("Transient part response")
            need((response.status==206 and response.getheader("Content-Range")==f"bytes {offset}-{size-1}/{size}") or
                 (offset==0 and response.status==200),"Unscoped part response")
            need(response.getheader("Content-Length")==str(size-offset) and
                 response.getheader("Content-Encoding","identity")=="identity","Incorrect full part length")
            while block:=response.read(CHUNK):
                need(time.time()<until and offset+len(block)<=size,"Expired or oversized part")
                dest.write(block)
                whole.update(block)
                offset+=len(block)
            if offset<size:
                raise OSError("Short response")
            need(whole.hexdigest()==sha,"Full private part hash mismatch")
            return
        except (OSError,http.client.HTTPException):
            if tries==2 or offset>=size:
                raise ValueError("Incomplete full private part") from None
        finally:
            conn.close()
    raise ValueError("Part not received")


def read():
    thaw.check_role("receive")
    need(not os.environ.get("GH_TOKEN") and not os.environ.get("GITHUB_TOKEN"),"Credential in CDN reader")
    c=scope()
    sealed=ROOT/"incoming/descriptor.cms"
    thaw.small(sealed,65536)
    payload=json.loads(b.openssl("cms","-decrypt","-inform","DER","-binary","-in",sealed,"-recip",ROOT/"public.pem",
                       "-inkey",ROOT/"key.pem",capture=True,timeout=30))
    need(all(payload.get(k)==v for k,v in c.items()) and payload["recipient"]==b.fingerprint(ROOT/"public.pem"),
         "Grant for a different receiver or attempt")
    ref=payload["ref"]
    raw=base64.b64decode(payload["manifest"],validate=True)
    need(type(ref["id"]) is int and ref["id"]>0 and ref["name"] in (thaw.PREFIX+"manifest.json",thaw.PREFIX+"manifest.json-retry1")
         and len(raw)==ref["bytes"]<=12288 and hashlib.sha256(raw).hexdigest()==ref["sha256"],"Bad manifest reference")
    manifest_inputs(ref,c["attempt"])
    m=json.loads(raw)
    part,=m["parts"]
    need(type(part["id"]) is int and part["id"]>0 and part["name"] in (thaw.PREFIX+"p00",thaw.PREFIX+"p00-retry1") and
         part["bytes"]==thaw.SIZE and part["sha256"]==thaw.SHA and raw==thaw.manifest(part),"Different historical checkpoint")
    url=payload["url"]
    need(expires(url)==payload["url_expiry"] and time.time()<payload["until"]<=min(payload["url_expiry"],time.time()+25*60+1),
         "Grant expiry mismatch")
    fs=os.statvfs(thaw.TEMP)
    need(fs.f_bavail*fs.f_frsize>=20*1024**3+thaw.SIZE and fs.f_favail>=20002,"Receiver disk floor")
    checkpoint=thaw.TEMP/"r28-child.tar.zst"
    manifest=thaw.TEMP/"r28-child.json"
    need(not checkpoint.exists() and not manifest.exists(),"Original receiver destination occupied")
    with frames.staged(checkpoint) as dest:
        download(url,payload["until"],thaw.SIZE,thaw.SHA,dest)
    with frames.staged(manifest) as dest:
        dest.write(raw)
    b.output(manifest_id=ref["id"],manifest_sha=ref["sha256"])
    print("R28_THAW_ORDINARY_READ "+json.dumps({**c,"part_id":part["id"],"manifest_id":ref["id"],"manifest_sha":ref["sha256"],
          "bytes":thaw.SIZE,"sha256":thaw.SHA,"full_part_verified":True,"full_archive_verified":True,
          "service_url_remaining_seconds":payload["url_expiry"]-int(time.time()),"repository_token":False},
          sort_keys=True),flush=True)


if __name__=="__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    commands=parser.add_subparsers(dest="operation",required=True)
    for name in ("key","issue","read"):
        commands.add_parser(name)
    commands.add_parser("wait").add_argument("kind",choices=("key","descriptor"))
    args=parser.parse_args()
    try:
        if args.operation=="wait":
            wait(args.kind)
        else:
            {"key":key,"issue":issue,"read":read}[args.operation]()
    except Exception as exc:
        # HTTP client errors and malformed waits can include bearer URLs. Emit a safe status.
        message=str(exc) if isinstance(exc,Rejected) else type(exc).__name__
        sys.exit("Private checkpoint "+args.operation+" failed ("+message+")")
