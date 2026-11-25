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
from urllib.parse import parse_qs, quote

import thaw

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
    (ROOT/"holder.json").write_text(json.dumps({**c,"fingerprint":b.fingerprint(ROOT/"public.pem")},sort_keys=True))


def label(c, kind):
    return f"r28-thaw-{c['run']}-a{c['attempt']}-" + {"key":"receiver-key","descriptor":"descriptor"}[kind]


def wait(kind):
    thaw.check_role("issue" if kind=="key" else "receive")
    c=service()
    name=label(c,kind)
    end=time.monotonic()+15*60
    while time.monotonic()<end:
        page=b.api_json(f"/repos/{b.REPO}/actions/runs/{c['run']}/artifacts?name={quote(name)}&per_page=100")
        rows=[a for a in page["artifacts"] if a["name"]==name]
        need(page["total_count"]==len(page["artifacts"]) and len(rows)<=1,"Ambiguous grant Artifact")
        if rows:
            a,=rows
            need(a["workflow_run"]["id"]==c["run"] and a["workflow_run"]["head_sha"]==c["head"] and
                 not a["expired"] and type(a["id"]) is int and a["id"]>0 and 0<a["size_in_bytes"]<=131072 and
                 b.sha(a["digest"].removeprefix("sha256:")),"Invalid grant Artifact")
            b.output(id=a["id"])
            print(f"thaw_peer={kind} artifact_id={a['id']} expires_at={a['expires_at']}",flush=True)
            return
        time.sleep(5)
    raise ValueError("Peer grant was not received before its deadline")


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


def issue():
    thaw.check_role("issue")
    c=service()
    thaw.gate("verify")
    pub=ROOT/"incoming/public.pem"
    fingerprint=b.fingerprint(pub)
    need(json.loads(thaw.small(ROOT/"incoming/holder.json",8192))=={**c,"fingerprint":fingerprint},
         "Receiver identity does not match the current run and attempt")
    api=thaw.private()
    part=thaw.saved(api,"p00",thaw.SIZE,thaw.SHA)
    need(part,"Original private part missing")
    ref=thaw.manifest_ref(api,part)
    need(ref,"Original completed manifest missing")
    manifest_inputs(ref,c["attempt"])
    thaw.verify_manifest(api,part,ref)
    for obj in (ref,part):
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
