"""Per-slot checkpoint transport for the bounded Bare Personal Actions chain."""
import argparse
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.parse import quote, urlsplit
import bridge as b
from verify_payload import check as verify_payload

ROOT = Path(os.environ["RUNNER_TEMP"]) / "r28-normal"
b.ROOT = ROOT
PARENT = {"sha": b.PARENT_SHA, "identity": b.PARENT_IDENTITY}
PART = 2_000_000_000
SCHEMA = "bare-r28-checkpoint-private-v1"
# Public only, approved in the R27 procedure. The trial has no access to its private key.
OWNER_PUBLIC_AGE = "age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx"


def slot():
    n = int(os.environ["R28_SLOT"])
    b.require(1 <= n <= 13, "Unbounded segment")
    return n


def logical(number):
    return f"bare-coexist-204-{b.env_int('GITHUB_RUN_ID')}-1-checkpoint-production-s{number}"


def stem(number=None):
    return f"r28-{b.env_int('GITHUB_RUN_ID')}-a1-s{slot() if number is None else number:02}"


def context():
    n = slot()
    head = os.environ["R28_HEAD_SHA"]
    parent, identity = os.environ["R28_PARENT_SHA"], os.environ["R28_PARENT_IDENTITY"]
    b.require(os.environ["GITHUB_REPOSITORY"] == b.REPO and re.fullmatch("[0-9a-f]{40}", head)
              and b.sha(parent) and b.sha(identity), "Invalid immutable generation")
    if n == 1:
        b.require((parent,identity) == (PARENT["sha"],PARENT["identity"]), "Initial parent differs from S2")
    return {"schema":SCHEMA, "key":logical(n), "run":b.env_int("GITHUB_RUN_ID"), "attempt":1,
            "ordinal":n,"producer_sha":head, "parent_sha":parent, "parent_identity":identity}


def same(binding):
    return all(binding.get(k) == v for k,v in context().items())


def names():
    b.output(key_name=stem()+"-key",descriptor_name=stem()+"-descriptor",outcome_name=stem()+"-outcome")


def keygen(role,check_run):
    b.require(b.env_int("GITHUB_RUN_ATTEMPT")==1,"Retry is read-only; ephemeral work is initial-attempt only")
    b.require(role in ("ordinary","limited") and check_run > 0,"Invalid slot key owner")
    ROOT.mkdir(mode=0o700)
    b.keygen()
    (ROOT/"holder.json").write_text(json.dumps({**context(),"role":role,"check_run":check_run,
       "fingerprint":b.fingerprint(ROOT/"public.pem")},sort_keys=True))


def wait(kind):
    require_kind = {"key":"-key","descriptor":"-descriptor","outcome":"-outcome"}
    b.require(kind in require_kind,"Unrecognized peer artifact")
    tag = stem()+require_kind[kind]
    run=b.env_int("GITHUB_RUN_ID")
    start=time.monotonic()
    deadline=start+(349*60 if kind=="outcome" else 20*60)
    observed_done=None
    while time.monotonic()<deadline:
        q=b.api_json(f"/repos/{b.REPO}/actions/runs/{run}/artifacts?name={quote(tag)}&per_page=100")
        found=[a for a in q["artifacts"] if a["name"]==tag]
        b.require(len(found)<=1,"Duplicate peer artifact")
        if found:
            a,=found
            bound=b.CAP+32*1024**2 if kind=="outcome" else 256*1024
            b.require(a["workflow_run"]["id"]==run and not a["expired"] and 0<a["size_in_bytes"]<=bound,
                      "Mismatched or expired peer artifact")
            b.output(id=a["id"])
            print(f"found {tag} artifact={a['id']} bytes={a['size_in_bytes']} expires_at={a['expires_at']}",flush=True)
            return
        if kind=="outcome":
            check=json.loads((ROOT/"peer.json").read_text())["check_run"]
            mine=[]
            for page in range(1, 11):
                jobs=b.api_json(f"/repos/{b.REPO}/actions/runs/{run}/attempts/1/jobs?per_page=100&page={page}")
                mine.extend(j for j in jobs["jobs"] if str(j["check_run_url"]).endswith("/"+str(check)))
                if len(jobs["jobs"])<100 or mine:
                    break
            else:
                raise ValueError("Unbounded run jobs query")
            b.require(len(mine)<=1,"Ambiguous ordinary job identity")
            if len(mine)==1 and mine[0]["status"]=="completed":
                observed_done=observed_done or time.monotonic()
                b.require(time.monotonic()-observed_done<75,"Ordinary job terminated without a durable outcome")
        time.sleep(8 if kind!="outcome" else 30)
    raise ValueError("Peer receipt unavailable before bounded deadline")


def info():
    p=ROOT/"input.json"
    rec=json.loads(p.read_text())
    b.require(same(rec),"Input descriptor not bound to this segment")
    return rec


def get_manifest(mid, expected_sha, expected_key):
    api=b.auth_api()
    rel=api.draft(b.RELEASE)
    row,=[r for r in rel["assets"] if r["id"]==mid]
    number=int(expected_key.rsplit("-s",1)[1])
    b.require(row["name"] in (stem(number)+"-manifest.json",stem(number)+"-manifest.json-retry1")
              and sha_check(expected_sha) and 0<row["size"]<32768,"Unrecognized private manifest")
    api.asset_info(rel,row["name"],row["size"],expected_sha,mid)
    buf=io.BytesIO()
    api.download(mid,row["size"],expected_sha,buf)
    m=json.loads(buf.getvalue())
    b.require(m["schema"]==SCHEMA and m["key"]==expected_key and m["ordinal"]==number
              and m["run"]==b.env_int("GITHUB_RUN_ID") and m["attempt"]==1 and
              m["producer_sha"]==os.environ["R28_HEAD_SHA"] and sha_check(m["sha256"]) and
              sha_check(m["identity"]) and sha_check(m["proof_sha"]) and 0<m["bytes"]<=b.CAP
              and 0<len(m["parts"])<=2 and sum(p["bytes"] for p in m["parts"])==m["bytes"],
              "Invalid generation receipt")
    for i,p in enumerate(m["parts"]):
        name=stem(number)+f"-p{i:02}"
        b.require(p["name"] in (name,name+"-retry1") and p["bytes"]==min(PART,m["bytes"]-i*PART)
                  and sha_check(p["sha256"]),"Unbound checkpoint part")
        api.asset_info(rel,p["name"],p["bytes"],p["sha256"],p["id"])
    return m


def sha_check(value):
    return bool(b.sha(value))


def issue():
    api=b.auth_api()
    peer=json.loads((ROOT/"incoming/holder.json").read_text())
    b.require(same(peer) and peer["role"]=="ordinary" and type(peer["check_run"]) is int
              and peer["check_run"]>0 and peer["fingerprint"]==b.fingerprint(ROOT/"incoming/public.pem"),
              "Invalid ordinary job certificate")
    (ROOT/"peer.json").write_text(json.dumps(peer))
    record={**context(),"worker_fpr":peer["fingerprint"],"writer_pem":(ROOT/"public.pem").read_text(),
            "lease_ends":int(time.time())+20*60,"source":None,"endpoints":[]}
    if os.environ.get("R28_WRAP_PUBLIC") == "1":
        wrapped = subprocess.run(["age","-r",OWNER_PUBLIC_AGE,str(ROOT/"key.pem")],check=True,
                                 stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15).stdout
        b.require(wrapped.startswith(b"age-encryption.org/v1\n") and 0<len(wrapped)<8192,
                  "Failed to preserve owner-wrapped transport-key backup")
        record["owner_wrapped_writer_key_age"] = base64.b64encode(wrapped).decode("ascii")
    if slot()>1:
        mid=b.env_int("R28_PARENT_MANIFEST")
        digest=os.environ["R28_PARENT_MANIFEST_SHA"]
        manifest=get_manifest(mid,digest,logical(slot()-1))
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
    b.decrypt(ROOT/"incoming/input.cms",ROOT/"input.json")
    rec=info()
    b.require(rec["worker_fpr"]==b.fingerprint(ROOT/"public.pem") and time.time()<rec["lease_ends"],
              "Input read lease invalid")
    pub=ROOT/"writer.pem";pub.write_text(rec["writer_pem"]);b.fingerprint(pub)
    m=rec["source"]
    if slot()==1:
        b.require(m is None and not rec["endpoints"],"First slot can use only pinned S2")
        return
    b.require(m["sha256"]==rec["parent_sha"] and m["identity"]==rec["parent_identity"] and
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
              0<file.stat().st_size<=b.CAP and sha_check(identity) and sha_check(proof_sha) and slot()<=12,
              "Unsafe checkpoint candidate")
    plain_hash=b.digest(file)
    b.require(plain_hash!=rec["parent_sha"],"Exact parent replay")
    sealed=ROOT/"checkpoint.cms"
    b.disk("before-checkpoint-encryption",file.stat().st_size+16*1024**2)
    b.encrypt(ROOT/"writer.pem",file,sealed)
    b.require(0<sealed.stat().st_size<=file.stat().st_size+16*1024**2,"Unbounded ciphertext")
    evidence={**context(),"status":"candidate","bytes":file.stat().st_size,"sha256":plain_hash,"identity":identity,
              "proof_sha":proof_sha,"sealed_bytes":sealed.stat().st_size,"sealed_sha":b.digest(sealed),
              "recipient_fpr":b.fingerprint(ROOT/"writer.pem")}
    if "owner_wrapped_writer_key_age" in rec:
        evidence["owner_wrapped_writer_key_age"] = rec["owner_wrapped_writer_key_age"]
    (ROOT/"outcome.json").write_text(json.dumps(evidence,sort_keys=True))
    logged={k:v for k,v in evidence.items() if k!="owner_wrapped_writer_key_age"}
    print("sealed_checkpoint="+json.dumps(logged,sort_keys=True))


def capacity():
    record=json.loads((ROOT/"outcome.json").read_text())
    b.require(same(record), "Wrong slot before peak measurement")
    if record["status"]!="candidate":
        return
    rows=b.inventory()
    name=stem()+"-outcome"
    b.require(not any(row["name"]==name for row in rows), "Existing exact outcome must be reconciled")
    active=sum(x["size_in_bytes"] for x in rows if not x["expired"])
    visible=sum(x["size_in_bytes"] for x in rows)
    sealed=(ROOT/"checkpoint.cms").stat().st_size
    b.require(sealed==record["sealed_bytes"], "Checkpoint changed since seal")
    outer=sealed+(ROOT/"outcome.json").stat().st_size+2*1024**2
    limit=os.environ.get("R28_RELAY_BYTE_CEILING","")
    if limit:
        b.require(limit.isdecimal() and int(limit)>0, "Invalid configured repository ceiling")
    print("checkpoint_artifact_peak="+json.dumps({"active_bytes":active,"expired_still_visible_bytes":visible-active,
        "visible_bytes":visible,"new_outer_zip_upper":outer,"projected_after_upload":visible+outer,
        "projected_with_remaining_slots_at_same_size":visible+(13-slot())*outer,"retention_days":1,
        "configured_ceiling_bytes":int(limit) if limit else None,
        "new_native_cache_bytes":0},sort_keys=True),flush=True)
    if limit:
        b.require(visible+outer<=int(limit), "Candidate exceeds configured repository Artifact storage ceiling")


def stop(reason):
    b.require(reason in ("apk","no-progress","verify-only","failed","cancelled"),"Unknown terminal state")
    with (ROOT/"outcome.json").open("x") as f:
        json.dump({**context(),"status":reason},f,sort_keys=True)


class Section:
    def __init__(self,file,length):self.file=file;self.left=length
    def read(self,n):
        block=self.file.read(min(self.left,n));self.left-=len(block)
        return block


def put(suffix,file,offset,length,digest):
    api=b.auth_api();base=stem()+"-"+suffix
    def find(name):
        rows=[r for r in api.draft(b.RELEASE)["assets"] if r["name"]==name]
        b.require(len(rows)<=1,"Asset name collision")
        return rows[0] if rows else None
    for name in (base,base+"-retry1"):
        row=find(name)
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
        obj=api.asset_info(api.draft(b.RELEASE),name,length,digest,row["id"])
        return {"id":obj["id"],"name":name,"bytes":length,"sha256":digest}
    raise ValueError("Empty residue on both permitted write attempts")


def verify_outputs(mid,sha_manifest):
    m=get_manifest(mid,sha_manifest,logical(slot()))
    b.require(same(m),"Accepted manifest no longer corresponds to selected parent")
    api=b.auth_api()
    full=hashlib.sha256()
    existing=api.draft(b.RELEASE)
    ids={mid,*[p["id"] for p in m["parts"]]}
    rows=[r for r in existing["assets"] if r["id"] in ids]
    b.require(len(rows)==len(ids),"Private generation lost assets before readback")
    for row in rows:
        url=urlsplit(row["browser_download_url"])
        b.require(url.scheme=="https" and url.netloc=="github.com" and not url.query and not url.fragment and
                  url.path.startswith("/"+b.REPO+"/releases/download/"),"Unexpected direct asset URI")
        for host,path,label in (("github.com",url.path,"direct"),(api.API,f"{api.BASE}/releases/assets/{row['id']}","api")):
            for attempt in range(2):
                retry_at=api.anonymous_status(host,path,label)
                if retry_at is None:break
                delay=max(0,retry_at-int(time.time()))
                b.require(attempt==0 and delay<=45,"Anonymous access not confirmed inside finite readback budget")
                time.sleep(delay)
    class Sink:
        def write(self,block):full.update(block)
    for part in m["parts"]:
        api.download(part["id"],part["bytes"],part["sha256"],Sink())
    b.require(full.hexdigest()==m["sha256"],"Independent private GET mismatch")
    b.output(checkpoint_manifest_id=mid,checkpoint_manifest_sha=sha_manifest,checkpoint_sha=m["sha256"],
             checkpoint_bytes=m["bytes"],checkpoint_identity=m["identity"],checkpoint_key=m["key"],
             checkpoint_ordinal=m["ordinal"],producer_sha=m["producer_sha"],private_readback_verified="true",
             checkpoint_advanced="true")


def publish():
    b.require(b.env_int("GITHUB_RUN_ATTEMPT")==1,"Rerun may only reconcile existing receipts")
    r=json.loads((ROOT/"incoming/outcome.json").read_text())
    b.require(same(r),"Stale user, version, segment or candidate")
    if r["status"]!="candidate":
        b.require(r["status"] in ("apk","no-progress","verify-only","failed","cancelled"),"Unknown result")
        b.output(private_readback_verified="false",checkpoint_advanced="false")
        return
    file=ROOT/"incoming/checkpoint.cms"
    b.require(0<r["bytes"]<=b.CAP and r["bytes"]<r["sealed_bytes"]<=r["bytes"]+16*1024**2
              and sha_check(r["sha256"]) and sha_check(r["identity"]) and sha_check(r["proof_sha"])
              and slot()<=12 and file.stat().st_size==r["sealed_bytes"] and b.digest(file)==r["sealed_sha"]
              and b.fingerprint(ROOT/"public.pem")==r["recipient_fpr"],"Sealed checkpoint mismatch")
    plain=ROOT/"candidate.tar.zst"
    b.disk("before-private-writer-decryption",r["bytes"])
    b.decrypt(file,plain)
    b.require(plain.stat().st_size==r["bytes"] and b.digest(plain)==r["sha256"],"Checkpoint content changed")
    verify_payload(plain,r)
    m={**context(),**{k:r[k] for k in ("bytes","sha256","identity","proof_sha")},"format":"tar.zst","parts":[]}
    with plain.open("rb") as source:
        for i,off in enumerate(range(0,m["bytes"],PART)):
            n=min(PART,m["bytes"]-off);h=hashlib.sha256()
            source.seek(off);remaining=Section(source,n)
            while block:=remaining.read(1024**2):h.update(block)
            b.require(remaining.left==0,"Short local candidate")
            m["parts"].append(put(f"p{i:02}",source,off,n,h.hexdigest()))
    data=json.dumps(m,sort_keys=True,separators=(",",":")).encode()
    receipt=put("manifest.json",io.BytesIO(data),0,len(data),hashlib.sha256(data).hexdigest())
    verify_outputs(receipt["id"],receipt["sha256"])


def recover():
    # After VM loss only an actually readable committed generation is a recovery
    # source. A surviving CMS archive alone cannot recover its vanished private key.
    api=b.auth_api()
    names=(stem()+"-manifest.json",stem()+"-manifest.json-retry1")
    found=[a for a in api.draft(b.RELEASE)["assets"] if a["name"] in names and a["state"]=="uploaded"]
    b.require(len(found)==1,"No unique committed generation; inspect exact ciphertext and owner-wrapped recovery receipt before any reissue; no automatic recomputation")
    row,=found
    verify_outputs(row["id"],row["digest"].removeprefix("sha256:"))


if __name__=="__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest="mode",required=True)
    for mode in ("names","issue","acquire","publish","recover","capacity"):sub.add_parser(mode)
    a=sub.add_parser("keygen");a.add_argument("role",choices=["ordinary","limited"]);a.add_argument("--check-run",type=int,required=True)
    a=sub.add_parser("wait");a.add_argument("kind",choices=["key","descriptor","outcome"])
    a=sub.add_parser("seal");a.add_argument("file",type=Path);a.add_argument("--identity",required=True);a.add_argument("--proof-sha",required=True)
    sub.add_parser("stop").add_argument("--reason",required=True)
    a=vars(parser.parse_args());op=a.pop("mode")
    globals()[op](**a)
