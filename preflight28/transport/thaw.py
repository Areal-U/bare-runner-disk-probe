"""Transfer-only recovery of the one original v2 S2 successor and its authenticated source."""
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import quote, urlsplit

PROJECT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(PROJECT/"preflight28/bridge"))
import bridge as b
import frames

ORIGINAL_RUN=45513782890
ORIGINAL_HEAD="81105d5f7b9ba994034753ce4fbd65d9b981dde3"
CIPHER_ID=14978478511
KEY_ID=14976353454
CLAIM_ID=789343072
CIPHER_ZIP_SHA="b7d84d5399d6bce27424370573375a965fabe568a97e0b8a16b1faa421daaa21"
KEY_ZIP_SHA="0cf210a57eb60e904189e1259ff55d077f6159c09d872c9e0545dcf2aa411c79"
WRAP_SHA="54ea50838cce1e0e5f371f649568c1879a0d3ad7d33938cd6b1f1902cf5e01fe"
SIZE=1745316602
SHA="532ca75915583a89e2830d062076e3d7130f1edabbe5c03159ce6b1e3c76c1ba"
CAMPAIGN="r28-preflight-s2-20261125-v2"
PREFIX=f"{CAMPAIGN}-run{ORIGINAL_RUN}-a1-seg01-"
KEY="bare-coexist-204-45285202990-1-checkpoint-production-s2"
REC={"schema":"bare-r28-fresh-split-v1","campaign":CAMPAIGN,"run":ORIGINAL_RUN,"attempt":1,
     "head":ORIGINAL_HEAD,"parent_sha":b.PARENT_SHA,"parent_identity":b.PARENT_IDENTITY,"parent_cache_id":11016400308,
     "bytes":SIZE,"sha256":SHA,"graph_sha":"1c00445b7ea5bc2dfbf493fab9a8f7fae0edb9eb13494d85bcbc9806717b47f5",
     "identity":"c98323daf2070e10aec251a63cef34058a4bac2568762b036c2e4ddd60448dda",
     "trial_provenance_sha":"82f1c55fde8d6b1a58518161ae40f26de22dcf777206ec12f369a1fdee6f53a8",
     "recipient_fpr":"56735d206310a24314a8b6ddf5d97ccac73843d4e7fd4e2901708add49dc84dd",
     "sealed_bytes":1747039590,"sealed_sha":"f11d6b4cb5cc22c8bac45a6443a96e2613fd33a59df68d7de208ff7fdab6aa27"}
HISTORY={"campaign":CAMPAIGN,"source_sha":ORIGINAL_HEAD,"producer_run":ORIGINAL_RUN,"producer_attempt":1,
         "segment":1,"parent_sha":b.PARENT_SHA,"parent_identity":b.PARENT_IDENTITY,"parent_cache_id":11016400308,
         "parent_key":KEY,"format":"tar.zst","bytes":SIZE,"identity":REC["identity"],"graph_sha":REC["graph_sha"],
         "trial_provenance_sha":REC["trial_provenance_sha"],"sha256":SHA}
ORIGINAL_FILES=("preflight28/transport/fresh.py","preflight28/bridge/bridge.py","preflight28/bridge/frames.py",
                "preflight28/bridge/check_archive.py",".github/workflows/bare-r28-s2-recovery.yml")
TEMP=Path(os.environ["RUNNER_TEMP"])
MIB=1024**2


def need(ok,why):
    if not ok: raise ValueError(why)


def small(p,n):
    s=p.lstat()
    need(stat.S_ISREG(s.st_mode) and 0<s.st_size<=n,"Invalid local file "+p.name)
    return p.read_bytes()


def check_role(job):
    need(os.environ["GITHUB_REPOSITORY"]==b.REPO and os.environ["GITHUB_JOB"]==job
         and b.env_int("GITHUB_RUN_ID")!=ORIGINAL_RUN
         and (job!="recover" or b.env_int("GITHUB_RUN_ATTEMPT")==1),"Invalid recovery execution role")


def clean_env():
    return {k:os.environ[k] for k in ("PATH","HOME","LANG","LC_ALL","RUNNER_TEMP") if k in os.environ}


def source_tree():
    tree=Path(os.environ["THAW_SOURCE_TREE"]).resolve(strict=True)
    head=subprocess.check_output(["git","-C",str(tree),"rev-parse","HEAD"],env=clean_env(),text=True).strip()
    need(head==ORIGINAL_HEAD,"Source checkout is not the immutable original v2 commit")
    return tree


def historical_proof(file):
    # Materialize only the original committed readers. Their path-derived PROJECT
    # locates the original YAML; no current deployment token reaches this process.
    tree=source_tree()
    with tempfile.TemporaryDirectory(dir=TEMP) as work:
        root=Path(work)
        for name in ORIGINAL_FILES:
            dest=root/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(subprocess.check_output(["git","-C",str(tree),"show",f"{ORIGINAL_HEAD}:{name}"],
                                env=clean_env()))
        script=("import sys,json;from pathlib import Path;"
                "sys.path.insert(0,sys.argv[1]);import fresh;"
                "child=json.loads(fresh.read_proofs(Path(sys.argv[2]),json.load(sys.stdin)));"
                "print('ORIGINAL_BUILD_IDENTITY='+child['identity_sha256'])")
        verified=subprocess.run([sys.executable,"-I","-c",script,str(root/"preflight28/transport"),str(file)],
                   input=json.dumps(REC),text=True,stdout=subprocess.PIPE,check=True,env=clean_env(),timeout=1200)
        lines=verified.stdout.splitlines()
        need(lines and lines[-1]=="ORIGINAL_BUILD_IDENTITY="+REC["identity"],"Complete original proof was not verified")
        print(verified.stdout,end="",flush=True)


def report_path():
    target=TEMP/"r28-thaw-audit.json"
    need(Path(os.environ.get("THAW_AUDIT",str(target)))==target,"Unexpected physical audit report")
    return target


def physical():
    return {"source_run":ORIGINAL_RUN,"source_head":ORIGINAL_HEAD,"source_claim_id":CLAIM_ID,
            "source_cipher_artifact_id":CIPHER_ID,"source_cipher_artifact_zip_sha":CIPHER_ZIP_SHA,
            "source_key_artifact_id":KEY_ID,"source_key_artifact_zip_sha":KEY_ZIP_SHA,
            "source_sha256":REC["sha256"],"source_bytes":REC["bytes"],"graph_sha":REC["graph_sha"],
            "trial_provenance_sha":REC["trial_provenance_sha"],"current_run":b.env_int("GITHUB_RUN_ID"),
            "current_head":os.environ["TRIAL_SHA"],"attempt":b.env_int("GITHUB_RUN_ATTEMPT")}


def stamp(name,obj):
    with (TEMP/name).open("x") as f:
        json.dump(obj,f,sort_keys=True,separators=(",",":"))


def checkpoint():
    file=TEMP/"r28-child.tar.zst"
    st=file.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_size==REC["bytes"] and b.digest(file)==REC["sha256"],"Original checkpoint changed")
    return file


def open_source():
    check_role("recover")
    receipts=Path(os.environ["THAW_CIPHER_DIR"])
    keys=Path(os.environ["THAW_KEY_ARTIFACT_DIR"])
    pem=Path(os.environ["THAW_KEY_PEM"])
    need(json.loads(small(receipts/"cipher-receipt.json",16384))==REC,"Wrong original source receipt")
    sealed=receipts/"checkpoint.cms"
    stat_sealed=sealed.lstat()
    need(stat.S_ISREG(stat_sealed.st_mode) and stat_sealed.st_size==REC["sealed_bytes"]
         and b.digest(sealed)==REC["sealed_sha"],"Original sealed checkpoint changed")
    cert=small(keys/"public.pem",16384)
    need(b.fingerprint(keys/"public.pem")==REC["recipient_fpr"] and
         hashlib.sha256(small(keys/"writer-key.age",16384)).hexdigest()==WRAP_SHA,"Wrong prior scoped writer package")
    st=pem.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_mode&0o077==0,"Unsafe session key file permissions")
    with tempfile.TemporaryDirectory(dir=TEMP) as work:
        previous=b.ROOT
        try:
            b.ROOT=Path(work)
            b.disk("thaw-before-reconstruct",REC["bytes"]+144*MIB)
            (b.ROOT/"public.pem").write_bytes(cert)
            fd=os.open(str(b.ROOT/"key.pem"),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,"wb") as out:out.write(small(pem,16384))
            key_spki=subprocess.check_output(["openssl","pkey","-in",str(b.ROOT/"key.pem"),"-pubout"],env=clean_env())
            cert_spki=subprocess.check_output(["openssl","x509","-in",str(b.ROOT/"public.pem"),"-pubkey","-noout"],env=clean_env())
            need(key_spki==cert_spki,"Session key does not correspond to original writer certificate")
            frames.receive(sealed,TEMP/"r28-child.tar.zst",REC["bytes"],REC["sha256"])
        finally:
            b.ROOT=previous
    file=checkpoint()
    historical_proof(file)
    stamp("r28-thaw-open.json",physical())
    print("original_sealed_source_restored="+json.dumps(physical(),sort_keys=True),flush=True)


def checked_report():
    path=report_path()
    import thaw_claim
    return thaw_claim.passed_audit(path)


def audit():
    check_role("recover")
    need(json.loads(small(TEMP/"r28-thaw-open.json",8192))==physical(),"Missing bound original-proof receipt")
    target=report_path()
    need(not target.exists(),"Audit destination already exists")
    subprocess.run([sys.executable,"-I",str(PROJECT/"preflight28/graph/retained.py"),"archives",
        "--parent",os.environ["THAW_PARENT"],"--child",str(checkpoint()),"--parent-sha",b.PARENT_SHA,
        "--child-sha",REC["sha256"],"--report",str(target)],check=True,env=clean_env(),timeout=1500)
    stamp("r28-thaw-audited.json",{**physical(),"report_sha256":checked_report()})


def private():
    sys.path.insert(0,os.environ["RUNNER_TEMP"])
    import transfer
    from recovery_claim import CompleteDraft
    return CompleteDraft(transfer)


def gate(op):
    args=[sys.executable,str(PROJECT/"preflight28/transport/thaw_claim.py"),op]
    if op=="authorize":args+=["--audit",str(report_path())]
    subprocess.run(args,check=True)


def asset_rows(api,suffix):
    names=(PREFIX+suffix,PREFIX+suffix+"-retry1")
    rows=[r for r in api.draft(b.RELEASE)["assets"] if r["name"] in names]
    need(len({r["name"] for r in rows})==len(rows),"Ambiguous original private names")
    for r in rows:
        need(r["state"]=="uploaded" or (r["state"]=="starter" and r["size"]==0),"Unexpected state for original generation")
    return {r["name"]:r for r in rows}


def saved(api,suffix,size,digest):
    rows=asset_rows(api,suffix)
    complete=[r for r in rows.values() if r["state"]=="uploaded"]
    need(len(complete)<=1,"Ambiguous completed original asset")
    if not complete:return None
    r=complete[0]
    api.asset_info(api.draft(b.RELEASE),r["name"],size,digest,r["id"])
    return {"id":r["id"],"name":r["name"],"bytes":size,"sha256":digest}


def put(api,suffix,file,size,digest):
    need(suffix in ("p00","manifest.json"),"Invalid original single-part generation name")
    existing=saved(api,suffix,size,digest)
    if existing:return existing
    for name in (PREFIX+suffix,PREFIX+suffix+"-retry1"):
        row=asset_rows(api,suffix).get(name)
        if row and row["state"]=="starter":continue
        if not row:
            file.seek(0)
            try:
                con,r=api.request(api.UPLOAD,"POST",f"{api.BASE}/releases/{b.RELEASE}/assets?name={quote(name)}",
                    auth=True,body=file,length=size,content_type="application/octet-stream")
                try:
                    status=r.status
                    r.read(65536)
                finally:con.close()
                need(status in (201,422,502),f"Private upload HTTP {status}")
            except (OSError,http.client.HTTPException):
                pass
        for delay in (0,2,5):
            if delay:time.sleep(delay)
            finished=saved(api,suffix,size,digest)
            if finished:return finished
            row=asset_rows(api,suffix).get(name)
            if row:break
        need(row and row["state"]=="starter","Upload outcome unknown; reconcile the same physical original before retry")
    raise ValueError("No available slot after two empty private starters")


def manifest(part):
    return json.dumps({**HISTORY,"parts":[part]},sort_keys=True,separators=(",",":")).encode()


def manifest_ref(api,part):
    body=manifest(part)
    return saved(api,"manifest.json",len(body),hashlib.sha256(body).hexdigest())


def publish():
    check_role("recover")
    path=checkpoint()
    need(json.loads(small(TEMP/"r28-thaw-open.json",8192))==physical() and
         json.loads(small(TEMP/"r28-thaw-audited.json",8192))=={**physical(),"report_sha256":checked_report()},
         "Open and retrospective receipts differ from current authorized transfer")
    gate("authorize")
    api=private()
    exists=any(r["state"]=="uploaded" for r in asset_rows(api,"manifest.json").values())
    part=saved(api,"p00",REC["bytes"],REC["sha256"])
    need(not exists or part is not None,"Existing original manifest no longer has its bound part")
    if not part:
        with path.open("rb") as src:part=put(api,"p00",src,REC["bytes"],REC["sha256"])
    body=manifest(part)
    ref=manifest_ref(api,part) or put(api,"manifest.json",io.BytesIO(body),len(body),hashlib.sha256(body).hexdigest())
    verify_manifest(api,part,ref)
    b.output(manifest_id=ref["id"],manifest_sha=ref["sha256"])
    print("original_manifest_receipt="+json.dumps(ref,sort_keys=True),flush=True)


def verify_manifest(api,part,ref):
    # Exact entire canonical historical payload including source run, parent,
    # identity, graph/trial proofs and numeric immutable part IDs.
    raw=io.BytesIO()
    api.download(ref["id"],ref["bytes"],ref["sha256"],raw)
    need(raw.getvalue()==manifest(part),"Changed original manifest bytes")


def invisible(api,obj):
    assets=api.draft(b.RELEASE)
    row=api.asset_info(assets,obj["name"],obj["bytes"],obj["sha256"],obj["id"])
    u=urlsplit(row["browser_download_url"])
    need(u.scheme=="https" and u.netloc=="github.com" and not u.query and not u.fragment
         and u.path.startswith("/"+b.REPO+"/releases/download/"),"Wrong original direct read")
    for host,path,label in (("github.com",u.path,"direct"),(api.API,f"{api.BASE}/releases/assets/{row['id']}","api")):
        for attempt in range(2):
            retry=api.anonymous_status(host,path,label)
            if retry is None:break
            delay=max(0,retry-int(time.time()))
            need(attempt==0 and delay<=45,"Cannot establish private visibility within receiver budget")
            time.sleep(delay)


def existing_permit(api,expected_id):
    import thaw_claim
    ev=json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    head=subprocess.check_output(["git","rev-parse","HEAD"],text=True,env=clean_env()).strip()
    holder=thaw_claim.check_event(api,os.environ,ev,head,"reserve")
    claim=thaw_claim.a.claim_info(api,thaw_claim.a.encode(holder),thaw_claim.CLAIM)
    need(claim is not None and (not os.getenv("THAW_CLAIM_ID") or str(claim)==os.environ["THAW_CLAIM_ID"])
         and thaw_claim.check_original_draft(api)==expected_id,
         "Original source or the existing audit-only reservation differs from admission")


def read_complete(api,ref,part):
    verify_manifest(api,part,ref)
    with frames.staged(TEMP/"r28-child.tar.zst") as out:
        api.download(part["id"],part["bytes"],part["sha256"],out)
    historical_proof(checkpoint())


def existing():
    check_role("recover")
    expected=b.env_int("THAW_ORIGINAL_MANIFEST_ID")
    api=private()
    existing_permit(api,expected)
    part=saved(api,"p00",REC["bytes"],REC["sha256"])
    need(part,"Existing source lacks original complete part")
    ref=manifest_ref(api,part)
    need(ref and ref["id"]==expected,"Current admitted original manifest ID differs")
    read_complete(api,ref,part)
    stamp("r28-thaw-open.json",physical())
    print(f"existing_full_source_reverified manifest={ref['id']} bytes={REC['bytes']} sha256={REC['sha256']}",flush=True)


def receive_source():
    check_role("issue")
    gate("verify")
    api=private()
    part=saved(api,"p00",REC["bytes"],REC["sha256"])
    need(part,"Original part is missing")
    ref=manifest_ref(api,part)
    need(ref and (not os.getenv("MANIFEST_ID") or os.environ["MANIFEST_ID"]==str(ref["id"])) and
         (not os.getenv("MANIFEST_SHA") or os.environ["MANIFEST_SHA"]==ref["sha256"]),"Wrong original manifest reference")
    for item in (ref,part):invisible(api,item)
    read_complete(api,ref,part)
    with (TEMP/"r28-child.json").open("xb") as out:out.write(manifest(part))
    b.output(manifest_id=ref["id"],manifest_sha=ref["sha256"])
    print(f"independent_private_source_manifest={ref['id']} bytes={REC['bytes']} sha256={REC['sha256']}",flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode",choices=["open","existing","audit","publish","receive-source"])
    os.umask(0o077)
    {"open":open_source,"existing":existing,"audit":audit,"publish":publish,"receive-source":receive_source}[parser.parse_args().mode]()
