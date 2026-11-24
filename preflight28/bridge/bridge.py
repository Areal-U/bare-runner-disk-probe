"""PR9's finite ordinary-runner / private-Draft-worker checkpoint handoff."""
import argparse
import datetime
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from urllib.parse import quote, urlsplit

REPO = "Areal-U/bare-runner-disk-probe"
RELEASE = 452114666
SOURCE_WORKFLOW = ".github/workflows/bare-r28-s2-preflight.yml"
SOURCE_CAMPAIGN = "r28-preflight-s2-20261125-v1"
ROOT = Path(os.environ["RUNNER_TEMP"]) / "r28-split"
CAP = 7 * 1024**3 // 2
HEAD = os.environ.get("TRIAL_SHA", "")
PARENT_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
PARENT_IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
CDN = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
GIB = 1024**3


def require(value, explanation):
    if not value:
        raise ValueError(explanation)


def env_int(key):
    value = os.environ[key]
    require(re.fullmatch("[1-9][0-9]*", value), key + " must be a positive integer")
    return int(value)


def sha(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)


def digest(file):
    with file.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def output(**items):
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        for key, value in items.items():
            require("\n" not in str(value), "Invalid multiline output")
            print(f"{key}={value}", file=f)


def api_json(path, expected=200):
    require(path.startswith("/repos/" + REPO + "/"), "Unscoped API access")
    conn = http.client.HTTPSConnection("api.github.com", timeout=30)
    try:
        conn.request("GET", path, headers={"User-Agent":"r28-split-reader/1", "Accept":"application/vnd.github+json",
                     "Authorization":"Bearer " + os.environ["GH_TOKEN"], "X-GitHub-Api-Version":"2022-11-28"})
        response = conn.getresponse()
        if expected == "denied":
            require(response.status in (403,404), f"Ordinary job unexpectedly accessed private source (HTTP {response.status})")
            print("ordinary_draft_get_status=" + str(response.status))
            return {}
        require(response.status == expected, f"Scoped API returned HTTP {response.status}")
        raw = response.read(4*1024**2 + 1)
        require(len(raw) <= 4*1024**2, "Oversized page")
        return json.loads(raw)
    finally:
        conn.close()


def auth_api():
    sys.path.insert(0, os.environ["RUNNER_TEMP"])
    import transfer
    return transfer


def label(kind):
    return f"r28-split-s2-{env_int('GITHUB_RUN_ID')}-a1-{kind}"


def guard():
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
    pr = event["pull_request"]
    require(env_int("GITHUB_RUN_ATTEMPT") == 1 and os.environ["GITHUB_REPOSITORY"] == REPO and
            event["repository"]["id"] == 1450926240 and pr["number"] == 9 and
            pr["head"]["repo"]["id"] == 1450926240 and pr["base"]["repo"]["id"] == 1450926240 and
            pr["base"]["ref"] == "bare-coexist-v2.0.4" and pr["head"]["ref"]=="work-bare-27-storage-check" and
            event["action"] == "synchronize" and event["before"] == os.environ["PRIOR_SHA"] and
            event["after"] == HEAD == pr["head"]["sha"] and event["sender"]["id"] == 292261483,
            "Unauthorized trial generation")
    sid = env_int("SOURCE_RUN")
    info = api_json(f"/repos/{REPO}/actions/runs/{sid}/attempts/1")
    require(info["conclusion"]=="success" and info["head_sha"] == os.environ["SOURCE_HEAD"] and
            info["run_attempt"]==1 and info["head_branch"]==pr["head"]["ref"] and info["path"]==SOURCE_WORKFLOW and
            info["repository"]["id"]==1450926240 and info["actor"]["id"]==292261483,
            "Real source workflow not independently successful")
    jobs = api_json(f"/repos/{REPO}/actions/runs/{sid}/attempts/1/jobs?per_page=100")["jobs"]
    steps = {s["name"] for j in jobs if j["conclusion"]=="success" for s in j["steps"] if s["conclusion"]=="success"}
    require({"Send only the verified generation to the existing owner Draft",
             "Rebuild fixed environment and prove full restored APK frontier without new compilation"} <= steps,
             "No previously accepted source generation")
    if os.environ["GITHUB_JOB"]=="ordinary":
        api_json(f"/repos/{REPO}/releases/{RELEASE}", expected="denied")
    require(not ROOT.exists(), "Runner staging directory already exists")
    ROOT.mkdir(mode=0o700)
    disk("begin", 2*CAP + 24*1024**2 + (2753879385 if os.environ["GITHUB_JOB"]=="ordinary" else 0))
    inventory()


def disk(stage, future=0):
    info = os.statvfs(ROOT)
    free = info.f_frsize * info.f_bavail
    print(f"disk_stage={stage} free={free} free_inodes={info.f_favail} incremental_reserved={future}", flush=True)
    require(free >= 20*GIB + future and info.f_favail >= 20000 + 20, "Trial disk floor not preserved")


def inventory():
    rows = []
    for page in range(1,51):
        listing = api_json(f"/repos/{REPO}/actions/artifacts?per_page=100&page={page}")
        batch = listing["artifacts"]
        rows.extend(batch)
        if len(batch)<100:
            require(len(rows)==listing["total_count"] and len({row["id"] for row in rows})==len(rows),
                    "Inconsistent repository artifact inventory")
            break
    else:
        raise ValueError("Unbounded artifact listing")
    active = sum(r["size_in_bytes"] for r in rows if not r["expired"])
    visible = sum(r["size_in_bytes"] for r in rows)
    print("repo_artifact_inventory="+json.dumps({"active_bytes":active,"all_visible_bytes":visible,
        "visible_expired_bytes":visible-active,"artifact_count":len(rows),
        "visible_trial":[[r["id"],r["name"],r["size_in_bytes"],r["expired"],r["expires_at"]]
                         for r in rows if r["name"].startswith("r28-split-s2-")]}, separators=(",",":")))
    return rows


def before_upload():
    rows=inventory()
    current=label("cipher")
    require(not any(r["name"]==current for r in rows),"Existing same-run ciphertext must be reconciled")
    receipt=json.loads((ROOT/"cipher-receipt.json").read_text())
    # compression level zero; allow ZIP headers and block framing outside ciphertext.
    zip_ceiling=receipt["sealed_bytes"]+receipt["native_test_object"]["cipher_bytes"]+(ROOT/"cipher-receipt.json").stat().st_size+2*1024**2
    visible=sum(r["size_in_bytes"] for r in rows)
    print("relay_peak_upper_bound="+json.dumps({"all_visible_existing":visible,"new_zip_ceiling":zip_ceiling,
          "simultaneous_repository_bytes":visible+zip_ceiling,"projected_if_twelve_same_sized_within_retention":visible+12*zip_ceiling,
          "retention_days":1,"normal_cache_added_bytes":0},sort_keys=True))


def wait(kind):
    name = label(kind)
    end = time.monotonic()+(28*60 if kind=="cipher" else 13*60)
    api = f"/repos/{REPO}/actions/runs/{env_int('GITHUB_RUN_ID')}/artifacts?name={quote(name)}&per_page=100"
    while time.monotonic()<end:
        listing = api_json(api)
        entries = [a for a in listing["artifacts"] if a["name"]==name]
        require(len(entries)<=1, "Multiple same-generation transfer candidates")
        if entries:
            a,=entries
            limit = CAP + 24*1024**2 if kind=="cipher" else 128*1024
            require(not a["expired"] and 0<a["size_in_bytes"]<=limit and a["workflow_run"]["id"]==env_int("GITHUB_RUN_ID")
                    and a["workflow_run"]["head_sha"]==HEAD, "Invalid artifact receipt")
            print(f"observed_artifact={a['id']} kind={kind} outer_zip_bytes={a['size_in_bytes']} expires={a['expires_at']}")
            output(id=a["id"])
            return
        time.sleep(7)
    raise ValueError("Peer stage unavailable before bounded receipt deadline")


def openssl(*args, capture=False):
    return subprocess.run(["openssl",*map(str,args)],check=True,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE,timeout=500).stdout


def fingerprint(key):
    require(key.is_file() and 0<key.stat().st_size<16384, "Unexpected certificate length")
    raw=key.read_bytes()
    require(raw.count(b"-----BEGIN CERTIFICATE-----")==1 and b"PRIVATE" not in raw, "Public certificate required")
    der=openssl("x509","-in",key,"-outform","DER",capture=True)
    return hashlib.sha256(der).hexdigest()


def keygen():
    sub="/CN=Bare R28 %d %s" % (env_int("GITHUB_RUN_ID"),os.environ["GITHUB_JOB"])
    openssl("req","-new","-x509","-newkey","rsa:3072","-keyout",ROOT/"key.pem","-out",ROOT/"public.pem",
            "-nodes","-sha256","-subj",sub,"-days","1")
    print("generated_ephemeral_public_fingerprint=" + fingerprint(ROOT/"public.pem"))


def encrypt(public, plain, sealed):
    fingerprint(public)
    openssl("cms","-encrypt","-binary","-stream","-outform","DER","-aes-256-gcm","-in",plain,"-out",sealed,
            "-recip",public,"-keyopt","rsa_padding_mode:oaep","-keyopt","rsa_oaep_md:sha256")


def decrypt(sealed, plain):
    openssl("cms","-decrypt","-inform","DER","-binary","-in",sealed,"-recip",ROOT/"public.pem",
            "-inkey",ROOT/"key.pem","-out",plain)


def get_source():
    api=auth_api()
    mid=env_int("SOURCE_MANIFEST_ID")
    expected=os.environ["SOURCE_MANIFEST_SHA"]
    require(sha(expected),"Invalid expected source receipt")
    rel=api.draft(RELEASE)
    asset,=[a for a in rel["assets"] if a["id"]==mid]
    stem=f"{SOURCE_CAMPAIGN}-run{env_int('SOURCE_RUN')}-a1-seg01-"
    require(asset["name"] in (stem+"manifest.json",stem+"manifest.json-retry1") and
            0<asset["size"]<16384,"Unexpected manifest name or length")
    api.asset_info(rel,asset["name"],asset["size"],expected,mid)
    buff=io.BytesIO()
    api.download(mid,asset["size"],expected,buff)
    m=json.loads(buff.getvalue())
    require(m["campaign"]==SOURCE_CAMPAIGN and m["source_sha"]==os.environ["SOURCE_HEAD"] and
        m["producer_run"]==env_int("SOURCE_RUN") and m["producer_attempt"]==1 and m["segment"]==1 and
        m["parent_sha"]==PARENT_SHA and m["parent_identity"]==PARENT_IDENTITY and m["parent_cache_id"]==11016400308
        and m["format"]=="tar.zst" and sha(m["sha256"]) and sha(m["identity"]) and sha(m["graph_sha"]) and
        0<m["bytes"]<=CAP and 0<len(m["parts"])<=2 and sum(p["bytes"] for p in m["parts"])==m["bytes"],
        "Wrong verified generation")
    for i,p in enumerate(m["parts"]):
        require(p["name"] in (stem+f"p{i:02}",stem+f"p{i:02}-retry1") and sha(p["sha256"]) and
                0<p["bytes"]<=2_000_000_000, "Unbound part")
        api.asset_info(rel,p["name"],p["bytes"],p["sha256"],p["id"])
    return m


def endpoint(url):
    parsed=urlsplit(url)
    require(parsed.scheme=="https" and parsed.netloc in CDN and parsed.path.startswith("/") and
            parsed.query and not parsed.fragment,"Invalid restricted asset endpoint")
    return parsed


def issue():
    api=auth_api()
    manifest=get_source()
    urls=[]
    for part in manifest["parts"]:
        conn,resp=api.request(api.API,"GET",f"{api.BASE}/releases/assets/{part['id']}",auth=True,accept="application/octet-stream")
        try:
            require(resp.status==302,"Specific private asset did not return a short-lived download endpoint")
            url=resp.getheader("Location","")
            endpoint(url)
            urls.append(url)
        finally:
            conn.close()
    record={"source":manifest,"release":RELEASE,"manifest_id":env_int("SOURCE_MANIFEST_ID"),
        "manifest_sha":os.environ["SOURCE_MANIFEST_SHA"],"trial_run":env_int("GITHUB_RUN_ID"),
        "trial_head":HEAD,"worker_fingerprint":fingerprint(ROOT/"incoming/public.pem"),
        "writer_key":(ROOT/"public.pem").read_text(),"lease_ends":int(time.time())+15*60,
        "endpoints":urls}
    private=ROOT/"private-input.json"
    private.write_text(json.dumps(record,separators=(",",":")))
    encrypt(ROOT/"incoming/public.pem",private,ROOT/"input.cms")
    print("issued_encrypted_generation_descriptor bytes=" + str((ROOT/"input.cms").stat().st_size))


def acquire():
    private=ROOT/"private-input.json"
    decrypt(ROOT/"incoming/input.cms",private)
    rec=json.loads(private.read_text())
    m=rec["source"]
    require(rec["trial_run"]==env_int("GITHUB_RUN_ID") and rec["trial_head"]==HEAD and
        rec["worker_fingerprint"]==fingerprint(ROOT/"public.pem") and
        rec["manifest_id"]==env_int("SOURCE_MANIFEST_ID") and rec["manifest_sha"]==os.environ["SOURCE_MANIFEST_SHA"]
        and rec["lease_ends"]>=time.time() and sha(m["sha256"]) and 0<m["bytes"]<=CAP and
        len(rec["endpoints"])==len(m["parts"]),"Missing or expired handoff")
    file=ROOT/"checkpoint.tar.zst"
    whole=hashlib.sha256()
    with file.open("xb") as f:
        for url,part in zip(rec["endpoints"], m["parts"],strict=True):
            u=endpoint(url)
            # No repository credentials in this step or on this connection.
            conn=http.client.HTTPSConnection(u.netloc,timeout=90)
            try:
                conn.request("GET",u.path+"?"+u.query,headers={"User-Agent":"bare-bounded-receiver"})
                resp=conn.getresponse()
                require(resp.status==200,"Scoped successor read unavailable")
                size=0
                h=hashlib.sha256()
                while b:=resp.read(1024**2):
                    size+=len(b)
                    require(size<=part["bytes"],"Private input outside manifest length")
                    h.update(b)
                    whole.update(b)
                    f.write(b)
                require(size==part["bytes"] and h.hexdigest()==part["sha256"],"Private input digest mismatch")
            finally:
                conn.close()
    require(file.stat().st_size==m["bytes"] and whole.hexdigest()==m["sha256"],"Full input mismatch")
    print(f"verified_ordinary_input source_manifest={rec['manifest_id']} bytes={m['bytes']} sha256={m['sha256']}")
    (ROOT/"writer.pem").write_text(rec["writer_key"])
    disk("ordinary-input",m["bytes"]+16*1024**2)


def seal(file):
    rec=json.loads((ROOT/"private-input.json").read_text())
    # The routine also accepts an independently generated regular checkpoint. In
    # this transport trial the authorized test file must equal the accepted parent.
    require(file.resolve()==file and file.is_file() and not file.is_symlink() and 0<file.stat().st_size<=CAP,
            "Candidate is not a bounded regular checkpoint")
    require(file.stat().st_size==rec["source"]["bytes"] and digest(file)==rec["source"]["sha256"],
            "This trial may transport only its existing verified generation")
    sealed=ROOT/"checkpoint.cms"
    encrypt(ROOT/"writer.pem",file,sealed)
    require(0<sealed.stat().st_size<=file.stat().st_size+16*1024**2,"Cipher overhead exceeds trial allocation")
    info={"run":env_int("GITHUB_RUN_ID"),"attempt":1,"trial_head":HEAD,"source_manifest":env_int("SOURCE_MANIFEST_ID"),
        "source_sha":rec["source"]["sha256"],"source_bytes":file.stat().st_size,"sealed_bytes":sealed.stat().st_size,
        "sealed_sha":digest(sealed),"recipient_fpr":fingerprint(ROOT/"writer.pem")}
    (ROOT/"cipher-receipt.json").write_text(json.dumps(info,sort_keys=True))
    print("outgoing="+json.dumps(info,sort_keys=True))
    disk("ordinary-sealed")


def accepted():
    api=auth_api()
    manifest=get_source()
    sealed=ROOT/"incoming/checkpoint.cms"
    evidence=json.loads((ROOT/"incoming/cipher-receipt.json").read_text())
    require(evidence["run"]==env_int("GITHUB_RUN_ID") and evidence["attempt"]==1 and evidence["trial_head"]==HEAD and
        evidence["source_manifest"]==env_int("SOURCE_MANIFEST_ID") and evidence["source_bytes"]==manifest["bytes"] and
        evidence["source_sha"]==manifest["sha256"] and evidence["recipient_fpr"]==fingerprint(ROOT/"public.pem") and
        sealed.stat().st_size==evidence["sealed_bytes"] and digest(sealed)==evidence["sealed_sha"],
        "Ciphertext receipt mismatch")
    disk("writer-cipher",manifest["bytes"])
    plain=ROOT/"restored.tar.zst"
    decrypt(sealed,plain)
    require(plain.stat().st_size==manifest["bytes"] and digest(plain)==manifest["sha256"],"Recovered checkpoint differs")
    combined=hashlib.sha256()
    class Sink:
        def write(self,block):
            combined.update(block)
    for part in manifest["parts"]:
        api.download(part["id"],part["bytes"],part["sha256"],Sink())
    require(combined.hexdigest()==manifest["sha256"],"Existing full owner checkpoint no longer matches")
    disk("writer-restored")
    print(f"writer_verified_existing_draft={RELEASE} manifest_id={env_int('SOURCE_MANIFEST_ID')} checkpoint_bytes={manifest['bytes']} sha256={combined.hexdigest()} additional_draft_upload_bytes=0")
    inventory()


if __name__=="__main__":
    os.umask(0o077)
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode",choices=["guard","keygen","wait","issue","acquire","seal","accepted","inventory","before_upload"])
    ap.add_argument("value",nargs="?")
    args=ap.parse_args()
    if args.mode=="wait":
        require(args.value in ("key","descriptor","cipher"),"Invalid artifact class")
        wait(args.value)
    elif args.mode=="seal":
        seal(Path(args.value))
    else:
        globals()[args.mode]()
