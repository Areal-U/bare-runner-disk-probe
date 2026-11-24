"""Carry the first new required Chromium edge from an ordinary runner to one private writer."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import time

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "preflight28/bridge"))
import bridge as b
import frames

CAMPAIGN = "r28-preflight-s2-20261125-v2"
SCHEMA = "bare-r28-fresh-split-v1"
PARENT_REV = "bf70ddbf474f3390a62220a076b8c43347fecc64"
TEMP = Path(os.environ["RUNNER_TEMP"])
CIPHER = "checkpoint.cms"
RECEIPT = "cipher-receipt.json"
GRAPH = "checkpoint-round28-graph.json"
CHILD = "checkpoint-provenance.json"
PARENT = "checkpoint-round28-parent-provenance.json"
TRIAL = "checkpoint-round28-trial-provenance.json"
WORKFLOW = ".github/workflows/bare-r28-s2-recovery.yml"
MIB = 1024**2
MAX_META = {CHILD: MIB, PARENT: MIB, GRAPH: 64*MIB, TRIAL: MIB}


def fixed():
    head = os.environ["TRIAL_SHA"]
    b.require(b.env_int("GITHUB_RUN_ATTEMPT")==1 and re.fullmatch(r"[0-9a-f]{40}",head)
              and os.environ.get("R28_CAMPAIGN")==CAMPAIGN and os.environ["GITHUB_REPOSITORY"]==b.REPO,"Unexpected fresh-run generation")
    return {"schema":SCHEMA,"campaign":CAMPAIGN,"run":b.env_int("GITHUB_RUN_ID"),"attempt":1,
            "head":head,"parent_sha":b.PARENT_SHA,"parent_identity":b.PARENT_IDENTITY,"parent_cache_id":11016400308}


def artifact_name(kind):
    return f"r28-fresh-{fixed()['run']}-"+{"key":"writer","cipher":"cipher","delta":"delta"}[kind]


def small(path, maximum):
    info=path.lstat()
    b.require(stat.S_ISREG(info.st_mode) and 0<info.st_size<=maximum,
              "Missing or oversized regular receipt "+path.name)
    return path.read_bytes()


def canonical(obj):
    return hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")).hexdigest()


def identity(data, revision):
    b.require(data.get("format")=="bare-checkpoint-provenance" and data.get("version")==2
              and isinstance(data.get("identity"),dict) and data["identity"].get("ci_revision")==revision
              and canonical(data["identity"])==data.get("identity_sha256"),"Unbound Chromium build provenance")
    return data["identity_sha256"]


PRODUCER_NAME="Ordinary read-only runner builds and seals new APK dependency"
AUDIT_NAME="Compare all retained APK payloads from original S2 against the securely deposited child"


def peer(run,name):
    jobs=b.api_json(f"/repos/{b.REPO}/actions/runs/{run}/attempts/1/jobs?per_page=100")
    b.require(len(jobs["jobs"])==jobs["total_count"],"Incomplete peer job inventory")
    matches=[j for j in jobs["jobs"] if j["name"]==name]
    b.require(len(matches)<=1,"Ambiguous original-attempt job")
    if not matches:
        return None
    row=matches[0]
    if row["status"]=="completed":
        b.require(row["conclusion"]=="success","Original peer ended without proof of success")
        if name==PRODUCER_NAME:
            b.require(any(s["name"]==AUDIT_NAME and s["conclusion"]=="success"
                          for s in row["steps"]),"Ordinary job did not pass final retained-byte audit")
    return row


def relay(kind):
    run=fixed()["run"]
    modes=(("key","key"),) if kind=="key" else (("cipher","full"),("delta","delta"))
    found={}
    for lookup,mode in modes:
        name=artifact_name(lookup)
        q=f"/repos/{b.REPO}/actions/runs/{run}/artifacts?name={name}&per_page=100"
        listing=b.api_json(q)
        rows=listing["artifacts"]
        b.require(len(rows)==listing["total_count"]<=1,"Unexpected same-run artifact multiplicity")
        if rows:
            row=rows[0]
            cap={"key":128*1024,"full":b.CAP+24*MIB,"delta":256*MIB}[mode]
            b.require(row["name"]==name and row["expired"] is False and 0<row["size_in_bytes"]<=cap
                      and row["workflow_run"]["id"]==run and row["workflow_run"]["head_sha"]==os.environ["TRIAL_SHA"]
                      and type(row["id"]) is int and row["id"]>0,"Unexpected fresh-run artifact")
            found[mode]=row
    return found


def wait(kind):
    b.require(os.environ["GITHUB_JOB"]==("produce" if kind=="key" else "send"),"Unexpected peer client")
    run=fixed()["run"]
    name=os.environ["FRESH_PEER_NAME"]
    b.require(name==(PRODUCER_NAME if kind=="cipher" else "Limited sender receives new complete bytes and publishes one private checkpoint"),
              "Unexpected service job name")
    end=time.monotonic()+(218*60 if kind=="cipher" else 20*60)
    while time.monotonic()<end:
        row=peer(run,name)
        if row and (kind=="key" or row["status"]=="completed"):
            found=relay(kind)
            if found:
                # Only return a cipher after the producing job closed successfully.
                mode=next(iter(found));primary=found[mode]
                other=found.get("delta") if mode=="full" else None
                for typ,item in found.items():
                    print(f"observed_artifact={item['id']} mode={typ} outer_bytes={item['size_in_bytes']} expires_at={item['expires_at']}")
                b.output(id=primary["id"],mode=mode,other_id=other["id"] if other else "")
                return
        time.sleep(20 if kind=="cipher" else 8)
    raise ValueError("Artifact was not visible before the bounded peer wait expired")


def acceptance(mode):
    run=fixed()["run"]
    job=peer(run,PRODUCER_NAME)
    b.require(job and job["status"]=="completed","Ordinary producer is not verified at private publication")
    # Include expired-but-still-visible occupancy before writing a private payload.
    rows=b.inventory()
    names={artifact_name("cipher"),artifact_name("delta")}
    seen=[(r["id"],r["name"],r["size_in_bytes"],r["expired"],r["expires_at"]) for r in rows if r["name"] in names]
    print("retained_candidate_artifacts="+json.dumps(seen),flush=True)
    found=relay("cipher")
    b.require(found and mode==next(iter(found)) and str(found[mode]["id"])==os.environ["FRESH_ARTIFACT_ID"],
              "Primary immutable transfer receipt changed before publication")
    other=found.get("delta") if mode=="full" else None
    b.require((str(other["id"]) if other else "")==os.environ.get("FRESH_OTHER_ID",""),
              "Late alternative needs independent receipt reconciliation")
    b.require({x[0] for x in seen}=={v["id"] for v in found.values()},
              "Expired or contradictory retained artifact inventory")
    if other:
        b.require(small(b.ROOT/"incoming"/RECEIPT,16384)==small(b.ROOT/"alternate"/RECEIPT,16384),
                  "Full and alternate transfer receipts differ")
    print(f"accepted_ordinary_job={job['id']} selected_artifact={found[mode]['id']} mode={mode} alternate={other['id'] if other else 0}",
          flush=True)


def capacity():
    b.require(os.environ["GITHUB_JOB"]=="produce","Only ordinary producer may reserve an outcome")
    rows=b.inventory()
    b.require(not any(a["name"]==artifact_name("cipher") for a in rows),"Existing ciphertext needs reconciliation")
    rec=json.loads(small(b.ROOT/RECEIPT,16384))
    size=(b.ROOT/CIPHER).stat().st_size
    b.require(size==rec["sealed_bytes"],"Sealed candidate changed")
    upper=size+(b.ROOT/RECEIPT).stat().st_size+2*MIB
    visible=sum(x["size_in_bytes"] for x in rows)
    active=sum(x["size_in_bytes"] for x in rows if not x["expired"])
    print("fresh_relay_peak="+json.dumps({"visible_before":visible,"active_bytes":active,
        "expired_still_visible":visible-active,"new_outer_zip_ceiling":upper,"projected_simultaneous":visible+upper,
        "twelve_equal_retained":visible+12*upper,"retention_days":1,"native_cache_added":0},sort_keys=True))
    ceiling=os.getenv("R28_RELAY_BYTE_CEILING","")
    if ceiling:
        b.require(ceiling.isdecimal() and visible+upper<=int(ceiling),"Configured relay capacity would be exceeded")


def seal():
    b.require(os.environ["GITHUB_JOB"]=="produce","Only ordinary producer may seal")
    file=TEMP/"r28-child.tar.zst"
    base=TEMP/"bare-official/exchange/checkpoint"
    rec=fixed()
    st=file.lstat()
    b.require(stat.S_ISREG(st.st_mode) and 0<st.st_size<=b.CAP,"Unbounded new archive")
    published=json.loads(small(base/"child-provenance.json",MIB))
    ident=published["identity_sha256"]
    b.require(set(published)=={"identity_sha256","identity"} and b.sha(ident)
              and published["identity"]=={"ci_revision":rec["head"]},"Unexpected host-side provenance projection")
    graph_sha=small(base/"graph-sha.txt",128).decode("ascii").strip()
    trial_sha=small(base/"trial-provenance-sha.txt",128).decode("ascii").strip()
    b.require(ident!=b.PARENT_IDENTITY and b.sha(graph_sha) and b.sha(trial_sha),"Missing new graph or producer evidence")
    digest=b.digest(file)
    b.require(digest!=b.PARENT_SHA,"Refused original source as child")
    recipient=b.ROOT/"incoming/public.pem"
    b.require(not recipient.is_symlink(),"Expected scoped certificate")
    fpr=b.fingerprint(recipient)
    b.disk("before-fresh-seal",st.st_size+160*MIB)
    dest=b.ROOT/CIPHER
    begin=time.monotonic()
    frames.seal(recipient,file,dest,digest)
    enc=dest.stat().st_size
    b.require(st.st_size<enc<=st.st_size+16*MIB,"Sealed candidate outside bounds")
    rec.update(bytes=st.st_size,sha256=digest,identity=ident,graph_sha=graph_sha,trial_provenance_sha=trial_sha,
               recipient_fpr=fpr,sealed_bytes=enc,sealed_sha=b.digest(dest))
    with (b.ROOT/RECEIPT).open("x") as out:
        json.dump(rec,out,sort_keys=True,separators=(",",":"))
    print("ordinary_fresh_child="+json.dumps(rec,sort_keys=True),flush=True)
    print(f"fresh_seal_seconds={time.monotonic()-begin:.3f}")


def read_proofs(file,rec):
    # The authenticated full state is never extracted in the credentialed job.
    from check_archive import StreamingTar
    meta={}
    files={}
    hardlinks={}
    names=set()
    payload=0
    with StreamingTar.open(file,"r|gz") as tar:
        for entry in tar:
            path=PurePosixPath(entry.name)
            b.require(path.parts[:2]==("out","Bare") and ".." not in path.parts and "\\" not in entry.name
                      and not path.is_absolute(),"Escaping tar path")
            b.require(path.name.casefold()!="chromepublic.apk","Terminal APK cannot enter a checkpoint")
            name="/".join(path.parts[2:])
            b.require(name not in names and len(names)<550000,"Duplicate or excessive tar members")
            names.add(name)
            b.require(0<=entry.size<=19*1024**3,"Unbounded archive member")
            payload+=entry.size
            b.require(payload<=19*1024**3,"Unbounded archive payload")
            if name in MAX_META:
                b.require(entry.isfile() and not entry.issparse() and 0<entry.size<=MAX_META[name],"Invalid provenance member")
                meta[name]=tar.extractfile(entry).read(entry.size)
                b.require(len(meta[name])==entry.size,"Truncated provenance member")
            elif entry.isfile():
                # Verify the actual object bytes even when a proof occurs later in the tar.
                h=hashlib.sha256()
                with tar.extractfile(entry) as stream:
                    while block:=stream.read(MIB):
                        h.update(block)
                files[name]=[entry.size,h.hexdigest()]
            elif entry.islnk():
                target=PurePosixPath(entry.linkname)
                b.require(target.parts[:2]==("out","Bare") and ".." not in target.parts,"Invalid hardlink")
                hardlinks[name]="/".join(target.parts[2:])
            else:
                b.require(entry.isdir() or entry.issym(),"Unexpected tar member type")
    b.require(set(meta)==set(MAX_META),"Missing private proof or provenance")
    child=json.loads(meta[CHILD])
    parent=json.loads(meta[PARENT])
    b.require(identity(child,rec["head"])==rec["identity"]
              and identity(parent,PARENT_REV)==rec["parent_identity"]
              and child["identity"]==dict(parent["identity"],ci_revision=rec["head"]),"S2 input or producer mismatch")
    b.require(hashlib.sha256(meta[GRAPH]).hexdigest()==rec["graph_sha"]
              and hashlib.sha256(meta[TRIAL]).hexdigest()==rec["trial_provenance_sha"],"Changed proof bytes")
    graph=json.loads(meta[GRAPH])
    target=graph["target_path"]
    outputs=graph["outputs"]
    before=set(graph["parent_pending"])
    after=set(graph["successor_pending"])
    b.require(graph["format"]=="bare-28-apk-frontier-2" and graph["target"]=="chrome_public_apk"
              and b.sha(graph["graph_sha256"]) and all(b.sha(h) for h in before|after)
              and after<before and isinstance(outputs,dict) and target in outputs and target.endswith(".o")
              and canonical(sorted(outputs)) in before-after,"Invalid advancing APK object group")
    for name,record in outputs.items():
        path=name
        visited=set()
        while path in hardlinks:
            b.require(path not in visited,"Cyclic object hardlink")
            visited.add(path)
            path=hardlinks[path]
        b.require(path in files and files[path]==record,"Archived new object differs")
    for key in ("parent_content","child_content"):
        value=graph.get(key,{})
        b.require(type(value.get("files")) is int and value["files"]>0 and b.sha(value.get("sha256")),
                  "Missing retained payload commitment")
    node=json.loads(meta[TRIAL])
    b.require(node.get("format")=="bare-r28-trial-provenance-v1" and node["source_revision"]==rec["head"]
              and node["s2_producer_revision"]==PARENT_REV and node["s2_archive_sha256"]==rec["parent_sha"]
              and node["graph_format"]==graph["format"] and node["graph_sha256"]==rec["graph_sha"]
              and node["child_identity"]==rec["identity"] and b.sha(node["effective_script_sha256"])
              and node["trial_workflow"]=={"path":WORKFLOW,"sha256":b.digest(PROJECT/WORKFLOW)},
              "Archive did not originate from the bound effective trial workflow")
    print("restricted_actual_compiler_evidence="+json.dumps({"target":target,"outputs":outputs,"before":len(before),
        "after":len(after),"input_sha256":rec["parent_sha"],"checkpoint_bytes":rec["bytes"],
        "checkpoint_sha256":rec["sha256"],"graph_sha":rec["graph_sha"],"trial_provenance_sha":rec["trial_provenance_sha"]},
        sort_keys=True),flush=True)
    return meta[CHILD]


def send():
    b.require(os.environ["GITHUB_JOB"]=="send","Only restricted sender may publish")
    import exchange
    b.require(exchange.CAMPAIGN==CAMPAIGN,"Incorrect private sender campaign")
    base=b.ROOT/"incoming"
    rec=json.loads(small(base/RECEIPT,16384))
    b.require(all(rec.get(k)==v for k,v in fixed().items()),"Stale initial-attempt ciphertext")
    for key in ("sha256","identity","graph_sha","trial_provenance_sha","sealed_sha"):
        b.require(b.sha(rec[key]),"Invalid digest in restricted receipt")
    size=rec["bytes"]
    b.require(type(size) is int and 0<size<=b.CAP and type(rec["sealed_bytes"]) is int
              and size<rec["sealed_bytes"]<=size+16*MIB and rec["sha256"]!=b.PARENT_SHA
              and rec["identity"]!=b.PARENT_IDENTITY and rec["recipient_fpr"]==b.fingerprint(b.ROOT/"public.pem"),
              "Wrong recipient or candidate")
    mode=os.environ.get("FRESH_MODE","full")
    file=TEMP/"r28-child.tar.zst"
    start=time.monotonic()
    if mode=="full":
        enc=base/CIPHER
        info=enc.lstat()
        b.require(stat.S_ISREG(info.st_mode) and info.st_size==rec["sealed_bytes"]
                  and b.digest(enc)==rec["sealed_sha"],"Wrong ciphertext")
        b.disk("before-fresh-private-read",size+144*MIB)
        frames.receive(enc,file,size,rec["sha256"])
    else:
        b.require(mode=="delta","Unknown transfer mode")
        # The preceding delta reader already authenticated the scoped compressed
        # delta and reconstructed the byte-exact full zstd from the verified basis.
        b.require((base/"delta.json").is_file() and (base/"delta.cms").is_file(),
                  "Missing encrypted-delta input and its receipt")
    restored=file.lstat()
    b.require(stat.S_ISREG(restored.st_mode) and restored.st_size==size and b.digest(file)==rec["sha256"],
              "Incomplete private reconstruction")
    print(f"verified_reconstructed_transport_mode={mode} bytes={size} sha256={rec['sha256']}",flush=True)
    child=read_proofs(file,rec)
    exchange_dir=TEMP/"bare-official/exchange/checkpoint"
    exchange_dir.mkdir(parents=True,exist_ok=True)
    for name,raw in (("child-provenance.json",child),("graph-sha.txt",rec["graph_sha"].encode()+b"\n"),
                     ("trial-provenance-sha.txt",rec["trial_provenance_sha"].encode()+b"\n")):
        with (exchange_dir/name).open("xb") as output:
            output.write(raw)
    print(f"fresh_reconstruct_and_validate_seconds={time.monotonic()-start:.3f}",flush=True)
    acceptance(mode)
    exchange.send()
    b.disk("after-authenticated-private-upload")


if __name__=="__main__":
    os.umask(0o077)
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("operation",choices=["wait","seal","capacity","send"])
    ap.add_argument("kind",nargs="?",choices=["key","cipher"])
    args=ap.parse_args()
    if args.operation=="wait":
        b.require(args.kind is not None,"Expected peer class")
        wait(args.kind)
    else:
        b.require(args.kind is None,"Unexpected extra argument")
        {"seal":seal,"capacity":capacity,"send":send}[args.operation]()
