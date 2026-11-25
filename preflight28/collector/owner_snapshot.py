"""GET-only transport for original bytes captured by the independent, signed-in personal collector."""
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
from urllib.parse import quote, urlencode
from zipfile import BadZipFile

import production as p

BASE = "https://api.github.com/repos/"+p.REPO+"/"
WEB = "https://github.com/"+p.REPO+"/releases/"
CLAIM_JOB = "Bind the prior private collection registration to this originating run"
REPLACEMENT_JOB = "Reserve one confirmed lost physical interval"
RESCUE_JOB = "Transfer the original cached ciphertext to its registered owner"
CLAIM_STEP = "Persist verified owner claim identities"
TERMINAL_STEP = "Persist verified owner terminal identities"
HEX = re.compile(r"[a-f0-9]{64}")
SAFE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,190}")
require = p.require


class OtherTerminalWitness(ValueError):
    """A different transfer-only run may address another source in the same campaign."""


def unique(items):
    result = {}
    for key, value in items:
        require(key not in result,"Duplicate capture field")
        result[key] = value
    return result


def checked_file(path, maximum):
    require(not path.is_symlink() and path.is_file() and 0 < path.stat().st_size <= maximum,
            "Missing, linked or oversized owner capture: "+path.name)
    return path


def document(path, maximum):
    return json.loads(checked_file(path,maximum).read_bytes(),object_pairs_hook=unique)


class OwnerSnapshot:
    def __init__(self, directory, helper):
        self.root=Path(directory)
        require(self.root.is_dir() and not self.root.is_symlink() and
                not any((self.root/name).is_symlink() for name in ("private","artifacts")), "Unsafe capture directory")
        self.helper=helper
        self.by_id={}
        self.actions=self.stable("actions",64*1024**2)
        require(isinstance(self.actions,dict) and all(k.startswith(BASE+"actions/") for k in self.actions),
                "Unexpected GitHub origin in owner capture")
        self.gui=self.stable("draft",2*1024**2)

    def stable(self,name,limit):
        first=document(self.root/(name+"-before.json"),limit)
        second=document(self.root/(name+"-after.json"),limit)
        require(first==second,"Provider changed during personal capture: "+name)
        return first

    def metadata(self,path):
        key=BASE+path
        require(key in self.actions,"Missing original GitHub GET "+key)
        return self.actions[key]

    def inventory(self,path,key):
        result=[]
        total=None
        sep="&" if "?" in path else "?"
        for n in range(1,101):
            response=self.metadata(f"{path}{sep}per_page=100&page={n}")
            batch=response[key]
            count=response["total_count"]
            require(type(count) is int and count>=0 and (total is None or total==count) and
                    isinstance(batch,list) and len(batch)<=100,"Incomplete or shifting Actions inventory")
            total=count
            result.extend(batch)
            if len(result)==total:
                require(len({r["id"] for r in result})==total,"Duplicate Actions ID")
                return result
            require(len(batch)==100 and len(result)<total,"Missing Actions page")
        raise ValueError("Actions inventory exceeds the bounded query")

    def artifact_file(self,aid,cap):
        require(type(aid) is int and aid>0,"Invalid immutable Artifact ID")
        return checked_file(self.root/"artifacts"/(str(aid)+".zip"),cap)

    def note(self,aid):
        return self.artifact_file(aid,p.journal.MAX_ZIP).read_bytes()

    def copy_artifact(self,row,target):
        path=self.artifact_file(row["id"],p.apk_seal.CIPHER_CAP+2*1024**2)
        require(path.stat().st_size==row["size_in_bytes"],"Original terminal archive size changed")
        with path.open("rb") as stream:
            while block:=stream.read(1024**2):
                target.write(block)

    def visible(self):
        h=self.helper
        gui=self.gui
        tag=gui["tag"]
        alias=hashlib.sha256(tag.encode()).hexdigest()
        import r28_verified_draft as anchor
        require(gui["form_id"]==f"edit_release_{p.RELEASE_ID}" and
                gui["release_url"]==WEB+"tag/"+tag and gui["label"]=="Draft" and
                gui["title"]==h.DRAFT_TITLE and gui["viewer"]==h.OWNER and gui["author"]==h.OWNER and gui["target"] in h.DRAFT_TARGETS and
                alias in (h.DRAFT_TAG_SHA256,anchor.TAG_SHA), "Different owner, release, alias, target or visibility")
        rows=gui["assets"]
        require(type(gui["asset_count"]) is int and len(rows)==gui["asset_count"]<=1000 and
                len({r["name"] for r in rows})==len(rows),"Incomplete or ambiguous owner Draft list")
        self.listed={}
        for row in rows:
            name=row["name"]
            require(SAFE.fullmatch(name) and row["href"]==WEB+"download/"+tag+"/"+quote(name,safe="") and
                    row["state"] in ("uploaded","starter") and row["created_at"].endswith("Z") and
                    (row["state"]!="uploaded" or HEX.fullmatch(row["sha256"])),
                    "Unbound or incomplete owner Draft asset row")
            p.journal.timestamp(row["created_at"])
            self.listed[name]=row
        probes=[(h.SAMPLE,h.PROBE_BYTES,h.PROBE_SHA)]
        if alias==anchor.TAG_SHA:
            probes.extend((name,size,sha) for name,_,size,sha in anchor.CLAIMS)
        for name,length,sha in probes:
            require(self.listed[name]["sha256"]==sha and self.listed[name]["state"]=="uploaded" and
                    self.private_file(name,length,sha).stat().st_size==length,"Different historical owner Draft anchor")
        old=self.listed["checkpoint-25-s2.tar.gz"]
        require(old["state"]=="uploaded" and old["sha256"]=="dd2177a80c72db7d0d6b558bec1fbd2c0acf448b28144d02dd26796104315413",
                "Historical owner archive anchor changed")

    def private_file(self,name,maximum,sha):
        require(SAFE.fullmatch(name),"Unsafe private asset name")
        row=self.listed[name]
        require(row["state"]=="uploaded" and row["sha256"]==sha,"Private browser row differs from immutable receipt")
        file=checked_file(self.root/"private"/name,maximum)
        require(p.digest(file)==sha,"Downloaded private bytes differ from authenticated browser row")
        return file

    def private_hint(self,name):
        row=self.listed[name]
        return document(self.private_file(name,16384,row["sha256"]),16384)

    def witness(self,run,head,kind,job_name,n=None,*,optional=False,names,owners):
        require(type(run) is int and run>0 and re.fullmatch("[0-9a-f]{40}",head),"Unbound source hint")
        base=f"actions/runs/{run}/attempts/1"
        p.physical_run(self.metadata(base),run,head)
        jobs=self.inventory(base+"/jobs","jobs")
        name=f"r28-{run}-a1-"+("owner-claim" if kind=="claim" else f"s{n:02}-owner-terminal")
        row=p.journal.one_artifact(self.inventory(f"actions/runs/{run}/artifacts","artifacts"),name)
        live=row and row["expired"] is False and p.journal.timestamp(row["expires_at"])>datetime.now(timezone.utc).timestamp()
        saved=self.listed.get(name+".json")
        if saved and saved["state"]!="uploaded":
            saved=None  # An unfinished Draft attachment supplies no evidence.
        if job_name==p.DRAFT_JOB:
            job=p.journal.original_job(jobs,run,head,n,job_name)
        else:
            matches=[j for j in jobs if j["name"]==job_name and j.get("conclusion")!="skipped"]
            require(len(matches)<=1,"No unique physical witness job")
            job=matches[0] if matches else None
        if not job and optional and not live and saved is None:
            return None
        require(job and job["run_id"]==run and job["run_attempt"]==1 and job["head_sha"]==head and
                job["status"]=="completed","Foreign or unsettled witness job")
        notes=[]
        errors=[]
        if live:
            try:
                p.journal.checked_artifact(row,run,head,job,CLAIM_STEP if kind=="claim" else TERMINAL_STEP,
                                           lambda aid:self.metadata(f"actions/artifacts/{aid}"))
                public=p.journal.decode(self.note(row["id"]),row,"witness.json")
                notes.append(self.witness_body(public,run,head,kind))
            except (ValueError, KeyError, OSError, EOFError, BadZipFile) as error:
                errors.append(str(error))
        if saved is not None:
            try:
                durable=self.private_witness(name,saved,job,kind)
                notes.append(self.witness_body(durable,run,head,kind))
            except (ValueError, KeyError, OSError) as error:
                errors.append(str(error))
        reconstructed=self.metadata_witness(run,head,kind,job,names,owners,notes[0] if notes else None)
        if reconstructed is not None:
            notes.append(reconstructed)
        if not notes:
            require(optional,"No authenticated owner witness: "+"; ".join(errors))
            return None
        require(all(note==notes[0] for note in notes),"Authenticated public and private witnesses disagree")
        return notes[0]["rows"]

    def metadata_witness(self,run,head,kind,job,names,owners,other):
        """Rebuild the attested canonical bytes from the owner's actual private objects."""
        prefix=f"Attest registered owner {kind} IDs "
        marks=[step for step in job["steps"] if step["name"].startswith(prefix) and step.get("conclusion")=="success"]
        if not marks:
            return None
        require(len(marks)==1, "Ambiguous original fixed-order ID attestation")
        mark,=marks
        values=mark["name"][len(prefix):].split(",")
        require(len(values)==len(names) and len(set(values))==len(values) and
                all(re.fullmatch("[1-9][0-9]{0,18}",i) for i in values), "Invalid original fixed-order IDs")
        digests=[step for step in job["steps"] if step["name"].startswith(f"Attest registered owner {kind} SHA256 ")
                 and step.get("conclusion")=="success"]
        require(len(digests)==1, "Missing unique original digest attestation")
        ack,=digests
        verified=p.journal.upload_step(job,f"Bind the allowlisted private {kind} identities for the registered owner")
        recorded=ack["name"].rsplit(" ",1)[-1]
        require(verified and verified["conclusion"]=="success" and HEX.fullmatch(recorded) and
                p.journal.timestamp(verified["completed_at"])<=p.journal.timestamp(ack["started_at"])<=
                p.journal.timestamp(ack["completed_at"])<=p.journal.timestamp(mark["started_at"])<=
                p.journal.timestamp(mark["completed_at"])<=p.journal.timestamp(job["completed_at"]),
                "Fixed-order IDs lack their successful original digest and producer")
        if other is None:
            rows=[]
            for name,number in zip(sorted(names),values,strict=True):
                row=self.listed[name]
                sha=row["sha256"]
                # Only an already verified claim or its exact terminal cipher and
                # receipt can be reconstructed. Sizes come from downloaded bytes.
                path=self.private_file(name,p.apk_seal.CIPHER_CAP if name.endswith((".age",".age-retry1")) else 16384,sha)
                rows.append(dict(name=name,id=int(number),bytes=path.stat().st_size,sha256=sha,owner_issued=name in owners))
            note=dict(schema="bare-r28-owner-witness-v1",run=run,attempt=1,head=head,release_id=p.RELEASE_ID,kind=kind,rows=rows)
        else:
            note=other
            require([str(r["id"]) for r in note["rows"]]==values, "Original fixed-order IDs conflict with retrieved witness")
        data=(json.dumps(note,sort_keys=True,separators=(",",":"))+"\n").encode("ascii")
        if hashlib.sha256(data).hexdigest()!=recorded:
            if kind=="terminal" and other is None:
                raise OtherTerminalWitness("Reconstructed terminal witness conflicts with original digest")
            raise ValueError("Reconstructed witness conflicts with original digest")
        return note

    @staticmethod
    def witness_body(note,run,head,kind):
        require(isinstance(note,dict) and note.keys()=={"schema","run","attempt","head","release_id","kind","rows"} and
                note["schema"]=="bare-r28-owner-witness-v1" and type(note["run"]) is int and note["run"]==run and
                type(note["attempt"]) is int and note["attempt"]==1 and note["release_id"]==p.RELEASE_ID and
                note["head"]==head and note["kind"]==kind and isinstance(note["rows"],list),
                "Invalid physical issuer or owner witness schema")
        return note

    def private_witness(self,name,saved,job,kind):
        sha=saved["sha256"]
        write=f"Preserve the registered owner {kind} witness in the original Draft"
        check=f"Attest registered owner {kind} SHA256 {sha}"
        put=p.journal.upload_step(job,write)
        ack=p.journal.upload_step(job,check)
        require(put and put["conclusion"]=="success" and ack and ack["conclusion"]=="success" and
                p.journal.timestamp(ack["started_at"])>=int(p.journal.timestamp(put["completed_at"])),
                "Private witness lacks original successful write and immutable SHA attestation")
        p.recover.same_time_as_upload(saved,job,write)
        data=self.private_file(name+".json",p.journal.MAX_NOTE,sha).read_bytes()
        durable=json.loads(data,object_pairs_hook=unique)
        require((json.dumps(durable,sort_keys=True,separators=(",",":"))+"\n").encode()==data,
                "Unexpected private witness encoding")
        return durable

    def terminal_witness(self,source,depositor,head,n,names):
        job=p.DRAFT_JOB if depositor==source else RESCUE_JOB
        direct=self.witness(depositor,head,"terminal",job,n,optional=True,names=names,owners=set())
        if direct is not None:
            return direct
        # A later transfer reader can attest the same pre-existing private ID
        # after a lost response. Discover it from the provider, without a new locator.
        start=self.metadata(f"actions/runs/{depositor}/attempts/1")["created_at"]
        query=urlencode(dict(branch=p.BASE_REF,event="workflow_dispatch",head_sha=head,status="completed",created=">="+start))
        path="actions/workflows/bare-checkpoint-transfer.yml/runs?"+query
        matches=[]
        for row in self.inventory(path,"workflow_runs"):
            rid=row["id"]
            if rid in (source,depositor):
                continue
            require(type(rid) is int and rid>0 and row["head_sha"]==head and row["head_branch"]==p.BASE_REF and
                    row["event"]=="workflow_dispatch" and row["status"]=="completed" and
                    p.journal.timestamp(row["created_at"])>=p.journal.timestamp(start),"Unbound rescue search result")
            jobs=self.inventory(f"actions/runs/{rid}/attempts/1/jobs","jobs")
            if not any(j["name"]==RESCUE_JOB and j.get("conclusion")!="skipped" for j in jobs):
                continue
            try:
                data=self.witness(rid,head,"terminal",RESCUE_JOB,n,optional=True,names=names,owners=set())
            except OtherTerminalWitness:
                continue
            if data is not None and any(r["name"] in names for r in data):
                matches.append(sorted(data,key=lambda r:r["name"]))
        require(matches and all(r==matches[0] for r in matches),"Missing or conflicting transfer-only witness")
        return matches[0]

    def merge(self,records,names,owners):
        require(len(records)==len(names) and {r["name"] for r in records}==set(names),
                "Owner witness did not certify the exact required private items")
        for r in records:
            name=r["name"]
            require(r.keys()=={"name","id","sha256","bytes","owner_issued"} and type(r["id"]) is int and r["id"]>0 and
                    type(r["bytes"]) is int and 0<r["bytes"]<=p.apk_seal.CIPHER_CAP and HEX.fullmatch(r["sha256"]) and
                    r["owner_issued"] is (name in owners),"Invalid immutable witness row")
            gui=self.listed[name]
            require(gui["state"]=="uploaded" and gui["sha256"]==r["sha256"], "Actions and the authenticated Draft disagree")
            normalized=dict(name=name,id=r["id"],size=r["bytes"],digest="sha256:"+r["sha256"],state="uploaded",
                            created_at=gui["created_at"],uploader=p.OWNER if name in owners else {})
            require(r["id"] not in self.by_id or self.by_id[r["id"]]==normalized,"Conflicting private immutable ID")
            self.by_id[r["id"]]=normalized

    def resolve_original_ticket(self, intent):
        """Complete an owner-pinned locator only from the original binder's evidence."""
        self.visible()
        ticket = p.CAMPAIGN + "-collection-registration.json"
        self.private_file(ticket, 4096, intent["ticket_sha"])
        origin = self.private_hint(p.CLAIM)["run_id"]
        names, owners = [ticket,p.CLAIM], [ticket]
        records = self.witness(origin,intent["head"],"claim",CLAIM_JOB,names=names,owners=owners)
        self.merge(records,names,owners)
        rows = [self.by_id[r["id"]] for r in records]
        aid = p.private_row(rows,ticket)["id"]
        if "ticket_asset_id" in intent:
            require(type(intent["ticket_asset_id"]) is int and intent["ticket_asset_id"] == aid,
                    "Different pre-registered ticket ID")
        locator = dict(intent,ticket_asset_id=aid)
        first, physical, _, scope = p.bind(self,rows,locator)
        require(first == physical == origin and not scope.replacement, "Foreign original binder")
        return locator

    def draft_rows(self,locator):
        self.visible()
        ticket=p.CAMPAIGN+"-collection-registration.json"
        require(self.listed[ticket]["sha256"]==locator["ticket_sha"],"Reservation differs from personal locator")
        origin=self.private_hint(p.CLAIM)["run_id"]
        head=locator["head"]
        run=origin
        names=[ticket,p.CLAIM]
        owners=[ticket]
        if p.REPLACEMENT in self.listed:
            claim=self.private_hint(p.REPLACEMENT)
            require(claim["origin_run"]==origin and type(claim["run_id"]) is int and claim["run_id"]!=origin,
                    "Replacement browser discovery conflicts with original operation")
            run=claim["run_id"]
            extra=[p.CAMPAIGN+f"-loss-{origin}.json",p.CAMPAIGN+f"-loss-evidence-{origin}.json"]
            names.extend([*extra,p.REPLACEMENT]);owners.extend(extra)
        records=self.witness(run,head,"claim",CLAIM_JOB if run==origin else REPLACEMENT_JOB,names=names,owners=owners)
        self.merge(records,names,owners)
        require(self.by_id[locator["ticket_asset_id"]]["name"]==ticket,"Different actual private registration ID")
        prefix=f"r28-{run}-a1-s"
        matches=[name for name in self.listed if name.startswith(prefix) and
                 re.fullmatch(re.escape(prefix)+r"(0[1-9]|1[0-2])-apk-owner-receipt\.json(?:-retry1)?",name)
                 and self.listed[name]["state"]=="uploaded"]
        require(len(matches)<=1,"Ambiguous final private receipt")
        if matches:
            name,=matches
            receipt=self.private_hint(name)
            n=int(name[len(prefix):len(prefix)+2])
            depositor=receipt["depositor_run"]
            cipher=receipt["cipher"]["name"]
            require(cipher in (prefix+f"{n:02}"+p.CIPHER_SUFFIX,prefix+f"{n:02}"+p.CIPHER_SUFFIX+"-retry1"),
                    "Unexpected private ciphertext discovery")
            records=self.terminal_witness(run,depositor,head,n,{name,cipher})
            self.merge(records,[name,cipher],[])
        return list(self.by_id.values())

    def download(self,aid,size,sha,target):
        row=self.by_id[aid]
        require(row["size"]==size and row["digest"]=="sha256:"+sha,"Unbound private byte request")
        file=self.private_file(row["name"],size,sha)
        require(file.stat().st_size==size,"Private browser transfer differs in length")
        with file.open("rb") as src:
            while block:=src.read(1024**2):
                target.write(block)
