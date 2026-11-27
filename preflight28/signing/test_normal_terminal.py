#!/usr/bin/env python3
"""Audit the normal terminal with public inputs only. Does not create a production APK."""
import argparse
import ast
from datetime import datetime, timezone, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from unittest.mock import patch
from zipfile import ZipFile
import zipfile

import yaml


U = "assets/bare/ublock_origin.crx"
NATIVE = "lib/arm64-v8a/libchrome.so"
CRX_SHA = "d688ed3f0262ec4f8bdcd4c8f65987c5444c560aeb387a9e02aca1facdfa7046"
CI_CERT = "32a2fc74d731105859e5a85df16d95f102d85b22099b8064c5d8915c61dad1e0"
CI_PACKAGE = "org.barebrowser.personal"
REV = "a"*40


def expect_reject(function, message):
    try:
        function()
    except (SystemExit,ValueError) as error:
        if message not in str(error):
            raise AssertionError(f"expected {message}: {error}") from error
    else:
        raise AssertionError(f"unsafe acceptance: {message}")


def normal_checks(workflows, reference, aapt2, signer):
    steps = yaml.safe_load((workflows/"bare-arm64-probe.yml").read_text())["jobs"]["compile-probe"]["steps"]
    shell = next(s["run"] for s in steps if s.get("id") == "apk_seal")
    marker = 'python3 - "$apk" "$temp" <<\'PYTHON\'\n'
    body = ast.parse(shell.split(marker)[1].split("\nPYTHON")[0])
    start = next(i for i,n in enumerate(body.body) if isinstance(n,ast.Assign)
                 and isinstance(n.targets[0],ast.Name) and n.targets[0].id == "expected_package")
    # Only the extraction point changes: these are the exact normal policy statements.
    body.body = body.body[start:]
    code = compile(body,"normal-embedded-apk-identity","exec")
    original_badging = subprocess.check_output([str(aapt2),"dump","badging",str(reference)],text=True)
    original_signing = subprocess.check_output(["java","-jar",str(signer),"verify","--verbose","--print-certs",str(reference)],text=True)
    assert "org.barebrowser'" in original_badging and "2.0.0-beta.6" in original_badging
    assert CI_CERT in original_signing
    with ZipFile(reference) as source:
        public_crx = source.read(U)
        assert hashlib.sha256(public_crx).hexdigest() == CRX_SHA
        with source.open(NATIVE) as f:
            public_elf_header = f.read(20)

    example = "\n".join(["package: name='org.barebrowser.personal' versionName='2.0.4' versionCode='802000415'",
                       "application-label:'Bare Personal'", "native-code: 'arm64-v8a'"])
    with TemporaryDirectory() as td:
        temp = Path(td)
        apk = temp/"policy-input.zip"  # local policy control; no Android manifest or signature
        def check(badging=example, signing=original_signing, crx=public_crx, core=public_elf_header):
            with ZipFile(apk,"w") as out:
                out.writestr(U,crx)
                out.writestr(NATIVE,core)
            (temp/"badging.txt").write_text(badging)
            (temp/"signing.txt").write_text(signing)
            values = dict(apk=apk,temp=temp,os=os,zipfile=zipfile,re=re,json=json,hashlib=hashlib,
                          info=apk.stat(),digest=hashlib.sha256(apk.read_bytes()).hexdigest())
            with patch.dict(os.environ,dict(BARE_REV=REV,CHROMIUM_REV=REV,CI_REVISION=REV)):
                exec(code,values)
            result=json.loads((temp/"apk-metadata.json").read_text())
            assert (result["package"],result["version_name"],result["version_code"],result["abi"],
                    result["embedded_ublock_origin_sha256"],result["signer_sha256"]) == (
                CI_PACKAGE,"2.0.4","802000415","arm64-v8a",CRX_SHA,CI_CERT)
        check()
        for positive,negative,why in [(CI_PACKAGE,"org.barebrowser","package name or version"),
                                      ("2.0.4","2.0.3","package name or version"),("802000415","802000414","package name or version"),
                                      ("Bare Personal","Bare","launcher label"),("arm64-v8a","x86_64","ARM64 ABI")]:
            expect_reject(lambda: check(example.replace(positive,negative)), why)
        expect_reject(lambda:check(badging=original_badging),"package name or version")
        expect_reject(lambda:check(signing=original_signing.replace(CI_CERT,"b"*64)),"signing certificate")
        expect_reject(lambda:check(signing=original_signing.replace("Number of signers: 1","Number of signers: 2")),"signing certificate")
        expect_reject(lambda:check(crx=public_crx+b"!"),"uBlock")
        expect_reject(lambda:check(core=public_elf_header[:18]+b"\x3e\0"),"AArch64 ELF")
    print("NORMAL_APK_POLICY 1 positive and 10 negatives, real old APK SDK signing/ABI/CRX, synthetic personal badging only")


def normal_binding(registration_dir, workflows):
    sys.path.insert(0,str(registration_dir))
    import registration as gate
    jobs=yaml.safe_load((workflows/"bare-checkpoint-transfer.yml").read_text())["jobs"]
    assert "validate-build" in jobs["bind-private-receiver"]["needs"]
    resumes_s1 = jobs["bind-private-receiver"].get("env", {}).get("R30_RESUME_S1") == "1"
    for n in ("production", "slot02" if resumes_s1 else "slot01"):
        assert "bind-private-receiver" in jobs[n]["needs"] and "claim_asset_id != ''" in jobs[n]["if"]
    native=yaml.safe_load((workflows/"bare-r28-native-slot.yml").read_text())["jobs"]
    assert "collection-lease" in native["arm"]["needs"]
    assert "needs.collection-lease.outputs.latest_start" in native["arm"]["with"]["collector_latest_start"]
    clock=datetime(2026,11,25,1,0,0,tzinfo=timezone.utc)
    env=dict(RUNNER_ENVIRONMENT="github-hosted",REGISTRATION_ASSET_ID="51",GITHUB_RUN_ID="101",GITHUB_RUN_ATTEMPT="1",GITHUB_SHA=REV,
             GITHUB_JOB="bind-private-receiver",GITHUB_REPOSITORY=gate.REPO,GITHUB_REF="refs/heads/"+gate.BASE_REF,
             GITHUB_EVENT_NAME="workflow_dispatch")
    event=dict(repository=dict(id=gate.REPO_ID),sender=gate.OWNER,
               inputs=dict(mode="build-apk",build_segments="12",apk_recipient=gate.RECIPIENT))
    ticket=dict(schema=1,campaign=gate.CAMPAIGN,repository_id=gate.REPO_ID,workflow=gate.WORKFLOW,
                branch=gate.BASE_REF,head=REV,initial_parent=gate.S2_SHA,release_id=gate.RELEASE_ID,recipient=gate.RECIPIENT,
                collector_registration_id="Automation_"+"1"*32,issued_at="2026-11-25T00:00:00Z",expires_at="2026-11-26T00:00:00Z")
    ticket.update(registration_nonce="c"*40, owner_destination_id="libfile_test_owner_slot", collector_ack_asset_id=53)
    ack={k:ticket[k] for k in ("campaign","branch","head","collector_registration_id",
                               "owner_destination_id","registration_nonce","recipient")}
    ack.update(schema=1, state="collector-read-back-owner-reservation",
               observed_at="2026-11-24T23:45:00Z", valid_until="2026-11-26T00:00:00Z",
               poll_seconds=3600, pickup_retry_seconds=900)
    storage = dict(storage_policy="github-public-standard-r28-v1", artifact_ceiling_bytes=10*1024**3,
                   storage_valid_until="2027-01-01T00:00:00Z")
    ticket.update(storage)
    ack.update(storage)
    class Draft:
        BASE=UPLOAD="example.invalid"
        def __init__(self):
            self.values={}
            self.writes=0
            self.values[54]=json.dumps(dict(ticket,head=gate.FIRST_HEAD,registration_nonce="a"*40,
                                            collector_ack_sha="b"*64)).encode()
            self.values[55]=json.dumps(dict(ticket,campaign=gate.PREVIOUS_CAMPAIGN,head=gate.PREVIOUS_HEAD,
                                           collector_registration_id="Automation_"+"2"*32,
                                           registration_nonce="e"*40)).encode()
            self.ticket_created="2026-11-25T00:00:00Z"
            self.ack_created="2026-11-24T23:50:00Z"
        def metadata(self,path):
            first = f"{self.BASE}/actions/runs/{gate.FIRST_RUN}/attempts/1"
            if path == first:
                return dict(id=gate.FIRST_RUN,run_attempt=1,head_sha=gate.FIRST_HEAD,path=gate.WORKFLOW,
                            event="workflow_dispatch",head_branch=gate.BASE_REF,actor=gate.OWNER,
                            repository=dict(id=gate.REPO_ID),head_repository=dict(id=gate.REPO_ID),
                            status="completed",conclusion="failure")
            if path == first+"/jobs?per_page=100":
                return dict(total_count=len(gate.FIRST_JOBS),jobs=[dict(id=k,run_id=gate.FIRST_RUN,run_attempt=1,
                            head_sha=gate.FIRST_HEAD,status="completed",conclusion=v) for k,v in gate.FIRST_JOBS.items()])
            if path == "/repos/"+gate.REPO:
                return dict(id=gate.REPO_ID,full_name=gate.REPO,private=False,fork=False,visibility="public")
            if "/actions/runs?status=" in path:
                return dict(total_count=0,workflow_runs=[])
            if "/actions/artifacts?" in path:
                return dict(total_count=0,artifacts=[])
            if "/releases/" in path:
                return self.draft(gate.RELEASE_ID)["assets"]
            return dict(id=int(env["GITHUB_RUN_ID"]),run_attempt=1,head_sha=REV,path=gate.WORKFLOW,event="workflow_dispatch",
                        head_branch=gate.BASE_REF,actor=gate.OWNER,repository=dict(id=gate.REPO_ID),
                        head_repository=dict(id=gate.REPO_ID),created_at="2026-11-25T00:10:00Z")
        def draft(self,_):
            self.values[51]=json.dumps(ticket).encode()
            self.values[53]=json.dumps(ack).encode()
            names={54:gate.CAMPAIGN+"-collection-registration.json",55:gate.PREVIOUS_CAMPAIGN+"-collection-registration.json",
                   51:gate.TICKET_NAME,52:gate.CLAIM,
                   53:gate.CAMPAIGN+"-collector-ack-"+ticket["registration_nonce"]+".json"}
            return dict(assets=[dict(id=k,size=len(v),name=names[k],digest="sha256:"+hashlib.sha256(v).hexdigest(),
                                     created_at=self.ack_created if k==53 else self.ticket_created,
                                     state="uploaded",uploader=gate.OWNER) for k,v in self.values.items()])
        def asset_info(self,release,name,length,digest,asset_id=None):
            found=[a for a in release["assets"] if a["name"]==name]
            assert len(found)==1
            a=found[0]
            if not (a["size"]==length and (asset_id is None or asset_id==a["id"])
                    and hashlib.sha256(self.values[a["id"]]).hexdigest()==digest):
                raise ValueError("conflicting canonical claim")
            return a
        def download(self,aid,length,digest,target):
            target.write(self.values[aid])
        def request(self,host,method,path,**kwargs):
            assert method=="POST" and host==self.UPLOAD and path.endswith(gate.CLAIM) and 52 not in self.values
            self.writes+=1
            self.values[52]=kwargs["body"]
            raise ConnectionResetError("simulated reply lost after durable create")
    helper=Draft()
    def bind(*,verify_only=False,now=clock):
        env["GITHUB_JOB"]="collection-lease" if verify_only else "bind-private-receiver"
        ticket["collector_ack_sha"]=hashlib.sha256(json.dumps(ack).encode()).hexdigest()
        env["REGISTRATION_SHA"]=hashlib.sha256(json.dumps(ticket).encode()).hexdigest()
        with patch.object(gate.slot1_handoff,"validate_source",autospec=True), \
             patch.object(gate,"FIRST_TICKET_SHA",hashlib.sha256(helper.values[54]).hexdigest()), \
             patch.object(gate,"PREVIOUS_TICKET_SHA",hashlib.sha256(helper.values[55]).hexdigest()):
            return gate.bind(helper,env,event,now,verify_only=verify_only)

    helper.ticket_created="2026-11-25T00:11:00Z"
    expect_reject(bind,"prepared after run")
    helper.ticket_created="2026-11-25T00:00:00Z"
    helper.ack_created="2026-11-25T00:11:00Z"
    expect_reject(bind,"deposited before the original run")
    helper.ack_created="2026-11-24T23:50:00Z"
    with patch.dict(ack,owner_destination_id="libfile_different_slot"):
        expect_reject(bind,"disagrees with owner ticket: owner_destination_id")
    with patch.dict(ack,valid_until="2026-11-25T04:00:00Z"):
        expect_reject(bind,"lease does not cover")
    with patch.dict(ack,registration_nonce="0"*40):
        expect_reject(bind,"disagrees with owner ticket: registration_nonce")
    with patch.dict(ticket,collector_ack_asset_id=99):
        expect_reject(bind,"Different pinned collector ACK ID")
    expect_reject(lambda:bind(verify_only=True),"No first-attempt receipt to recover")
    assert helper.writes==0
    end=min(gate.instant(ack["valid_until"]),gate.instant(ticket["expires_at"]))
    last=end-timedelta(seconds=(350+25+45+7)*60+2*ack["poll_seconds"]+ack["pickup_retry_seconds"])
    expected=(52,ticket["collector_registration_id"],int(last.timestamp()),storage["artifact_ceiling_bytes"],
              int(gate.instant(storage["storage_valid_until"]).timestamp()))
    assert bind()==expected and bind()==expected and helper.writes==1
    assert bind(verify_only=True,now=last)==expected and helper.writes==1
    expect_reject(lambda:bind(verify_only=True,now=last+timedelta(seconds=1)),"lease does not cover")
    env["GITHUB_RUN_ID"]="102"
    expect_reject(bind,"conflicting canonical claim")
    assert helper.writes==1
    print("NORMAL_REGISTRATION prior matching ACK and destination + lost POST + repeat + latest valid lease passed; "
          "late ticket, late ACK, absent ACK, wrong slot, wrong nonce, short coverage, expired effective lease, "
          "verify-only with no prior claim, competing run rejected; 1 POST")


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    for arg in ["repo","reference-apk","aapt2","apksigner-jar","registration-dir"]:
        parser.add_argument("--"+arg,type=Path,required=True)
    args=parser.parse_args()
    y=args.repo/".github/workflows"
    normal_checks(y,args.reference_apk,args.aapt2,args.apksigner_jar)
    normal_binding(args.registration_dir,y)
