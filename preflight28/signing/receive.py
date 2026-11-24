#!/usr/bin/env python3
"""Receive and sign the single synthetic R28 test APK. No production key inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
from zipfile import ZipFile


ROOT = Path(__file__).resolve().parent
CAMPAIGN = "r28-preflight-s2-20261125-v1"
FINAL_CERT = "ab516232747559dd84d0b80471b5c512124aaa41ce9898d2ceb7e44c580420ee"
PACKAGE = "org.barebrowser.r28preflight.testonly"
LABEL = "R28 preflight TEST ONLY"


def require(test, message):
    if not test:
        raise ValueError(message)


def sha(path):
    return hashlib.file_digest(path.open("rb"), "sha256").hexdigest()


def apksigner(*args):
    return subprocess.check_output(["java","-jar",str(ROOT/"apksigner.jar"),*map(str,args)],text=True)


def verify(apk, cert):
    output = apksigner("verify","--verbose","--print-certs",apk)
    signers = re.findall(r"^(?:Signer #[0-9]+|V[0-9.]+ Signer:) certificate SHA-256 digest: ([a-f0-9]{64})$", output, re.M)
    require(set(signers) == {cert}, "APK signer fingerprint differs")
    badging = subprocess.check_output([str(ROOT/"aapt2"),"dump","badging",str(apk)],text=True)
    require(f"package: name='{PACKAGE}' versionCode='1' versionName='1.0-preflight'" in badging
            and f"application: label='{LABEL}'" in badging, "test manifest identity differs")


def identity(record):
    require(record["operation"] == CAMPAIGN and type(record["run_id"]) is int and record["run_id"] > 0
            and type(record["attempt"]) is int and record["attempt"] == 1, "wrong workflow identity")
    require(re.fullmatch("[a-f0-9]{40}",record["head_sha"]), "wrong SHA shape")
    for key in ["ci_cert_sha256","clear_sha256","cipher_sha256"]:
        require(re.fullmatch("[a-f0-9]{64}",record[key]), f"invalid {key}")
    require(type(record["clear_bytes"]) is int and type(record["cipher_bytes"]) is int and
            0 < record["clear_bytes"] <= 450*1024**2 and 0 < record["cipher_bytes"] <= 451*1024**2,
            "unexpected receipt size")
    require(record["ci_cert_sha256"] != FINAL_CERT, "test signers must differ")


def receive(artifact, trusted, slot):
    identity(trusted)
    if slot.exists():
        raise ValueError("output exists; re-read the existing durable slot using the accepted receipt")
    with TemporaryDirectory(prefix="r28-test-") as tmp:
        d=Path(tmp)
        with ZipFile(artifact) as z:
            require(z.namelist() == ["test-apk.tar.age"], "unexpected artifact layout")
            cipher=d/"test-apk.tar.age"
            require(z.getinfo(cipher.name).file_size == trusted["cipher_bytes"], "cipher ZIP length mismatch")
            with z.open(cipher.name) as source,cipher.open("xb") as target:
                shutil.copyfileobj(source,target)
        subprocess.run([sys.executable,str(ROOT/"guard.py"),"size","cipher",str(cipher)],check=True)
        require(sha(cipher) == trusted["cipher_sha256"], "ciphertext digest mismatch")
        decrypted=d/"bundle.tar"
        subprocess.run([str(ROOT/"age"),"-d","-i",str(ROOT/"test-recipient.agekey"),"-o",str(decrypted),str(cipher)],check=True)
        with tarfile.open(decrypted,"r:") as t:
            members=t.getmembers()
            require([m.name for m in members] == ["ci-test.apk","receipt.json"] and all(m.isfile() for m in members)
                    and members[0].size == trusted["clear_bytes"] and members[1].size < 4096,"unrecognized payload")
            inner=json.load(t.extractfile(members[1]))
            require(inner == {k:v for k,v in trusted.items() if k not in {"cipher_sha256","cipher_bytes"}},
                    "receipt does not match the authenticated run log")
            clear=d/"ci-test.apk"
            with clear.open("xb") as out: shutil.copyfileobj(t.extractfile(members[0]),out)
        subprocess.run([sys.executable,str(ROOT/"guard.py"),"size","apk",str(clear)],check=True)
        require(sha(clear) == trusted["clear_sha256"],"CI APK SHA mismatch")
        verify(clear,trusted["ci_cert_sha256"])
        final=d/"signed.apk"
        apksigner("sign","--key",ROOT/"test-only.pk8","--cert",ROOT/"test-only.crt",
                  "--v4-signing-enabled","false","--out",final,clear)
        verify(final,FINAL_CERT)
        with final.open("rb") as src,slot.open("xb") as out: shutil.copyfileobj(src,out)
    return {"final_sha256":sha(slot),"final_bytes":slot.stat().st_size,"final_cert_sha256":FINAL_CERT,
            "package":PACKAGE,**trusted}


def main():
    p=argparse.ArgumentParser()
    sub=p.add_subparsers(dest="action",required=True)
    r=sub.add_parser("receive")
    r.add_argument("artifact",type=Path)
    r.add_argument("receipt",type=Path)
    r.add_argument("out",type=Path)
    v=sub.add_parser("verify-final")
    v.add_argument("apk",type=Path)
    v.add_argument("sha256")
    args=p.parse_args()
    os.umask(0o077)
    if args.action == "receive":
        print("C1_PRIVATE_RECEIPT "+json.dumps(receive(args.artifact,json.loads(args.receipt.read_text()),args.out),sort_keys=True))
    else:
        require(sha(args.apk)==args.sha256,"final APK digest mismatch")
        verify(args.apk,FINAL_CERT)
        print("C1_FINAL_REREAD "+json.dumps(dict(sha256=sha(args.apk),certificate=FINAL_CERT,package=PACKAGE,size=args.apk.stat().st_size)))


if __name__ == "__main__":
    main()
