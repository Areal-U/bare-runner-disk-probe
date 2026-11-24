"""Small positive control for ordinary-job compilation and restricted-job receipt."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess

import bridge as b


def fixture_source(anchor):
    marker = f"{anchor['run']}:{anchor['attempt']}:{anchor['trial_head']}:{anchor['source_sha']}"
    return ('__attribute__((used)) const char bare_r28_payload[] = "' + marker + '";\n'
            'unsigned bare_r28_fixture(void) { return sizeof(bare_r28_payload) - 1; }\n').encode("ascii"), marker.encode()


def assert_elf(path, marker):
    data = path.read_bytes()
    b.require(64 <= len(data) <= 32768 and data[:7] == b'\x7fELF\x02\x01\x01'
              and struct.unpack_from("<HH", data, 16) == (1, 62) and data.count(marker + b"\x00")==1,
              "Unexpected test object contents, architecture, or ELF type")
    return hashlib.sha256(data).hexdigest()


def produce():
    root = b.ROOT
    anchor = json.loads((root/"cipher-receipt.json").read_text())
    source, marker = fixture_source(anchor)
    obj = root/"worker.o"
    subprocess.run(["cc", "-x", "c", "-std=c11", "-c", "-O2", "-g0", "-fno-ident",
                    "-frandom-seed=r28-object-fixture", "-o", str(obj), "-"],
                   input=source, check=True, timeout=20)
    digest = assert_elf(obj, marker)
    b.encrypt(root/"writer.pem", obj, root/"fixture.cms")
    anchor["native_test_object"] = {"source_sha256": hashlib.sha256(source).hexdigest(), "sha256": digest,
        "bytes": obj.stat().st_size, "cipher_sha256": b.digest(root/"fixture.cms"),
        "cipher_bytes": (root/"fixture.cms").stat().st_size}
    (root/"cipher-receipt.json").write_text(json.dumps(anchor,sort_keys=True))
    print("ordinary_compiler_test_object="+json.dumps(anchor["native_test_object"],sort_keys=True))


def receive():
    root = b.ROOT
    anchor = json.loads((root/"incoming/cipher-receipt.json").read_text())
    b.require(anchor["run"] == b.env_int("GITHUB_RUN_ID") and anchor["attempt"] == 1 and anchor["trial_head"] == b.HEAD
              and anchor["source_manifest"] == b.env_int("SOURCE_MANIFEST_ID") and b.sha(anchor["source_sha"]) and
              anchor["recipient_fpr"] == b.fingerprint(root/"public.pem"),"Fixture generation mismatch")
    rec = anchor["native_test_object"]
    sealed = root/"incoming/fixture.cms"
    b.require(sealed.stat().st_size==rec["cipher_bytes"] and 0<rec["cipher_bytes"]<=65536 and
              b.digest(sealed)==rec["cipher_sha256"],"Changed object envelope")
    source, marker = fixture_source(anchor)
    obj = root/"received.o"
    b.decrypt(sealed,obj)
    digest=assert_elf(obj,marker)
    b.require(obj.stat().st_size==rec["bytes"] and digest==rec["sha256"] and
              hashlib.sha256(source).hexdigest()==rec["source_sha256"],"Object differs from ordinary compiler result")
    print("writer_received_ordinary_compiler_test_object="+json.dumps(rec,sort_keys=True))


if __name__=="__main__":
    os.umask(0o077)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation",choices=["produce","receive"])
    globals()[parser.parse_args().operation]()
