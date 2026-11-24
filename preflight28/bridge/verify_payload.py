"""Bind the claimed frontier and Chromium provenance to bytes valid for private storage."""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
from types import FunctionType

from check_archive import StreamingTar

PROOF = "out/Bare/checkpoint-segment-frontier.json"


def check(file, record):
    source = Path(__file__).resolve().parents[2]/"checkpoint.py"
    spec = importlib.util.spec_from_file_location("current_checkpoint_validator",source)
    ck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ck)
    sampled = {}
    bounds = {PROOF: 64*1024**2, ck.PROVENANCE_RECORD: 1024**2}

    @contextmanager
    def open_validated(path, mode):
        with StreamingTar.open(path,mode) as actual:
            class Sampler:
                def __iter__(self):
                    for member in actual:
                        name = ck.archive_relative(member.name).as_posix()
                        if name in bounds:
                            if name in sampled or not member.isfile() or not 0<member.size<=bounds[name]:
                                raise ValueError("Invalid bounded private archive evidence")
                            sampled[name] = actual.extractfile(member).read(member.size)
                        yield member
                def extractfile(self, member):
                    return actual.extractfile(member)
            yield Sampler()
    # Keep the pinned parser and link/type/path rules. Only a final APK must be
    # absent from this private full-state checkpoint. Android intermediates are needed.
    actual_tar = StreamingTar()
    class InstrumentedTar:
        def __getattr__(self,key):
            if key == "open":
                return open_validated
            return getattr(actual_tar,key)
    ck.tarfile = InstrumentedTar()
    validate_gn = ck.gn_packaging_dependencies
    ck.gn_packaging_dependencies = FunctionType(validate_gn.__code__,dict(validate_gn.__globals__))
    ck.is_android_packaging = lambda path: path.name.casefold()=="chromepublic.apk"
    ck.validate_archive(file, ck.PRODUCTION_ARCHIVE_BYTES, ck.PRODUCTION_UNPACKED_BYTES,
                        ck.PRODUCTION_ARCHIVE_MEMBERS, exclude_android_packaging=True)
    if set(sampled)!=set(bounds) or hashlib.sha256(sampled[PROOF]).hexdigest()!=record["proof_sha"]:
        raise ValueError("Private candidate lost or changed actual graph proof")
    p = json.loads(sampled[ck.PROVENANCE_RECORD])
    if (p.get("format")!=ck.PROVENANCE_FORMAT or p.get("version")!=ck.CHECKPOINT_VERSION or
            p["identity"]["ci_revision"]!=record["producer_sha"] or
            p.get("identity_sha256")!=record["identity"] or ck.canonical_hash(p["identity"])!=record["identity"]):
        raise ValueError("Private checkpoint SHA and producer identity differ")
    proof = json.loads(sampled[PROOF])
    before, after = set(proof["before"]), set(proof["after"])
    if (proof.get("format")!="bare-apk-segment-frontier-v2" or proof.get("target")!="chrome_public_apk"
            or proof.get("parent_sha256")!=record["parent_sha"] or not after<before or
            not proof.get("witnesses") or len(before)!=len(proof["before"]) or len(after)!=len(proof["after"])):
        raise ValueError("Private archive lacks the declared forward APK transition")
