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
    graph_spec = importlib.util.spec_from_file_location('checkpoint_retention', Path(__file__).resolve().parents[1] / 'graph/retained.py')
    retention = importlib.util.module_from_spec(graph_spec)
    graph_spec.loader.exec_module(retention)
    sampled = {}
    stamps = {}
    payload_paths = set()
    bounds = {PROOF: 64*1024**2, ck.PROVENANCE_RECORD: 1024**2}

    @contextmanager
    def open_validated(path, mode):
        with StreamingTar.open(path,mode) as actual:
            class Sampler:
                def __iter__(self):
                    for member in actual:
                        # Let the pinned parser reject excessive unpacked bytes/member count
                        # and unsafe headers before consuming even one candidate data block.
                        yield member
                        name = ck.archive_relative(member.name).as_posix()
                        if member.isfile() or member.issym() or member.islnk():
                            payload_paths.add(name)
                        if name in bounds:
                            if name in sampled or not member.isfile() or not 0<member.size<=bounds[name]:
                                raise ValueError("Invalid bounded private archive evidence")
                            sampled[name] = actual.extractfile(member).read(member.size)
                        if member.isfile() and (name.endswith(('.md5.stamp', '.desugardeps')) or
                                (name.startswith(('out/Bare/gen/', 'out/Bare/obj/')) and name.endswith(('.jar','.dex','.zip','.json')))):
                            digest = hashlib.sha256()
                            with actual.extractfile(member) as stamp:
                                for block in iter(lambda: stamp.read(1024**2), b''):
                                    digest.update(block)
                            stamps[name] = [member.size, digest.hexdigest()]
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
    if (proof.get("format")!="bare-apk-segment-frontier-v3" or proof.get("target")!="chrome_public_apk"
            or proof.get("parent_sha256")!=record["parent_sha"] or not after<before or
            not proof.get("witnesses") or len(before)!=len(proof["before"]) or len(after)!=len(proof["after"])):
        raise ValueError("Private archive lacks the declared forward APK transition")
    closed = proof.get("closed_groups")
    if not isinstance(closed, list) or len(closed) != len(before - after):
        raise ValueError("Private candidate omitted completed APK output groups")
    ids = set()
    for group in closed:
        if (not isinstance(group, list) or not group or group != sorted(set(group))
                or any(not isinstance(name, str) or "out/Bare/" + name not in payload_paths for name in group)):
            raise ValueError("Private archive lacks a required completed output")
        ids.add(ck.canonical_hash(group))
    if ids != before - after:
        raise ValueError("Archived output groups do not match the complete APK frontier change")
    for name, expected in retention.stamp_metadata(proof, ck.canonical_hash).items():
        if stamps.get('out/Bare/' + name) != expected:
            raise ValueError('Archived runtime stamp absent or changed')
    for row in proof.get('runtime_stamps', {}).values():
        for binding, digest in row['fileargs'].items():
            source = 'out/Bare/' + binding.partition(':')[0]
            if source not in stamps or stamps[source][1] != digest:
                raise ValueError('Archived runtime output source absent or changed')
