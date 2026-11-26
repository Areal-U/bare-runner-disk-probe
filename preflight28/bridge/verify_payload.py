"""Bind the claimed frontier and Chromium provenance to bytes valid for private storage."""
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import FunctionType

from check_archive import StreamingTar

PROOF = "out/Bare/checkpoint-segment-frontier.json"


def check(file, record, *, require_current=False):
    source = Path(__file__).resolve().parents[2]/"checkpoint.py"
    spec = importlib.util.spec_from_file_location("current_checkpoint_validator",source)
    ck = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ck)
    graph_spec = importlib.util.spec_from_file_location('checkpoint_retention', Path(__file__).resolve().parents[1] / 'graph/retained.py')
    retention = importlib.util.module_from_spec(graph_spec)
    graph_spec.loader.exec_module(retention)
    sampled = {}
    stamps = {}
    kotlin_classes = {}
    payload_paths = set()
    link_text = None
    executable_files = set()
    hard_links = {}
    reported_paths = set()
    ninja_rows, log_identity = {}, None
    report_only = {'out/Bare/' + n for n in retention.NOMINAL_REPORTED}
    nominal_material = {'out/Bare/' + n for n in retention.NOMINAL_MATERIAL}
    bounds = {PROOF: 64*1024**2, ck.PROVENANCE_RECORD: 1024**2}

    @contextmanager
    def open_validated(path, mode):
        with StreamingTar.open(path,mode) as actual:
            class Sampler:
                def __iter__(self):
                    nonlocal link_text, ninja_rows, log_identity
                    for member in actual:
                        # Let the pinned parser reject excessive unpacked bytes/member count
                        # and unsafe headers before consuming even one candidate data block.
                        yield member
                        name = ck.archive_relative(member.name).as_posix()
                        if name == 'out/Bare/' + retention.DEVIL_LINK and member.issym():
                            link_text = member.linkname
                        if member.islnk():
                            hard_links[name] = ck.archive_relative(member.linkname).as_posix()
                        elif member.isfile() and member.mode & 0o111 and member.size:
                            executable_files.add(name)
                        if name in report_only:
                            reported_paths.add(name)
                        elif '.md5.stamp/' in name:
                            directory = name.partition('.md5.stamp/')[0] + '.md5.stamp'
                            if directory in report_only:
                                reported_paths.add(directory)
                        if name == 'out/Bare/.ninja_log' and member.isfile():
                            with actual.extractfile(member) as stream:
                                ninja_rows, log_identity = retention.scan_ninja_log(stream)
                        if member.isfile() or member.issym() or member.islnk():
                            payload_paths.add(name)
                        if name in bounds:
                            if name in sampled or not member.isfile() or not 0<member.size<=bounds[name]:
                                raise ValueError("Invalid bounded private archive evidence")
                            sampled[name] = actual.extractfile(member).read(member.size)
                        if member.isfile() and (name in nominal_material or name.endswith(('.md5.stamp', '.desugardeps')) or
                                (name.startswith(('out/Bare/gen/', 'out/Bare/obj/')) and name.endswith(('.jar','.dex','.zip','.json')))):
                            digest = hashlib.sha256()
                            relative = name.removeprefix('out/Bare/')
                            # Proof order in a streaming tar is not guaranteed. Record
                            # structural validity only; unretired partial files may exist.
                            jar = (io.BytesIO() if relative in retention.KOTLIN_JARS and
                                   0 < member.size <= retention.KOTLIN_JAR_LIMIT else None)
                            with actual.extractfile(member) as stamp:
                                for block in iter(lambda: stamp.read(1024**2), b''):
                                    digest.update(block)
                                    if jar is not None:
                                        jar.write(block)
                            stamps[name] = [member.size, digest.hexdigest()]
                            if jar is not None:
                                try:
                                    kotlin_classes[relative] = retention.verify_kotlin_jar(relative, jar, member.size)
                                except ValueError:
                                    pass
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
    retention.check_frontier_log(proof, log_identity, require_current=require_current)
    before, after = set(proof["before"]), set(proof["after"])
    if (proof.get("target")!="chrome_public_apk"
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
    if any(retention.DEVIL_LINK in group for group in closed):
        host = 'out/Bare/' + retention.DEVIL_TARGET
        seen = set()
        while host in hard_links and host not in seen:
            seen.add(host)
            host = hard_links[host]
        retention.check_devil_link(link_text, host in executable_files)
    for name, expected in retention.stamp_metadata(proof, ck.canonical_hash).items():
        if name in retention.KOTLIN_JARS and name not in kotlin_classes:
            raise ValueError('Missing or invalid archived fixed Kotlin JAR: ' + name)
        if stamps.get('out/Bare/' + name) != expected:
            raise ValueError('Archived runtime stamp absent or changed')
    retention.check_nominal_state(proof, lambda n: 'out/Bare/' + n in reported_paths, ninja_rows)
    for row in proof.get('runtime_stamps', {}).values():
        retention.verify_kotlin_roles(row['primary'], kotlin_classes)
        for binding, digest in row['fileargs'].items():
            source = 'out/Bare/' + binding.partition(':')[0]
            if source not in stamps or stamps[source][1] != digest:
                raise ValueError('Archived runtime output source absent or changed')
