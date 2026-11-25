"""Check the fixed public S2 filesystem across normal-entry GN regeneration."""
import argparse
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile

from retained import (ArchiveEvidence, DESCRIPTORS, DIAGNOSTIC, S2, commitment,
                      graph_input, inventory)

S2_CONTENT = {"files":252024,"sha256":"1fbed862f70b2ba2086642edd432e95497c4bf11fb67a91516d8c5cc92f9c7cb"}


def evidence(out, files):
    with tempfile.TemporaryDirectory(prefix="s2-gn-proof-") as tmp:
        receiver = ArchiveEvidence(Path(tmp))
        for root, dirs, entries in os.walk(out, followlinks=False):
            root = Path(root)
            for name in [*entries,*dirs]:
                p = root/name
                rel = p.relative_to(out).as_posix()
                if p.is_symlink():
                    if DIAGNOSTIC in Path(os.readlink(p)).parts or rel == DIAGNOSTIC:
                        receiver.aliases.add(rel)
                    if graph_input(rel):
                        receiver.unreadable_graph.add(rel)
                elif rel == DIAGNOSTIC or graph_input(rel):
                    st = p.lstat()
                    if not stat.S_ISREG(st.st_mode) or (rel==DIAGNOSTIC and st.st_nlink!=1):
                        raise ValueError("Unexpected type or alias of observed graph input: "+rel)
                    entry = tarfile.TarInfo(name=rel)
                    entry.mode,entry.size = st.st_mode,st.st_size
                    with p.open("rb") as f:
                        receiver.read(rel,entry,f,False)
        gn = receiver.prove_diagnostic()
        if not gn["regeneration_dependency"]:
            raise ValueError("S2 must bind GN log to the fixed regeneration edge")
        descriptors = {k:receiver.generator_input(k) for k in sorted(DESCRIPTORS)}
        return {"log":files[DIAGNOSTIC],"gn":gn,"descriptors":descriptors}


def observe(phase, out, path, *, required_content=None):
    if phase not in ("before","after"):
        raise ValueError("Invalid migration phase")
    files = inventory(out)
    current = commitment(files)
    original = S2_CONTENT if required_content is None else required_content
    if phase=="before":
        if current != original or DESCRIPTORS.intersection(files):
            raise ValueError("Thawed S2 differs from the complete physical R27 S2 archive")
        state = evidence(out,files)
        with path.open("x",encoding="ascii") as f:
            json.dump(state,f,sort_keys=True)
        return {"phase":phase,"retained":current,"parent_sha256":S2}
    prior = json.loads(path.read_text(encoding="ascii"))
    observed = evidence(out,files)
    if (prior["descriptors"] != observed["descriptors"] or
            prior["gn"]["regeneration_dependency"] != observed["gn"]["regeneration_dependency"] or
            prior["gn"]["manifest_content"] != observed["gn"]["manifest_content"]):
        raise ValueError("GN regenerated a different graph or descriptor input set")
    restored = {}
    for name in sorted(DESCRIPTORS):
        st = (out/name).lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_mode & 0o111 or not 0<st.st_size<=4096:
            raise ValueError("Missing or substituted GN packaging descriptor: "+name)
        restored[name] = files.pop(name)
    files[DIAGNOSTIC] = prior["log"]
    if commitment(files)!=original:
        raise ValueError("GN migration changed another inherited path, including pre-existing Siso metrics")
    return {"phase":phase,"previous":original,"retained":current,"parent_sha256":S2,
            "descriptor_outputs":restored,"old_log":prior["log"],"new_log":observed["log"]}


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase",choices=("before","after"))
    parser.add_argument("--out",type=Path,default=Path("out/Bare"))
    parser.add_argument("--state",type=Path,required=True)
    args=parser.parse_args()
    print(json.dumps(observe(args.phase,args.out.resolve(),args.state),sort_keys=True))
