"""Reconstruct the one Git clock consumed by the two fixed ANGLE generators."""
import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path
import stat
import subprocess
import sys
import tempfile

S1_SHA = "fa44728d39b61c25d4116579e6da2c63ca7898cec24ada0e7ae453548bbd73bf"
S1_PROOF_SHA = "27b52991ec81306daf99437ba9c0488a5a510180e75bc3d3e3be9cfa32cc482a"
GRAPH = "a553fc84a2cea62d5ef2beba03a0a8daba6e7e1d790132969f94221563ea5a5a"
REVISION = "751417514a521b2e92d6928260c62122138824d3"
COMMIT_TIME = 1793649209
GENERATOR_SHA = "8b0965c295de21426a6ee76238a761ea391abc234ef674f18475b73d20ce844a"
HEADER_SHA = "fec4c9cd81c879016fcf660deddd847b0e2cff43fcfce1241eebdbc10536a37f"
HEADERS = ("clang_x64_v8_arm64/gen/angle/angle_commit.h", "gen/angle/angle_commit.h")
DEPENDENCY = "../../third_party/angle/.git/HEAD"


def small_file(path, limit):
    info = path.lstat()
    if path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError(f"Unexpected ANGLE input or output: {path.name}")
    return path.read_bytes()


def restore_git_clock(out):
    """Change only a disposable, detached checkout after proving semantic equality."""
    out = out.resolve(strict=True)
    angle = out.parent.parent / "third_party/angle"
    head = angle / ".git/HEAD"
    script = angle / "src/commit_id.py"
    expected_head = f"{REVISION}\n".encode("ascii")
    if small_file(head, 256) != expected_head:
        raise ValueError("Wrong ANGLE checkout or non-detached HEAD")
    if hashlib.sha256(small_file(script, 65536)).hexdigest() != GENERATOR_SHA:
        raise ValueError("Wrong ANGLE header generator")
    if os.environ.get("ANGLE_UPSTREAM_HASH"):
        raise ValueError("Unexpected ANGLE_UPSTREAM_HASH")
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_NOSYSTEM="1",
               GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
    commit = subprocess.check_output(
        ["git", "-C", str(angle), "show", "-s", "--format=%H %ct", "HEAD"],
        env=env, timeout=20, text=True).strip()
    if commit != f"{REVISION} {COMMIT_TIME}":
        raise ValueError("ANGLE commit object or commit timestamp differs")
    with tempfile.TemporaryDirectory(prefix="bare-angle-receipt-") as directory:
        temporary = Path(directory).resolve() / "angle_commit.h"
        dep = temporary.with_suffix(".h.d")
        subprocess.run([sys.executable, "-I", str(script), "gen", str(temporary), str(dep)],
                       cwd=out, env=env, check=True, timeout=30)
        generated = small_file(temporary, 2048)
        if hashlib.sha256(generated).hexdigest() != HEADER_SHA:
            raise ValueError("Fresh ANGLE commit header differs from the fixed revision")
        if small_file(dep, 4096) != f"{temporary}: {DEPENDENCY}\n".encode():
            raise ValueError("Fresh ANGLE depfile refers to unexpected Git inputs")
        for name in HEADERS:
            if small_file(out / name, 2048) != generated:
                raise ValueError(f"Restored ANGLE header differs: {name}")
            if small_file(out / (name + ".d"), 4096) != f"{name}: {DEPENDENCY}\n".encode():
                raise ValueError(f"Restored ANGLE dependency differs: {name}")
    # The commit timestamp is intrinsic to the authenticated Git object. It is
    # stable across fresh checkouts. Preserve all producer logs and outputs.
    with open(head, "rb", opener=lambda name, flags: os.open(name, flags | os.O_NOFOLLOW)) as stream:
        info = os.fstat(stream.fileno())
        if not os.path.samestat(info, head.lstat()) or info.st_nlink != 1 or stream.read(257) != expected_head:
            raise ValueError("ANGLE HEAD changed during reconstruction")
        canonical_ns = COMMIT_TIME * 1_000_000_000
        os.utime(stream.fileno(), ns=(info.st_atime_ns, canonical_ns))
        if os.fstat(stream.fileno()).st_mtime_ns != canonical_ns:
            raise ValueError("Could not restore ANGLE Git input time")
    result = dict(revision=REVISION, outputs=len(HEADERS), header_sha256=HEADER_SHA,
                  checkout_head_mtime_ns=info.st_mtime_ns, normalized_head_mtime_ns=canonical_ns)
    print("BARE_ANGLE_RESTORE " + json.dumps(result, sort_keys=True), flush=True)
    return result


def negative_controls(out):
    """Exercise the same entry point on disposable copies backed by read-only Git objects."""
    out = out.resolve(strict=True)
    source = out.parent.parent / "third_party/angle"
    with tempfile.TemporaryDirectory(prefix="bare-angle-controls-") as directory:
        src = Path(directory).resolve()
        angle = src / "third_party/angle"
        (angle / "src").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(angle)], check=True, timeout=10)
        head = angle / ".git/HEAD"
        (angle / ".git/objects/info/alternates").write_text(str(source / ".git/objects") + "\n")
        (angle / ".git/shallow").write_text(REVISION + "\n")
        head.write_bytes(small_file(source / ".git/HEAD", 256))
        shutil.copy2(source / "src/commit_id.py", angle / "src/commit_id.py")
        scratch = src / "out/Bare"
        for name in HEADERS:
            (scratch / name).parent.mkdir(parents=True)
            for suffix in ("", ".d"):
                shutil.copy2(out / (name + suffix), scratch / (name + suffix))
        # The clean control must pass before a failure is allowed to count.
        restore_git_clock(scratch)
        cases = [
            (head, "Wrong ANGLE checkout or non-detached HEAD"),
            (angle / "src/commit_id.py", "Wrong ANGLE header generator"),
            (scratch / HEADERS[0], f"Restored ANGLE header differs: {HEADERS[0]}"),
            (scratch / (HEADERS[1] + ".d"), f"Restored ANGLE dependency differs: {HEADERS[1]}"),
        ]
        for path, expected in cases:
            original = path.read_bytes()
            path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
            before = head.stat().st_mtime_ns
            try:
                restore_git_clock(scratch)
            except ValueError as error:
                if str(error) != expected:
                    raise
            else:
                raise ValueError(f"Accepted a corrupt ANGLE control: {path.name}")
            if head.stat().st_mtime_ns != before:
                raise ValueError("Repaired Git clock on rejected control")
            path.write_bytes(original)
        print("BARE_ANGLE_NEGATIVE " + json.dumps({"clean": "accepted", "rejected": len(cases),
              "controls": ["commit", "generator", "host_header", "android_depfile"]}), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--negative-control", action="store_true")
    args = parser.parse_args()
    if args.negative_control:
        negative_controls(args.out)
    else:
        restore_git_clock(args.out)
