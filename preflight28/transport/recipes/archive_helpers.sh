cat > "$RUNNER_TEMP/checkpoint_parts.py" <<'ROUND26_REVIEWED_SOURCE_EOF'
"""Local byte transport. Expected identity, byte count and digest come from the original receipt."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile, TemporaryDirectory

PART_BYTES = 2_000_000_000  # Below the 2 GiB single-asset limit.
IO_BYTES = 4 * 1024 * 1024


def check(condition, message):
    if not condition:
        raise ValueError(message)


def part_name(index):
    return f"part-{index:05d}"


def validate_expected(count, digest, identity, generation):
    check(isinstance(generation, str) and bool(generation.strip()), "missing generation key")
    check(type(count) is int and count > 0, "invalid archive size")
    for value in (digest, identity):
        check(isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value), "invalid SHA-256")


def stream_part(reader, writer, remaining, whole_hash):
    part_hash = hashlib.sha256()
    while remaining:
        block = reader.read(min(remaining, IO_BYTES))
        check(bool(block), "short input")
        part_hash.update(block)
        whole_hash.update(block)
        if writer is not None:
            writer.write(block)
        remaining -= len(block)
    return part_hash.hexdigest()


def publish_directory(staged, destination):
    """Linux renameat2 publishes a directory atomically without replacing any existing entry."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    at_fdcwd, rename_noreplace = -100, 1
    if rename(at_fdcwd, os.fsencode(staged), at_fdcwd, os.fsencode(destination), rename_noreplace):
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(destination))


def split(source, dest, count, digest, identity, generation, part_bytes=PART_BYTES):
    validate_expected(count, digest, identity, generation)
    check(type(part_bytes) is int and 0 < part_bytes <= PART_BYTES, "invalid part size")
    whole_hash = hashlib.sha256()
    check(not source.is_symlink() and source.is_file() and source.stat().st_size == count,
          "source type or size disagrees with receipt")
    if dest.exists():
        with source.open("rb") as file:
            check(hashlib.file_digest(file, "sha256").hexdigest() == digest,
                  "source digest disagrees with receipt")
        verify_parts(dest, None, count, digest, identity, generation)
        return  # Verified prior output; leave it in place.
    with TemporaryDirectory(dir=dest.parent, prefix=".split-") as temporary:
        staged = Path(temporary) / "parts"
        staged.mkdir(mode=0o700)
        parts = []
        with source.open("rb") as src:
            for offset in range(0, count, part_bytes):
                name = part_name(len(parts))
                size = min(count - offset, part_bytes)
                with (staged / name).open("xb") as part:
                    part_hash = stream_part(src, part, size, whole_hash)
                parts.append({"name": name, "bytes": size, "sha256": part_hash})
            check(not src.read(1), "source grew during split")
        check(whole_hash.hexdigest() == digest, "source digest disagrees with receipt")
        manifest = {"version": 1, "archive_bytes": count, "archive_sha256": digest,
                    "input_identity": identity, "generation": generation, "part_bytes": part_bytes, "parts": parts}
        with (staged / "manifest.json").open("x") as fp:
            json.dump(manifest, fp, indent=2)
            fp.write("\n")
        try:
            publish_directory(staged, dest)
        except FileExistsError:
            # A concurrent publisher won; accept its result only after checking the original receipt.
            verify_parts(dest, None, count, digest, identity, generation)


def verify_parts(src, writer, count, digest, identity, generation):
    validate_expected(count, digest, identity, generation)
    manifest_file = src / "manifest.json"
    check(not src.is_symlink() and src.is_dir() and not manifest_file.is_symlink() and
          manifest_file.is_file(), "missing or invalid manifest")
    manifest = json.loads(manifest_file.read_text())
    check(manifest["version"] == 1 and manifest["archive_bytes"] == count and
          manifest["archive_sha256"] == digest and manifest["input_identity"] == identity and
          manifest["generation"] == generation,
          "manifest disagrees with original receipt")
    part_bytes = manifest["part_bytes"]
    check(type(part_bytes) is int and 0 < part_bytes <= PART_BYTES, "invalid part size")
    parts = manifest["parts"]
    expected_count = (count + part_bytes - 1) // part_bytes
    check(isinstance(parts, list) and len(parts) == expected_count, "unexpected part count")
    expected_names = [part_name(i) for i in range(expected_count)]
    check([p["name"] for p in parts] == expected_names, "invalid or out-of-order part names")
    check({p.name for p in src.iterdir()} == set(expected_names) | {"manifest.json"},
          "missing or unlisted file")
    whole_hash = hashlib.sha256()
    for i, part in enumerate(parts):
        size = min(count - i * part_bytes, part_bytes)
        path = src / part["name"]
        check(part["bytes"] == size and not path.is_symlink() and
              path.is_file() and path.stat().st_size == size, "part size/type mismatch")
        with path.open("rb") as inp:
            part_hash = stream_part(inp, writer, size, whole_hash)
            check(not inp.read(1), "part grew during validation")
        check(part_hash == part["sha256"], "part digest mismatch")
    check(whole_hash.hexdigest() == digest, "reassembled SHA disagrees with original receipt")


def join(src, output, count, digest, identity, generation):
    if output.exists() or output.is_symlink():
        verify_parts(src, None, count, digest, identity, generation)
        check(not output.is_symlink() and output.is_file() and output.stat().st_size == count,
              "pre-existing destination differs")
        with output.open("rb") as file:
            check(hashlib.file_digest(file, "sha256").hexdigest() == digest,
                  "pre-existing destination digest differs")
        return
    with NamedTemporaryFile(dir=output.parent, prefix=".join-") as temp:
        verify_parts(src, temp, count, digest, identity, generation)
        temp.flush()
        os.fsync(temp.fileno())
        os.link(temp.name, output)  # Publish only after validation, never overwrite an existing file.


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("split", "join"))
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--bytes", dest="count", type=int, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--generation", required=True, help="original exact checkpoint cache key")
    args = parser.parse_args()
    (split if args.action == "split" else join)(
        args.source, args.destination, args.count, args.sha256, args.identity, args.generation)
ROUND26_REVIEWED_SOURCE_EOF
