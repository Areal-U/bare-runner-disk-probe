#!/usr/bin/env python3
"""Reconcile the official Bare 2.0.9 Android inputs and apply the Personal changes."""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LOCK = json.loads(Path(__file__).with_name("upstream-lock.json").read_bytes())
GUIDE = "docs/build-from-source.md"
PACKAGE_LINE = 'chrome_public_manifest_package = "org.barebrowser"'
CRX = "third_party/ublock_origin/uBlockOrigin-1.75.0.crx"
MANIFEST = "chrome/android/java/AndroidManifest.xml"
STRING_BASE = "chrome/android/java/res_chromium_base/values/"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(directory, *args):
    return subprocess.check_output(list(args), cwd=directory, text=True).strip()


def require_revision(directory, expected):
    actual = run(directory, "git", "rev-parse", "HEAD")
    require(actual == expected, f"{directory}: expected commit {expected}, got {actual}")


def verify_bare(root):
    require_revision(root, LOCK["bare_commit"])
    require(run(root, "git", "rev-parse", "HEAD^{tree}") == LOCK["bare_tree"], "Unexpected Bare release tree")
    require(run(root, "git", "rev-parse", "HEAD:patches") == LOCK["patch_tree"], "Unexpected patch series tree")
    require(not run(root, "git", "diff", "--name-only", "HEAD", "--"), "Bare tracked inputs were modified")
    tracked = run(root, "git", "ls-files", "--", "patches/*.patch").splitlines()
    actual = sorted(p.relative_to(root).as_posix() for p in (root / "patches").glob("*.patch"))
    require(actual == tracked and len(tracked) == LOCK["patch_count"], "Unexpected, missing or extra patch")
    require(sha((root / CRX).read_bytes()) == LOCK["ubo_sha256"], "Incorrect embedded uBlock Origin input")
    building = (root / "BUILDING.md").read_text()
    require(f'Chromium commit: `{LOCK["chromium_commit"]}`' in building, "BUILDING.md disagrees with Chromium pin")
    return {"bare": LOCK["bare_commit"], "patches": len(tracked), "ubo_sha256": LOCK["ubo_sha256"]}


def gn(root, output):
    verify_bare(root)
    guide = (root / GUIDE).read_text()
    blocks = [x for x in re.findall(r"^```gn[ \t]*\n(.*?)^```[ \t]*$", guide, re.M | re.S)
              if PACKAGE_LINE in x.splitlines()]
    require(len(blocks) == 1 and blocks[0].splitlines().count(PACKAGE_LINE) == 1,
            "Expected exactly one official Android release package in one GN block")
    block = blocks[0]
    require(sha(block.encode()) == LOCK["upstream_gn_sha256"], "Official ARM64 GN block changed")
    version_args = run(root, sys.executable, "tools/version.py", "gn", "arm64")
    expected_version = (f'android_override_version_code = "{LOCK["version_code"]}"\n'
                        f'android_override_version_name = "{LOCK["version"]}"')
    require(version_args == expected_version and block.endswith(expected_version + "\n"),
            "Official version utility and release block disagree")
    personal = block.replace(PACKAGE_LINE, f'chrome_public_manifest_package = "{LOCK["personal_package"]}"')
    require(sha(personal.encode()) == LOCK["personal_gn_sha256"], "Personal GN digest differs")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(personal)
    return {"personal_gn_sha256": LOCK["personal_gn_sha256"], "version_code": LOCK["version_code"]}


def verify_chromium(root, depot):
    require_revision(root, LOCK["chromium_commit"])
    require_revision(depot, LOCK["depot_tools_commit"])
    require_revision(root / "third_party/depot_tools", LOCK["depot_tools_commit"])
    require_revision(root / "v8", LOCK["v8_commit"])
    for name, expected in LOCK["source_files"].items():
        require(sha((root / name).read_bytes()) == expected, f"Fixed source fingerprint mismatch: {name}")
    return {"chromium": LOCK["chromium_commit"], "depot_tools": LOCK["depot_tools_commit"],
            "clang": LOCK["clang_package"], "siso_revision": LOCK["siso_revision"], "v8": LOCK["v8_commit"]}


def label(root):
    manifest = (root / MANIFEST).read_bytes()
    require(sha(manifest) == LOCK["patched_manifest_sha256"], "Unexpected upstream merged manifest template")
    require(manifest.count(b'android:label="{% block application_label %}@string/bare_launcher_label{% endblock %}"') == 1,
            "The current manifest does not refer to the expected launcher resource")
    updates = {}
    for key, fingerprints in LOCK["label_files"].items():
        path = root / STRING_BASE / fingerprints["file"]
        data = path.read_bytes()
        digest = sha(data)
        if digest == fingerprints["personal_sha256"]:
            continue
        require(digest == fingerprints["official_sha256"], f"Unexpected upstream {key} resource bytes")
        old = f'<string name="{key}" translatable="false">Bare</string>'.encode()
        new = old.replace(b">Bare<", b">Bare Personal<")
        require(data.count(old) == 1, f"Expected one upstream {key} resource")
        result = data.replace(old, new, 1)
        require(sha(result) == fingerprints["personal_sha256"], f"Incorrect transformed {key} bytes")
        updates[path] = result
    for path, data in updates.items():
        temporary = path.with_name(path.name + ".personal-tmp")
        temporary.write_bytes(data)
        temporary.chmod(path.stat().st_mode & 0o777)
        os.replace(temporary, path)
    return {"app_name": "Bare Personal", "bare_launcher_label": "Bare Personal", "changed": len(updates)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    bare = commands.add_parser("verify-bare")
    bare.add_argument("--bare-root", type=Path, required=True)
    config = commands.add_parser("gn")
    config.add_argument("--bare-root", type=Path, required=True)
    config.add_argument("--output", type=Path, required=True)
    src = commands.add_parser("verify-chromium")
    src.add_argument("--chromium-src", type=Path, required=True)
    src.add_argument("--depot-tools", type=Path, required=True)
    labels = commands.add_parser("label")
    labels.add_argument("--chromium-src", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "verify-bare":
        report = verify_bare(args.bare_root)
    elif args.command == "gn":
        report = gn(args.bare_root, args.output)
    elif args.command == "verify-chromium":
        report = verify_chromium(args.chromium_src, args.depot_tools)
    else:
        report = label(args.chromium_src)
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Bare source inputs: {exc}")
