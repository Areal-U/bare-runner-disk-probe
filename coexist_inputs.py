#!/usr/bin/env python3
"""Prepare the pinned Bare 2.0.4 ARM64 configuration and launcher label."""

import argparse
import hashlib
import re
import sys
from pathlib import Path


PACKAGE_SETTING = 'chrome_public_manifest_package = "org.barebrowser"'
PERSONAL_PACKAGE_SETTING = 'chrome_public_manifest_package = "org.barebrowser.personal"'
UPSTREAM_ARM64_ARGS_SHA256 = "5dfaaf3d8851f136266f14cc83f0feea80d83ffd7b3ebdcc2d385b25a8e3bb89"
BUILD_GUIDE = Path("docs/build-from-source.md")
LABEL_RESOURCE = Path("chrome/android/java/res_chromium_base/values/channel_constants.xml")
UPSTREAM_LABEL = '<string name="app_name" translatable="false">Bare</string>'
PERSONAL_LABEL = '<string name="app_name" translatable="false">Bare Personal</string>'


def generate_gn_args(bare_root: Path, output: Path) -> None:
    guide = (bare_root / BUILD_GUIDE).read_text(encoding="utf-8")
    blocks = re.findall(r"^```gn[ \t]*\n(.*?)^```[ \t]*$", guide, re.MULTILINE | re.DOTALL)
    arm64_blocks = [block for block in blocks if PACKAGE_SETTING in block.splitlines()]
    if len(arm64_blocks) != 1:
        raise ValueError("expected one release GN configuration in the Bare build guide")
    upstream = arm64_blocks[0]
    if hashlib.sha256(upstream.encode("utf-8")).hexdigest() != UPSTREAM_ARM64_ARGS_SHA256:
        raise ValueError("release GN configuration differs from the pinned Bare 2.0.4 ARM64 block")

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(upstream.replace(PACKAGE_SETTING, PERSONAL_PACKAGE_SETTING, 1), encoding="utf-8")


def set_launcher_label(chromium_src: Path) -> None:
    resource = chromium_src / LABEL_RESOURCE
    contents = resource.read_text(encoding="utf-8")
    labels = re.findall(r'^[ \t]*<string name="app_name"[^>]*>[^<]*</string>[ \t]*$', contents, re.MULTILINE)
    if len(labels) == 1 and labels[0].strip() == PERSONAL_LABEL:
        return
    if len(labels) != 1 or labels[0].strip() != UPSTREAM_LABEL:
        raise ValueError("unexpected app_name resource after applying Bare 2.0.4 patches")
    resource.write_text(contents.replace(UPSTREAM_LABEL, PERSONAL_LABEL, 1), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    gn = commands.add_parser("gn", help="write GN arguments for the coexisting APK")
    gn.add_argument("--bare-root", type=Path, required=True)
    gn.add_argument("--output", type=Path, required=True)
    label = commands.add_parser("label", help="set the Android label after upstream patches")
    label.add_argument("--chromium-src", type=Path, required=True)
    args = parser.parse_args()

    try:
        if args.command == "gn":
            generate_gn_args(args.bare_root, args.output)
        else:
            set_launcher_label(args.chromium_src)
    except (OSError, ValueError) as error:
        print(f"coexist_inputs.py: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
