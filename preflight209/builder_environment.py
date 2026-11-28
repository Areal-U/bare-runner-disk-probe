"""Pin the upstream container and adapt the verified Ubuntu transaction to this checkout."""

import argparse
import hashlib
from pathlib import Path


IMAGE = "ubuntu@sha256:076e7bf82319619f28dd0aa9c02ab34b055ad37100395b4f49a2ffba04fb5e11"
SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z"
CHROMIUM = "52bdd21723d5db0c9ab11716d38feac74828cf84"
RESOLVER_SHA = "a89e1810377176a5dc4546c9aed1b5b98abbe707547007f75ad30b1fb20812e1"
# Jammy on the pinned amd64 image, after the upstream Dockerfile's first apt install.
# Maps all 809 pool paths to [package, version, architecture, size, signed SHA-256].
APT_PLAN_SHA = "4266f54068174e20b14474e93ecf74d4be6c957864467be5403ec396189580a8"


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError("Unexpected pinned source when preparing the container")
    return source.replace(before, after, 1)


def dockerfile(source):
    # The full upstream file is pinned, including the builder account and its permissions.
    data = source.encode()
    blob = b"blob " + str(len(data)).encode() + b"\0" + data
    if hashlib.sha1(blob).hexdigest() != "f0560d9eefe09860e11732cdec2135cacd76df59":
        raise ValueError("Different upstream Dockerfile")
    source = replace_once(source, "FROM --platform=linux/amd64 ubuntu:22.04",
                          "FROM --platform=linux/amd64 " + IMAGE)
    options = "-o Acquire::Retries=3 -o Acquire::https::CAInfo=/tmp/bare-ci-apt-ca.pem"
    install = "RUN apt-get update " + "\\" + "\n    && apt-get install"
    bootstrap = (
        "RUN --mount=type=bind,source=bare-ci-apt-ca.pem,target=/tmp/bare-ci-apt-ca.pem "
        "--mount=type=bind,source=bare-bootstrap.sh,target=/tmp/bare-bootstrap.sh "
        f"sed -Ei 's@http://(archive|security)\\.ubuntu\\.com/ubuntu/?@{SNAPSHOT}/@g' /etc/apt/sources.list"
        f" && grep -qF 'deb {SNAPSHOT}/ jammy-security ' /etc/apt/sources.list"
        f" && grep -qF 'deb {SNAPSHOT}/ jammy-updates ' /etc/apt/sources.list"
        f" && apt-get {options} -o APT::Update::Error-Mode=any update"
        " && /bin/bash /tmp/bare-bootstrap.sh"
    )
    return replace_once(source, install, bootstrap)


def installer(source):
    # Keep the existing signed-index, download, receipt and installed-state checks.
    if hashlib.sha256(source.encode()).hexdigest() != "e4f42fd4b0510eb9b5e63bcd53b31915d7685a77a46cd908456c7ef8fbd6297e":
        raise ValueError("Different signed-index installer template")
    source = replace_once(source, 'REV = "800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6"',
                          f'REV = "{CHROMIUM}"')
    source = replace_once(source, '    if packages:\n',
                          '    if not packages:\n'
                          '        fail("Empty Chromium dependency transaction")\n'
                          '    else:\n')
    source = replace_once(source, 'def download(host, path, record, dest):',
                          Path(__file__).with_name("apt_librarian.py").read_text()
                          + '\n\ndef download(host, path, record, dest):')
    source = replace_once(source, '            con.request("GET",url,',
                          '            if host == "launchpadlibrarian.net":\n'
                          '                url = librarian_path(path, record)\n'
                          '                if url is None:\n'
                          '                    fail("No immutable Ubuntu pin for " + path)\n'
                          '            con.request("GET",url,')
    source = replace_once(source,
                          '    for host in ("archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com"):',
                          '    hosts = ["archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com"]\n'
                          '    if librarian_path(path, record) is not None:\n'
                          '        hosts.append("launchpadlibrarian.net")\n'
                          '    for host in hosts:')
    return replace_once(source, '    return records\n',
                        '    canonical = json.dumps(records, sort_keys=True, separators=(",", ":")).encode("ascii")\n'
                        '    actual = sha256(canonical).hexdigest()\n'
                        f'    if len(records) != 809 or actual != "{APT_PLAN_SHA}":\n'
                        '        fail(f"Different signed Chromium dependency transaction: {len(records)} records, SHA256 {actual}")\n'
                        '    return records\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("dockerfile", "installer", "verify-resolver"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    if args.action == "verify-resolver":
        if args.output or hashlib.sha256(args.source.read_bytes()).hexdigest() != RESOLVER_SHA:
            raise SystemExit("Different Chromium build dependency resolver")
        return
    if args.output is None:
        parser.error("An output path is required")
    transform = dockerfile if args.action == "dockerfile" else installer
    args.output.write_text(transform(args.source.read_text()))


if __name__ == "__main__":
    main()
