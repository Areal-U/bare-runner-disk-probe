set -euo pipefail
mkdir -m 700 "$RUNNER_TEMP/verified-six"
cat > "$RUNNER_TEMP/verified-six/public_urls.py" <<'PUBLIC_SIX_URLS'
"""Read only six known Ubuntu binaries, validating against the signed November 12 snapshot."""
from concurrent.futures import ThreadPoolExecutor
import email.parser
import hashlib
import http.client
import json
import lzma
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from urllib.parse import urlencode, quote, unquote, urljoin, urlsplit

SNAP = "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/"
API = "https://api.launchpad.net/devel/ubuntu/+archive/primary"
F = {
    "pool/main/g/glibc/libc6-i386_2.35-0ubuntu3.15_amd64.deb": ("libc6-i386","2.35-0ubuntu3.15","amd64"),
    "pool/main/g/glibc/libc6_2.35-0ubuntu3.15_i386.deb": ("libc6","2.35-0ubuntu3.15","i386"),
    "pool/main/l/linux/linux-libc-dev_5.15.0-203.213_i386.deb": ("linux-libc-dev","5.15.0-203.213","i386"),
    "pool/main/libc/libcpanel-json-xs-perl/libcpanel-json-xs-perl_4.27-1ubuntu0.2_amd64.deb": ("libcpanel-json-xs-perl","4.27-1ubuntu0.2","amd64"),
    "pool/main/r/ruby3.0/libruby3.0_3.0.2-7ubuntu2.13_amd64.deb": ("libruby3.0","3.0.2-7ubuntu2.13","amd64"),
    "pool/main/r/ruby3.0/ruby3.0_3.0.2-7ubuntu2.13_amd64.deb": ("ruby3.0","3.0.2-7ubuntu2.13","amd64"),
}
DENIED_PATH = "pool/main/l/linux/linux-libc-dev_5.15.0-203.213_i386.deb"

def url_ok(url, kind, filename=None):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.username or parsed.password or parsed.port or parsed.fragment
            or parsed.hostname != parsed.netloc or ".." in unquote(parsed.path).split("/")):
        return False
    host, path = parsed.hostname, unquote(parsed.path)
    if kind == "index":
        return host == "snapshot.ubuntu.com" and url.startswith(SNAP+"dists/") and not parsed.query
    if kind == "meta":
        return host=="api.launchpad.net" and (path=="/devel/ubuntu/+archive/primary" or re.fullmatch(r"/devel/ubuntu/\+archive/primary/\+binarypub/[0-9]+",path))
    if filename is None or path.rsplit("/",1)[-1]!=filename or parsed.query:
        return False
    if kind=="original":
        return host=="snapshot.ubuntu.com" and url.startswith(SNAP+"pool/") and url != SNAP+DENIED_PATH
    if host in {"launchpad.net","api.launchpad.net"}:
        return ("/+files/" in path and (path.startswith("/ubuntu/") or path.startswith("/devel/ubuntu/")))
    return host=="launchpadlibrarian.net" and re.fullmatch(r"/[0-9]+/[^/]+",path) is not None

def get(url, kind, limit, filename=None):
    for i in range(5):
        if not url_ok(url,kind,filename):
            raise ValueError("Unrecognized URL scope for "+kind)
        p=urlsplit(url)
        conn=http.client.HTTPSConnection(p.hostname,timeout=40)
        try:
            conn.request("GET",p.path+("?"+p.query if p.query else ""),headers={"User-Agent":"Bare-checkpoint-official-package-probe/1.0"})
            response=conn.getresponse()
            if 300 <= response.status < 400:
                location=response.getheader("Location")
                if kind!="binary" or not location:
                    return response.status,b"",p.hostname
                url=urljoin(url,location)
                continue
            if response.status != 200:
                return response.status,b"",p.hostname
            body=response.read(limit+1)
            if len(body)>limit:
                raise ValueError("Bound exceeded for "+kind)
            return 200,body,p.hostname
        finally:
            conn.close()
    raise ValueError("Excess redirects for "+kind)
PUBLIC_SIX_URLS
cat > "$RUNNER_TEMP/verified-six/receive_six.py" <<'SIX_RECEIVER_PY'
"""Use six exact probe receipts on the recipient, including its own APT indexes."""
from concurrent.futures import ThreadPoolExecutor
import email.parser
import hashlib
import http.client
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys
import time
from urllib.parse import urlsplit


def replay(root, receipts):
    probe = runpy.run_path(str(root / "public_urls.py"))
    if set(receipts) != set(probe["F"]):
        raise ValueError("The fixed six package receipts are incomplete")

    def fetch_one(path):
        item = receipts[path]
        name = Path(path).name
        kind = item["route"]
        if kind not in ("original", "binary") or (kind == "original" and item["url"] != probe["SNAP"] + path):
            raise ValueError("Unexpected download route")
        if not probe["url_ok"](item["url"], kind, name):
            raise ValueError("Unexpected download URL")
        for delay in (0, 4, 12):
            time.sleep(delay)
            try:
                status, data, host = probe["get"](item["url"], kind, item["bytes"], name)
            except (OSError, http.client.HTTPException):
                if delay == 12:
                    raise
                continue
            if status == 200:
                break
            if delay == 12 or status not in (500, 502, 503, 504):
                raise ValueError(f"Recorded package route returned {status}: {name}")
        if (host, len(data), hashlib.sha256(data).hexdigest()) != (item["source"], item["bytes"], item["sha256"]):
            raise ValueError("The source, bytes or SHA-256 differ from the accepted trial: " + name)
        payload = root / name
        payload.write_bytes(data)
        for key, expected in zip(("Package", "Version", "Architecture"), probe["F"][path]):
            actual = subprocess.check_output(["dpkg-deb", "-f", str(payload), key], text=True).strip()
            if actual != expected:
                raise ValueError("Wrong package control record for " + name)
        print(f"Verified {name}: {len(data)} bytes, SHA-256 {item['sha256']}", flush=True)

    with ThreadPoolExecutor(max_workers=3) as pool:
        list(pool.map(fetch_one, sorted(receipts)))


def verify_indexes(receipts):
    lists = Path("/var/lib/apt/lists")
    checked = set()
    for item in receipts.values():
        key = (item["inrelease_url"], item["inrelease_sha256"], item["index_url"], item["index_sha256"])
        if key in checked:
            continue
        checked.add(key)
        release_url, release_hash, index_url, index_hash = key
        pocket = release_url.split("/")[-2]
        if not re.fullmatch(r"jammy(?:-updates|-security|-backports)?", pocket):
            raise ValueError("Unrecognized signed distribution")
        prefix = "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/" + pocket + "/"
        if release_url != prefix + "InRelease" or index_url != prefix + "main/binary-" + item["arch"] + "/Packages.xz":
            raise ValueError("Unrecognized signed Packages index")
        local_release = lists / release_url.removeprefix("https://").replace("/", "_")
        if hashlib.sha256(local_release.read_bytes()).hexdigest() != release_hash:
            raise ValueError("Installed InRelease differs from the successful signed-index probe")
        clear = subprocess.check_output(["gpgv", "--keyring", "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                                         "--output", "-", str(local_release)], text=True)
        release = email.parser.Parser().parsestr(clear)
        records = {p: (digest, int(n)) for digest, n, p in
                   (row.split() for row in release["SHA256"].splitlines() if row.strip())}
        name = index_url.removeprefix(prefix)
        if (release["Suite"], release["Codename"], records[name][0]) != (pocket, "jammy", index_hash):
            raise ValueError("Signed Packages.xz SHA-256 differs from the probe")
        # APT often stores the index as LZ4. Hash the decoded local index against
        # the uncompressed Packages entry from exactly the same signed InRelease.
        local_stem = index_url.removesuffix(".xz").removeprefix("https://").replace("/", "_")
        hits = [lists / (local_stem + ext) for ext in ("", ".lz4", ".xz", ".gz", ".bz2", ".zst")
                if (lists / (local_stem + ext)).is_file()]
        if len(hits) != 1:
            raise ValueError("Ambiguous or absent local Packages list: " + local_stem)
        digest = hashlib.sha256()
        size = 0
        with subprocess.Popen(["/usr/lib/apt/apt-helper", "cat-file", str(hits[0])], stdout=subprocess.PIPE) as reader:
            for chunk in iter(lambda: reader.stdout.read(1024 * 1024), b""):
                digest.update(chunk)
                size += len(chunk)
            if reader.wait() != 0 or (digest.hexdigest(), size) != records[name.removesuffix(".xz")]:
                raise ValueError("Local Packages list does not match the probe's signed release")
        print(f"Verified {pocket} {name}, signed InRelease {release_hash}", flush=True)


if __name__ == "__main__":
    root = Path(sys.argv[2])
    receipts = json.loads((root / "receipts.json").read_text())
    if sys.argv[1] == "replay":
        replay(root, receipts)
    elif sys.argv[1] == "index":
        verify_indexes(receipts)
    else:
        raise SystemExit("Unknown receipt check")
SIX_RECEIVER_PY
cat > "$RUNNER_TEMP/verified-six/receipts.json" <<'SIX_VERIFIED_RECEIPTS'
{
  "pool/main/g/glibc/libc6-i386_2.35-0ubuntu3.15_amd64.deb": {
    "arch": "amd64",
    "bytes": 2837042,
    "index_sha256": "a7248f5209906b0bef40b8a2bfe76dccbb24ecf5049f68534184ef8e7981378b",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-amd64/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "libc6-i386",
    "route": "binary",
    "sha256": "79771324e20dc574aee8abc9a9993a4863847f1001d7cc4fe16345c110c80482",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/libc6-i386_2.35-0ubuntu3.15_amd64.deb",
    "version": "2.35-0ubuntu3.15"
  },
  "pool/main/g/glibc/libc6_2.35-0ubuntu3.15_i386.deb": {
    "arch": "i386",
    "bytes": 3012074,
    "index_sha256": "77a5369c2e817555e32c0f8b4c6dc682a431752f46130b93257f71d26bccce08",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-i386/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "libc6",
    "route": "binary",
    "sha256": "1eb59c77a26204391e01f5b339a4aa3805bb972230923398634b4bae72f0de16",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/libc6_2.35-0ubuntu3.15_i386.deb",
    "version": "2.35-0ubuntu3.15"
  },
  "pool/main/l/linux/linux-libc-dev_5.15.0-203.213_i386.deb": {
    "arch": "i386",
    "bytes": 1408846,
    "index_sha256": "77a5369c2e817555e32c0f8b4c6dc682a431752f46130b93257f71d26bccce08",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-i386/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "linux-libc-dev",
    "route": "binary",
    "sha256": "9549efbe71c34be03df091310b0b6e3e477a3a68cf4aa4d969a3b279a117f0ca",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/linux-libc-dev_5.15.0-203.213_i386.deb",
    "version": "5.15.0-203.213"
  },
  "pool/main/libc/libcpanel-json-xs-perl/libcpanel-json-xs-perl_4.27-1ubuntu0.2_amd64.deb": {
    "arch": "amd64",
    "bytes": 114566,
    "index_sha256": "a7248f5209906b0bef40b8a2bfe76dccbb24ecf5049f68534184ef8e7981378b",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-amd64/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "libcpanel-json-xs-perl",
    "route": "binary",
    "sha256": "c10796ff7f11ad279c95d670aa4f16bd62187992582fae28964502dbd3468ae3",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/libcpanel-json-xs-perl_4.27-1ubuntu0.2_amd64.deb",
    "version": "4.27-1ubuntu0.2"
  },
  "pool/main/r/ruby3.0/libruby3.0_3.0.2-7ubuntu2.13_amd64.deb": {
    "arch": "amd64",
    "bytes": 5116024,
    "index_sha256": "a7248f5209906b0bef40b8a2bfe76dccbb24ecf5049f68534184ef8e7981378b",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-amd64/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "libruby3.0",
    "route": "binary",
    "sha256": "2c975f8bfae64b53634170a720366e15c43a3b073fe5673dfd9eb59d5438de1d",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/libruby3.0_3.0.2-7ubuntu2.13_amd64.deb",
    "version": "3.0.2-7ubuntu2.13"
  },
  "pool/main/r/ruby3.0/ruby3.0_3.0.2-7ubuntu2.13_amd64.deb": {
    "arch": "amd64",
    "bytes": 50134,
    "index_sha256": "a7248f5209906b0bef40b8a2bfe76dccbb24ecf5049f68534184ef8e7981378b",
    "index_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/main/binary-amd64/Packages.xz",
    "inrelease_sha256": "38779968b85d8159f5cd5330a740c6a3c562a5bea87d5234d76a1eb36804b3e4",
    "inrelease_url": "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/dists/jammy-updates/InRelease",
    "package": "ruby3.0",
    "route": "binary",
    "sha256": "5069a4f9fe2f1784f7df8832afa2cebe90860355774f6c3185c32dc8040d7cda",
    "source": "launchpadlibrarian.net",
    "url": "https://launchpad.net/ubuntu/+archive/primary/+files/ruby3.0_3.0.2-7ubuntu2.13_amd64.deb",
    "version": "3.0.2-7ubuntu2.13"
  }
}
SIX_VERIFIED_RECEIPTS
python3 -I "$RUNNER_TEMP/verified-six/receive_six.py" replay "$RUNNER_TEMP/verified-six"
