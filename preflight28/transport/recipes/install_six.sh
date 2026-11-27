cat > "$RUNNER_TEMP/round26-pool-install.py" <<'SIGNED_APT_POOL_PY'
"""Install the pinned Chromium dependency plan using public, integrity-matched Ubuntu pool objects."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote, unquote, urlsplit
import http.client
import json
import os
import re
import runpy
import shlex
import subprocess
import sys
import time

SNAP = "https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/"
REV = "800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6"
ALLOWED_POOL = re.compile(r"pool/(main|universe|restricted|multiverse)/[a-z0-9]+/[a-z0-9][a-z0-9+.\-]*/[a-zA-Z0-9.+~_%:\-]+\.deb")
DEB_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+~_%:\-]*\.deb")

# Keep the accepted receipts for all six separately staged packages intact.
SIX_RECEIPTS_SHA256 = "0e07cf7378adb98e54164297bbfee7ed4e884b3d1a62ceef8e8b572bbe703fb3"

# Retain the two additional receipt pins from the earlier expat repair.
EXPAT_SNAPSHOT = {
    "pool/main/e/expat/libexpat1-dev_2.4.7-1ubuntu0.9_amd64.deb": (
        "libexpat1-dev", "2.4.7-1ubuntu0.9", "amd64", 151246,
        "5ed152003cdb6e840985d41a5fbc72a72dfe2e92e187d57b66052de3ea8ee2cd"),
    "pool/main/e/expat/libexpat1_2.4.7-1ubuntu0.9_i386.deb": (
        "libexpat1", "2.4.7-1ubuntu0.9", "i386", 98396,
        "9318c7c4cb706b3db32f31d4236be469f9e2f0533b4a003146fac7dc9870bc64"),
}

def fail(reason):
    raise ValueError(reason)

def checked(cmd):
    return subprocess.check_output(cmd, text=True).strip()

def fields(lines):
    record = {}
    for line in lines:
        line = line.rstrip("\n")
        if not line:
            if record:
                yield record
                record = {}
        elif not line[0].isspace() and ": " in line:
            key, value = line.split(": ", 1)
            record[key] = value
    if record:
        yield record

def requested(lines):
    plan = {}
    for line in lines.splitlines():
        if not line.startswith("'"):
            continue
        uri, dest, size, _hash = shlex.split(line)
        path = unquote(uri.removeprefix(SNAP))
        if not uri.startswith(SNAP) or urlsplit(uri).query or not ALLOWED_POOL.fullmatch(path) or not DEB_NAME.fullmatch(dest):
            fail("Unrecognized package URI or local cache filename in APT transaction: " + uri)
        item = (dest, int(size))
        if item[1] <= 0 or (path in plan and plan[path] != item):
            fail("Conflicting APT transaction entry")
        plan[path] = item
    if len(plan) != len({v[0] for v in plan.values()}):
        fail("Conflicting APT destination filenames")
    return plan

def records_for(plan):
    targets = list(fields(checked(["apt-get","indextargets"]).splitlines()))
    package_indexes = [t for t in targets if t.get("Identifier") == "Packages"]
    if not package_indexes:
        fail("No verified APT Packages indexes")
    records = {}
    for target in package_indexes:
        index = Path(target["Filename"])
        if target.get("Trusted") != "yes" or not target["URI"].startswith(SNAP+"dists/") or index.parent != Path("/var/lib/apt/lists"):
            fail("Repository outside the exact trusted snapshot: "+target.get("URI","?"))
        with subprocess.Popen(["/usr/lib/apt/apt-helper","cat-file",str(index)],stdout=subprocess.PIPE,text=True) as proc:
            for rec in fields(proc.stdout):
                path = rec.get("Filename")
                if path not in plan:
                    continue
                record = (rec["Package"], rec["Version"], rec["Architecture"], int(rec["Size"]), rec["SHA256"])
                if record[2] not in ("amd64","i386","all") or not re.fullmatch(r"[0-9a-f]{64}",record[4]) or record[3] != plan[path][1]:
                    fail("Signed package metadata does not match APT transaction: " + path)
                if path in records and records[path] != record:
                    fail("Conflicting signed package metadata: " + path)
                records[path] = record
            if proc.wait():
                fail("Failed to read signed Packages data")
    if records.keys() != plan.keys():
        fail("Missing signed records: " + str(sorted(plan.keys()-records.keys())))
    return records

def download(host, path, record, dest):
    with open(dest,"wb") as f:
        con = http.client.HTTPSConnection(host, timeout=35)
        try:
            # Use the official pool's path; credentials and cross-host redirects are unnecessary.
            base_path = "/ubuntu/"
            if host == "snapshot.ubuntu.com":
                if not ALLOWED_POOL.fullmatch(path):
                    fail("Unrecognized fixed snapshot pool path")
                base_path = urlsplit(SNAP).path
            url = base_path + quote(path, safe="/+.~_:-")
            con.request("GET",url,headers={"User-Agent":"bare-checkpoint-dependency-readback"})
            response = con.getresponse()
            if response.status != 200:
                return f"HTTP {response.status}"
            digest = sha256()
            total = 0
            while block := response.read(512*1024):
                total += len(block)
                if total > record[3]:
                    fail("Oversized public package: " + path)
                f.write(block)
                digest.update(block)
        finally:
            con.close()
    if (total, digest.hexdigest()) != (record[3], record[4]):
        fail("Size/SHA256 mismatch for " + host + "/" + path)
    for field, expected in zip(("Package","Version","Architecture"),record[:3]):
        if checked(["dpkg-deb","-f",str(dest),field]) != expected:
            fail(f"Public package {field} differs from signed index: {path}")
    return "verified"

def acquire(args):
    path,record,dest = args
    status = []
    if path in EXPAT_SNAPSHOT and EXPAT_SNAPSHOT[path] != record:
        fail("Pinned expat record differs from signed APT index: " + path)
    # Every remote task comes from records_for(plan), excluding the staged six.
    # Use the same signed snapshot when its ordinary pool object has disappeared.
    for host in ("archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com"):
        try:
            result = download(host,path,record,dest)
        except (OSError,http.client.HTTPException) as exc:
            result = type(exc).__name__
        if result == "verified":
            if host == "snapshot.ubuntu.com":
                print("Read exact signed package from the fixed snapshot: " + path, flush=True)
            return None
        status.append(host+"="+result)
    return (path, *status)

def fixed_receipts(staged):
    receipt_bytes = (staged / "receipts.json").read_bytes()
    if sha256(receipt_bytes).hexdigest() != SIX_RECEIPTS_SHA256:
        fail("Different fixed six package receipts")
    return json.loads(receipt_bytes)

def main():
    os.environ["LC_ALL"] = "C"
    source = "build/install-build-deps.py"
    if checked(["git","rev-parse","HEAD"]) != REV or checked(["git","hash-object",source]) != checked(["git","rev-parse",REV+":"+source]):
        fail("Chromium dependency resolver differs from the reviewed revision")
    # Start from this new runner's signed release indexes; the apt repository
    # configuration comes from the fixed image build above.
    apt_dir = Path("/etc/apt")
    for src in [apt_dir/"sources.list", *(apt_dir/"sources.list.d").glob("*.list"), *(apt_dir/"sources.list.d").glob("*.sources")]:
        if not src.exists():
            continue
        for line in src.read_text().splitlines():
            stripped = line.split("#",1)[0].strip()
            if stripped and (not stripped.startswith(("deb ","deb-src ")) or not stripped.split()[1].rstrip("/")+"/" == SNAP):
                fail("Unexpected APT source; need only the fixed snapshot")
    module = runpy.run_path(source)
    options = module["parse_args"](["--android","--no-prompt"])
    for check in ["check_lsb_release","check_architecture","check_root"]:
        module[check]()
    module["check_distro"](options)
    module["quick_check"](options)
    if options.lib32 or options.backwards_compatible:
        subprocess.run(["sudo","dpkg","--add-architecture","i386"],check=True)
    staged = Path("/exchange/verified-six")
    receipts = fixed_receipts(staged)
    subprocess.run(["python3", "-I", str(staged / "receive_six.py"), "index", str(staged)], check=True)

    packages = module["find_missing_packages"](options)
    if packages:
        base = ["apt-get","--allow-downgrades","--assume-yes"]
        plan = requested(checked([*base,"--print-uris","--download-only","install",*packages]))
        records = records_for(plan)
        if not set(receipts) <= records.keys():
            fail("The six fixed packages no longer match the APT install plan")
        for path, entry in receipts.items():
            receipt = (entry["package"],entry["version"],entry["arch"],entry["bytes"],entry["sha256"])
            if records[path] != receipt:
                fail("Local signed APT plan differs from accepted evidence for " + path)
        total = sum(r[3] for r in records.values())
        print(f"Signed snapshot plan: {len(plan)} downloadable files, {total} bytes, {len(packages)} install arguments",flush=True)
        with TemporaryDirectory(prefix="bare-signed-pool-") as tmp:
            destination = Path(tmp)
            tasks = [(p,records[p],destination/plan[p][0]) for p in sorted(plan)]
            for path, entry in receipts.items():
                local = staged / Path(path).name
                if local.is_symlink() or not local.is_file():
                    fail("Missing staged file: " + path)
                data = local.read_bytes()
                if (len(data),sha256(data).hexdigest()) != (entry["bytes"],entry["sha256"]):
                    fail("Staged bytes changed: " + path)
                (destination / plan[path][0]).write_bytes(data)
            remote = [task for task in tasks if task[0] not in receipts]
            with ThreadPoolExecutor(max_workers=8) as pool:
                missing = [result for result in pool.map(acquire,remote) if result is not None]
            if missing:
                print(json.dumps({"failure":"unavailable exact files at official public pools","count":len(missing),"files":missing},sort_keys=True),flush=True)
                sys.exit(1)
            if tasks:
                subprocess.run(["sudo","cp","--",*(str(t[2]) for t in tasks),"/var/cache/apt/archives/"],check=True)
        # APT still controls package installation and dependency resolution; disallow
        # any transport back to the original archive or installation of an unsigned item.
        subprocess.run(["sudo","DEBIAN_FRONTEND=noninteractive",*base,"--no-download","-o","APT::Get::AllowUnauthenticated=false","-qq","install",*packages],check=True)
        for name,version,arch,size,digest in set(records.values()):
            package = name if arch == "all" else name+":"+arch
            actual = checked(["dpkg-query","-W","-f=${db:Status-Status} ${Version} ${Architecture}",package])
            if actual != f"installed {version} {arch}":
                fail(f"Unmatched installed package: {package} {actual}")
        print(f"Installed and verified the sealed APT transaction using {len(plan)} exact pool files.",flush=True)
    module["install_chromeos_fonts"](options)
    module["install_locales"]()

if __name__ == "__main__":
    main()
SIGNED_APT_POOL_PY
