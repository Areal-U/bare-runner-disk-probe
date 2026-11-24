"""Send/receive one bounded zstd checkpoint on the existing owner-only draft."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import quote, urlsplit

TEMP = Path(os.environ["RUNNER_TEMP"])
sys.path.insert(0, str(TEMP))
import transfer as api  # materialized from the verified prior PR9 workflow

PARENT = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
PARENT_KEY = "bare-coexist-204-45285202990-1-checkpoint-production-s2"
INPUT = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
PART = 2_000_000_000
TOTAL = 7 * 1024**3 // 2
CAMPAIGN = "r28-preflight-s2-20261125-v1"


def demand(yes, why):
    if not yes:
        raise ValueError(why)


def hashed(value):
    return bool(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))


def ctx():
    run = os.environ["GITHUB_RUN_ID"]
    sha = os.environ["TRIAL_SHA"]
    demand(re.fullmatch(r"[1-9][0-9]*", run) and re.fullmatch(r"[0-9a-f]{40}", sha), "Invalid generation")
    return {"campaign": CAMPAIGN, "source_sha": sha, "producer_run": int(run), "producer_attempt": 1,
            "segment": 1, "parent_sha": PARENT, "parent_identity": INPUT, "parent_cache_id": 11016400308,
            "parent_key": PARENT_KEY, "format": "tar.zst"}


def prefix():
    return f'{CAMPAIGN}-run{ctx()["producer_run"]}-a1-seg01-'


def source():
    query = f"?key={PARENT_KEY}&ref=refs%2Fheads%2Fbare-coexist-v2.0.4&per_page=100"
    resp = api.metadata(f"{api.BASE}/actions/caches" + query)
    rows = resp["actions_caches"]
    demand(resp["total_count"] == len(rows), "Incomplete cache response")
    exact = [r for r in rows if r["key"] == PARENT_KEY]
    demand(len(exact) == 1 and exact[0]["ref"] == "refs/heads/bare-coexist-v2.0.4"
           and exact[0]["id"] == 11016400308 and exact[0]["size_in_bytes"] == 2742685925,
           "Canonical parent is missing or changed")
    print(f'protected_s2_id=11016400308 outer=2742685925 version={exact[0]["version"]}')


def locate(name):
    assets = [a for a in api.draft(api.RELEASE_ID)["assets"] if a["name"] == name]
    demand(len(assets) <= 1, "Multiple identically named assets")
    return assets[0] if assets else None


class Section:
    def __init__(self, file, count):
        self.file = file
        self.left = count

    def read(self, requested=-1):
        if requested <= 0:
            requested = 1024**2
        block = self.file.read(min(self.left, requested))
        self.left -= len(block)
        return block


def upload(suffix, stream, offset, size, digest):
    name = prefix() + suffix
    logical = name
    # Retry only a known empty starter under a second physical name.
    # An ambiguous response is reconciled by ID/name/hash before another POST.
    for index in range(2):
        name = logical if index == 0 else logical + "-retry1"
        row = locate(name)
        if row is None:
            stream.seek(offset)
            try:
                conn, response = api.request(api.UPLOAD, "POST",
                    f"{api.BASE}/releases/{api.RELEASE_ID}/assets?name=" + quote(name),
                    auth=True, body=Section(stream, size), length=size, content_type="application/octet-stream")
                try:
                    status = response.status
                    response.read(65536)
                finally:
                    conn.close()
                demand(status in (201, 422, 502), f"Asset upload status {status}")
            except (OSError, api.http.client.HTTPException):
                pass
            for delay in (0, 2, 5):
                if delay:
                    time.sleep(delay)
                row = locate(name)
                if row:
                    break
            demand(row is not None, "Upload outcome unknown; keep original candidate and reconcile")
        if row["state"] == "starter" and row["size"] == 0:
            continue
        checked = api.asset_info(api.draft(api.RELEASE_ID), name, size, digest, row["id"])
        print(f"asset={checked['id']} bytes={size} sha256={digest}", flush=True)
        return {"name": name, "id": checked["id"], "bytes": size, "sha256": digest}
    raise ValueError("Both upload attempts have an empty starter")


def send():
    source()
    demand(os.environ["GITHUB_RUN_ATTEMPT"] == "1", "Only initial attempt may publish")
    file = TEMP / "r28-child.tar.zst"
    size = file.stat().st_size
    demand(0 < size <= TOTAL, "Total compressed size limit")
    base = TEMP / "bare-official/exchange/checkpoint"
    identity = json.loads((base / "child-provenance.json").read_text())["identity_sha256"]
    graph = (base / "graph-sha.txt").read_text().strip()
    demand(hashed(identity) and identity != INPUT and hashed(graph), "Incomplete graph/producer receipt")
    manifest = {**ctx(), "bytes": size, "identity": identity, "graph_sha": graph, "parts": []}
    with file.open("rb") as f:
        full = hashlib.sha256()
        for index, offset in enumerate(range(0, size, PART)):
            length = min(size-offset, PART)
            digest = hashlib.sha256()
            f.seek(offset)
            region = Section(f, length)
            while block := region.read():
                full.update(block)
                digest.update(block)
            demand(region.left == 0, "Short local candidate")
            manifest["parts"].append(upload(f"p{index:02}", f, offset, length, digest.hexdigest()))
        manifest["sha256"] = full.hexdigest()
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    receipt = upload("manifest.json", io.BytesIO(raw), 0, len(raw), hashlib.sha256(raw).hexdigest())
    print("manifest_receipt=" + json.dumps(receipt, sort_keys=True))
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        print("manifest_id=" + str(receipt["id"]), file=f)
        print("manifest_sha=" + receipt["sha256"], file=f)


def anonymous(row):
    url = urlsplit(row["browser_download_url"])
    demand(url.scheme == "https" and url.netloc == "github.com" and not url.query and not url.fragment
           and url.path.startswith("/" + api.REPO + "/releases/download/"), "Unexpected download URL")
    paths = [("github.com", url.path, "direct"),
             (api.API, f"{api.BASE}/releases/assets/{row['id']}", "api")]
    for host, path, label in paths:
        for i in range(4):
            until = api.anonymous_status(host, path, label)
            if until is None:
                break
            delay = max(0, until-int(time.time()))
            demand(i < 3 and delay <= 3900, "Anonymous access still unconfirmed")
            time.sleep(delay)


def receive():
    source()
    found = [row for suffix in ("manifest.json", "manifest.json-retry1")
             if (row := locate(prefix() + suffix)) and row["state"] == "uploaded"]
    demand(len(found) == 1, "Canonical completed manifest missing or ambiguous")
    row = found[0]
    expected_id = os.environ.get("MANIFEST_ID")
    expected_hash = os.environ.get("MANIFEST_SHA")
    demand(not expected_id or str(row["id"]) == expected_id, "Manifest ID differs from job output")
    digest = row["digest"].removeprefix("sha256:")
    demand(0 < row["size"] <= 12288 and hashed(digest) and (not expected_hash or digest == expected_hash),
           "Manifest digest differs")
    anonymous(row)
    raw = io.BytesIO()
    api.download(row["id"], row["size"], digest, raw)
    manifest = json.loads(raw.getvalue())
    demand(all(manifest.get(k) == v for k, v in ctx().items()), "Run, input, segment or source mismatch")
    size = manifest["bytes"]
    demand(type(size) == int and 0 < size <= TOTAL and hashed(manifest["sha256"]) and
           hashed(manifest["identity"]) and manifest["identity"] != INPUT and hashed(manifest["graph_sha"]),
           "Unbounded or unbound successor")
    parts = manifest["parts"]
    demand(isinstance(parts, list) and len(parts) == (size+PART-1)//PART and
           len(set(p["id"] for p in parts)) == len(parts), "Parts are incomplete or repeated")
    destination = TEMP / "r28-child.tar.zst"
    with destination.open("xb") as f:
        for index, part in enumerate(parts):
            wanted = prefix() + f"p{index:02}"
            demand(part["name"] in (wanted, wanted + "-retry1") and
                   part["bytes"] == min(PART, size-index*PART) and hashed(part["sha256"]), "Invalid part")
            row = api.asset_info(api.draft(api.RELEASE_ID), part["name"], part["bytes"], part["sha256"], part["id"])
            anonymous(row)
            api.download(part["id"], part["bytes"], part["sha256"], f)
        f.flush()
        os.fsync(f.fileno())
    demand(destination.stat().st_size == size and api.sha256_file(destination) == manifest["sha256"], "Reassembled content differs")
    (TEMP / "r28-child.json").write_bytes(raw.getvalue())
    print(f"independent_draft_read_id={found[0]['id']} archive_bytes={size} sha256={manifest['sha256']}")


if __name__ == "__main__":
    mode, = sys.argv[1:]
    {"parent": source, "send": send, "receive": receive}[mode]()
