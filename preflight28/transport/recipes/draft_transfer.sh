cat > "$RUNNER_TEMP/transfer.py" <<'ROUND26_REVIEWED_SOURCE_EOF'
"""Transfer the fixed 2.0.4 checkpoint using the owner-created, preflighted draft."""
import argparse
import io
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import tarfile
from tempfile import TemporaryDirectory
import time
from urllib.parse import quote, urlencode, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import checkpoint_parts as parts

REPO = "Areal-U/bare-runner-disk-probe"
OWNER = "Areal-U"
BASE = "/repos/" + REPO
DRAFT_TAG_SHA256 = "87e74b8d9cea507bbd968b4ef71a0f0398b7f1eb861a13b16ca8a54c16eae9bb"
DRAFT_TITLE = "Private checkpoint transport probe (25-s2)"
DRAFT_TARGETS = {"main", "7e82bca69557079315df4813effbe46c41644c0f"}
OWNER_ID = 292261483
PROBE_BYTES = 49
PROBE_SHA = "6d3adfcb254e849273bf1acb809da3e670b55706abda9e791798b2f4002a9055"
KEY = "bare-coexist-204-44477110657-1-checkpoint-production"
CACHE_ID = 10780907241
CACHE_BYTES = 2318534667
BYTES = 2328180957
SHA = "47c60e1b6c7e9d9668234a7ec3d6cedcf9ae041d1bb8e183c4c4630d40098b57"
IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
SAMPLE = "owner-storage-probe.txt"
RELEASE_ID = 452114666
PREFIX = "checkpoint-26-44477110657-1.tar.gz."
PARTS = ("part-00000", "part-00001")
NAMES = (*PARTS, "manifest.json")
API = "api.github.com"
UPLOAD = "uploads.github.com"
CDNS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
CHUNK = 1024 * 1024


class Invalid(Exception):
    pass


def require(value, message):
    if not value:
        raise Invalid(message)


def request(host, method, path, *, auth=False, accept="application/vnd.github+json",
            body=None, length=None, content_type=None):
    headers = {"Accept": accept, "User-Agent": "bare-private-checkpoint-trial/1"}
    if host in {API, UPLOAD}:
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if auth:
        require(host in {API, UPLOAD}, "Refusing authentication to asset host")
        token = os.environ.get("GH_TOKEN", "")
        require(token, "Job token missing")
        headers["Authorization"] = "Bearer " + token
    if length is not None:
        headers["Content-Length"] = str(length)
    if content_type:
        headers["Content-Type"] = content_type
    conn = http.client.HTTPSConnection(host, timeout=150, blocksize=CHUNK)
    try:
        conn.request(method, path, body, headers)
        return conn, conn.getresponse()
    except BaseException:
        conn.close()
        raise


def metadata(path, *, auth=True):
    conn, response = request(API, "GET", path, auth=auth)
    try:
        require(response.status == 200, f"GitHub metadata GET returned {response.status}")
        raw = response.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "Unexpectedly large metadata")
        return json.loads(raw)
    finally:
        conn.close()


def is_owner(user):
    return user.get("id") == OWNER_ID and user.get("login") == OWNER


def draft_matches(record, release_id=None):
    require(record["draft"] is True and record["published_at"] is None and
            record["name"] == DRAFT_TITLE and is_owner(record["author"]) and
            isinstance(record["id"], int) and record["id"] > 0 and
            (release_id is None or record["id"] == release_id),
            "Draft owner, name, numeric ID, or publication state changed")
    target = record["target_commitish"]
    tag = record["tag_name"]
    # The editor assigns an untagged-... permalink when the owner saves an
    # untagged draft. Accept an empty API tag only with that exact permalink.
    url = urlsplit(record.get("html_url") or "")
    prefix = f"/{REPO}/releases/tag/"
    permalink_tag = url.path[len(prefix):] if url.scheme == "https" and url.netloc == "github.com" and url.path.startswith(prefix) else ""
    def pinned_tag(value):
        return isinstance(value, str) and hashlib.sha256(value.encode()).hexdigest() == DRAFT_TAG_SHA256
    require(pinned_tag(tag) or (tag in (None, "") and pinned_tag(permalink_tag)),
            "Draft tag or permalink differs from the independently verified owner draft")
    require(target in DRAFT_TARGETS, "Draft target differs from the owner receipt")
    return record


def draft(release_id):
    require(release_id == RELEASE_ID, "Only the fixed release may be accessed")
    release = draft_matches(metadata(f"{BASE}/releases/{release_id}"), release_id)
    asset_info(release, SAMPLE, PROBE_BYTES, PROBE_SHA, 769833795)
    asset_info(release, "checkpoint-25-s2.tar.gz", 2042700560,
               "dd2177a80c72db7d0d6b558bec1fbd2c0acf448b28144d02dd26796104315413", 770240309)
    for item in release["assets"]:
        name = item["name"]
        if name.startswith(PREFIX):
            require(name[len(PREFIX):] in NAMES, "Unrecognized member for this generation")
        elif re.search(r"checkpoint[-_]?26|44477110657", name, re.I):
            raise Invalid("An alternative Round 26 receipt needs reconciliation")
    return release


def asset_info(release, name, size, digest, asset_id=None):
    items = [a for a in release["assets"] if a["name"] == name]
    require(len(items) == 1, "Expected one asset on this draft")
    asset = items[0]
    require(asset["state"] == "uploaded" and asset["size"] == size and
            asset.get("digest") == "sha256:" + digest and
            isinstance(asset["id"], int) and asset["id"] > 0 and
            (asset_id is None or asset["id"] == asset_id),
            "Draft asset receipt does not match")
    if name == SAMPLE:
        require(is_owner(asset.get("uploader") or {}), "Probe asset owner changed")
    return asset


def download(asset_id, size, expected_hash, destination):
    path = f"{BASE}/releases/assets/{asset_id}"
    conn, response = request(API, "GET", path, auth=True, accept="application/octet-stream")
    try:
        if response.status == 302:
            target = urlsplit(response.getheader("Location", ""))
            require(target.scheme == "https" and target.netloc in CDNS and
                    target.path.startswith("/") and not target.fragment, "Unrecognized asset redirect")
            conn.close()
            # Signed URL is consumed in memory. Never send the repository token to a CDN.
            conn, response = request(target.netloc, "GET", target.path + ("?" + target.query if target.query else ""),
                                     accept="application/octet-stream")
        require(response.status == 200, f"Asset retrieval returned {response.status}")
        found = 0
        digest = hashlib.sha256()
        while block := response.read(CHUNK):
            found += len(block)
            require(found <= size, "Download exceeded expected length")
            digest.update(block)
            if destination is not None:
                destination.write(block)
        require(found == size and digest.hexdigest() == expected_hash, "Retrieved asset bytes differ")
    finally:
        conn.close()


def archive_identity(path):
    with tarfile.open(path, mode="r|gz") as archive:
        for member in archive:
            if member.name.removeprefix("./") != "out/Bare/checkpoint-provenance.json":
                continue
            require(member.isfile() and 0 < member.size <= 1024 * 1024, "Invalid provenance member")
            with archive.extractfile(member) as stream:
                provenance = json.load(stream)
            require(provenance["identity_sha256"] == IDENTITY, "Incorrect checkpoint input identity")
            return
    raise Invalid("Checkpoint provenance was absent")


def source_receipt():
    query = urlencode({"key": KEY, "ref": "refs/heads/bare-coexist-v2.0.4", "per_page": 100})
    result = metadata(f"{BASE}/actions/caches?{query}")
    entries = [r for r in result["actions_caches"] if r["key"] == KEY]
    require(result["total_count"] == len(result["actions_caches"]) and len(entries) == 1 and
            entries[0]["id"] == CACHE_ID and entries[0]["size_in_bytes"] == CACHE_BYTES and
            entries[0]["ref"] == "refs/heads/bare-coexist-v2.0.4", "Original cache receipt differs")
    require(os.environ.get("MATCHED_CACHE_KEY") == KEY, "Restore action did not report the exact key")


def rate_reason(response):
    # Print only a known classification. Never echo an error body, IP address, or redirect.
    try:
        raw = response.read(4097)
        if len(raw) > 4096:
            return "unclassified"
        body = json.loads(raw)
    except (OSError, http.client.HTTPException, ValueError, RecursionError):
        return "unclassified"
    message = body.get("message") if isinstance(body, dict) else None
    if not isinstance(message, str):
        return "unclassified"
    if message.startswith("API rate limit exceeded"):
        return "primary_rate_limit"
    if message.startswith(("You have exceeded a secondary rate limit", "You have triggered an abuse detection mechanism")):
        return "secondary_rate_limit"
    if message.removesuffix(".") == "Resource not accessible by integration":
        return "integration_access_denied"
    return "unclassified"


def rate_deadline(response, reason, now):
    remaining = response.getheader("X-RateLimit-Remaining")
    reset = response.getheader("X-RateLimit-Reset")
    retry = response.getheader("Retry-After")
    if any(value is not None and not re.fullmatch(r"[0-9]{1,12}", value) for value in (remaining, reset, retry)):
        return None
    if reason == "primary_rate_limit":
        if remaining != "0" or reset is None or int(reset) < now:
            return None
    elif reason == "secondary_rate_limit":
        if retry is None or int(retry) <= 0 or (remaining == "0" and reset is None):
            return None
    else:
        return None
    # A reset for a nonempty quota need not be reached, unless GitHub has also asked for a longer delay.
    reset_at = int(reset) if remaining == "0" and reset else 0
    return max(reset_at, now + int(retry or 0)) + 5


def anonymous_status(host, path, label):
    conn, response = request(host, "GET", path, accept="application/octet-stream")
    try:
        status = response.status
        location = response.getheader("Location") is not None
        reason = rate_reason(response) if host == API and status in (403, 429) and not location else "unclassified"
        print(f"anonymous_{label}={status} location_present={location} reason={reason}", flush=True)
        if status == 404 and not location:
            return None
        if host == API and status in (403, 429) and not location:
            deadline = rate_deadline(response, reason, int(time.time()))
            if deadline is not None:
                return deadline
        raise Invalid(f"Anonymous {label} did not return a nonredirecting 404")
    finally:
        conn.close()




def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_one(release, suffix, path, digest):
    require(suffix in NAMES, "Unrecognized upload")
    size = path.stat().st_size
    if suffix in PARTS:
        expected_sizes = (parts.PART_BYTES, BYTES - parts.PART_BYTES)
        require(size == expected_sizes[PARTS.index(suffix)], "Unexpected part size")
    else:
        require(0 < size < 4096, "Unexpected manifest size")
    name = PREFIX + suffix
    if any(item["name"] == name for item in release["assets"]):
        return asset_info(release, name, size, digest)["id"], "reused"
    endpoint = f"{BASE}/releases/{RELEASE_ID}/assets?name=" + quote(name)
    with path.open("rb") as stream:
        conn, response = request(UPLOAD, "POST", endpoint, auth=True, body=stream,
                                 length=size, content_type="application/octet-stream")
        try:
            if response.status == 422:  # Possible concurrent writer. Match its exact receipt.
                return asset_info(draft(RELEASE_ID), name, size, digest)["id"], "reused"
            require(response.status == 201, f"Upload HTTP {response.status}")
            result = json.loads(response.read(128 * 1024))
        finally:
            conn.close()
    return asset_info(draft(RELEASE_ID), name, size, digest, result["id"])["id"], "created"


def sender(temp):
    release = draft(RELEASE_ID)
    source_receipt()
    src = temp / "bare-official/exchange/checkpoint/checkpoint.tar.gz"
    archive_identity(src)
    with TemporaryDirectory(dir=temp, prefix="round26-send-") as local:
        split = Path(local) / "parts"
        parts.split(src, split, BYTES, SHA, IDENTITY, KEY)
        manifest = json.loads((split / "manifest.json").read_text())
        digests = [p["sha256"] for p in manifest["parts"]] + [sha256_file(split / "manifest.json")]
        # Precheck all existing names before uploading any missing name.
        for name, digest in zip(NAMES, digests, strict=True):
            if any(item["name"] == PREFIX + name for item in release["assets"]):
                asset_info(release, PREFIX + name, (split / name).stat().st_size, digest)
        result = []
        for name, digest in zip(NAMES, digests, strict=True):
            id_, state = write_one(draft(RELEASE_ID), name, split / name, digest)
            print(f"release={RELEASE_ID} {name} asset={id_} {state} "
                  f"bytes={(split / name).stat().st_size} sha256={digest}", flush=True)
            result.append(id_)
        release = draft(RELEASE_ID)
        for name, id_, digest in zip(NAMES, result, digests, strict=True):
            asset_info(release, PREFIX + name, (split / name).stat().st_size, digest, id_)
        with open(os.environ["GITHUB_OUTPUT"], "a") as outputs:
            print("asset_ids=" + ",".join(map(str, result)), file=outputs)
            print("manifest_sha=" + digests[-1], file=outputs)


def receipts():
    ids = os.environ["ARCHIVE_ASSET_IDS"]
    require(re.fullmatch(r"[1-9][0-9]{0,18}(,[1-9][0-9]{0,18}){2}", ids), "Invalid sender asset IDs")
    asset_ids = list(map(int, ids.split(",")))
    require(len(set(asset_ids)) == len(NAMES), "Repeated sender asset IDs")
    manifest_sha = os.environ["ARCHIVE_MANIFEST_SHA"]
    require(re.fullmatch("[a-f0-9]{64}", manifest_sha), "Invalid sender manifest digest")
    release = draft(RELEASE_ID)
    name = PREFIX + "manifest.json"
    items = [item for item in release["assets"] if item["name"] == name]
    require(len(items) == 1 and 0 < items[0]["size"] < 4096, "Wrong manifest size")
    info = asset_info(release, name, items[0]["size"], manifest_sha, asset_ids[-1])
    data = io.BytesIO()
    download(info["id"], info["size"], manifest_sha, data)
    manifest = json.loads(data.getvalue())
    require(manifest["version"] == 1 and manifest["generation"] == KEY and
            manifest["archive_sha256"] == SHA and manifest["input_identity"] == IDENTITY and
            manifest["archive_bytes"] == BYTES and manifest["part_bytes"] == parts.PART_BYTES and
            [p["name"] for p in manifest["parts"]] == list(PARTS), "Wrong received manifest")
    objects = []
    for index, part in enumerate(manifest["parts"]):
        size = min(parts.PART_BYTES, BYTES - index * parts.PART_BYTES)
        require(part["bytes"] == size and re.fullmatch("[a-f0-9]{64}", part["sha256"]),
                "Wrong received part descriptor")
        objects.append(asset_info(release, PREFIX + part["name"], size, part["sha256"], asset_ids[index]))
    return data.getvalue(), objects, info


def receive(temp):
    data, objects, manifest_asset = receipts()
    out = temp / "round26-received.tar.gz"
    with TemporaryDirectory(dir=temp, prefix="round26-recv-") as local:
        split = Path(local)
        (split / "manifest.json").write_bytes(data)
        for name, asset in zip(PARTS, objects, strict=True):
            with (split / name).open("xb") as stream:
                download(asset["id"], asset["size"], asset["digest"].removeprefix("sha256:"), stream)
        parts.join(split, out, BYTES, SHA, IDENTITY, KEY)
    archive_identity(out)
    release = draft(RELEASE_ID)
    for asset in [*objects, manifest_asset]:
        asset_info(release, asset["name"], asset["size"], asset["digest"].removeprefix("sha256:"), asset["id"])
    print(f"release={RELEASE_ID} asset_ids={os.environ['ARCHIVE_ASSET_IDS']} "
          f"verified_archive_bytes={BYTES} sha256={SHA} identity={IDENTITY}", flush=True)


def privacy():
    _, objects, manifest = receipts()
    budget_end = time.monotonic() + 7800
    for asset in [*objects, manifest]:
        ref = urlsplit(asset["browser_download_url"])
        require(ref.scheme == "https" and ref.netloc == "github.com" and
                ref.path.startswith("/" + REPO + "/releases/download/") and
                ref.path.endswith("/" + asset["name"]) and not ref.query and not ref.fragment,
                "Unexpected direct asset URL")
        anonymous_status("github.com", ref.path, "direct")
        for attempt in range(4):
            deadline = anonymous_status(API, f"{BASE}/releases/assets/{asset['id']}", "asset_api")
            if deadline is None:
                break
            delay = max(0, deadline - int(time.time()))
            require(attempt < 3 and time.monotonic() + delay <= budget_end, "Anonymous API retry budget exhausted")
            print(f"asset_id={asset['id']} retry_at_epoch={deadline} wait_seconds={delay}", flush=True)
            time.sleep(delay)
        asset_info(draft(RELEASE_ID), asset["name"], asset["size"],
                   asset["digest"].removeprefix("sha256:"), asset["id"])
        print(f"private_asset_verified={asset['id']} release_id={RELEASE_ID}", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("stage", choices=("send", "receive", "privacy"))
    args = parser.parse_args()
    require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_ACTOR") == OWNER and
            os.environ.get("GITHUB_TRIGGERING_ACTOR") == OWNER, "Unexpected repository or actor")
    if args.stage == "privacy":
        privacy()
    elif args.stage == "send":
        sender(Path(os.environ["RUNNER_TEMP"]))
    else:
        receive(Path(os.environ["RUNNER_TEMP"]))


if __name__ == "__main__":
    try:
        main()
    except Invalid as exc:
        sys.exit(str(exc))
    except Exception as exc:
        sys.exit("Transfer interrupted: " + type(exc).__name__)
ROUND26_REVIEWED_SOURCE_EOF
