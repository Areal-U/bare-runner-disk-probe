"""I/O helpers shared by the normal compiler, limited sender, and recipient."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit

REPO = "Areal-U/bare-runner-disk-probe"
RELEASE = 452114666
ROOT = Path(os.environ["RUNNER_TEMP"]) / "r28-normal"
CAP = 7 * 1024**3 // 2
PARENT_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
PARENT_IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
CDN = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}
GIB = 1024**3


def require(value, explanation):
    if not value:
        raise ValueError(explanation)


def env_int(key):
    value = os.environ[key]
    require(re.fullmatch("[1-9][0-9]*", value), key + " must be a positive integer")
    return int(value)


def sha(value):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value)


def digest(file):
    with file.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def output(**items):
    with open(os.environ["GITHUB_OUTPUT"], "a") as f:
        for key, value in items.items():
            require("\n" not in str(value), "Invalid multiline output")
            print(f"{key}={value}", file=f)


class ScopedHTTPError(ValueError):
    def __init__(self, status):
        self.status = status
        super().__init__(f"Scoped API returned HTTP {status}")


class TransientReadError(OSError):
    """A scoped GET could not establish whether the requested object exists."""


def api_json(path, expected=200, *, timeout=30):
    require(path == "/repos/" + REPO or path.startswith("/repos/" + REPO + "/"), "Unscoped API access")
    conn = http.client.HTTPSConnection("api.github.com", timeout=timeout)
    try:
        headers = {"User-Agent":"r28-split-reader/1", "Accept":"application/vnd.github+json",
                   "Authorization":"Bearer " + os.environ["GH_TOKEN"], "X-GitHub-Api-Version":"2022-11-28"}
        if os.environ.get("BARE_NEXT_FRESH_RUN_GATE") == "1" and "/actions/runs?status=" in path:
            headers["Cache-Control"] = "no-cache, max-age=0"
            conn.timeout = min(conn.timeout, 6)
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        limited = response.status == 403 and (
            response.getheader("X-RateLimit-Remaining") == "0" or bool(response.getheader("Retry-After")))
        if limited or response.status in (408, 429, 500, 502, 503, 504):
            raise TransientReadError(f"Scoped API temporarily returned HTTP {response.status}")
        if expected == "denied":
            require(response.status in (403,404), f"Ordinary job unexpectedly accessed private source (HTTP {response.status})")
            print("ordinary_draft_get_status=" + str(response.status))
            return {}
        if response.status != expected:
            raise ScopedHTTPError(response.status)
        raw = response.read(4*1024**2 + 1)
        require(len(raw) <= 4*1024**2, "Oversized page")
        return json.loads(raw)
    except (TimeoutError, ConnectionError, http.client.IncompleteRead, ssl.SSLEOFError) as error:
        raise TransientReadError("Scoped API connection interrupted") from error
    except socket.gaierror as error:
        if error.errno != socket.EAI_AGAIN:
            raise
        raise TransientReadError("Scoped API DNS temporarily unavailable") from error
    finally:
        conn.close()


def api_before(deadline):
    def get(path):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TransientReadError("Scoped GET deadline reached")
        return api_json(path, timeout=min(30, remaining))
    return get


def auth_api():
    sys.path.insert(0, os.environ["RUNNER_TEMP"])
    import transfer
    return transfer


def disk(stage, future=0):
    info = os.statvfs(ROOT)
    free = info.f_frsize * info.f_bavail
    print(f"disk_stage={stage} free={free} free_inodes={info.f_favail} incremental_reserved={future}", flush=True)
    require(free >= 20*GIB + future and info.f_favail >= 20000 + 20, "Trial disk floor not preserved")


def inventory():
    rows = []
    for page in range(1,51):
        listing = api_json(f"/repos/{REPO}/actions/artifacts?per_page=100&page={page}")
        batch = listing["artifacts"]
        rows.extend(batch)
        if len(batch)<100:
            require(len(rows)==listing["total_count"] and len({row["id"] for row in rows})==len(rows),
                    "Inconsistent repository artifact inventory")
            break
    else:
        raise ValueError("Unbounded artifact listing")
    active = sum(r["size_in_bytes"] for r in rows if not r["expired"])
    visible = sum(r["size_in_bytes"] for r in rows)
    print("repo_artifact_inventory="+json.dumps({"active_bytes":active,"all_visible_bytes":visible,
        "visible_expired_bytes":visible-active,"artifact_count":len(rows)}, separators=(",",":")))
    return rows


def openssl(*args, capture=False, timeout=500):
    return subprocess.run(["openssl",*map(str,args)],check=True,stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE,timeout=timeout).stdout


def fingerprint(key):
    require(key.is_file() and 0<key.stat().st_size<16384, "Unexpected certificate length")
    raw=key.read_bytes()
    require(raw.count(b"-----BEGIN CERTIFICATE-----")==1 and b"PRIVATE" not in raw, "Public certificate required")
    der=openssl("x509","-in",key,"-outform","DER",capture=True)
    return hashlib.sha256(der).hexdigest()


def keygen():
    sub="/CN=Bare R28 %d %s" % (env_int("GITHUB_RUN_ID"),os.environ["GITHUB_JOB"])
    openssl("req","-new","-x509","-newkey","rsa:3072","-keyout",ROOT/"key.pem","-out",ROOT/"public.pem",
            "-nodes","-sha256","-subj",sub,"-days","1")
    print("generated_ephemeral_public_fingerprint=" + fingerprint(ROOT/"public.pem"))


def encrypt(public, plain, sealed, *, timeout=500):
    fingerprint(public)
    openssl("cms","-encrypt","-binary","-stream","-outform","DER","-aes-256-gcm","-in",plain,"-out",sealed,
            "-recip",public,"-keyopt","rsa_padding_mode:oaep","-keyopt","rsa_oaep_md:sha256",timeout=timeout)


def decrypt(sealed, plain, *, timeout=500):
    openssl("cms","-decrypt","-inform","DER","-binary","-in",sealed,"-recip",ROOT/"public.pem",
            "-inkey",ROOT/"key.pem","-out",plain,timeout=timeout)


def endpoint(url):
    parsed=urlsplit(url)
    require(parsed.scheme=="https" and parsed.netloc in CDN and parsed.path.startswith("/") and
            parsed.query and not parsed.fragment,"Invalid restricted asset endpoint")
    return parsed
