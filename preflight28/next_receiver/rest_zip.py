"""Download one pre-identified small Actions Artifact, following only service redirects."""
import hashlib
import http.client
import io
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import tempfile
import time
from urllib.parse import urlsplit
import zipfile

import bridge

TRANSIENT = {404, 408, 425, 429, 500, 502, 503, 504}


def checked_host(url):
    parts = urlsplit(url)
    allowed = re.fullmatch(r"(?:[a-z0-9-]+\.blob\.core\.windows\.net|[a-z0-9.-]+\.actions\.githubusercontent\.com|objects\.githubusercontent\.com|release-assets\.githubusercontent\.com)", parts.netloc)
    bridge.require(parts.scheme == "https" and allowed and parts.path.startswith("/") and
                   not parts.fragment and parts.query, "Unexpected Artifact download redirect")
    return parts


def timeout(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("Artifact transfer deadline")
    return min(12.0, left)


def read_zip(row, deadline):
    ident, size = row["id"], row["size_in_bytes"]
    host = "api.github.com"
    path = f"/repos/{bridge.REPO}/actions/artifacts/{ident}/zip"
    headers = {"User-Agent": "bare-receiver-diagnostic", "Accept": "application/vnd.github+json",
               "Authorization": "Bearer " + os.environ["GH_TOKEN"], "X-GitHub-Api-Version": "2022-11-28"}
    for _ in range(4):
        connection = http.client.HTTPSConnection(host, timeout=timeout(deadline))
        try:
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status in TRANSIENT:
                raise bridge.TransientReadError(f"Artifact service HTTP {response.status}")
            if response.status in (301, 302, 303, 307, 308):
                parts = checked_host(response.getheader("Location") or "")
                host, path = parts.netloc, parts.path + "?" + parts.query
                headers = {"User-Agent": "bare-receiver-diagnostic"}
                continue
            bridge.require(response.status == 200, f"Artifact GET refused with HTTP {response.status}")
            length = response.getheader("Content-Length")
            bridge.require(length is None or length == str(size), "Archive Content-Length differs from receipt")
            data = bytearray()
            while len(data) <= size:
                if connection.sock is not None:
                    connection.sock.settimeout(timeout(deadline))
                else:
                    timeout(deadline)
                block = response.read1(min(65536, size + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
            if len(data) < size:
                raise bridge.TransientReadError("Incomplete immutable Artifact transfer")
            bridge.require(len(data) == size and "sha256:" + hashlib.sha256(data).hexdigest() == row["digest"],
                           "Immutable Artifact ZIP size or digest mismatch")
            return bytes(data)
        except ssl.SSLError:
            raise
        except (TimeoutError, ConnectionError, socket.gaierror, http.client.IncompleteRead) as exc:
            raise bridge.TransientReadError("Transient Artifact transport failure") from exc
        finally:
            connection.close()
    raise ValueError("Too many Artifact redirects")


def unpack(data, dest, names, limit):
    dest = Path(dest)
    bridge.require(not dest.exists(), "A previous download already occupies the destination")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=dest.parent) as tmp, zipfile.ZipFile(io.BytesIO(data)) as archive:
        staging = Path(tmp) / "decoded"
        staging.mkdir()
        entries = archive.infolist()
        bridge.require(len(entries) == len(names) and {i.filename for i in entries} == names and
                       all(not i.is_dir() and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG) and
                           0 < i.file_size <= limit for i in entries) and sum(i.file_size for i in entries) <= limit,
                       "Unexpected or oversized Artifact members")
        for item in entries:
            with archive.open(item) as source, (staging / item.filename).open("xb") as out:
                out.write(source.read(item.file_size))
        staging.rename(dest)
