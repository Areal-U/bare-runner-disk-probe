"""Stage a signed worker packet on the fixed private Draft, then acknowledge its exact cache."""
import hashlib
import http.client
import io
import json
import os
import re
import time

import bridge as b
import normal
import owner_recovery
import checkpoint_packets as packets


MANIFEST_SCHEMA = "bare-personal-209-private-packet-v1"
STATE_FIELDS = ("id", "key", "ref", "version", "size_in_bytes")


def suffix(index):
    return f"packet-{index:03}"


def raw(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")


def check_outcome(outcome):
    b.require(isinstance(outcome, dict) and normal.same(outcome), "Foreign packet outcome")
    base = set(normal.context()) | {"status"}
    if outcome.get("status") in normal.STOPS:
        b.require(set(outcome) == base, "Unexpected control outcome fields")
        return
    b.require(set(outcome) == base | {"bytes", "sha256", "identity", "proof_sha", "sealed_bytes", "sealed_sha",
                                       "recipient_fpr", "owner_recovery"}
              and outcome["status"] == "candidate" and type(outcome["bytes"]) is int
              and type(outcome["sealed_bytes"]) is int and 0 < outcome["bytes"] <= b.CAP
              and outcome["bytes"] < outcome["sealed_bytes"] <= outcome["bytes"] + 16 * 1024**2
              and all(b.sha(outcome[k]) for k in ("sha256", "identity", "proof_sha", "sealed_sha"))
              and outcome["sha256"] != outcome["parent_sha"]
              and b.fingerprint(normal.ROOT / "public.pem") == outcome["recipient_fpr"],
              "Mismatched ciphertext or private receiver generation")
    owner_recovery.checked(outcome["owner_recovery"], normal.context(), os.environ["R28_OWNER_RECIPIENT"],
                           b.env_int("R28_COLLECTION_CLAIM"), outcome["recipient_fpr"])
    b.require(outcome["owner_recovery"] == normal.info()["owner_recovery"], "Foreign owner recovery envelope")


def identity(row, index):
    b.require(isinstance(row, dict) and all(k in row for k in STATE_FIELDS)
              and type(row["id"]) is int and row["id"] > 0 and row["key"] == packets.key(index)
              and row["ref"] == os.environ["GITHUB_REF"] and isinstance(row["version"], str)
              and re.fullmatch("[0-9a-f]{64}", row["version"])
              and type(row["size_in_bytes"]) is int and 0 < row["size_in_bytes"] <= packets.archive_bound(packets.PACKET_BYTES),
              "Foreign physical packet cache")
    return {k: row[k] for k in STATE_FIELDS}


def delete_exact(api, index, saved, deadline):
    """Reconcile absent/deleted IDs and never delete by prefix, name, or a replacement ID."""
    key = packets.key(index)
    current = packets.exact(key, deadline)
    if current is None:
        return
    b.require(identity(current, index) == saved and time.time() < deadline, "Packet changed before exact cleanup")
    cache_id = saved["id"]
    try:
        conn, response = api.request(api.API, "DELETE", f"/repos/{b.REPO}/actions/caches/{cache_id}", auth=True)
        try:
            status = response.status
        finally:
            conn.close()
    except (OSError, http.client.HTTPException):
        status = None  # The service may have committed the delete before losing its reply.
    b.require(status in (None, 204, 404, 408, 429, 500, 502, 503, 504), f"Exact packet cleanup returned HTTP {status}")
    for delay in (0, 1, 2, 4, 8):
        b.require(time.time() + delay < deadline, "Exact packet cleanup verification timed out")
        if delay:
            time.sleep(delay)
        current = packets.exact(key, deadline)
        if current is None:
            return
        b.require(identity(current, index) == saved, "Replacement cache appeared during exact cleanup")
    raise b.TransientReadError("Deleted packet is still listed; reconcile its immutable ID")


def record_bytes(api, row):
    b.require(type(row["size"]) is int and 0 < row["size"] <= 96 * 1024
              and isinstance(row["digest"], str) and row["digest"].startswith("sha256:")
              and b.sha(row["digest"][7:]), "Unbounded private packet receipt")
    buf = io.BytesIO()
    api.download(row["id"], row["size"], row["digest"][7:], buf)
    return buf.getvalue()


def reserve(rel, index, piece):
    # Each new private asset may need the one permitted residue-recovery name.
    count = piece["count"]
    names = [name for number in range(index, count) for name in (suffix(number), suffix(number) + ".json")]
    if piece["outcome"]["status"] == "candidate":
        parts = (piece["outcome"]["bytes"] + normal.PART - 1) // normal.PART
        names += ["intent.json", "manifest.json", *(f"p{i:02}" for i in range(parts))]
    names.append("packet-outcome.json")
    remaining = sum(normal.existing(rel, name) is None for name in names)
    b.require(len(rel["assets"]) + 2 * remaining <= 1000, "Private Draft lacks packet and final publication slots")


class Receiver:
    """One instance per normal.wait. Missing packets never advance the caller."""
    def __init__(self):
        b.require(normal.R209 and os.environ.get("GITHUB_JOB") == "draft-publisher", "Unexpected packet receiver job")
        self.api = b.auth_api()
        self.deadline = normal.sender_deadline(normal.info())
        self.index = 0
        self.outcome = None
        self.count = None
        self.received = 0
        self.ready = False

    def read_data(self, piece, data):
        """Full independent private GET before ACK. Repeated reads replace the same bytes."""
        outcome = piece["outcome"]
        if outcome["status"] != "candidate":
            seen = io.BytesIO()
            self.api.download(data["id"], data["bytes"], data["sha256"], seen)
            b.require(json.loads(seen.getvalue()) == piece, "Private control record differs")
            return
        size = outcome["sealed_bytes"]
        if self.index == 0:
            b.disk("before-private-packet-assembly", size + 16 * 1024**2)
        partial = normal.ROOT / "checkpoint-packets.partial"
        with partial.open("w+b" if self.index == 0 else "r+b") as dest:
            dest.seek(0, os.SEEK_END)
            b.require(piece["offset"] == self.received and dest.tell() >= self.received,
                      "Gap in checkpoint packet assembly")
            dest.seek(self.received)
            dest.truncate()
            self.api.download(data["id"], data["bytes"], data["sha256"], dest)
            b.require(dest.tell() == self.received + piece["bytes"], "Incomplete private packet readback")

    def check_piece(self, piece, data):
        outcome = piece["outcome"]
        check_outcome(outcome)
        candidate = outcome["status"] == "candidate"
        total = outcome["sealed_bytes"] if candidate else 0
        count = max(1, (total + packets.PACKET_BYTES - 1) // packets.PACKET_BYTES)
        offset = self.index * packets.PACKET_BYTES
        b.require(all(type(piece[k]) is int for k in ("index", "claim", "count", "offset", "bytes"))
                  and piece["index"] == self.index and piece["claim"] == b.env_int("R28_COLLECTION_CLAIM")
                  and piece["offset"] == offset == self.received and piece["count"] == count
                  and piece["bytes"] == min(total - offset, packets.PACKET_BYTES) and b.sha(piece["sha256"])
                  and (self.outcome is None or self.outcome == outcome), "Missing, changed or out-of-order packet")
        if data is not None:
            bound = normal.existing(normal.list_private(self.api), suffix(self.index))
            b.require(bound and data["name"] == bound["name"] and data["id"] == bound["id"]
                      and (not candidate or (data["bytes"], data["sha256"]) == (piece["bytes"], piece["sha256"])),
                      "Private stage receipt differs from packet")
        self.outcome, self.count = outcome, count

    def deposit(self, row, piece):
        self.check_piece(piece, None)
        reserve(normal.list_private(self.api), self.index, piece)
        if self.index == 0:
            # normal.seal and normal.stop both use json.dumps(sort_keys=True).
            original = json.dumps(self.outcome, sort_keys=True).encode("ascii")
            digest = hashlib.sha256(original).hexdigest()
            saved = normal.put("packet-outcome.json", io.BytesIO(original), 0, len(original), digest)
            row_outcome = normal.existing(normal.list_private(self.api), "packet-outcome.json")
            b.require(row_outcome and row_outcome["id"] == saved["id"]
                      and record_bytes(self.api, row_outcome) == original, "Private owner outcome readback differs")
        folder = packets.folder("packet")
        candidate = self.outcome["status"] == "candidate"
        path = folder / ("piece.bin" if candidate else "piece.json")
        sha = piece["sha256"] if candidate else b.digest(path)
        size = piece["bytes"] if candidate else path.stat().st_size
        with path.open("rb") as source:
            stage = normal.put(suffix(self.index), source, 0, size, sha)
        self.check_piece(piece, stage)
        self.read_data(piece, stage)
        manifest = dict(schema=MANIFEST_SCHEMA, release=b.RELEASE, piece=piece, cache=identity(row, self.index), stage=stage)
        rec = normal.put_json(suffix(self.index) + ".json", manifest)
        rel = normal.list_private(self.api)
        private = normal.existing(rel, suffix(self.index) + ".json")
        b.require(private and rec["id"] == private["id"] and record_bytes(self.api, private) == raw(manifest),
                  "Missing or changed durable private packet receipt")
        return manifest

    def recover(self, row):
        manifest = json.loads(record_bytes(self.api, row))
        b.require(manifest.get("schema") == MANIFEST_SCHEMA and manifest.get("release") == b.RELEASE,
                  "Foreign private packet receipt")
        piece, stage = manifest["piece"], manifest["stage"]
        identity(manifest["cache"], self.index)
        self.check_piece(piece, stage)
        self.api.asset_info(normal.list_private(self.api), stage["name"], stage["bytes"], stage["sha256"], stage["id"])
        self.read_data(piece, stage)
        return manifest

    def poll(self):
        if self.ready:
            return True
        b.require(time.time() < self.deadline, "Packet receiver cutoff reached")
        i = self.index
        row = packets.exact(packets.key(i), self.deadline)
        # Reconcile private stage after an unknown ACK result or local step restart. A completed
        # packet can legitimately have no transient cache left. Do the private scan once per index.
        if row is None and getattr(self, "last_absent", None) == i:
            return False
        rel = normal.list_private(self.api)
        prior = normal.existing(rel, suffix(i) + ".json")
        if prior:
            manifest = self.recover(prior)
            if row is not None:
                b.require(identity(row, i) == manifest["cache"], "Transient cache differs from its private receipt")
        elif row is None:
            self.last_absent = i
            return False
        else:
            identity(row, i)
            packets.restore("packet", i, row, self.deadline)
            piece = packets.read_piece(i)
            manifest = self.deposit(row, piece)
        piece = manifest["piece"]
        last = i + 1 == self.count
        if last and self.outcome["status"] == "candidate":
            partial = normal.ROOT / "checkpoint-packets.partial"
            b.require(partial.stat().st_size == self.outcome["sealed_bytes"]
                      and b.digest(partial) == self.outcome["sealed_sha"], "Assembled ciphertext differs before ACK")
        packets.make_receipt(piece, manifest["cache"], manifest["stage"])
        folder = packets.folder("receipt")
        # p.save reconciles an exact hit. Only the unique signed record for this immutable
        # cache and private asset may be acknowledged, including after a missing PUT reply.
        signed = {n: (folder / n).read_bytes() for n in ("receipt.json", "receipt.sig")}
        whole = self.outcome.get("sealed_bytes", len(raw(self.outcome)))
        ack = packets.save("receipt", i, self.deadline, whole)
        packets.restore("receipt", i, ack, self.deadline)
        b.require(all((folder / n).read_bytes() == v for n, v in signed.items()), "Wrong or incomplete packet ACK")
        if row is not None:
            packets.before_delete(piece, row, self.deadline)
        delete_exact(self.api, i, manifest["cache"], self.deadline)
        self.received += piece["bytes"]
        self.index += 1
        if not last:
            return False
        incoming = normal.ROOT / "incoming"
        incoming.mkdir(exist_ok=True)
        if self.outcome["status"] == "candidate":
            partial.replace(incoming / "checkpoint.cms")
        tmp = normal.ROOT / "packet-outcome.tmp"
        tmp.write_text(json.dumps(self.outcome, sort_keys=True))
        tmp.replace(incoming / "outcome.json")
        print(f"R209_PRIVATE_PACKET_SET run={self.outcome['run']} slot={normal.slot()} count={self.count}"
              f" sealed_bytes={self.received} release={b.RELEASE}", flush=True)
        self.ready = True
        return True
