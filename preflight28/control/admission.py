"""Bind one normal build to a unique immutable owner-Draft claim."""
import hashlib
import http.client
import io
import json
import re
import time

REPO = "Areal-U/bare-runner-disk-probe"
REPO_ID = 1450926240
BASE_REF = "bare-coexist-v2.0.4"
BASE_SHA = "bf70ddbf474f3390a62220a076b8c43347fecc64"
S2_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
RELEASE_ID = 452114666


def require(condition, message):
    if not condition:
        raise ValueError(message)


def encode(holder):
    return (json.dumps(holder, sort_keys=True, separators=(",", ":")) + "\n").encode()


class PagedOwnerDraft:
    """Keep the pinned Draft checks and enumerate the full owner asset inventory for each read."""
    def __init__(self, helper):
        self.helper = helper

    def __getattr__(self, key):
        return getattr(self.helper, key)

    def draft(self, release_id):
        require(release_id == RELEASE_ID, "Unexpected private release")
        release = self.helper.draft(release_id)
        assets = []
        for page in range(1, 12):
            batch = self.helper.metadata(f"{self.BASE}/releases/{release_id}/assets?per_page=100&page={page}")
            require(isinstance(batch, list) and len(batch) <= 100, "Invalid private asset page")
            assets.extend(batch)
            if len(batch) < 100:
                break
        else:
            raise ValueError("Private asset inventory exceeds the bounded listing")
        ids = {a["id"]: a["name"] for a in assets}
        require(len(ids) == len(assets) and all(ids.get(a["id"]) == a["name"] for a in release["assets"]),
                "Private asset inventory changed during pagination")
        return {**release, "assets": assets}


def claim_info(helper, payload, name, *, before_write=False):
    release = helper.draft(RELEASE_ID)
    names = [a for a in release["assets"] if a["name"] == name]
    if not names:
        if before_write:
            require(len(release["assets"]) < 1000, "Private Release has no remaining asset slot")
        return None
    digest = hashlib.sha256(payload).hexdigest()
    asset = helper.asset_info(release, name, len(payload), digest)
    retrieved = io.BytesIO()
    helper.download(asset["id"], len(payload), digest, retrieved)
    require(retrieved.getvalue() == payload, "Existing claim belongs to another producer")
    return asset["id"]


def admit(mode, holder, helper, pause=time.sleep, *, name, before_write=None):
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,125}\.json", name), "Invalid claim name")
    payload = encode(holder)
    found = claim_info(helper, payload, name, before_write=(mode == "compute"))
    if found:
        return found
    require(mode == "compute", "No first-attempt receipt to recover")
    # The asset name is unique within this one fixed draft. No replace, cleanup or
    # alternate filename is allowed for a run claim, even on a lost response.
    path = f"{helper.BASE}/releases/{RELEASE_ID}/assets?name={name}"
    status = None
    if before_write is not None:
        before_write()
    try:
        connection, response = helper.request(helper.UPLOAD, "POST", path, auth=True, body=payload,
                                              length=len(payload), content_type="application/json")
        try:
            status = response.status
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        pass  # Read back, without assuming the POST failed or duplicating it.
    for delay in (0, 1, 3, 6):
        if delay:
            pause(delay)
        found = claim_info(helper, payload, name)
        if found:
            return found
    raise ValueError(f"Canonical claim not confirmed (POST {status}); no compute")
