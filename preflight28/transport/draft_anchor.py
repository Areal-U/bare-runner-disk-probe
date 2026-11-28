"""Bind an owner Draft permalink to the fixed release and the original physical claims."""
import hashlib
import io
import re

RELEASE_ID = 452114666
TAG_SHA = "b56067c162517f62c320a068708c221d1c02b2b1289fc287ad6caff0ea391d40"
# A second editor save rotated the route again during the R30 owner registration.
R30_TAG_SHA = "08c0c8dc0f5b8602b32ff767f5b3dc0dcf6b07dd7860ea881567e68c25a459d0"
CLAIMS = (
    ("r28-preflight-s2-20261125-v1-s2-run-claim.json",789237341,401,"3529cf591b7db037e44bb01243f61320df941ffaeef764b612844e222ed6c9ee"),
    ("r28-preflight-s2-20261125-v2-s2-run-claim.json",789343072,636,"ff2b0475fdeb177b6125dac8d59b18643b82136615b463930da0271ab57edffe"),
)
_read_claims = set()


def is_observed_rotation(tag_sha):
    return tag_sha in (TAG_SHA, R30_TAG_SHA)


def validate(record, release_id, tag, permalink, api_base, metadata, asset_info, download, *,
             generation_209=False, observed_alias_sha=None):
    # The originating R26 helper checks private/unpublished, title, owner, target
    # and historical sample/archive assets before returning this release to any caller.
    def check(ok, message="Rotated owner Draft alias did not match its immutable receipts"):
        if not ok:
            raise ValueError(message)
    check(release_id==record["id"]==RELEASE_ID and api_base=="/repos/Areal-U/bare-runner-disk-probe")
    check(isinstance(permalink,str))
    alias_sha = hashlib.sha256(permalink.encode()).hexdigest()
    if generation_209:
        check(re.fullmatch(r"untagged-[0-9a-f]{20}", permalink), "Unexpected owner Draft permalink format")
        check(isinstance(observed_alias_sha, str) and re.fullmatch(r"[0-9a-f]{64}", observed_alias_sha) and
              observed_alias_sha == alias_sha, "Owner Draft permalink differs from the registered dispatch digest")
        check(record.get("url") == f"https://api.github.com{api_base}/releases/{release_id}",
              "Different owner Draft API URL")
    else:
        check(is_observed_rotation(alias_sha))
    check(tag in (None,"",permalink), "Owner Draft API tag differs from its permalink")
    check(record.get("html_url")=="https://github.com/Areal-U/bare-runner-disk-probe/releases/tag/"+permalink,
          "Unexpected owner Draft web URL")
    listed=record["assets"]
    if generation_209 or not {c[1] for c in CLAIMS} <= {r["id"] for r in listed}:
        listed=[]
        for page in range(1,12):
            batch=metadata(f"{api_base}/releases/{release_id}/assets?per_page=100&page={page}")
            check(isinstance(batch,list) and len(batch)<=100)
            listed.extend(batch)
            if len(batch)<100:
                break
        else:
            raise ValueError("Incomplete immutable owner-Draft inventory")
    by_id={r["id"]:r["name"] for r in listed}
    check(len(by_id)==len(listed) and all(by_id.get(r["id"])==r["name"] for r in record["assets"]))
    if generation_209:
        check(len(set(by_id.values())) == len(listed), "Ambiguous owner Draft asset names")
        complete = {row["id"]: row for row in listed}
        check(all(all(row.get(key) == complete[row["id"]].get(key) for key in ("name", "state", "size", "digest"))
                  for row in record["assets"]), "Owner Draft asset inventory changed during pagination")
    release={**record,"assets":listed}
    for name,aid,size,sha in CLAIMS:
        asset_info(release,name,size,sha,aid)
        if not generation_209 and (alias_sha, aid) in _read_claims:
            continue
        sink=io.BytesIO()
        download(aid,size,sha,sink)
        raw=sink.getvalue()
        check(len(raw)==size and hashlib.sha256(raw).hexdigest()==sha)
        if not generation_209:
            _read_claims.add((alias_sha, aid))
    return release if generation_209 else record
