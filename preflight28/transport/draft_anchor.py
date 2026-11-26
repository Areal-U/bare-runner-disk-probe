"""Bind the separately observed untagged URLs to the original private release and existing claims."""
import hashlib
import io

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


def validate(record, release_id, tag, permalink, api_base, metadata, asset_info, download):
    # The originating R26 helper checks private/unpublished, title, owner, target
    # and historical sample/archive assets before returning this release to any caller.
    def check(ok):
        if not ok: raise ValueError("Rotated owner Draft alias did not match its immutable receipts")
    check(release_id==record["id"]==RELEASE_ID and api_base=="/repos/Areal-U/bare-runner-disk-probe")
    check(isinstance(permalink,str))
    alias_sha = hashlib.sha256(permalink.encode()).hexdigest()
    check(is_observed_rotation(alias_sha) and
          tag in (None,"",permalink) and record.get("html_url")=="https://github.com/Areal-U/bare-runner-disk-probe/releases/tag/"+permalink)
    listed=record["assets"]
    if not {c[1] for c in CLAIMS} <= {r["id"] for r in listed}:
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
    release={**record,"assets":listed}
    for name,aid,size,sha in CLAIMS:
        asset_info(release,name,size,sha,aid)
        if (alias_sha, aid) in _read_claims:
            continue
        sink=io.BytesIO()
        download(aid,size,sha,sink)
        raw=sink.getvalue()
        check(len(raw)==size and hashlib.sha256(raw).hexdigest()==sha)
        _read_claims.add((alias_sha, aid))
