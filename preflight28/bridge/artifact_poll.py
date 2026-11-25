"""Resolve one physical, unexpired Actions Artifact from a complete run inventory."""
import re


class UnstableInventory(ValueError):
    """The service's count, membership or object view has not yet converged."""


def require(value,message):
    if not value:
        raise ValueError(message)


def identity(row):
    return tuple(row.get(key) for key in ("id","name","size_in_bytes","digest","expired","expires_at"))


def complete(run, name, get, base, head):
    by_id={}
    named={}
    advertised=None
    for page in range(1,17):
        data=get(f"{base}/actions/runs/{run}/artifacts?per_page=100&page={page}")
        count,rows=data.get("total_count"),data.get("artifacts")
        require(type(count) is int and 0<=count<=1500 and isinstance(rows,list) and len(rows)<=100,
                "Out-of-bounds run Artifact inventory")
        if advertised is not None and count!=advertised:
            raise UnstableInventory("Artifact page count changed")
        advertised=count
        for item in rows:
            ident=item.get("id")
            require(type(ident) is int and ident>0,"Invalid Artifact ID")
            if ident in by_id:
                raise UnstableInventory("Artifact pages overlap")
            by_id[ident]=identity(item)
            if item["name"]==name:
                owner=item.get("workflow_run") or {}
                if not owner.get("id") or (head and not owner.get("head_sha")):
                    raise UnstableInventory("Matching Artifact lacks its live run binding")
                require(owner["id"]==run and (not head or owner["head_sha"]==head),
                        "Foreign run or revision for named Artifact")
                named[ident]=item
        if len(named)>1:
            raise ValueError("Multiple distinct physical IDs share the exact Artifact name")
        if len(rows)<100:
            break
    if len(by_id)!=advertised:
        raise UnstableInventory("Artifact count and complete run page membership differ")
    return by_id,named


def lookup(run, name, get, *, repo, head=None):
    require(type(run) is int and run>0 and re.fullmatch(r"[\w.-]+/[\w.-]+",repo) and
            isinstance(name,str) and 0<len(name)<=256 and (head is None or re.fullmatch("[0-9a-f]{40}",head)),
            "Invalid Artifact lookup scope")
    base="/repos/"+repo
    first,found=complete(run,name,get,base,head)
    second,again=complete(run,name,get,base,head)
    if first!=second or set(found)!=set(again):
        raise UnstableInventory("Named Artifact inventory is still propagating")
    if not found:
        return None
    row,=again.values()
    try:
        direct=get(f"{base}/actions/artifacts/{row['id']}")
    except ValueError as exc:
        if "HTTP 404" in str(exc):
            raise UnstableInventory("Listed Artifact is not yet visible by ID") from None
        raise
    if identity(direct)!=identity(row):
        raise UnstableInventory("Specific Artifact differs from run inventory")
    if direct.get("workflow_run"):
        owner=direct["workflow_run"]
        require(owner.get("id")==run and (not head or owner.get("head_sha")==head),"Specific Artifact has a foreign owner")
    require(row["expired"] is False and type(row["size_in_bytes"]) is int and row["size_in_bytes"]>0 and
            isinstance(row["digest"],str) and re.fullmatch("sha256:[0-9a-f]{64}",row["digest"]) and row.get("expires_at"),
            "Named Artifact expired or lacks complete physical metadata")
    return row
