"""Supplement the issuer's direct privacy check with a second origin's anonymous API 404."""
import http.client
import os
import re
import time

REPO = "Areal-U/bare-runner-disk-probe"
API = "api.github.com"
SOURCE_RUN = 45513782890
SOURCE_HEAD = "81105d5f7b9ba994034753ce4fbd65d9b981dde3"
RELEASE = 452114666
ASSETS = (789542812, 789540148)
SCHEMA = "bare-r28-anonymous-api-evidence-v1"
MAX_AGE = 600


def scope(record):
    run, attempt, head = record["run"], record["attempt"], record["head"]
    if (type(run) is not int or run <= SOURCE_RUN or type(attempt) is not int or attempt <= 0
            or not isinstance(head,str) or not re.fullmatch("[a-f0-9]{40}",head)
            or record["source_run"] != SOURCE_RUN or record["source_head"] != SOURCE_HEAD
            or record["release"] != RELEASE):
        raise ValueError("Unexpected anonymous witness generation")
    return {"repo": REPO, "run": run, "attempt": attempt, "head": head, "release": RELEASE,
            "source_run": SOURCE_RUN, "source_head": SOURCE_HEAD}


def sample(binding=None):
    if os.environ.get("GITHUB_JOB") != "receive" or os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise ValueError("Only the ordinary receiver may supply independent evidence")
    env={"run":int(os.environ["GITHUB_RUN_ID"]), "attempt":int(os.environ["GITHUB_RUN_ATTEMPT"]),
         "head":os.environ["TRIAL_SHA"],"source_run":SOURCE_RUN,"source_head":SOURCE_HEAD,"release":RELEASE}
    bound=scope(env)
    if binding is not None and scope(binding)!=bound:
        raise ValueError("Anonymous witness is not the current physical generation")
    observed=int(time.time())
    ids=[]
    for asset in ASSETS:
        connection=http.client.HTTPSConnection(API,timeout=10)
        try:
            # No credential source, redirect handling, cookies or configurable endpoint.
            connection.request("GET",f"/repos/{REPO}/releases/assets/{asset}",
                    headers={"User-Agent":"bare-owner-split-anonymous-observer/1","Accept":"application/octet-stream",
                             "X-GitHub-Api-Version":"2022-11-28"})
            response=connection.getresponse()
            if response.getheader("Location") is not None or 200<=response.status<400:
                raise ValueError("Original asset yielded anonymous content or a redirect")
            if response.status==404:
                ids.append(asset)
            print(f"ordinary_anonymous_asset={asset} api_status={response.status}",flush=True)
        except (OSError,http.client.HTTPException):
            print(f"ordinary_anonymous_asset={asset} api_status=unavailable",flush=True)
        finally:
            connection.close()
    return {"schema":SCHEMA,"scope":bound,"observed_at":observed,"ids":ids}


def valid(record,asset,binding,*,now=None):
    """Caller must authenticate the enclosing holder to this run/attempt and verify direct 404 itself."""
    if type(asset) is not int or asset not in ASSETS or not isinstance(record,dict):
        return False
    if set(record)!={"schema","scope","observed_at","ids"} or record["schema"]!=SCHEMA:
        return False
    try:
        expected=scope(binding)
        if not isinstance(record["scope"],dict) or scope(record["scope"])!=expected:
            return False
    except (KeyError,TypeError,ValueError):
        return False
    observed,ids=record["observed_at"],record["ids"]
    t=time.time() if now is None else now
    return (record["scope"]==expected and type(observed) is int and 0<=t-observed<=MAX_AGE
            and isinstance(ids,list) and len(ids)<=len(ASSETS) and all(type(i) is int and i in ASSETS for i in ids)
            and len(set(ids))==len(ids) and asset in ids)
