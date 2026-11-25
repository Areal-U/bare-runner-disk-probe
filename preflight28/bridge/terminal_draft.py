"""Deposit an already owner-encrypted cache-only APK on the pinned private Draft."""
import http.client
import io
import json
import os
from pathlib import Path
import sys
import time

import normal

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control"))
import apk_seal
import recover

b = normal.b


def publish(folder, env, api):
    physical, ordinal = int(env["GITHUB_RUN_ID"]), int(env["R28_SLOT"])
    rescue = env["GITHUB_JOB"] == "deliver-recovered-cached-apk"
    run = int(env["R28_SOURCE_RUN"]) if rescue else physical
    prefix = {"origin_prefix": f"r28-{run}-a1-s{ordinal:02}"} if rescue else {}
    if rescue:
        rows = [a for a in recover.current_caches(env["CACHE_KEY"],env["GITHUB_REF"])
                if a["key"] == env["CACHE_KEY"] and a["ref"] == env["GITHUB_REF"]]
        b.require(run != physical and len(rows)==1 and str(rows[0]["id"]) == env["CACHE_ID"],
                  "The authorized original cache changed before rescue")

    if (env["GITHUB_REPOSITORY"] != b.REPO or env["GITHUB_REF"] != "refs/heads/bare-coexist-v2.0.4"
            or env["GITHUB_EVENT_NAME"] != "workflow_dispatch" or env["GITHUB_RUN_ATTEMPT"] != "1"
            or env["GITHUB_JOB"] not in ("deliver-cached-apk","deliver-recovered-cached-apk") or env["GITHUB_ACTOR"] != "Areal-U"
            or int(env["R28_COLLECTION_CLAIM"]) <= 0
            or env["CACHE_KEY"] != f"bare-coexist-204-apk-v1-{run}-1-s{ordinal}"
            or env["CACHE_MATCH"] != env["CACHE_KEY"] or env["CACHE_HIT"] != "true"):
        raise ValueError("Invalid cache-only APK job identity or cache receipt")
    path = folder / apk_seal.CIPHER_FILE
    seal_path = folder / "seal.json"
    if (folder.is_symlink() or not folder.is_dir() or set(folder.iterdir()) != {path, seal_path}
            or path.is_symlink() or not path.is_file() or seal_path.is_symlink() or not seal_path.is_file()
            or not 0 < seal_path.stat().st_size <= 4096):
        raise ValueError("Unexpected terminal recovery cache contents")
    seal = apk_seal.validate(json.loads(seal_path.read_bytes()), run=run, ordinal=ordinal,
                             head=env["GITHUB_SHA"], parent=env["R28_PARENT_SHA"])
    if (seal["sha"] != env["CIPHER_SHA"] or seal["bytes"] != int(env["CIPHER_BYTES"])
            or path.stat().st_size != seal["bytes"] or b.digest(path) != seal["sha"]):
        raise ValueError("Cache ciphertext conflicts with the original APK seal")
    # Reject conflicting physical copies, including a lost reply followed by a later retry.
    for suffix in ("apk.age", "apk-owner-receipt.json"):
        normal.existing(normal.list_private(api), suffix, **prefix)
    with path.open("rb") as data:
        if data.readline(64) != b"age-encryption.org/v1\n":
            raise ValueError("Only sealed age ciphertext may enter the private Draft")
        data.seek(0)
        part = normal.put("apk.age", data, 0, seal["bytes"], seal["sha"], **prefix)
    api.download(part["id"], seal["bytes"], seal["sha"], None)
    ticket = {"schema":"bare-r28-private-apk-v1", "seal":seal, "source_cache_key":env["CACHE_KEY"],
              "collection_claim_id":int(env["R28_COLLECTION_CLAIM"]), "cipher":part}
    prior=normal.existing(normal.list_private(api), "apk-owner-receipt.json", **prefix)
    if prior:
        b.require(0 < prior["size"] <= 4096 and prior["digest"].startswith("sha256:"), "Invalid prior terminal receipt")
        existing=io.BytesIO()
        api.download(prior["id"],prior["size"],prior["digest"][7:],existing)
        prior_data=json.loads(existing.getvalue())
        depositor=prior_data.pop("depositor_run")
        b.require(type(depositor) is int and depositor>0 and prior_data == ticket,
                  "Conflicting prior terminal receipt")
    else:
        depositor=physical
    ticket["depositor_run"]=depositor
    receipt = normal.put_json("apk-owner-receipt.json", ticket, **prefix)
    reread = io.BytesIO()
    api.download(receipt["id"], receipt["bytes"], receipt["sha256"], reread)
    if json.loads(reread.getvalue()) != ticket:
        raise ValueError("Private APK receipt changed after deposit")
    current = normal.list_private(api)
    for suffix, saved in (("apk.age", part), ("apk-owner-receipt.json", receipt)):
        seen = normal.existing(current, suffix, **prefix)
        if seen is None or seen["id"] != saved["id"]:
            raise ValueError("Private terminal asset disappeared or was replaced")
    return receipt


def publish_once_with_reconciliation(folder, env, api, *, pause=time.sleep):
    # One transport retry on the same immutable names. Never relax any content, source or owner check.
    for attempt in range(2):
        try:
            return publish(folder, env, api)
        except Exception as error:
            transient = (isinstance(error, (OSError, http.client.HTTPException)) or
                         str(error).startswith("Private write unresolved.") or
                         any(str(error).endswith("returned " + str(status)) for status in (429,500,502,503,504)))
            if attempt or not transient:
                raise
            pause(4)


def authorize_rescue(env, api):
    sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"collector"))
    import production as owner
    from recover_private import read_only
    api.request = read_only(api.request)
    api=owner.PagedOwnerDraft(api)
    require=b.require
    require(env["GITHUB_JOB"] == "deliver-recovered-cached-apk" and env["GITHUB_RUN_ATTEMPT"] == "1" and
            env["GITHUB_ACTOR"] == "Areal-U" and env["GITHUB_REPOSITORY"] == b.REPO and
            env["GITHUB_REF"] == "refs/heads/"+owner.BASE_REF and env["GITHUB_EVENT_NAME"] == "workflow_dispatch",
            "Unauthorized transfer-only runner")
    event=json.loads(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
    inputs=event["inputs"]
    require(inputs["mode"]=="recover-encrypted-apk" and all(event["sender"].get(k)==v for k,v in owner.OWNER.items()) and
            event["repository"]["id"] == owner.REPO_ID,"Wrong transfer-only event")
    rows=api.draft(b.RELEASE)["assets"]
    row=owner.private_row(rows,owner.CAMPAIGN+"-collection-registration.json")
    ticket=owner.private_document(api,row,owner=True)
    head=env["GITHUB_SHA"]
    locator=dict(ticket_asset_id=row["id"],ticket_sha=row["digest"][7:],head=head,
                 registration_id=ticket["collector_registration_id"],owner_destination_id=ticket["owner_destination_id"])
    _,run,claim,scope=owner.bind(api,rows,locator)
    require(str(run)==inputs["loss_origin_run"] and str(run)!=env["GITHUB_RUN_ID"],
            "Requested cache is not from the registered original terminal")
    current=int(env["GITHUB_RUN_ID"])
    owner.physical_run(json.loads(recover.get(f"actions/runs/{current}/attempts/1")),current,head)
    base=f"actions/runs/{run}/attempts/1"
    source=json.loads(recover.get(base))
    owner.physical_run(source,run,head)
    require(source["status"]=="completed","Original runner is still active")
    jobs=recover.inventory(base+"/jobs","jobs")
    artifacts=recover.inventory(f"actions/runs/{run}/artifacts","artifacts")
    metadata=lambda aid: json.loads(recover.get(f"actions/artifacts/{aid}"))
    chain=recover.slot_chain(jobs,artifacts,run,head,metadata,recover.download_note,scope,terminal_salvage=True)
    out=recover.terminal_source(chain,jobs,artifacts,run,head,metadata,recover.download_note,recover.current_caches,scope)
    require(out["status"]=="inspect-terminal" and out["cipher_cache"] and out["cipher_cache"]==inputs["checkpoint_key"]
            and not out["cipher_id"] and (not out["cipher_sha"] or out["cipher_sha"]==inputs["checkpoint_sha"])
            and (not out["cipher_bytes"] or str(out["cipher_bytes"])==inputs["encrypted_apk_bytes"])
            and b.sha(inputs["checkpoint_sha"]) and inputs["encrypted_apk_bytes"].isdecimal()
            and 0<int(inputs["encrypted_apk_bytes"])<=apk_seal.CIPHER_CAP,"Wrong original sealed bytes or existing Artifact")
    b.output(source_run=run,ordinal=out["ordinal"],parent=out["accepted_parent"],claim_id=claim,
             cache_id=out["cipher_cache_id"],cache_key=out["cipher_cache"],
             sha=inputs["checkpoint_sha"],bytes=int(inputs["encrypted_apk_bytes"]))


if __name__ == "__main__":
    if sys.argv[1:] == ["authorize-rescue"]:
        authorize_rescue(os.environ, b.auth_api())
    elif not sys.argv[1:]:
        result = publish_once_with_reconciliation(Path(os.environ["RUNNER_TEMP"]) / "bare-apk-delivery", os.environ, b.auth_api())
        print("Verified private ciphertext receipt " + json.dumps(result, sort_keys=True))
    else:
        raise SystemExit("Unknown private terminal transfer")
