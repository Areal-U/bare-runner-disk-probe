"""Validate independent GitHub and owner receipt records for the Run 28 test."""

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path


class ReceiptError(ValueError):
    pass


def require(value, message):
    if not value:
        raise ReceiptError(message)


def sha256_file(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def verify_source(ticket, run, job, asset, reported, ciphertext, now):
    expected = ticket["expected"]
    physical = (run["id"], run["run_attempt"])
    require(run["repository"]["full_name"] == expected["repository"]
            and run["head_repository"]["full_name"] == expected["repository"]
            and run["head_branch"] == expected["source_branch"]
            and run["event"] == "pull_request", "unexpected run source")
    require(any(pr.get("number") == expected["pull_request"]
                for pr in run["pull_requests"]), "PR mismatch")
    require(run["display_title"] == expected["run_name"]
            and run["path"] == ".github/workflows/" + expected["workflow"],
            "wrong workflow or operation")
    require(run["status"] == "completed" and run["conclusion"] == "success",
            "producer run is not complete")
    require(physical[1] == expected["initial_attempt"], "not original generation")
    require(job["run_id"] == physical[0] and job["run_attempt"] == physical[1]
            and job["conclusion"] == "success", "wrong producer job")
    head = run["head_sha"]
    pinned = expected.get("head_sha")
    require(re.fullmatch("[0-9a-f]{40}", head) and (not pinned or head == pinned),
            "source commit mismatch")
    require(reported["operation"] == ticket["operation"]
            and int(reported["run_id"]) == physical[0]
            and int(reported["attempt"]) == physical[1]
            and reported["head_sha"] == head, "incorrect producer receipt")
    asset_name = expected["artifact_name"].replace("<run_id>", str(physical[0])).replace(
        "<attempt>", str(physical[1]))
    require(asset["name"] == asset_name and int(asset["id"]) > 0
            and asset["workflow_run"]["id"] == physical[0]
            and asset["workflow_run"]["head_sha"] == head
            and not asset["expired"], "artifact identity or expiry mismatch")
    if "artifact_id" in reported:
        require(int(reported["artifact_id"]) == asset["id"], "artifact ID mismatch")
    expires = datetime.fromisoformat(asset["expires_at"].replace("Z", "+00:00"))
    require(expires > now, "artifact expired")
    require(ciphertext.stat().st_size == int(reported["cipher_bytes"])
            and sha256_file(ciphertext) == reported["cipher_sha256"],
            "downloaded ciphertext mismatch")
    require(re.fullmatch("[0-9a-f]{64}", reported["clear_sha256"]),
            "missing clear APK digest")
    # Download immediately. This threshold defines escalation, not a reason to
    # abandon an artifact that can still be saved.
    warning_at = expires - timedelta(hours=2, minutes=15)
    return {"state": "encrypted-bytes-verified", "run_id": physical[0],
            "attempt": physical[1], "head_sha": head, "job_id": job["id"],
            "artifact_id": asset["id"], "artifact_expires_at": expires.isoformat(),
            "backup_urgent": now >= warning_at,
            "cipher_sha256": reported["cipher_sha256"], "clear_sha256": reported["clear_sha256"]}


def verify_owner(ticket, listing, publication, downloaded, apksigner_jar):
    destination = ticket["destination"]
    exact_id = destination["allocated_file_id"]
    matched = [item for item in listing["items"] if item.get("library_file_id") == exact_id]
    require(len(matched) == 1, "final file is missing from the authenticated owner's folder")
    item = matched[0]
    require(not item.get("is_shared", False) and listing["surface"] == "library"
            and item.get("surface") == "library" and item["kind"] == "file"
            and item["path"] == destination["owned_folder"] + "/" + destination["completed_filename"],
            "ownership, folder, or final filename mismatch")
    version = int(item["version_id"])
    require(int(publication["version"]) == version
            and version > destination["expected_pending_version"]
            and publication["library_file_id"] == exact_id
            and publication["file_id"] == item["file_id"], "version or file identity mismatch")
    require(downloaded.stat().st_size == item["size_bytes"]
            and sha256_file(downloaded) == publication["signed_sha256"],
            "retrieved final bytes differ")
    result = subprocess.run(["java", "-jar", str(apksigner_jar), "verify", "--print-certs",
                             "--verbose", str(downloaded)], capture_output=True, text=True,
                            timeout=60, check=True)
    signers = re.findall(r"^(?:Signer #\d+|V[0-9.]+ Signer:) certificate SHA-256 digest: ([a-fA-F0-9]{64})$",
                         result.stdout, re.MULTILINE)
    expected_cert = ticket["expected"]["trusted_test_kit"]["certificate_sha256"]
    require({signer.lower() for signer in signers} == {expected_cert}
            and expected_cert == publication["certificate_sha256"],
            "retrieved signer differs from registered test certificate")
    link = "https://chatgpt.com/library?file_id=" + exact_id + "&account_id=personal"
    require(destination["account_id"] == "personal", "unexpected account")
    return {"state": "delivered", "library_file_id": exact_id, "file_id": item["file_id"],
            "version": version, "signed_sha256": publication["signed_sha256"],
            "certificate_sha256": publication["certificate_sha256"], "owner_link": link}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="stage", required=True)
    source = sub.add_parser("source")
    for key in ("ticket", "run", "job", "asset", "reported", "ciphertext"):
        source.add_argument(key, type=Path)
    owner = sub.add_parser("owner")
    for key in ("ticket", "listing", "publication", "downloaded", "apksigner_jar"):
        owner.add_argument(key, type=Path)
    args = vars(cli.parse_args())
    stage = args.pop("stage")
    documents = {k: (v if k in ("ciphertext", "downloaded", "apksigner_jar") else json.loads(v.read_text()))
                 for k, v in args.items()}
    if stage == "source":
        result = verify_source(**documents, now=datetime.now(timezone.utc))
    else:
        result = verify_owner(**documents)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
