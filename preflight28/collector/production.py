"""Read one owner-registered production campaign. All GitHub operations are GETs."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "control"))
import apk_seal
from admission import BASE_REF, PagedOwnerDraft, RELEASE_ID, REPO, REPO_ID, S2_SHA, require
import receipt_journal as journal
import recover
from registration import CAMPAIGN, CLAIM, OWNER, WORKFLOW

REPLACEMENT = CAMPAIGN + "-loss-replacement-claim.json"
DRAFT_JOB = "Deliver the verified cache-only terminal ciphertext to the original owner Draft"
DRAFT_STEP = "Deposit and read back the owner-encrypted bytes and immutable receiver record"
CI_CERT = "32a2fc74d731105859e5a85df16d95f102d85b22099b8064c5d8915c61dad1e0"
UBO_SHA = "d688ed3f0262ec4f8bdcd4c8f65987c5444c560aeb387a9e02aca1facdfa7046"
BARE_REV = "21cb542601950cbd5ee2eddcad6a9163bdf5ea99"
CHROMIUM_REV = "800628ad1ca1fd0c51e3b43b5b2bca081e81c3f6"
CIPHER_SUFFIX = "-apk.age"
RECEIPT_SUFFIX = "-apk-owner-receipt.json"


def digest(path):
    with path.open("rb") as data:
        return hashlib.file_digest(data, "sha256").hexdigest()


def private_row(rows, name, *, retry=False, optional=False):
    allowed = {name, name + "-retry1"} if retry else {name}
    matches = [r for r in rows if r["name"] in allowed]
    require(len({r["name"] for r in matches}) == len(matches), "Duplicate private asset name")
    done = [r for r in matches if r["state"] == "uploaded"]
    if optional and not done:
        return None
    require(len(done) == 1, "Missing or ambiguous immutable private asset: " + name)
    row, = done
    require(type(row["id"]) is int and row["id"] > 0 and
            re.fullmatch(r"sha256:[0-9a-f]{64}", row.get("digest") or ""), "Invalid service digest")
    return row


def private_document(api, row, *, owner=False):
    require(0 < row["size"] <= 16384 and (not owner or all(
        row["uploader"].get(k) == v for k, v in OWNER.items())), "Private owner document mismatch")
    buf = io.BytesIO()
    sha = row["digest"][7:]
    api.download(row["id"], row["size"], sha, buf)
    data = buf.getvalue()
    require(len(data) == row["size"] and hashlib.sha256(data).hexdigest() == sha,
            "Private document differs from its immutable ID")
    return json.loads(data)


def bind(api, rows, locator):
    ticket_row = private_row(rows, CAMPAIGN + "-collection-registration.json")
    require(ticket_row["id"] == locator["ticket_asset_id"] and
            ticket_row["digest"] == "sha256:" + locator["ticket_sha"], "Different registered ticket")
    ticket = private_document(api, ticket_row, owner=True)
    common = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, workflow=WORKFLOW,
                  branch=BASE_REF, head=locator["head"], recipient=apk_seal.RECIPIENT)
    require(all(ticket.get(k) == v for k, v in common.items()) and
            ticket["initial_parent"] == S2_SHA and ticket["release_id"] == RELEASE_ID and
            ticket["owner_destination_id"] == locator["owner_destination_id"] and
            ticket["collector_registration_id"] == locator["registration_id"], "Foreign reservation or destination")
    source = private_row(rows, CLAIM)
    claim = private_document(api, source)
    require(all(claim.get(k) == v for k, v in common.items()) and claim["producer_attempt"] == 1 and
            claim["registration_id"] == locator["registration_id"] and claim["release_id"] == RELEASE_ID and
            (claim["ticket_asset_id"], claim["ticket_sha"], claim["initial_parent"]) ==
            (ticket_row["id"], ticket_row["digest"][7:], S2_SHA), "Unbound original production claim")
    origin = claim["run_id"]
    require(type(origin) is int and origin > 0, "Missing original run")
    replacement = private_row(rows, REPLACEMENT, optional=True)
    scope = recover.ChainStart()
    if replacement:
        claim = private_document(api, replacement)
        loss = private_row(rows, f"{CAMPAIGN}-loss-{origin}.json")
        directive = private_document(api, loss, owner=True)
        evidence = private_row(rows, f"{CAMPAIGN}-loss-evidence-{origin}.json")
        require(all(claim.get(k) == v for k, v in common.items()) and
                claim["producer_attempt"] == 1 and claim["registration_id"] == locator["registration_id"] and
                claim["origin_run"] == origin and claim["original_claim_id"] == source["id"] and
                claim["owner_destination_id"] == ticket["owner_destination_id"] and
                claim["ticket_asset_id"] == loss["id"] and claim["ticket_sha"] == loss["digest"][7:] and
                directive["state"] == "original-operation-closed-no-durable-output" and
                directive["origin_run"] == origin and directive["original_claim_id"] == source["id"] and
                directive["collector_registration_id"] == locator["registration_id"] and
                directive["owner_destination_id"] == ticket["owner_destination_id"] and
                directive["ordinal"] == claim["ordinal"] and directive["evidence_asset_id"] == evidence["id"] and
                directive["evidence_sha"] == evidence["digest"][7:], "Unbound exceptional replacement")
        observed = private_document(api, evidence, owner=True)
        require(all(observed.get(k) == v for k, v in common.items()) and
                observed["state"] == "ledger-closed-no-durable-output" and observed["owner_copy"] == "confirmed-absent" and
                observed["pending_writes"] == 0 and observed["origin_run"] == origin and
                observed["original_claim_id"] == source["id"] and observed["ordinal"] == claim["ordinal"] and
                observed["collector_registration_id"] == locator["registration_id"] and
                observed["owner_destination_id"] == ticket["owner_destination_id"] and
                claim["evidence_asset_id"] == evidence["id"] and claim["evidence_sha"] == evidence["digest"][7:] and
                observed["parent_sha"] == claim["parent_sha"] == claim["initial_parent"] and
                re.fullmatch("[0-9a-f]{64}", claim["parent_identity"]), "Different closed origin owner ledger")
        run = claim["run_id"]
        require(type(run) is int and run > 0 and run != origin and
                type(claim["ordinal"]) is int and 1 <= claim["ordinal"] <= 12 and
                re.fullmatch("[0-9a-f]{64}", claim["initial_parent"]) and
                (claim["ordinal"] != 1 or claim["initial_parent"] == S2_SHA), "Invalid replacement origin")
        # The journal chain checks the accepted SHA. No private sender state is consumed by the collector.
        scope = recover.ChainStart(claim["ordinal"], claim["initial_parent"], claim["parent_identity"], True)
        source = replacement
    return origin, claim["run_id"], source["id"], scope


def physical_run(row, run, head):
    require(row["id"] == run and row["run_attempt"] == 1 and row["path"] == WORKFLOW and row["head_sha"] == head and
            row["event"] == "workflow_dispatch" and row["head_branch"] == BASE_REF and
            row["repository"]["id"] == row["head_repository"]["id"] == REPO_ID and
            all(row["actor"].get(k) == v for k, v in OWNER.items()), "Unexpected physical originating attempt")


def install(staged, dest):
    try:
        os.link(staged, dest)
    except FileExistsError:
        require(dest.is_file() and not dest.is_symlink() and dest.stat().st_size == staged.stat().st_size and
                digest(dest) == digest(staged), "Conflicting prior private output. Never replace accepted bytes.")


def check_cipher(file, seal):
    require(file.stat().st_size == seal["bytes"] and digest(file) == seal["sha"], "Ciphertext length or SHA changed")
    with file.open("rb") as data:
        require(data.readline(64) == b"age-encryption.org/v1\n", "Unexpected encrypted payload format")


def unwrap(outer, row, cipher, **binding):
    require(0 < outer.stat().st_size == row["size_in_bytes"] <= apk_seal.CIPHER_CAP + 2*1024**2 and
            row["digest"] == "sha256:" + digest(outer), "Incorrect outer Artifact bytes")
    with ZipFile(outer) as z:
        require(sorted(z.namelist()) == sorted(["seal.json", apk_seal.CIPHER_FILE]) and
                0 < z.getinfo("seal.json").file_size <= 4096, "Unexpected production terminal archive layout")
        seal = apk_seal.validate(json.loads(z.read("seal.json")), **binding)
        require(z.getinfo(apk_seal.CIPHER_FILE).file_size == seal["bytes"], "Wrong inner ciphertext length")
        with z.open(apk_seal.CIPHER_FILE) as src, cipher.open("xb") as output:
            shutil.copyfileobj(src, output, 1024**2)
    check_cipher(cipher, seal)
    return seal


def decide(jobs, arts, rows, chain, run, head, scope):
    # Slot journals pin the accepted parent; individual terminal bytes can predate the last journal.
    outcome = recover.follow(chain, run, head, scope)
    terminal = outcome["status"] == "apk"
    require(terminal or outcome["status"] == "recovery-no-terminal", "Operation already stopped without an APK")
    n = outcome["ordinal"] if terminal else scope.ordinal + len(chain)
    require(n <= 12 and n < scope.last, "No generating slot is eligible for this pickup")
    parent = scope.sha if n == scope.ordinal else chain[n-scope.ordinal-1]["sha"]
    prefix = f"r28-{run}-a1-s{n:02}"
    artifact = journal.one_artifact(arts, f"bare-personal-204-encrypted-{run}-1-s{n}")
    private = private_row(rows, prefix + RECEIPT_SUFFIX, retry=True, optional=True)
    if artifact:
        job = journal.original_job(jobs, run, head, n, f"Compile or verify authenticated APK slot {n}")
        journal.checked_artifact(artifact, run, head, job, "Upload the encrypted APK bundle",
                                 lambda aid: json.loads(recover.get(f"actions/artifacts/{aid}")))
        require(not terminal or outcome["cipher_id"] in ("", str(artifact["id"])), "Different accepted Artifact ID")
        if artifact["expired"] or journal.timestamp(artifact["expires_at"]) <= datetime.now(timezone.utc).timestamp():
            artifact = None
    require(artifact or private, "Pending a retrievable terminal object for the currently accepted parent")
    return n, parent, outcome if terminal else {}, artifact, private


def private_depositor(record, row, jobs, run, head, n):
    depositor = record["depositor_run"]
    require(type(depositor) is int and depositor > 0, "No physical private depositor")
    if depositor == run:
        job = journal.original_job(jobs,run,head,n,DRAFT_JOB)
        require(job is not None, "No original private terminal handoff")
    else:
        base=f"actions/runs/{depositor}/attempts/1"
        physical_run(json.loads(recover.get(base)),depositor,head)
        rescue = [j for j in recover.inventory(base+"/jobs", "jobs")
                  if j["name"] == "Transfer the original cached ciphertext to its registered owner" and
                  j["status"] == "completed" and j["run_attempt"] == 1 and j["run_id"] == depositor and
                  j["head_sha"] == head]
        require(len(rescue) == 1 and journal.upload_step(rescue[0],"Bind the exact original cache to its registered owner")
                and any(s["name"] == "Bind the exact original cache to its registered owner" and
                        s["conclusion"] == "success" for s in rescue[0]["steps"]), "Unconfirmed authorized transfer-only job")
        job, = rescue
    recover.same_time_as_upload(row,job,DRAFT_STEP)


def collect(locator, directory, api):
    api = PagedOwnerDraft(api)
    rows = api.draft(RELEASE_ID)["assets"]
    origin, run, claim_id, scope = bind(api, rows, locator)
    head = locator["head"]
    base = f"actions/runs/{run}/attempts/1"
    physical_run(json.loads(recover.get(base)), run, head)
    jobs = recover.inventory(base+"/jobs", "jobs")
    arts = recover.inventory(f"actions/runs/{run}/artifacts", "artifacts")
    chain = recover.slot_chain(jobs, arts, run, head,
            lambda aid: json.loads(recover.get(f"actions/artifacts/{aid}")), recover.download_note, scope, terminal_salvage=True)
    n, parent, receipt, artifact, private = decide(jobs, arts, rows, chain, run, head, scope)
    binding = dict(run=run, ordinal=n, head=head, parent=parent)
    directory.mkdir(exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=directory) as temp:
        temp = Path(temp)
        cipher = temp / apk_seal.CIPHER_FILE
        seal = None
        locations = {}
        if private:
            record = private_document(api, private)
            private_depositor(record,private,jobs,run,head,n)
            seal = apk_seal.validate(record["seal"], **binding)
            key = f"bare-coexist-204-apk-v1-{run}-1-s{n}"
            require(record["schema"] == "bare-r28-private-apk-v1" and record["collection_claim_id"] == claim_id and
                    record["source_cache_key"] == key and (not receipt or receipt["cipher_cache"] == key),
                    "Wrong private ciphertext origin")
            part = record["cipher"]
            row = private_row(rows, f"r28-{run}-a1-s{n:02}" + CIPHER_SUFFIX, retry=True)
            require((row["id"], row["name"], row["size"], row["digest"]) ==
                    (part["id"], part["name"], seal["bytes"], "sha256:"+seal["sha"]) and
                    part["bytes"] == seal["bytes"] and part["sha256"] == seal["sha"], "Wrong private ciphertext ID")
            with cipher.open("xb") as target:
                api.download(row["id"], seal["bytes"], seal["sha"], target)
            check_cipher(cipher, seal)
            locations.update(draft_asset_id=row["id"], draft_receipt_id=private["id"])
        if artifact:
            outer = temp/"terminal.zip"
            with outer.open("xb") as target:
                subprocess.run(["gh", "api", "--method", "GET", f"repos/{REPO}/actions/artifacts/{artifact['id']}/zip"],
                               stdout=target, check=True, timeout=900)
            second = temp/"artifact.age"
            note = unwrap(outer, artifact, second, **binding)
            require(seal is None or seal == note, "Durable terminal sources disagree")
            seal, cipher = note, second
            locations.update(artifact_id=artifact["id"], artifact_expires_at=artifact["expires_at"])
        require(not receipt or (seal["sha"], seal["bytes"]) ==
                (receipt["cipher_sha"], int(receipt["cipher_bytes"])), "Outcome conflicts with terminal bytes")
        install(cipher, directory/apk_seal.CIPHER_FILE)
        return dict(schema=1, campaign=CAMPAIGN, origin_run=origin, source_run=run, claim_asset_id=claim_id,
                    owner_destination_id=locator["owner_destination_id"], seal=seal, **locations)


def verify_signer(file, expected, apksigner):
    out = subprocess.check_output(["java", "-jar", str(apksigner), "verify", "--verbose", "--print-certs", str(file)],
                                  text=True, timeout=120)
    pattern = r"^(?:Signer #\d+ certificate|V\d+(?:\.\d+)? Signer(?: #\d+)?: certificate) SHA-256 digest: ([a-f0-9]{64})\s*$"
    require(re.search(r"^Number of signers: 1\s*$",out,re.M) and
            {s.lower() for s in re.findall(pattern,out,re.I|re.M)} == {expected}, "Wrong final signer")


def verify_application(file, aapt2):
    binding = subprocess.check_output([str(aapt2), "dump", "badging", str(file)], text=True, timeout=120)
    lines = binding.splitlines()
    packages = [line for line in lines if line.startswith("package:")]
    require(len(packages) == 1, "Expected one package")
    fields = dict(re.findall(r"\b([A-Za-z][A-Za-z0-9]*)='([^']*)'", packages[0]))
    require((fields.get("name"), fields.get("versionName"), fields.get("versionCode")) ==
            ("org.barebrowser.personal", "2.0.4", "802000415") and "application-label:'Bare Personal'" in lines and
            [line for line in lines if line.startswith("native-code:")] == ["native-code: 'arm64-v8a'"],
            "Incorrect Bare Personal application, label, version or ABI")
    with ZipFile(file) as apk:
        names = apk.namelist()
        require(len(set(names)) == len(names) and apk.testzip() is None, "Duplicate or corrupt APK contents")
        with apk.open("assets/bare/ublock_origin.crx") as crx:
            require(hashlib.file_digest(crx, "sha256").hexdigest() == UBO_SHA, "Bundled uBlock Origin differs")
        with apk.open("lib/arm64-v8a/libchrome.so") as library:
            h=library.read(20)
            require(h[:6] == b"\x7fELF\x02\x01" and h[18:20] == b"\xb7\x00", "Expected the AArch64 Chrome library")


def clear_bundle(bundle, pickup, directory, aapt2, apksigner):
    """Inspect and extract only the APK generated by the authenticated physical source, before release signing."""
    require(pickup["campaign"] == CAMPAIGN and pickup["source_run"] == pickup["seal"]["run"] and
            0 < bundle.stat().st_size <= apk_seal.CIPHER_CAP and
            apk_seal.validate(pickup["seal"], run=pickup["source_run"], ordinal=pickup["seal"]["ordinal"],
                              head=pickup["seal"]["producer_sha"], parent=pickup["seal"]["accepted_parent"]),
            "Wrong pickup or oversized decrypted tar")
    directory.mkdir(mode=0o700, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=directory) as temp, tarfile.open(bundle, "r:") as archive:
        members = []
        for member in archive:
            require(len(members) < 2 and member.isreg() and not getattr(member, "sparse", None),
                    "Unexpected link, sparse file or extra entry in clear transfer")
            members.append(member)
        require([m.name for m in members] == ["ChromePublic.apk", "apk-metadata.json"] and
                0 < members[0].size <= 450*1024**2 and 0 < members[1].size <= 16384, "Incorrect clear payload")
        expected = dict(apk="ChromePublic.apk",package="org.barebrowser.personal",version_name="2.0.4",
                        version_code="802000415", abi="arm64-v8a", signer_sha256=CI_CERT,
                        embedded_ublock_origin_sha256=UBO_SHA, bare_revision=BARE_REV,chromium_revision=CHROMIUM_REV,
                        ci_revision=pickup["seal"]["producer_sha"],bytes=members[0].size)
        with archive.extractfile(members[1]) as data:
            metadata = json.load(data)
        require(all(metadata.get(k) == v for k,v in expected.items()), "Generated APK input metadata differs")
        staged=Path(temp)/"ChromePublic.apk"
        with archive.extractfile(members[0]) as data, staged.open("xb") as out:
            shutil.copyfileobj(data,out,1024**2)
        require(digest(staged) == metadata["sha256"] and staged.stat().st_size == metadata["bytes"],
                "Generated APK hash or byte count differs")
        verify_signer(staged,CI_CERT,apksigner)
        verify_application(staged,aapt2)
        install(staged,directory/staged.name)
    return metadata


def owner_check(ticket, listing, publication, file, apksigner):
    """Verify the exact final version from the owner's own listing, download and trusted signing kit."""
    dest = ticket["owner_destination_id"]
    expected = ticket["final_certificate_sha256"]
    require(re.fullmatch("[0-9a-f]{64}", expected) and ticket["account_id"] == "personal" and
            publication["certificate_sha256"] == expected, "Final signing identity changed")
    items = [i for i in listing["items"] if i.get("library_file_id") == dest]
    require(len(items) == 1 and listing["surface"] == "library", "Owner destination missing or ambiguous")
    item, = items
    require(item["kind"] == "file" and item["surface"] == "library" and not item.get("is_shared", False) and
            item["path"] == ticket["final_path"] and int(item["version_id"]) == int(publication["version"]) and
            int(item["version_id"]) > int(ticket["reserved_version"]) and
            item["file_id"] == publication["file_id"] and publication["library_file_id"] == dest and
            item["size_bytes"] == file.stat().st_size and digest(file) == publication["signed_sha256"],
            "Final owner access, publication version, object or bytes differ")
    verify_signer(file, expected, apksigner)
    return dict(state="delivered", owner_link=f"https://chatgpt.com/library?file_id={dest}&account_id=personal",
                library_file_id=dest, version=int(item["version_id"]), signed_sha256=publication["signed_sha256"],
                certificate_sha256=expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    src = sub.add_parser("collect")
    src.add_argument("locator", type=Path)
    src.add_argument("directory", type=Path)
    clear = sub.add_parser("clear")
    for name in ("tar", "pickup", "directory", "aapt2", "apksigner_jar"):
        clear.add_argument(name, type=Path)
    final = sub.add_parser("owner")
    for name in ("ticket", "listing", "publication", "apk", "aapt2", "apksigner_jar"):
        final.add_argument(name, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "collect":
        sys.path.insert(0, str(Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)))
        import transfer
        from recover_private import read_only
        transfer.request = read_only(transfer.request)
        result = collect(json.loads(args.locator.read_bytes()), args.directory, transfer)
    elif args.operation == "clear":
        result = clear_bundle(args.tar,json.loads(args.pickup.read_bytes()),args.directory,args.aapt2,args.apksigner_jar)
    else:
        verify_application(args.apk,args.aapt2)
        result = owner_check(*[json.loads(path.read_bytes()) for path in (args.ticket, args.listing, args.publication)],
                             args.apk, args.apksigner_jar)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
