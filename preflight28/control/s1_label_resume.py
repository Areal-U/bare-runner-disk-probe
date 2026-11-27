"""Admit one new, owner-acknowledged label repair from the immutable R30 S1."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryFile

from admission import BASE_REF, REPO, REPO_ID, require
import s1_resume as s1
from slot1_handoff import read_fixed

SOURCE_RUN = s1.SOURCE_RUN
PARENT_SHA = s1.PARENT_SHA
PARENT_IDENTITY = s1.PARENT_IDENTITY
CONSUMED = 45841492691
CONSUMED_HEAD = "06bb17ab5a6c17b59b06c9c4566e123780c2a3ca"
COMPUTE = 139984606696
SOURCE_CLAIM_ID = 796328557
SOURCE_CLAIM_SHA = "bc0dd939c925a363d14a831eced03f0965fb687fc9b2c60bf93f611eaefd1c7c"
OLD_TICKET_ID = 796306810
OLD_TICKET_SHA = "e21fc767b4c5ea8a5a6264ff44fd5af410d9b95376591632a02c150c48a3986c"
OLD_ACK_SHA = "c03da98452f428f3856f2715852275085d781c665b8c2ecbb8f58efda25307e2"
CLOSURE_SHA = "1a22b4050ad0493db3f1a3bac6d0f3bea8bd2ff19422af033cfe75dba2c2e46c"
OWNER_CERT_COMMITMENT = "5c7257bce4824872e737c11b2bcb7d26da60d8cb8488b6555819dce77a58ddd5"
TICKET_NAME = s1.CAMPAIGN + "-s02-label-repair-preclaim-45938899386-collection-registration.json"
CLAIM = s1.CAMPAIGN + "-s02-label-repair-796328557.json"
TRIAL_BRANCH = "bare-r30-s1-label-20261127"
FAILED_TRIAL = 45905086655
CERTIFY = "Certify the fixed S1 resource-label test"
LABEL_STEP = "Rebuild the linked resource package and verify effective Personal launcher labels"
SEAL = "Verify the completed APK and encrypt it for private recovery"
TRIAL_JOB = "Check resource regeneration from the fixed R30 S1 / "
COMPUTE_NAME = TRIAL_JOB + "Compile or verify authenticated APK slot 2"
SENDER_NAME = TRIAL_JOB + "Private checkpoint receipt for slot 2"
HELPERS = ("preflight28/graph/graph.py", "preflight28/graph/personal_label.py",
           "preflight28/signing/launcher_labels.py", "preflight28/graph/label_resource_trial.py")
COMMON = (*HELPERS, "coexist_inputs.py", "checkpoint.py", "build_trial.py",
          "preflight28/graph/angle_restore.py", "preflight28/graph/segment_graph.py",
          "preflight28/graph/retained.py", "preflight28/graph/contract_gate.py",
          "preflight28/graph/android_outputs.py", "preflight28/graph/metrics_evidence.py",
          "preflight28/bridge/storage_admission.py", "preflight28/bridge/bridge.py",
          "preflight28/bridge/artifact_poll.py", "preflight28/bridge/normal.py",
          "preflight28/transport/prepare.py", "preflight28/transport/recipes/install_six.sh")
WORKER = ".github/workflows/bare-arm64-probe.yml"
ROOT = Path(__file__).resolve().parents[2]
CERT_PATH = "preflight28/graph/label_trial_certificate.json"
# Independently derived from the fixed S1 frontier and GN copy edge.
PENDING_SHA = "0f475e82f12516553f7e6d7278be9fcca3a5a5b87cbc7ab2ad5689faa1dcd5fd"
PATHMAP = dict(group="ea99def354ace13d91376294e40913863e1920533923f66324f93583fdfaedaa",
               source="gen/chrome/android/chrome_public_apk_resources_path_map.txt",
               output="apks/ChromePublic.apk.pathmap.txt", bytes=203458,
               sha256="72fc4945715ff35ece4aff242172f614e1385a6bd0d57bd34fba43855690d956")


def checked_pathmap(record):
    require(isinstance(record, dict) and type(record.get("executed")) is bool and
            type(record.get("bytes")) is int and record == dict(PATHMAP, executed=record["executed"]),
            "Unverified resource path map in the independent trial")
    return record


def checked_final_certificate(value):
    # The owner issues the fingerprint privately; the public repository has only
    # a commitment to its 64-character lowercase spelling in the closed ledger.
    require(isinstance(value, str) and re.fullmatch("[0-9a-f]{64}", value) and
            hashlib.sha256(value.encode("ascii")).hexdigest() == OWNER_CERT_COMMITMENT,
            "Different final signing certificate")
    return value


def route(ticket):
    result = s1.route(ticket)
    require(result["trial_run_id"] not in (CONSUMED, FAILED_TRIAL) and
            result["trial_head"] != CONSUMED_HEAD, "A consumed or failed trial cannot authorize a build")
    fixed = dict(parent_identity=PARENT_IDENTITY, consumed_run_id=CONSUMED,
                 consumed_claim_id=SOURCE_CLAIM_ID, consumed_claim_sha=SOURCE_CLAIM_SHA,
                 prior_owner_closure_sha=CLOSURE_SHA,
                 final_certificate_sha256=checked_final_certificate(ticket.get("final_certificate_sha256")))
    s1.fields(ticket, fixed, "Different owner closure, signer or consumed operation")
    return dict(result, **fixed)


def source_rows():
    return ((s1.CLAIM, SOURCE_CLAIM_ID, 980, SOURCE_CLAIM_SHA, False),
            (s1.TICKET_NAME, OLD_TICKET_ID, 1158, OLD_TICKET_SHA, True))


def check_reference(claim, ticket):
    s1.fields(claim, dict(route(ticket), source_claim_id=SOURCE_CLAIM_ID, source_claim_sha=SOURCE_CLAIM_SHA),
              "Unbound label repair claim")
    rid = claim.get("run_id")
    require(type(rid) is int and rid > 0 and rid not in
            (SOURCE_RUN, CONSUMED, FAILED_TRIAL, ticket["trial_run_id"]), "Circular label repair claim")


def check_binding(old_claim, prior, ticket):
    s1.check_reference(old_claim, prior)
    s1.fields(old_claim, dict(run_id=CONSUMED, producer_attempt=1, head=CONSUMED_HEAD,
              ticket_asset_id=OLD_TICKET_ID, ticket_sha=OLD_TICKET_SHA,
              registration_id=prior["collector_registration_id"]), "Wrong consumed continuation")
    s1.fields(prior, dict(head=CONSUMED_HEAD, collector_ack_sha=OLD_ACK_SHA), "Different owner ticket")
    fields = ("schema", "repository_id", "release_id", "campaign", "workflow", "branch", "recipient",
              "owner_destination_id", "collector_registration_id", "storage_policy",
              "artifact_ceiling_bytes", "storage_valid_until", "expires_at")
    s1.fields(ticket, {k: prior[k] for k in fields}, "Changed owner, private destination, expiry or free storage")
    require(all(ticket[k] != prior[k] for k in ("registration_nonce", "head", "collector_ack_sha")),
            "Cannot reuse the consumed owner's reservation")
    route(ticket)


def steps(job):
    rows = job.get("steps") or []
    result = {s["name"]: s["conclusion"] for s in rows}
    require(len(result) == len(rows), "Ambiguous GitHub job steps")
    return result


def check_consumed(helper):
    from registration import WORKFLOW
    jobs = s1.checked_run(helper, CONSUMED, CONSUMED_HEAD, BASE_REF, WORKFLOW, "failure")
    success = {139984059474, 139984121222, 139984475407, 139984606391}
    failed = {COMPUTE, 140023883234, 140023956273}
    require(len(jobs) == 37 and {k for k,j in jobs.items() if j["conclusion"] == "success"} == success
            and {k for k,j in jobs.items() if j["conclusion"] == "failure"} == failed
            and all(j["conclusion"] == "skipped" for k,j in jobs.items() if k not in success | failed),
            "Consumed production run changed")
    skipped = ("Persist the original sealed APK receipt", "Upload the encrypted APK bundle",
               "Save only the encrypted APK for retrieval retry", "Record the encrypted APK fallback receipt",
               "Classify progress on the fixed APK graph after all writers stop", "Pack the completed intermediate outputs")
    s1.fields(steps(jobs[COMPUTE]), dict({s1.FRONTIER: "success", s1.COMPILE: "success",
              "Stop every build writer before making the archive": "success", SEAL: "failure"},
              **dict.fromkeys(skipped, "skipped")), "The original run has a different terminal disposition")


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def source_tree(helper, revision):
    tree = helper.metadata(f"{helper.BASE}/git/trees/{revision}?recursive=1")
    require(tree["truncated"] is False, "Incomplete implementation tree")
    return {r["path"]: r["sha"] for r in tree["tree"] if r["type"] == "blob"}


def migration_report(job_id):
    # Resolve the logs using the runner's authenticated GitHub client. Print neither
    # the temporary URL nor arbitrary archived log text.
    pattern = re.compile(rb"^\d{4}-\d\d-\d\dT[0-9:.]+Z BARE_LABEL_MIGRATION (\{[^\r\n]*\})\r?\n?$")
    with TemporaryFile() as log:
        # Hosted job logs contain ANSI formatting. Keep the original bytes in
        # this private file so only the exact timestamped report is parsed.
        subprocess.run(["gh", "api", "--allow-escape-sequences", f"repos/{REPO}/actions/jobs/{job_id}/logs"],
                       stdout=log, timeout=90, check=True)
        require(log.tell() <= 128 * 1024**2, "Unexpected trial log size")
        log.seek(0)
        reports = [json.loads(m[1]) for line in log if (m := pattern.fullmatch(line))]
    require(len(reports) == 1, "Expected exactly one actual trial migration")
    return reports[0]


def verify_trial(helper, ticket):
    fixed = route(ticket)
    rid, head = fixed["trial_run_id"], fixed["trial_head"]
    cert_bytes = (ROOT / CERT_PATH).read_bytes()
    cert = json.loads(cert_bytes)
    s1.fields(cert, dict(status="accepted", trial_run_id=rid, trial_attempt=1, trial_head=head,
                        source_sha256=PARENT_SHA), "Resource trial certificate has not been accepted")
    trial = source_tree(helper, head)
    normal = source_tree(helper, ticket["head"])
    require(normal.get(CERT_PATH) == git_blob(cert_bytes) and
            all(trial[p] == normal[p] == git_blob((ROOT / p).read_bytes()) for p in COMMON),
            "Different trial and production helpers or certificate")
    s1.fields(cert, dict(trial_workflow_blob=trial[s1.TRIAL_WORKFLOW], trial_worker_blob=trial[WORKER],
              helpers={Path(p).name: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in HELPERS}),
              "Unreviewed trial workflow or resource verifier")
    jobs = s1.checked_run(helper, rid, head, TRIAL_BRANCH, s1.TRIAL_WORKFLOW, "success")
    cert_jobs = [j for j in jobs.values() if j["name"] == CERTIFY]
    workers = [(jid,j) for jid,j in jobs.items() if LABEL_STEP in steps(j)]
    require(len(jobs) == 4 and len(cert_jobs) == len(workers) == 1 and
            {j["name"] for j in jobs.values()} == {CERTIFY, COMPUTE_NAME, SENDER_NAME, "measure"} and
            all(j["conclusion"] == ("skipped" if j["name"] == "measure" else "success") for j in jobs.values()),
            "The fixed resource trial did not complete")
    s1.fields(steps(cert_jobs[0]), {"Check the independent restore result": "success"}, "No trial certification")
    jid, worker = workers[0]
    require(worker["name"] == COMPUTE_NAME, "Wrong resource compute job")
    s1.fields(steps(worker), {s1.NEGATIVE: "success", s1.FRONTIER: "success", LABEL_STEP: "success",
              s1.COMPILE: "skipped"}, "Independent trial did not prove this migration")
    report = migration_report(jid)
    s1.fields(report, dict(mode="trial", parent_sha256=PARENT_SHA, old_pending=1911, remaining=1911,
                           pending_sha256=PENDING_SHA),
              "The independent resource work changed the remaining APK actions")
    require(cert.get("pending_sha256") == PENDING_SHA and
            checked_pathmap(cert.get("pathmap_copy")) == checked_pathmap(report.get("pathmap_copy")),
            "The certificate does not match the independently measured path map or frontier")
    previous = {"b319b80fae9723d99a5d3441a4e6bcb778ea35e32b63f203cb3a289aa8baa40e",
                "a01ff002507636f864c6fc62b4b153f5fec8e8fa3436af79a012098b659420db"}
    hashes = {"raw_sha256": report["resource_sha256"], "optimized_sha256": report["optimized_sha256"]}
    require(len(set(hashes.values())) == 2 and all(re.fullmatch("[0-9a-f]{64}", v) and v not in previous
            for v in hashes.values()), "Resources were not both regenerated")
    s1.fields(cert, hashes, "The normal certificate differs from the actual trial data")
    main = "com.google.android.apps.chrome.Main"
    launchers = {main + suffix for suffix in ("", "NewIcon", "IconDark", "IconRetro")}
    for key in ("raw_labels", "optimized_labels"):
        labels = report[key]
        require(labels["application"] == ["Bare Personal"] and labels["enabled"] == [main] and
                labels["launchers"].keys() == launchers and
                all(v == ["Bare Personal"] for v in labels["launchers"].values()), "Wrong trial launcher label")


def validate_source(helper, release, ticket, *, initial):
    old = [read_fixed(helper, release, name, aid, size, sha, owner=owner)
           for name, aid, size, sha, owner in source_rows()]
    check_binding(*old, ticket)
    if initial:
        require(not any(row["name"] == s1.CAMPAIGN + "-loss-replacement-claim.json" for row in release["assets"]),
                "Conflicting exceptional producer")
        check_consumed(helper)
        rows = [r for r in release["assets"] if r["id"] == s1.MANIFEST_ID]
        supported = {f"r28-{SOURCE_RUN}-a1-s01-manifest.json" + suffix for suffix in ("", "-retry1")}
        require(len(rows) == 1 and rows[0]["name"] in supported, "Original S1 manifest missing")
        read_fixed(helper, release, rows[0]["name"], s1.MANIFEST_ID, 948, s1.MANIFEST_SHA)
        verify_trial(helper, ticket)
