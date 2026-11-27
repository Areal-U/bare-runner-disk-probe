"""One distinct S1 handoff after the witnessed package-setup failure."""
from admission import BASE_REF, require
import s1_label_resume as previous
from slot1_handoff import read_fixed

SOURCE_RUN = previous.SOURCE_RUN
PARENT_SHA, PARENT_IDENTITY = previous.PARENT_SHA, previous.PARENT_IDENTITY
FAILED_RUN = 45941809628
FAILED_HEAD = "be0124934efb819a95202215ccf1601a44d86f81"
SOURCE_CLAIM_ID = 799012388
SOURCE_CLAIM_SHA = "4e8cbddeb6dc0fcdd2a5c49819ad811c3716a80dbe232087890f73008c749a11"
TICKET_ID = 799006738
TICKET_SHA = "05c030b22b66fea61505b40f56e2e0bb86e55f10095629608b54322297f64200"
# Exact bytes of the closed owner ledger, including the four historical Artifact
# receipts and the failed outcome ZIP and member digests. Jobs are checked below.
CLOSURE_SHA = "d316a6fea8b2946b66c3fc418a223b96dc4d2fda72b45b2bda3c5a9a900e03b8"
CLAIM = previous.s1.CAMPAIGN + "-s02-setup-repair-799012388.json"
TICKET_NAME = previous.s1.CAMPAIGN + "-s02-setup-repair-799012388-collection-registration.json"
PREVIOUS_TRIAL = 45929712881
PREVIOUS_TRIAL_HEAD = "cc748c38aec27a16d8004bda30de36bb083c0ad3"


def failure_fields():
    return dict(setup_failure_run_id=FAILED_RUN, setup_failure_claim_id=SOURCE_CLAIM_ID,
                 setup_failure_claim_sha=SOURCE_CLAIM_SHA, setup_failure_closure_sha=CLOSURE_SHA)


def route(ticket):
    accepted = previous.route(ticket)
    fixed = failure_fields()
    previous.s1.fields(ticket, fixed, "Wrong preceding setup failure, claim or owner closure")
    require(accepted["trial_run_id"] not in (FAILED_RUN, PREVIOUS_TRIAL) and
            accepted["trial_head"] != PREVIOUS_TRIAL_HEAD, "A fresh dependency and resource trial is required")
    return dict(accepted, **fixed)


def source_rows():
    return ((previous.CLAIM, SOURCE_CLAIM_ID, 1400, SOURCE_CLAIM_SHA, False),
            (previous.TICKET_NAME, TICKET_ID, 1578, TICKET_SHA, True))


def check_binding(claim, old_ticket, ticket):
    previous.check_reference(claim, old_ticket)
    previous.s1.fields(claim, dict(run_id=FAILED_RUN, producer_attempt=1, head=FAILED_HEAD,
                       ticket_asset_id=TICKET_ID, ticket_sha=TICKET_SHA,
                       registration_id=old_ticket["collector_registration_id"]), "Wrong prior admitted run")
    previous.s1.fields(old_ticket, dict(head=FAILED_HEAD, trial_run_id=PREVIOUS_TRIAL,
                       trial_head=PREVIOUS_TRIAL_HEAD), "Wrong prior owner registration")
    stable = ("schema", "repository_id", "release_id", "campaign", "workflow", "branch", "recipient",
              "owner_destination_id", "collector_registration_id", "storage_policy", "artifact_ceiling_bytes",
              "storage_valid_until", "expires_at", "final_certificate_sha256")
    previous.s1.fields(ticket, {k: old_ticket[k] for k in stable}, "Changed destination, signing or free grant")
    require(all(ticket[k] != old_ticket[k] for k in ("head", "registration_nonce", "collector_ack_sha")),
            "Setup retry requires a new revision, nonce and receiver acknowledgement")
    route(ticket)


def check_reference(claim, ticket):
    previous.s1.fields(claim, dict(route(ticket), source_claim_id=SOURCE_CLAIM_ID, source_claim_sha=SOURCE_CLAIM_SHA),
                       "Unbound setup retry claim")
    rid = claim.get("run_id")
    require(type(rid) is int and rid > 0 and rid not in (FAILED_RUN, SOURCE_RUN, previous.CONSUMED,
            previous.FAILED_TRIAL, PREVIOUS_TRIAL, ticket["trial_run_id"]), "Circular setup retry claim")


def check_failed_run(helper):
    from registration import WORKFLOW
    jobs = previous.s1.checked_run(helper, FAILED_RUN, FAILED_HEAD, BASE_REF, WORKFLOW, "failure")
    successful = {140317588514, 140317617454, 140317767829, 140317851385}
    failed = {140317851617, 140323733601, 140323786254}
    require(len(jobs) == 37 and {k for k, j in jobs.items() if j["conclusion"] == "success"} == successful and
            {k for k, j in jobs.items() if j["conclusion"] == "failure"} == failed and
            all(j["conclusion"] == "skipped" for k, j in jobs.items() if k not in successful | failed),
            "Prior production run is not the completed pre-compilation failure")
    previous.s1.fields(previous.steps(jobs[140317851617]), {
        "Open restricted peer descriptor and verify the exact input archive": "success",
        "Install build tools and apply the pinned Bare patches": "failure",
        previous.s1.FRONTIER: "skipped", previous.s1.COMPILE: "skipped", previous.SEAL: "skipped",
        "Pack the completed intermediate outputs": "skipped"}, "Previous run produced or advanced an output")
    previous.s1.fields(previous.steps(jobs[140317851385]), {
        "Discover exact peer outcome": "success", "Fetch authenticated outcome by immutable artifact ID": "success",
        "Receive bounded ciphertext and independently verify fixed private publication": "success"},
        "Previous failed outcome lacks its actual independent receipt")
    previous.s1.fields(previous.steps(jobs[140323786254]), {
        "Check every causal transition and select the sole outcome": "failure"},
        "Unexpected overall terminal disposition")


def validate_source(helper, release, ticket, *, initial):
    documents = [read_fixed(helper, release, name, aid, size, sha, owner=owner)
                 for name, aid, size, sha, owner in source_rows()]
    check_binding(*documents, ticket)
    if initial:
        check_failed_run(helper)
    # Validate the original S1, its older grant, and the exact new trial using
    # the same verifier and source equivalence checks as the prior label repair.
    previous.validate_source(helper, release, ticket, initial=initial)
