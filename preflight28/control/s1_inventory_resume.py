"""Admit one S1 successor to the closed, pre-restore artifact-inventory failure."""
import hashlib
import json

from admission import BASE_REF, require
from slot1_handoff import read_fixed
import s1_label_resume as label
import s1_resume as s1
import s1_setup_resume as previous

SOURCE_RUN = s1.SOURCE_RUN
PARENT_SHA, PARENT_IDENTITY = s1.PARENT_SHA, s1.PARENT_IDENTITY
FAILED_RUN = 45954444176
FAILED_HEAD = "0ac89e1aec85756f69a0bbbce38fe326b47240dd"
SOURCE_CLAIM_ID = 799332558
SOURCE_CLAIM_SHA = "4a1f6a401cbbd806777144cd37e0182ce474a0494a2513f00415af7c00dfaf4f"
TICKET_ID = 799318316
TICKET_SHA = "2c65a148d07d1360a64c753415e1a3c11a54ecad55ec05050cbfc40a6c4d4669"
WITNESS_ID = 799332810
WITNESS_SHA = "46855c9a1ab97a25dbb85e056dde2df571315fa3306ffcd84f41e516514a266a"
TRIAL_RUN = 45945428584
TRIAL_HEAD = "d5951590ba22fb23b75b5af2a04d643fd4a4b9ab"
# Owner ledger v27 pins the no-APK closure, original witness and both private reservations.
CLOSURE_SHA = "0b94251d4eeda5355563fa9373e89dfbaab76a254a6d174dfd72eb9a73fd98a3"
TERMINAL_JOBS_SHA = "b4c824344904821353e8f7326bc75144e0bc5a96e3b3761ce630d5739e1634a0"
CLAIM = s1.CAMPAIGN + "-s02-inventory-repair-799332558.json"
TICKET_NAME = s1.CAMPAIGN + "-s02-inventory-repair-799332558-collection-registration.json"


def failure_fields():
    return dict(inventory_failure_run_id=FAILED_RUN, inventory_failure_claim_id=SOURCE_CLAIM_ID,
                inventory_failure_claim_sha=SOURCE_CLAIM_SHA, inventory_failure_closure_sha=CLOSURE_SHA)


def route(ticket):
    carried = previous.route(ticket)
    fixed = failure_fields()
    s1.fields(ticket, fixed, "Different inventory failure, claim or owner closure")
    s1.fields(carried, dict(trial_run_id=TRIAL_RUN, trial_head=TRIAL_HEAD), "Wrong accepted resource trial")
    return dict(carried, **fixed)


def source_rows():
    return ((previous.CLAIM, SOURCE_CLAIM_ID, 1658, SOURCE_CLAIM_SHA, False),
            (previous.TICKET_NAME, TICKET_ID, 1836, TICKET_SHA, True))


def check_binding(claim, old_ticket, ticket):
    previous.check_reference(claim, old_ticket)
    s1.fields(claim, dict(run_id=FAILED_RUN, producer_attempt=1, head=FAILED_HEAD,
                          ticket_asset_id=TICKET_ID, ticket_sha=TICKET_SHA,
                          registration_id=old_ticket["collector_registration_id"]),
              "Wrong prior inventory-failure producer")
    s1.fields(old_ticket, dict(head=FAILED_HEAD, trial_run_id=TRIAL_RUN, trial_head=TRIAL_HEAD),
              "Wrong owner ticket for the pre-restore failure")
    previous.same_owner_policy(old_ticket, ticket)
    route(ticket)


def check_reference(claim, ticket):
    s1.fields(claim, dict(route(ticket), source_claim_id=SOURCE_CLAIM_ID, source_claim_sha=SOURCE_CLAIM_SHA),
              "Unbound inventory retry claim")
    rid = claim.get("run_id")
    known = (SOURCE_RUN, label.CONSUMED, label.FAILED_TRIAL, previous.FAILED_RUN,
             previous.PREVIOUS_TRIAL, FAILED_RUN, TRIAL_RUN)
    require(type(rid) is int and rid > 0 and rid not in known, "Circular inventory retry claim")


def terminal_jobs_sha(jobs):
    # Hash stable service fields only, including every skipped, failed and successful step.
    report = [(jid, job["name"], job["conclusion"],
               sorted((row["number"], row["name"], row["conclusion"]) for row in job.get("steps", [])))
              for jid, job in sorted(jobs.items())]
    return hashlib.sha256(json.dumps(report, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


def check_failed_run(helper):
    from registration import WORKFLOW
    jobs = s1.checked_run(helper, FAILED_RUN, FAILED_HEAD, BASE_REF, WORKFLOW, "failure")
    require(terminal_jobs_sha(jobs) == TERMINAL_JOBS_SHA,
            "Different terminal inventory or failed transfer before S1")
    s1.fields(label.steps(jobs[140357901621]), {
        "Create an ephemeral ordinary transfer key": "failure",
        "Deposit key in this run": "skipped",
        "Open restricted peer descriptor and verify the exact input archive": "skipped",
        s1.FRONTIER: "skipped", s1.COMPILE: "skipped", label.SEAL: "skipped"},
        "Prior producer reached S1 or completed a build")


def validate_source(helper, release, ticket, *, initial):
    documents = [read_fixed(helper, release, name, aid, size, sha, owner=owner)
                 for name, aid, size, sha, owner in source_rows()]
    check_binding(*documents, ticket)
    if initial:
        read_fixed(helper, release, f"r28-{FAILED_RUN}-a1-owner-claim.json", WITNESS_ID, 569, WITNESS_SHA)
        check_failed_run(helper)
    previous.validate_source(helper, release, ticket, initial=initial)
