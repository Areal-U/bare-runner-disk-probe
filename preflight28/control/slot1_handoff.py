"""Consume the one R30 right whose first segment never reached restore or computation."""
import hashlib
import io
import json

from admission import BASE_REF, RELEASE_ID, REPO_ID, S2_SHA, require


CAMPAIGN = "bare-personal-204-r30"
SOURCE_RUN = 45765306771
SOURCE_HEAD = "44f0ac2e1b4fe438b028f6b7bd51945a0b978f99"
SOURCE_CLAIM_NAME = CAMPAIGN + "-production-run-claim.json"
SOURCE_CLAIM_ID = 794539925
SOURCE_CLAIM_SHA = "25241bad2c3fec02bd89d660800e266ae033ee5ead20daa70dc42d1f84357755"
SOURCE_TICKET_NAME = CAMPAIGN + "-preclaim-1-collection-registration.json"
SOURCE_TICKET_ID = 794535293
SOURCE_TICKET_SHA = "e081621545f0e1c24d5a001ca76ad7137b2d89b3177f2da7afdda85af6154f91"
SOURCE_ACK_ID = 794533360
SOURCE_ACK_SHA = "17e1ab8b0410918f5e625c2144da84f79e5eeb2050aa4d30311110c5a3f7c5f8"

# One immutable asset name across all successor run IDs, ticket IDs and attempts.
CLAIM = CAMPAIGN + "-slot1-handoff-794539925.json"
TICKET_NAME = CAMPAIGN + "-slot1-handoff-collection-registration.json"
SOURCE_JOBS = {139724689961: "success", 139724744160: "success", 139724941018: "failure",
               139725001309: "failure", 139725069495: "failure"}
SOURCE_WITNESS_ID = 15091985701
SOURCE_WITNESS_DIGEST = "sha256:823c608c02416299aba5b253ed1afbdbb41c8029392fd62a671461cbd493c600"


def check_reference(holder):
    require(type(holder.get("run_id")) is int and holder["run_id"] > 0 and holder["run_id"] != SOURCE_RUN and
            type(holder.get("source_run_id")) is int and holder["source_run_id"] == SOURCE_RUN and
            type(holder.get("source_claim_id")) is int and holder["source_claim_id"] == SOURCE_CLAIM_ID and
            holder.get("source_claim_sha") == SOURCE_CLAIM_SHA, "Unbound or circular slot 1 handoff")


def check_binding(source_claim, source_ticket, new_ticket):
    from registration import RECIPIENT, WORKFLOW

    prior = dict(schema=1, campaign=CAMPAIGN, release_id=RELEASE_ID, repository_id=REPO_ID,
                 branch=BASE_REF, workflow=WORKFLOW, recipient=RECIPIENT, initial_parent=S2_SHA)
    require(all(source_claim.get(k) == source_ticket.get(k) == new_ticket.get(k) == value
                for k, value in prior.items()), "Slot 1 handoff changed its parent, recipient or build route")
    physical = dict(run_id=SOURCE_RUN, producer_attempt=1, head=SOURCE_HEAD, ticket_asset_id=SOURCE_TICKET_ID,
                    ticket_sha=SOURCE_TICKET_SHA, collector_ack_asset_id=SOURCE_ACK_ID)
    require(all(source_claim.get(k) == v for k, v in physical.items()) and
            source_ticket["head"] == SOURCE_HEAD and source_ticket["collector_ack_sha"] == SOURCE_ACK_SHA and
            source_claim["registration_id"] == source_ticket["collector_registration_id"],
            "Unbound originating R30 compute claim")
    unchanged = ("collector_registration_id", "owner_destination_id", "artifact_ceiling_bytes", "storage_policy",
                 "storage_valid_until", "expires_at")
    require(all(new_ticket[k] == source_ticket[k] for k in unchanged) and
            all(new_ticket[k] != source_ticket[k] for k in ("head", "registration_nonce", "collector_ack_sha")),
            "Slot 1 handoff requires the same owner and grant with a fresh revision, nonce and ACK")


def read_fixed(helper, release, name, aid, length, sha, *, owner=False):
    from registration import OWNER

    row = helper.asset_info(release, name, length, sha, aid)
    if owner:
        require(all((row.get("uploader") or {}).get(k) == v for k, v in OWNER.items()),
                "Unknown issuer of the original R30 receipt")
    sink = io.BytesIO()
    helper.download(aid, length, sha, sink)
    raw = sink.getvalue()
    require(len(raw) == length and hashlib.sha256(raw).hexdigest() == sha, "Changed original R30 receipt")
    return json.loads(raw)


def check_unstarted(helper):
    from registration import OWNER, WORKFLOW

    base = f"{helper.BASE}/actions/runs/{SOURCE_RUN}"
    run = helper.metadata(base)
    require(run["id"] == SOURCE_RUN and run["run_attempt"] == 1 and run["head_sha"] == SOURCE_HEAD and
            run["head_branch"] == BASE_REF and run["path"] == WORKFLOW and run["event"] == "workflow_dispatch" and
            run["repository"]["id"] == run["head_repository"]["id"] == REPO_ID and
            all(run["actor"].get(k) == v for k, v in OWNER.items()) and
            run["status"] == "completed" and run["conclusion"] == "failure",
            "Original run is unfinished, rerun or foreign")
    page = helper.metadata(base + "/attempts/1/jobs?per_page=100")
    jobs = page["jobs"]
    require(page["total_count"] == len(jobs) == len({j["id"] for j in jobs}) == 37 and
            all(j["run_id"] == SOURCE_RUN and j["run_attempt"] == 1 and j["head_sha"] == SOURCE_HEAD and
                j["status"] == "completed" for j in jobs) and
            {j["id"]: j["conclusion"] for j in jobs if j["conclusion"] != "skipped"} == SOURCE_JOBS,
            "Original run's 37 jobs do not establish an unstarted first segment")
    page = helper.metadata(base + "/artifacts?per_page=100")
    rows = page["artifacts"]
    require(page["total_count"] == len(rows) == 1, "Unexpected original build or recovery Artifact")
    witness = rows[0]
    expected = dict(id=SOURCE_WITNESS_ID, name=f"r28-{SOURCE_RUN}-a1-owner-claim", size_in_bytes=683,
                    digest=SOURCE_WITNESS_DIGEST, expired=False)
    require(all(witness.get(k) == v for k, v in expected.items()) and
            witness["workflow_run"]["id"] == SOURCE_RUN and witness["workflow_run"]["head_sha"] == SOURCE_HEAD,
            "Original run's only Artifact must be its fixed owner claim witness")


def validate_source(helper, release, ticket, *, initial):
    claim = read_fixed(helper, release, SOURCE_CLAIM_NAME, SOURCE_CLAIM_ID, 649, SOURCE_CLAIM_SHA)
    prior = read_fixed(helper, release, SOURCE_TICKET_NAME, SOURCE_TICKET_ID, 941, SOURCE_TICKET_SHA, owner=True)
    check_binding(claim, prior, ticket)
    if initial:
        ack_name = f"{CAMPAIGN}-collector-ack-{prior['registration_nonce']}.json"
        old_ack = read_fixed(helper, release, ack_name, SOURCE_ACK_ID, 824, SOURCE_ACK_SHA, owner=True)
        require(all(old_ack.get(k) == prior[k] for k in ("head", "collector_registration_id", "owner_destination_id",
                "registration_nonce", "recipient")) and old_ack["state"] == "collector-read-back-owner-reservation",
                "Original independent acknowledgement disagrees with its fixed owner ticket")
        require(all(r["name"] != CAMPAIGN + "-loss-replacement-claim.json" for r in release["assets"]),
                "Already admitted an exceptional replacement of this compute right")
        check_unstarted(helper)
