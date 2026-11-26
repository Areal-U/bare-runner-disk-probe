"""Generate inert, exact-length private documents for the slot-1 readback tests."""
import hashlib
import json
from unittest.mock import patch

import slot1_handoff as h


def sample(test, ticket):
    ticket.update(registration_nonce="1"*32, collector_ack_sha="5"*64,
                  artifact_ceiling_bytes=48*1024**3, storage_policy="github-public-standard-r28-v1",
                  storage_valid_until="2027-01-04T09:00:00Z", expires_at="2026-12-04T09:00:00Z")
    old = dict(ticket, head=h.SOURCE_HEAD, registration_nonce="2"*32, collector_ack_sha=h.SOURCE_ACK_SHA)

    def fixed(document, size):
        data = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        assert len(data) <= size
        return data.ljust(size, b" ")

    previous = fixed(old, 941)
    test.enterContext(patch.object(h, "SOURCE_TICKET_SHA", hashlib.sha256(previous).hexdigest()))
    common = {k: old[k] for k in ("schema","campaign","head","repository_id","release_id","branch",
                                  "workflow","recipient","initial_parent")}
    source = dict(common, run_id=h.SOURCE_RUN, producer_attempt=1, registration_id=old["collector_registration_id"],
                  ticket_asset_id=h.SOURCE_TICKET_ID, ticket_sha=h.SOURCE_TICKET_SHA,
                  collector_ack_asset_id=h.SOURCE_ACK_ID)
    grant = fixed(source, 649)
    test.enterContext(patch.object(h, "SOURCE_CLAIM_SHA", hashlib.sha256(grant).hexdigest()))
    refs = dict(source_run_id=h.SOURCE_RUN,source_claim_id=h.SOURCE_CLAIM_ID,source_claim_sha=h.SOURCE_CLAIM_SHA)
    return ((h.SOURCE_CLAIM_NAME,h.SOURCE_CLAIM_ID,grant,False),
            (h.SOURCE_TICKET_NAME,h.SOURCE_TICKET_ID,previous,True)), refs
