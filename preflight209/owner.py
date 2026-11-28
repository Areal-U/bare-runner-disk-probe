"""Bind one 2.0.9 production attempt to the prior, independently acknowledged owner ticket."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'preflight28' / part) for part in ('control', 'bridge')]
from admission import PagedOwnerDraft, RELEASE_ID, REPO, REPO_ID, admit, encode, require
import storage_admission as storage
import precompile_cold as cold
import unpublished_cold as unpublished

BRANCH = 'bare-coexist-v2.0.9'
WORKFLOW = '.github/workflows/bare-checkpoint-transfer.yml'
VERSION = '2.0.9'
UPSTREAM = '019a612f7bb758da20c33ecf43c086e696391aec'
CERT = '8e15b0c83367964534fa7bf48999605263f4d9099d79d4134dccd0749a92cd13'
RECIPIENT = 'age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx'
# Bind the three reserved private IDs without placing the owner's private links in public source.
DESTINATION_HASH = '172b36f744781e3317c3be9f830561de316644b3d6c3d94721a5c3d9f6908655'
CAMPAIGN = 'bare-personal-209'
CLAIM = CAMPAIGN + '-origin-claim.json'
OWNER = {'id': 292261483, 'login': 'Areal-U'}
CEILING = 48 * 1024 ** 3
SEGMENT = 350 * 60
TAIL = 77 * 60


def instant(text):
    require(isinstance(text, str) and text.endswith('Z'), 'Expected UTC service timestamp')
    return datetime.fromisoformat(text.removesuffix('Z') + '+00:00')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def owner_account(user):
    return isinstance(user, dict) and all(user.get(k) == v for k, v in OWNER.items())


def pick(receipt, fields):
    require(all(k in receipt for k in fields), 'Missing ticket/acknowledgement fields')
    return {k: receipt[k] for k in fields}


def doc(api, release, name, aid, digest, created, *, producer_claim=False):
    require((aid == 'lookup' or (type(aid) is int and aid > 0)) and isinstance(digest, str) and
            re.fullmatch('[0-9a-f]{64}', digest), 'Invalid immutable owner document selector or digest')
    rows = [a for a in release['assets'] if a['name'] == name]
    require(len(rows) == 1, 'Missing or duplicate owner document')
    row = rows[0]
    # The binder writes the origin claim with GITHUB_TOKEN. Owner-authored
    # tickets and ACKs use the independent personal identity.
    uploader = row['uploader']
    claim_names = (CLAIM, f'{CAMPAIGN}-after-{cold.RUN}-claim.json')
    from_ci = producer_claim and name in claim_names and (uploader.get('login'), uploader.get('id')) == (
        'github-actions[bot]', 41898282)
    require(type(row['id']) is int and row['id'] > 0 and (aid == 'lookup' or aid == row['id']) and type(row['size']) is int and 0 < row['size'] <= 16 * 1024 and
            (owner_account(uploader) or from_ci) and instant(row['created_at']) <= created,
            'Wrong owner document, source or timing')
    aid = row['id']  # Resolved service ID is persisted in the immutable claim, including name+digest selection.
    api.asset_info(release, name, row['size'], digest, aid)
    raw = io.BytesIO()
    api.download(aid, row['size'], digest, raw)
    require(len(raw.getvalue()) == row['size'] and sha(raw.getvalue()) == digest, 'Unconfirmed private document bytes')
    return aid, json.loads(raw.getvalue())


def validate_identity(env, event, run, head):
    require(env['GITHUB_REPOSITORY'] == REPO and env['GITHUB_REF'] == 'refs/heads/' + BRANCH and
            env['GITHUB_RUN_ATTEMPT'] == '1' and env['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and
            run['id'] == int(env['GITHUB_RUN_ID']) and run['run_attempt'] == 1 and run['head_branch'] == BRANCH and
            run['head_sha'] == head and run['path'] == WORKFLOW and run['event'] == 'workflow_dispatch' and
            run['repository']['id'] == run['head_repository']['id'] == event['repository']['id'] == REPO_ID and
            owner_account(run['actor']) and owner_account(event['sender']) and event['inputs']['mode'] == 'build-apk',
            'Foreign physical run, ref, attempt or event')


def resume_input(event):
    return cold.parse_selector(event['inputs'].get('resume'))


def cold_parent(api, release, ticket, ack, genesis, head, now, created, *, verify_only, newest_ticket=None):
    prior = api.metadata(f'{api.BASE}/actions/runs/{cold.RUN}')
    require(prior['id'] == cold.RUN and prior['run_attempt'] == 1 and
            prior['head_sha'] == cold.HEAD and head != cold.HEAD and prior['head_branch'] == BRANCH and
            prior['path'] == WORKFLOW and prior['event'] == 'workflow_dispatch' and
            prior['repository']['id'] == prior['head_repository']['id'] == REPO_ID and owner_account(prior['actor']) and
            prior['status'] == 'completed' and prior['conclusion'] == 'failure' and
            instant(prior['updated_at']) <= instant(ack['observed_at']) <= created,
            'Origin is not the final precompile failure or owner acknowledgement predates closure')
    rows = [row for row in release['assets'] if row['name'] == CLAIM]
    require(len(rows) == 1 and re.fullmatch('sha256:[0-9a-f]{64}', rows[0]['digest']), 'Missing original claim')
    claim_sha = rows[0]['digest'][7:]
    claim_id, claim = doc(api, release, CLAIM, rows[0]['id'], claim_sha, instant(prior['updated_at']),
                          producer_claim=True)
    original = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, release_id=RELEASE_ID, branch=BRANCH,
                    workflow=WORKFLOW, head=cold.HEAD, genesis=genesis, producer_attempt=1, origin_run=cold.RUN,
                    recipient=RECIPIENT, destination_commitment=DESTINATION_HASH)
    require(all(claim.get(key) == value for key, value in original.items()) and 'resume' not in claim,
            'Original claim does not bind the initial run and genesis')
    cold.owner_proof(ticket, ack, claim_id, claim_sha)
    cutoff = instant(prior['created_at'])
    _, old_ticket = doc(api, release, f'{CAMPAIGN}-{cold.HEAD}-ticket.json', claim['ticket_asset_id'],
                        claim['ticket_sha'], cutoff)
    nonce = old_ticket['registration_nonce']
    _, old_ack = doc(api, release, f'{CAMPAIGN}-ack-{nonce}.json', claim['collector_ack_asset_id'],
                     claim['collector_ack_sha'], cutoff)
    require(nonce == old_ack['registration_nonce'] != ticket['registration_nonce'] and
            old_ticket['collector_registration_id'] == old_ack['collector_registration_id'] ==
            claim['collector_registration_id'] != ticket['collector_registration_id'] and
            old_ticket['collector_ack_sha'] == claim['collector_ack_sha'] and
            old_ticket['head'] == old_ack['head'] == cold.HEAD and
            old_ticket['genesis'] == old_ack['genesis'] == genesis and
            old_ticket['resume'] is None and old_ack['resume'] is None and
            old_ticket['destinations'] == old_ack['destinations'] == ticket['destinations'],
            'Independent successor must preserve the original destination and use a fresh finite registration')
    if newest_ticket is not None:
        require(nonce != newest_ticket['registration_nonce']
                and old_ticket['collector_registration_id'] != newest_ticket['collector_registration_id'],
                'Latest collector reuses the original closed registration')
    if not verify_only:
        cold.unavailable_outputs(api, release, now, BRANCH, storage, instant)
    return claim_id


def unpublished_parent(api, release, ticket, ack, genesis, head, now, created, *, verify_only):
    prior = api.metadata(f'{api.BASE}/actions/runs/{unpublished.RUN}')
    unpublished.check_run(prior, REPO_ID, owner_account)
    closed = instant(prior['updated_at'])
    require(head not in (cold.HEAD, unpublished.HEAD) and closed <= instant(ack['observed_at']) <= created,
            'A reviewed replacement head and owner closure before dispatch are required')
    proof = ack.get('unpublished_origin')
    required_fields = {'claim_asset_id', 'claim_sha256', 'ledger_sha256', 'ledger_state',
                       'intermediate_outcome_pickup'}
    require(isinstance(proof, dict) and set(proof) == required_fields and proof == ticket.get('unpublished_origin')
            and proof['ledger_state'] == 'closed-no-apk' and proof['intermediate_outcome_pickup'] is True
            and proof['ledger_sha256'] == unpublished.CLOSED_LEDGER_SHA256
            and cold.claim_commitment(proof['claim_asset_id'], proof['claim_sha256']) == unpublished.CLAIM_COMMITMENT,
            'New receipts do not bind the actual closed ledger and unpublished origin claim')

    name = f'{CAMPAIGN}-after-{cold.RUN}-claim.json'
    claim_id, claim = doc(api, release, name, proof['claim_asset_id'], proof['claim_sha256'], closed,
                          producer_claim=True)
    expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, release_id=RELEASE_ID, branch=BRANCH,
                    workflow=WORKFLOW, head=unpublished.HEAD, genesis=genesis, producer_attempt=1,
                    origin_run=unpublished.RUN, recipient=RECIPIENT, destination_commitment=DESTINATION_HASH,
                    resume=cold.SELECTOR)
    require(all(claim.get(k) == value for k, value in expected.items()), 'Unexpected prior checkpoint claim')
    cutoff = instant(prior['created_at'])
    _, old_ticket = doc(api, release, f'{CAMPAIGN}-{unpublished.HEAD}-after-{cold.RUN}-ticket.json',
                          claim['ticket_asset_id'], claim['ticket_sha'], cutoff)
    nonce = old_ticket['registration_nonce']
    aid, old_ack = doc(api, release, f'{CAMPAIGN}-ack-{nonce}.json',
                       claim['collector_ack_asset_id'], claim['collector_ack_sha'], cutoff)
    validate_route(old_ticket, old_ack, head=unpublished.HEAD, genesis=genesis, created=cutoff, now=cutoff,
                   resume=cold.SELECTOR)
    require(old_ticket['collector_ack_asset_id'] in ('lookup', aid)
            and old_ticket['collector_ack_sha'] == claim['collector_ack_sha']
            and old_ticket['collector_registration_id'] == claim['collector_registration_id']
            and old_ticket['destinations'] == ticket['destinations']
            and old_ticket['registration_nonce'] != ticket['registration_nonce']
            and old_ticket['collector_registration_id'] != ticket['collector_registration_id'],
            'Unpublished origin had a different receipt chain, owner or reused registration')
    original_id = cold_parent(api, release, old_ticket, old_ack, genesis, unpublished.HEAD, now, cutoff,
                              verify_only=True, newest_ticket=ticket)
    require(original_id == claim['prior_claim_asset_id'], 'Original genesis claim is not the exact ancestor')
    if not verify_only:
        unpublished.unavailable_outputs(api, release, now, BRANCH, storage, instant, REPO_ID)
    return claim_id


def parent_run(api, release, resume, head, genesis, now_run, created):
    # Only one continuation can claim a given prior producer. Recovering an already
    # published APK uses the existing receiver even when the workflow later failed.
    old = resume['origin_run']
    prior = api.metadata(f'{api.BASE}/actions/runs/{old}/attempts/1')
    require(old != now_run and prior['id'] == old and prior['run_attempt'] == 1 and
            prior['head_sha'] == head and prior['head_branch'] == BRANCH and prior['path'] == WORKFLOW and
            prior['event'] == 'workflow_dispatch' and prior['repository']['id'] == prior['head_repository']['id'] == REPO_ID and
            owner_account(prior['actor']) and prior['status'] == 'completed' and
            prior['conclusion'] in ('failure', 'cancelled', 'timed_out', 'startup_failure') and
            instant(prior['updated_at']) <= created, 'Continuation parent is active, successful or from another build')
    def prior_artifacts(path):
        query = path.split('?', 1)[1]
        return api.metadata(f'{api.BASE}/actions/runs/{old}/artifacts?{query}')
    artifacts = storage.receipt_rows(prior_artifacts)
    envelope = re.compile(fr'bare-personal-209-owner-{old}-a1-s[1-9][0-9]*')
    require(not any(envelope.fullmatch(row[3]) for row in artifacts.values()),
            'Prior encrypted APK exists: continue owner pickup before another build')
    deposit = re.compile(fr'r209-{old}-a1-s[0-9]{{2}}-apk(?:\.age|-seal\.json|-owner-receipt\.json)(?:-retry1)?')
    require(not any(deposit.fullmatch(a['name']) for a in release['assets']),
            'A private terminal deposit exists: check the original owner delivery first')
    prefix = f'{CAMPAIGN}-terminal-{old}-1-s'
    ref = 'refs/heads/' + BRANCH
    query = urlencode(dict(key=prefix, ref=ref, per_page=100))
    cached = api.metadata(f'{api.BASE}/actions/caches?{query}')
    entries = cached['actions_caches']
    require(type(entries) is list and type(cached['total_count']) is int and
            len(entries) == cached['total_count'] <= 100 and len({e['id'] for e in entries}) == len(entries),
            'Incomplete sealed cache inventory')
    require(not any(row['ref'] == ref and re.fullmatch(re.escape(prefix)+r'[1-9][0-9]*-[0-9a-f]{64}',row['key'])
                    for row in entries), 'A sealed cache exists: check the original owner delivery first')
    rows = [a for a in release['assets'] if a['name'] == CLAIM or
            re.fullmatch(r'bare-personal-209-after-[0-9]+-claim\.json', a['name'])]
    found = []
    for row in rows:
        require(type(row['size']) is int and 0 < row['size'] <= 4096 and
                re.fullmatch(r'sha256:[0-9a-f]{64}', row['digest']), 'Unverifiable previous claim')
        raw = io.BytesIO()
        api.download(row['id'], row['size'], row['digest'][7:], raw)
        require(len(raw.getvalue()) == row['size'] and sha(raw.getvalue()) == row['digest'][7:], 'Prior claim readback failed')
        body = json.loads(raw.getvalue())
        if body.get('origin_run') == old:
            expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, release_id=RELEASE_ID,
                            branch=BRANCH, workflow=WORKFLOW, head=head, genesis=genesis, producer_attempt=1,
                            destination_commitment=DESTINATION_HASH, recipient=RECIPIENT)
            require(all(body.get(k) == v for k,v in expected.items()), 'Prior claim does not bind these inputs and owner')
            found.append(row['id'])
    require(len(found) == 1, 'Missing or ambiguous physical claim for the prior run')
    return found[0]


def validate_route(ticket, ack, *, head, genesis, created, now, resume, terminal_delivery=False):
    expected = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, release_id=RELEASE_ID,
                    workflow=WORKFLOW, branch=BRANCH, head=head, genesis=genesis, bare_revision=UPSTREAM,
                    version_name=VERSION, version_code=802000915, package='org.barebrowser.personal',
                    abi='arm64-v8a', recipient=RECIPIENT, final_certificate_sha256=CERT,
                    artifact_ceiling_bytes=CEILING, storage_policy=storage.POLICY)
    require(all(ticket.get(k) == ack.get(k) == v for k, v in expected.items()),
            'Owner registration does not bind the fixed production head, inputs, product and free storage policy')
    require('resume' in ticket and 'resume' in ack and ticket['resume'] == ack['resume'] == resume,
            'Different continuation or an old claim used as a production origin')
    fields = ('destinations', 'registration_nonce', 'collector_registration_id', 'expires_at', 'storage_valid_until')
    require(pick(ticket, fields) == pick(ack, fields), 'Independent owner acknowledgement or destination differs')
    require(ack.get('state') == 'collector-read-back-owner-reservation' and
            re.fullmatch('[0-9a-f]{32,64}', ticket['registration_nonce']) and
            re.fullmatch('Automation_[0-9a-f]{32}', ticket['collector_registration_id']) and
            sha(encode(ticket['destinations'])) == DESTINATION_HASH, 'Different receiving registration or reserved IDs')
    require(instant(ack['observed_at']) <= instant(ticket['issued_at']) <= created <= now,
            'Owner ticket/ACK was not issued before physical dispatch')
    period, retry = ack['poll_seconds'], ack['pickup_retry_seconds']
    require(all(type(i) is int and 0 < i <= 86400 for i in (period, retry)), 'Invalid finite pickup schedule')
    # The full production worker allowance plus sealing, receiver checks, pickup delay and retry.
    end = min(instant(ticket['expires_at']), instant(ack['valid_until']))
    compute = 0 if terminal_delivery else SEGMENT
    return int((end - timedelta(seconds=compute + TAIL + 2 * period + retry)).timestamp())


def bind(api, env, event, ticket_id, ticket_sha, genesis, *, verify_only=False, terminal_delivery=False, clock=None):
    require(not terminal_delivery or verify_only, 'Terminal recovery must only read the existing claim')
    storage_time = None if clock is None else clock().timestamp()
    clock = clock or (lambda: datetime.now(timezone.utc))
    head, rid = env['GITHUB_SHA'], int(env['GITHUB_RUN_ID'])
    require(bool(re.fullmatch('[0-9a-f]{40}', head)) and bool(re.fullmatch('[0-9a-f]{64}', genesis)), 'Malformed head/genesis')
    run = api.metadata(f'{api.BASE}/actions/runs/{rid}/attempts/1')
    validate_identity(env, event, run, head)
    created = instant(run['created_at'])
    release = api.draft(RELEASE_ID)
    resume = resume_input(event)
    suffix = '-after-' + str(resume['origin_run']) if resume else ''
    ticket_id, ticket = doc(api, release, f'{CAMPAIGN}-{head}{suffix}-ticket.json', ticket_id, ticket_sha, created)
    ack_id, ack_sha, nonce = ticket['collector_ack_asset_id'], ticket['collector_ack_sha'], ticket['registration_nonce']
    ack_id, ack = doc(api, release, f'{CAMPAIGN}-ack-{nonce}.json', ack_id, ack_sha, created)
    latest = validate_route(ticket, ack, head=head, genesis=genesis, created=created, now=clock(), resume=resume,
                            terminal_delivery=terminal_delivery)
    ceiling, until = storage.policy(ticket, ack)
    cfg = dict(env, R28_STORAGE_CEILING=str(ceiling), R28_STORAGE_UNTIL=str(until))
    def window():
        t = clock().timestamp()
        retention = TAIL if terminal_delivery else SEGMENT + storage.JOURNAL_TAIL + storage.JOURNAL_DAYS * storage.DAY
        require(t <= latest and t <= until - retention, 'The authenticated coverage is too short for this operation and pickup')
    window()
    if terminal_delivery:
        # The origin's sealed bytes go directly to the owner Draft. Its writer checks
        # real room before each deposit. No new compute, Actions artifact or journal.
        storage.public_host(api.metadata(api.BASE), cfg.get('RUNNER_ENVIRONMENT'))
    else:
        storage.draft_room(release, cfg, claim=not verify_only)
        from checkpoint_packets import max_draft_assets
        require(len(release['assets']) + max_draft_assets() + (0 if verify_only else 2) <= 1000,
                'Private Draft cannot hold the sealed transfer and its verified canonical checkpoint')
        for index, pause in enumerate((0, 8, 16)):
            if pause:
                time.sleep(pause)
                window()
            try:
                storage.admit(api.metadata, cfg, storage.lease_size(cfg), 1, stage='lease', lead=SEGMENT, now=storage_time)
                break
            except storage.StorageUnconfirmed as error:
                if index == 2 or 'inventory' not in str(error).lower():
                    raise
                print(f'Owner admission read {index+1}: {error}; requiring a new full inventory', flush=True)

    holder = dict(schema=1, campaign=CAMPAIGN, repository_id=REPO_ID, workflow=WORKFLOW, branch=BRANCH,
                  head=head, genesis=genesis, release_id=RELEASE_ID, origin_run=rid, producer_attempt=1,
                  ticket_asset_id=ticket_id, ticket_sha=ticket_sha, collector_ack_asset_id=ack_id,
                  collector_ack_sha=ack_sha, collector_registration_id=ticket['collector_registration_id'],
                  destination_commitment=DESTINATION_HASH, recipient=RECIPIENT)
    name = CLAIM
    if resume:
        holder['resume'] = resume
        if resume == cold.SELECTOR:
            holder['prior_claim_asset_id'] = cold_parent(api, release, ticket, ack, genesis, head, clock(), created,
                                                       verify_only=verify_only)
        elif resume == unpublished.SELECTOR:
            holder['prior_claim_asset_id'] = unpublished_parent(api, release, ticket, ack, genesis, head, clock(),
                                                               created, verify_only=verify_only)
        else:
            holder['prior_claim_asset_id'] = parent_run(api, release, resume, head, genesis, rid, created)
        name = f"{CAMPAIGN}{suffix}-claim.json"
    window()
    claim = admit('recover' if verify_only else 'compute', holder, api, name=name, before_write=window)
    window()
    return dict(claim=claim, claim_asset_id=claim, latest_start=latest, storage_ceiling=ceiling,
                storage_until=until, draft_id=RELEASE_ID, ticket_asset_id=ticket_id, collector_ack_asset_id=ack_id)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('bind', 'lease', 'delivery'))
    parser.add_argument('--ticket-id', required=True, help='Physical ID, or lookup by unique prior name and verified SHA-256')
    parser.add_argument('--ticket-sha', required=True)
    parser.add_argument('--genesis', required=True)
    args = parser.parse_args()
    # Reuse the immutable owner Draft transport without treating any old archive/claim as a new production parent.
    sys.path.insert(0, str(ROOT / 'preflight28' / 'transport'))
    import prepare
    prepare.stage_tools()
    import transfer
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    selector = 'lookup' if args.ticket_id == 'lookup' else int(args.ticket_id)
    outputs = bind(PagedOwnerDraft(transfer), os.environ, event, selector, args.ticket_sha, args.genesis,
                   verify_only=args.mode != 'bind', terminal_delivery=args.mode == 'delivery')
    with open(os.environ['GITHUB_OUTPUT'], 'a') as out:
        for key, value in outputs.items():
            print(f'{key}={value}', file=out)
    print(f'Confirmed 2.0.9 registration for run {os.environ["GITHUB_RUN_ID"]}, ticket {outputs["ticket_asset_id"]}, '
          f'ACK {outputs["collector_ack_asset_id"]}, claim {outputs["claim"]}')


if __name__ == '__main__':
    main()
