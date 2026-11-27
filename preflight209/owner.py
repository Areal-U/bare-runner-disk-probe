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


def doc(api, release, name, aid, digest, created):
    require((aid == 'lookup' or (type(aid) is int and aid > 0)) and isinstance(digest, str) and
            re.fullmatch('[0-9a-f]{64}', digest), 'Invalid immutable owner document selector or digest')
    rows = [a for a in release['assets'] if a['name'] == name]
    require(len(rows) == 1, 'Missing or duplicate owner document')
    row = rows[0]
    require(type(row['id']) is int and row['id'] > 0 and (aid == 'lookup' or aid == row['id']) and type(row['size']) is int and 0 < row['size'] <= 16 * 1024 and
            owner_account(row['uploader']) and instant(row['created_at']) <= created,
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
    value = event['inputs'].get('resume')
    if value in (None, ''):
        return None
    record = json.loads(value)
    require(isinstance(record, dict) and set(record) == {'origin_run', 'ordinal', 'manifest_id', 'manifest_sha'},
            'Incomplete continuation reference')
    require(all(type(record[k]) is int and record[k] > 0 for k in ('origin_run', 'ordinal', 'manifest_id')) and
            record['ordinal'] <= 98 and bool(re.fullmatch('[0-9a-f]{64}', record['manifest_sha'])),
            'Invalid continuation identity or ordinal')
    return record


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
