"""Permit one cold successor of the physically verified, pre-compile 2.0.9 failure."""
import hashlib
import json
import re
from urllib.parse import urlencode

from checkpoint209 import require

RUN = 45996971462
HEAD = 'a17316eecfdc92f77db46e5f48604e65ad41508c'
# The independently retrieved, closed owner ledger for this physical attempt.
# Its private contents and destination identifiers are retained by its owner.
CLOSED_LEDGER_SHA256 = 'c6d070a24ba8c187e90498b9bedf308de517671a37a4f5a0713937df07c36dd3'
ORIGIN_CLAIM_COMMITMENT = '982821680b01820702b9032c822ae0865bfe452239d47643b4b0ad25fa297d04'
SELECTOR = {'kind': 'precompile-cold', 'origin_run': RUN}
PUBLISHER = 140499020591
WORKER = 140499020631
# Only the original ephemeral control records are permitted. Their disappearance
# after normal expiry does not turn the original, independently witnessed
# absence of an APK into evidence for a different run.
CONTROLS = {
    15196716409: ('key', 2285, '00968bf503583200c9d8840ab06e8e7e2e61b06f9f1baaa335ca6e68957866b1',
                  '2026-11-28T12:17:24Z'),
    15196696550: ('descriptor', 10196, 'bc442688b70f49585eecf8d9eec5fd57f6b564eee31864099cdf2ddc27672c80',
                  '2026-11-28T12:17:57Z'),
}


def parse_selector(raw):
    if raw in ('', None):
        return None

    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), 'Duplicate field in recovery selector')
        return obj

    value = json.loads(raw, object_pairs_hook=unique)
    require(isinstance(value, dict), 'Recovery selector must be an object')
    if 'kind' in value:
        require(type(value.get('origin_run')) is int and value == SELECTOR, 'Wrong precompile-cold origin')
    else:
        require(set(value) == {'origin_run', 'ordinal', 'manifest_id', 'manifest_sha'}
                and all(type(value[k]) is int and value[k] > 0 for k in ('origin_run', 'ordinal', 'manifest_id'))
                and value['ordinal'] <= 98 and isinstance(value['manifest_sha'], str)
                and re.fullmatch('[0-9a-f]{64}', value['manifest_sha']), 'Invalid continuation identity or ordinal')
    return value


def check_jobs(view):
    rows = view['jobs']
    require(type(view['total_count']) is int and view['total_count'] == len(rows) == 18
            and len({j['id'] for j in rows}) == len(rows) and len({j['name'] for j in rows}) == len(rows),
            'Incomplete precompile job inventory')
    names = {'Verify new generation and bind owner registration': 'success',
             'slot01 / Check owner lease, retention and free storage before interval': 'success',
             'slot01 / Receive private checkpoint slot 1': 'failure',
             'slot01 / Compile APK slot 1': 'failure',
             'slot01 / Recover original owner ciphertext from exact cache': 'skipped',
             'slot01 / Certify exact private result': 'skipped',
             'Check terminal certificate': 'failure',
             **{f'slot{i:02}': 'skipped' for i in range(2, 13)}}
    require({j['name']: j['conclusion'] for j in rows} == names and
            all(j['run_id'] == RUN and j['run_attempt'] == 1 and j['head_sha'] == HEAD
                and j['status'] == 'completed' for j in rows), 'Unexpected precompile job result or origin')
    by_id = {j['id']: j for j in rows}
    for jid, name, checks in (
            (WORKER, 'slot01 / Compile APK slot 1',
             {13: ('Prepare pinned Chromium, official patches, tools and Personal resources', 'failure'),
              14: ('Compile on the reviewed normal entry and freeze its actual frontier', 'skipped')}),
            (PUBLISHER, 'slot01 / Receive private checkpoint slot 1',
             {12: ('Discover exact peer outcome', 'failure'),
              13: ('Fetch authenticated outcome by immutable artifact ID', 'skipped'),
              14: ('Receive bounded ciphertext and independently verify fixed private publication', 'skipped')})):
        job = by_id.get(jid)
        require(job and job['name'] == name, 'Missing precompile worker or publisher')
        actual = {s['number']: (s['name'], s['conclusion']) for s in job['steps']}
        require(len(actual) == len(job['steps']) and all(actual.get(n) == v for n, v in checks.items()),
                'Origin did not stop before compilation/receipt')


def unavailable_outputs(api, release, now, branch, storage, instant):
    run_path = f'{api.BASE}/actions/runs/{RUN}'
    check_jobs(api.metadata(run_path + '/attempts/1/jobs?per_page=100&page=1'))

    def prior_artifacts(path):
        page = api.metadata(run_path + '/artifacts?' + path.split('?', 1)[1])
        for row in page['artifacts']:
            control = CONTROLS.get(row['id'])
            require(control is not None, 'Prior physical run has a recoverable or unknown artifact')
            suffix, size, digest, expiry = control
            origin = row['workflow_run']
            require(row['name'] == f'r209-{RUN}-a1-s01-{suffix}' and row['size_in_bytes'] == size
                    and row['digest'] == 'sha256:' + digest and row['expires_at'] == expiry
                    and origin['id'] == RUN and origin['head_sha'] == HEAD, 'Original control artifact changed')
        return page

    controls = storage.receipt_rows(prior_artifacts)
    require(all(aid in controls or now >= instant(item[3]) for aid, item in CONTROLS.items()),
            'Missing original control before expiry')
    require(not any(row['name'].startswith(f'r209-{RUN}-') for row in release['assets']),
            'Prior run has a private intent, partial transfer or result; recover it first')
    # The cache service matches exact keys and prefixes. Any hit for this
    # run's terminal prefix must be inspected by its original collector.
    q = urlencode(dict(key=f'bare-personal-209-terminal-{RUN}-', ref='refs/heads/' + branch, per_page=100))
    caches = api.metadata(api.BASE + '/actions/caches?' + q)
    require(type(caches['total_count']) is int and caches['total_count'] == 0 and caches['actions_caches'] == [],
            'Prior run has a sealed cache or an incomplete cache inventory')


def claim_commitment(asset_id, digest):
    require(type(asset_id) is int and asset_id > 0 and isinstance(digest, str)
            and re.fullmatch('[0-9a-f]{64}', digest), 'Invalid original claim physical reference')
    return hashlib.sha256(f'{asset_id}:{digest}'.encode('ascii')).hexdigest()


def owner_proof(ticket, ack, claim_id, claim_sha):
    proof = ack.get('precompile_origin')
    require(isinstance(proof, dict) and ticket.get('precompile_origin') == proof
            and set(proof) == {'claim_asset_id', 'claim_sha256', 'ledger_sha256', 'ledger_state',
                               'intermediate_outcome_pickup'}
            and proof['claim_asset_id'] == claim_id and proof['claim_sha256'] == claim_sha
            and claim_commitment(claim_id, claim_sha) == ORIGIN_CLAIM_COMMITMENT
            and proof['ledger_state'] == 'closed-no-apk' and proof['intermediate_outcome_pickup'] is True
            and proof['ledger_sha256'] == CLOSED_LEDGER_SHA256,
            'Independent closure, original claim or intermediate pickup coverage missing')
