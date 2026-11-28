"""Evidence for the one 2.0.9 producer whose sealed checkpoint never left its runner."""
import json
from pathlib import Path
from urllib.parse import urlencode

from checkpoint209 import require

RUN = 46092059335
SELECTOR = {'kind': 'unpublished-checkpoint-cold', 'origin_run': RUN}
ORIGIN = json.loads(Path(__file__).with_name(f'unpublished-{RUN}.json').read_bytes())
HEAD = ORIGIN['run']['head_sha']
CLAIM_COMMITMENT = '3dbd3c3181bab0d7a4bf25c37ae1f974ab9c2f7eb0a2a17ee53d99fb9631c7e5'
CLOSED_LEDGER_SHA256 = '3540b6bc5d1fe347ad6eeafe4fe585d5191b474fd4af00bb3e8057c4e4112441'


def check_run(run, repo_id, owner_account):
    expected = ORIGIN['run']
    require(all(run.get(k) == value for k, value in expected.items())
            and run['head_commit']['id'] == HEAD and run['head_commit']['tree_id'] == ORIGIN['tree']
            and run['repository']['id'] == run['head_repository']['id'] == repo_id
            and owner_account(run['actor']), 'Wrong terminated checkpoint origin, tree, attempt or owner')


def check_jobs(view):
    rows = view['jobs']
    expected = {j['id']: j for j in ORIGIN['jobs']}
    require(type(view['total_count']) is int and view['total_count'] == len(rows) == len(expected)
            and {j['id'] for j in rows} == expected.keys(), 'Incomplete unpublished-checkpoint job inventory')
    for row in rows:
        known = expected[row['id']]
        steps = [[s['number'], s['name'], s['conclusion']] for s in row['steps']]
        require(row['run_id'] == RUN and row['run_attempt'] == 1 and row['head_sha'] == HEAD
                and row['status'] == 'completed' and row['name'] == known['name']
                and row['conclusion'] == known['conclusion'] and steps == known['steps'],
                'Changed result of the historical checkpoint or publication jobs')


def unavailable_outputs(api, release, now, branch, storage, instant, repo_id):
    base = f'{api.BASE}/actions/runs/{RUN}'
    check_jobs(api.metadata(base + '/attempts/1/jobs?per_page=100&page=1'))
    expected = {a['id']: a for a in ORIGIN['artifacts']}

    def run_artifacts(path):
        page = api.metadata(base + '/artifacts?' + path.split('?', 1)[1])
        for row in page['artifacts']:
            known = expected.get(row['id'])
            origin = row['workflow_run']
            require(known and all(row.get(k) == value for k, value in known.items())
                    and origin['id'] == RUN and origin['head_sha'] == HEAD and origin['head_branch'] == branch
                    and origin['repository_id'] == origin['head_repository_id'] == repo_id,
                    'Unrecognized or recoverable artifact on the checkpoint origin')
        return page

    controls = storage.receipt_rows(run_artifacts)
    require(all(aid in controls or now >= instant(row['expires_at']) for aid, row in expected.items()),
            'Unpublished-checkpoint control disappeared before expiry')
    # The failed tree's private payload names use the first prefix. Also reject
    # alternative names in this campaign/slot namespace, including partials.
    prefixes = (f'r209-{RUN}-', f'bare-personal-209-{RUN}-', f'bare-personal-209-terminal-{RUN}-')
    require(not any(a['name'].startswith(prefixes) for a in release['assets']),
            'Private material from the failed slot must be recovered before a cold start')
    for prefix in prefixes:
        query = urlencode(dict(ref='refs/heads/' + branch, key=prefix, per_page=100))
        cache = api.metadata(f'{api.BASE}/actions/caches?{query}')
        require(type(cache['total_count']) is int and cache['total_count'] == 0 and cache['actions_caches'] == [],
                'Prior slot has a cache or an incomplete cache response')
