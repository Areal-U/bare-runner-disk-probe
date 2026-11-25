#!/usr/bin/env python3
"""Inspect the exact source pair and the existing R28 claim before planning the next build."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'preflight28/collector'), str(ROOT / 'preflight28/control'), str(ROOT)]
import production
import coexist_inputs
from admission import require
from owner_snapshot import OwnerSnapshot
from recover import follow, slot_chain


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], timeout=45,
                                   env=dict(os.environ, GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1'))


def exact(repo, oid):
    require(re.fullmatch('[0-9a-f]{40}', oid), 'Supply an exact commit, not a tag, branch or abbreviated SHA')
    require(git(repo, 'rev-parse', '--verify', oid + '^{commit}').decode().strip() == oid,
            'Expected the commit itself, not a tag object')


def entries(repo, rev, *paths, recursive=False):
    raw = git(repo, 'ls-tree', *(['-r'] if recursive else []), '-z', rev, '--', *paths)
    result = {}
    for item in raw.decode().rstrip('\0').split('\0'):
        if item:
            attrs, name = item.split('\t', 1)
            mode, kind, oid = attrs.split(' ')
            result[name] = [mode, kind, oid]
    return result


def one(pattern, text):
    match = re.findall(pattern, text, re.M)
    require(len(match) == 1, 'Missing or ambiguous upstream field: ' + pattern)
    return match[0]


def inputs(bare, chromium, rev, expected_chromium=None, *, emit_gn=False):
    exact(bare, rev)
    def blob(name):
        return git(bare, 'show', rev + ':' + name)
    guide = blob('BUILDING.md').decode()
    chrome = one(r'^- Chromium commit: `([a-f0-9]{40})`$', guide)
    if expected_chromium is not None:
        require(chrome == expected_chromium, 'Requested Chromium revision is not the one pinned by this Bare revision')
    exact(chromium, chrome)
    chromium_paths = ['DEPS', 'chrome/VERSION', 'tools/clang/scripts/update.py', 'chrome/build/android-arm64.orderfile.txt']
    upstream = entries(chromium, chrome, *chromium_paths)
    require(set(upstream) == set(chromium_paths), 'Chromium pin lacks an expected build/toolchain input; review new layout')
    gn = blob('docs/build-from-source.md').decode()
    matches = [block for block in re.findall(r'^\x60{3}gn[ \t]*\n(.*?)^\x60{3}[ \t]*$', gn, re.M | re.S)
               if coexist_inputs.PACKAGE_SETTING in block.splitlines() and 'target_cpu = "arm64"' in block.splitlines()]
    require(len(matches) == 1, 'Expected one compatible upstream ARM64 GN block')
    block, = matches
    version = one(r'^android_override_version_name = "([^"]+)"$', block)
    code = int(one(r'^android_override_version_code = "([1-9][0-9]*)"$', block))
    version_data = blob('VERSION').decode()
    fields = {k: one(r'^' + k + r'=([0-9]+)$', version_data) for k in ('MAJOR','MINOR','PATCH','BUILD')}
    channel = one(r'^CHANNEL=(stable|alpha|beta)$', version_data)
    expected_name = '.'.join(fields[k] for k in ('MAJOR','MINOR','PATCH'))
    if channel != 'stable':
        expected_name += '-' + channel + '.' + one(r'^CHANNEL_NUM=([0-9]+)$', version_data)
    expected_code = (800000000 + int(fields['MAJOR'])*1000000 + int(fields['MINOR'])*10000 +
                     int(fields['PATCH'])*100 + int(fields['BUILD'])*10 + 5)
    require((version, code) == (expected_name, expected_code) and int(fields['BUILD']) <= 9 and code < 2100000000,
            'Official VERSION and documented ARM64 Android version fields disagree or changed format')
    personal_gn = block.replace(coexist_inputs.PACKAGE_SETTING, coexist_inputs.PERSONAL_PACKAGE_SETTING, 1)
    tree_names = ['VERSION', 'patches', 'tools/version.py', 'docker/Dockerfile', 'docker-compose.yml']
    tree = entries(bare, rev, *tree_names)
    require(set(tree) == set(tree_names) and tree['patches'][1] == 'tree', 'Expected complete official inputs')
    patches = entries(bare, rev, 'patches', recursive=True)
    require(patches and all(re.fullmatch('patches/[^/]+[.]patch', n) and row[:2] == ['100644','blob']
                            for n,row in patches.items()), 'Patch layout changed; review before adopting')
    extensions = entries(bare, rev, 'third_party/ublock_origin', recursive=True)
    binaries = [p for p in extensions if p.endswith('.crx')]
    require(len(binaries) == 1 and binaries[0]+'.sha256' in extensions, 'Bundled uBlock pin changed')
    crx, = binaries
    digest = hashlib.sha256(blob(crx)).hexdigest()
    require(blob(crx+'.sha256').decode().split() == [digest, crx], 'Bundled uBlock SHA disagrees with the official checksum')
    data = {
        'bare': rev, 'chromium': chrome, 'bare_git_entries': tree, 'chromium_git_entries': upstream,
        'patches': len(patches), 'upstream_gn_sha256': hashlib.sha256(block.encode()).hexdigest(),
        'personal_gn_sha256': hashlib.sha256(personal_gn.encode()).hexdigest(),
        'package': 'org.barebrowser.personal', 'abi': 'arm64-v8a', 'version_name': version,
        'version_code': code, 'extension': crx, 'extension_sha256': digest,
    }
    if rev == production.BARE_REV:
        require(chrome == production.CHROMIUM_REV and data['upstream_gn_sha256'] == coexist_inputs.UPSTREAM_ARM64_ARGS_SHA256
                and data['extension_sha256'] == production.UBO_SHA and (version, code) == ('2.0.4', 802000415)
                and len(patches) == 313, 'Source pair differs from the current production product')
        action = 'same-source-pair-check-owner-campaign'
    else:
        action = 'new-source-generation-review-normal-entry-and-owner-registration'
    if emit_gn:
        return personal_gn
    return dict(disposition=action, build_dispatch=False, reusable_checkpoint=None, source_pins=data)


def compare_sources(before, after):
    old = before['source_pins']
    new = after['source_pins']
    groups = {}
    for field in ('bare_git_entries', 'chromium_git_entries'):
        keys = set(old[field]) | set(new[field])
        groups[field] = {p: ('same-object' if old[field].get(p) == new[field].get(p) else 'changed')
                         for p in sorted(keys)}
    if new['version_code'] > old['version_code']:
        install = 'greater-version-code'
    elif new['version_code'] == old['version_code']:
        install = 'equal-version-code-confirm-rebuild-purpose'
    else:
        install = 'lower-version-code-block-in-place-update'
    return dict(compared_to=old['bare'], install_order=install, files=groups,
                embedded_extension=('same-bytes' if new['extension_sha256'] == old['extension_sha256'] else 'changed'),
                personal_gn=('same-bytes' if new['personal_gn_sha256'] == old['personal_gn_sha256'] else 'changed'))


def outcome(records, run, head, scope):
    state = follow(records, run, head, scope)
    status = state['status']
    if status == 'apk':
        return dict(disposition='collect-and-verify-owner-delivery', slot=state['ordinal'])
    if status == 'limit-verified':
        candidates = [r for r in records if r['status'] == 'candidate' and r['sha'] == state['sha']]
        require(len(candidates) == 1, 'Independent frontier has no unique producing receipt')
        r, = candidates
        require(re.fullmatch(r'[1-9][0-9]*', r['manifest_id']) and re.fullmatch(r'[a-f0-9]{64}', r['manifest_sha']),
                'Verified frontier has no immutable private manifest')
        return dict(disposition='prepare-new-campaign-from-independently-verified-parent',
                    reviewed_parent={key:r[key] for key in ('ordinal','key','sha','identity','manifest_id','manifest_sha','producer_sha')})
    if status in {'apk-size-exceeded','cipher-size-exceeded','no-progress'}:
        return dict(disposition='correct-stop-before-any-new-build', stop=status, slot=state['ordinal'])
    return dict(disposition='reconcile-original-transfer-or-confirm-loss', stop=status)


def campaign(locator, captured):
    if 'ticket_asset_id' not in locator:
        locator = captured.resolve_original_ticket(locator)
    rows = captured.draft_rows(locator)
    origin, run, claim, scope = production.bind(captured, rows, locator)
    head = locator['head']
    basis = dict(build_dispatch=False, registered_campaign=production.CAMPAIGN, original_run=origin,
                 physical_run=run, first_attempt=1, head=head, verified_claim_id=claim)
    base = f'actions/runs/{run}/attempts/1'
    first = captured.metadata(base)
    production.physical_run(first,run,head)
    latest = captured.metadata(f'actions/runs/{run}')
    require(type(latest['run_attempt']) is int and latest['run_attempt'] >= 1,'Invalid latest attempt')
    # Reuse first-attempt identity predicates for stable fields; identity above is never taken
    # from latest-attempt logs. A manually retried run still has exactly one computing attempt.
    production.physical_run(dict(latest, run_attempt=1),run,head)
    if first['status'] != 'completed' or latest['status'] != 'completed':
        return dict(basis, disposition='existing-operation-active', latest_attempt=latest['run_attempt'])
    jobs = captured.inventory(base+'/jobs', 'jobs')
    require(all(row['status'] == 'completed' for row in jobs), 'Original VM or job remains unsettled')
    arts = captured.inventory(f'actions/runs/{run}/artifacts', 'artifacts')
    records = slot_chain(jobs,arts,run,head,lambda aid:captured.metadata(f'actions/artifacts/{aid}'),captured.note,scope,
                         terminal_salvage=True)
    decision = outcome(records,run,head,scope)
    # A private or Actions APK can exist even when the slot receipt was lost.
    if decision['disposition'] == 'reconcile-original-transfer-or-confirm-loss':
        possible = any(r['name'].startswith(f'r28-{run}-a1-s') and '-apk-owner-receipt.json' in r['name'] for r in rows)
        possible |= any(r['name'].startswith(f'bare-personal-204-encrypted-{run}-1-s') for r in arts)
        if possible:
            decision = dict(disposition='collect-and-verify-owner-delivery')
    return dict(basis, **decision)


def delivered(locator, directory, aapt2, apksigner):
    ticket, listing, publication = (json.loads((directory / name).read_bytes()) for name in
                                   ('owner.json','listing.json','publication.json'))
    require(ticket['owner_destination_id'] == locator['owner_destination_id'], 'Different registered owner destination')
    apk=directory / 'retrieved.apk'
    production.verify_application(apk, aapt2)
    receipt=production.owner_check(ticket,listing,publication,apk,apksigner)
    return {'disposition':'already-delivered-use-existing-apk', 'build_dispatch':False, **receipt}


def main():
    arg=argparse.ArgumentParser(description=__doc__)
    sub=arg.add_subparsers(dest='op', required=True)
    src=sub.add_parser('source',help='Inspect an immutable upstream source pair from its existing Git object stores')
    src.add_argument('bare_repo',type=Path)
    src.add_argument('chromium_repo',type=Path)
    src.add_argument('bare_sha')
    src.add_argument('--expected-chromium')
    src.add_argument('--emit-gn',action='store_true',help='Print the verified coexisting APK args.gn, for isolated preparation only')
    src.add_argument('--compare-to', help='Exact prior Bare commit in the same stores; reports source component identities')
    camp=sub.add_parser('campaign',help='Use an existing owner capture and original/current GETs to reconcile R28')
    camp.add_argument('locator',type=Path)
    camp.add_argument('capture',type=Path)
    sent=sub.add_parser('delivered',help='Independently revalidate the existing final owner handoff')
    for name in ('locator','directory','aapt2','apksigner_jar'):
        sent.add_argument(name,type=Path)
    a=arg.parse_args()
    if a.op == 'source':
        result = inputs(a.bare_repo,a.chromium_repo,a.bare_sha,a.expected_chromium, emit_gn=a.emit_gn)
        if a.emit_gn:
            require(not a.compare_to, 'Select either GN output or comparison JSON')
            sys.stdout.write(result)
            return
        if a.compare_to:
            result['comparison'] = compare_sources(inputs(a.bare_repo,a.chromium_repo,a.compare_to), result)
    elif a.op == 'campaign':
        sys.path.insert(0,str(Path(os.environ['RUNNER_TEMP']).resolve(strict=True)))
        import transfer
        result = campaign(json.loads(a.locator.read_bytes()),OwnerSnapshot(a.capture, transfer))
    else:
        result = delivered(json.loads(a.locator.read_bytes()),a.directory,a.aapt2,a.apksigner_jar)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as e:
        print(f'Input decision stopped: {e}',file=sys.stderr)
        sys.exit(1)
