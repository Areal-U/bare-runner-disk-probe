#!/usr/bin/env python3
"""Render reviewed product assertions for inspection on an isolated copy."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory

import inputs

PRODUCER = '.github/workflows/bare-arm64-probe.yml'
COLLECTOR = 'preflight28/collector/production.py'
COEXIST = 'coexist_inputs.py'


def render_text(path, text, old, new):
    # Keep complete, unique old assertions. Check even anchors whose value stays equal.
    if path == PRODUCER:
        anchors = [
            '      BARE_REV: {bare}\n', '      CHROMIUM_REV: {chromium}\n',
            '        [[ $' + '{{#patches[@]}} == {patches} ]]\n', '        crx={extension}\n',
            r"""        printf '%s  %s\n' {extension_sha256} "$crx" | sha256sum --check --strict""",
            "        expected_version = '{version_name}'\n", "        expected_code = '{version_code}'\n",
            "        expected_crx = '{extension_sha256}'\n",
        ]
    elif path == COLLECTOR:
        anchors = [
            'UBO_SHA = "{extension_sha256}"\n', 'BARE_REV = "{bare}"\n', 'CHROMIUM_REV = "{chromium}"\n',
            '("{package}", "{version_name}", "{version_code}") and "application-label:\'Bare Personal\'"',
            'package="{package}",version_name="{version_name}",\n',
            '                        version_code="{version_code}", abi="{abi}", signer_sha256=CI_CERT,\n',
        ]
    elif path == COEXIST:
        anchors = [
            '"""Prepare the pinned Bare {version_name} ARM64 configuration and launcher label."""',
            'UPSTREAM_ARM64_ARGS_SHA256 = "{upstream_gn_sha256}"\n',
            'differs from the pinned Bare {version_name} ARM64 block"',
            'unexpected app_name resource after applying Bare {version_name} patches"',
        ]
    else:
        raise ValueError('Unexpected render target')
    for anchor in anchors:
        expected = anchor.format(**old)
        if text.count(expected) != 1:
            raise ValueError(f'Cannot locate a unique reviewed assertion in {path}: {expected!r}')
        text = text.replace(expected, anchor.format(**new))
    return text


def files(root, head, before, after):
    for name in (PRODUCER, COLLECTOR, COEXIST):
        source = inputs.git(root, 'show', head + ':' + name).decode()
        yield name, source, render_text(name, source, before, after)


def write_preview(root, head, bare, chromium, revision, expected_chromium, out):
    root = root.resolve(strict=True)
    inputs.exact(root, head)
    out = out.resolve()
    repo = Path(inputs.git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    if out == repo or repo in out.parents or out.exists() or not out.parent.is_dir():
        raise ValueError('Use a new output directory outside the checkout, beneath an existing directory')
    original = inputs.inputs(bare, chromium, inputs.production.BARE_REV)['source_pins']
    upstream = inputs.inputs(bare, chromium, revision, expected_chromium)['source_pins']
    gn = inputs.inputs(bare, chromium, revision, expected_chromium, emit_gn=True)
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-(?:alpha|beta)\.[0-9]+)?', upstream['version_name']):
        raise ValueError('Unexpected Bare version grammar')
    if not re.fullmatch(r'third_party/ublock_origin/[a-zA-Z0-9._-]+\.crx',upstream['extension']):
        raise ValueError('Unexpected CRX source path')
    changed = {}
    reviewed_files = list(files(root,head,original,upstream))
    patch = []
    for path, old, new in reviewed_files:
        if old == new:
            continue
        changed[path]=dict(before=hashlib.sha256(old.encode()).hexdigest(),after=hashlib.sha256(new.encode()).hexdigest())
        patch.extend(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                          'a/'+path, 'b/'+path))
    rules = []
    for path, protection in [('BUILD.gn','retained-output diagnostic exception'),
                             ('build/install-build-deps.py','six-package installer transaction')]:
        old_tree = inputs.entries(chromium, original['chromium'], path)
        new_tree = inputs.entries(chromium, upstream['chromium'], path)
        if path not in old_tree or path not in new_tree:
            raise ValueError('Required Chromium rule not found: '+path)
        rules.append(dict(rule=protection,path=path,before=old_tree[path][-1],after=new_tree[path][-1],
                          status='same-upstream-object' if old_tree[path] == new_tree[path] else 'changed-review-required'))
    remaining = ['Select the target and reconcile the owner ledger for prior delivery or operations.',
                 'Bind the selected parent or cold generation, promoted CI SHA, new claim, independent collector ACK and private destination before a new campaign.']
    if revision != original['bare']:
        remaining += ['Review selected upstream patches, launcher label and APK in the full patched tree.',
                      'Recheck the target Chromium graph/GN diagnostic classification, Ubuntu snapshot/installer and toolchain/PGO before enabling segments.',
                      'Keep R28 wire names, recipient, branch and recovery on the original campaign. Bind the next receiver and its versioned ciphertext names only to a separate campaign.']
    report = dict(schema=1, ci_input_head=head, product_inputs=upstream, output_files=changed, rules=rules,
                  remaining=remaining, dispatch_ready=False,
                  preserved=['historical claims', 'R28 branch/dispatch guards', 'original recovery namespace',
                             'encrypted transport names','destination, recipient and signing identity'])
    # Verify all source ids, hashes and old assertions before writing any output.
    with TemporaryDirectory(dir=out.parent) as tmp:
        stage=Path(tmp)/'preview'
        stage.mkdir()
        for path, _, updated in reviewed_files:
            target=stage/'rendered'/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(updated)
        (stage/'product-assertions.patch').write_text(''.join(patch))
        (stage/'args.gn').write_text(gn)
        (stage/'review.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
        out.mkdir(mode=0o700)
        # The report is the completion marker and is published last.
        for result in ('rendered','product-assertions.patch','args.gn','review.json'):
            (stage/result).rename(out/result)
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('bare_git','chromium_git','output'):
        parser.add_argument(name,type=Path)
    parser.add_argument('--ci-head',required=True)
    parser.add_argument('--bare-sha',required=True)
    parser.add_argument('--chromium-sha',required=True)
    args=parser.parse_args()
    report=write_preview(inputs.ROOT,args.ci_head,args.bare_git,args.chromium_git,
                         args.bare_sha,args.chromium_sha,args.output)
    print(json.dumps({'dispatch_ready':False,'changed_files':len(report['output_files']),
                      'review':str(args.output/'review.json')}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, KeyError, OSError, inputs.subprocess.SubprocessError) as exc:
        print('Preview rejected: '+str(exc), file=sys.stderr)
        sys.exit(1)
