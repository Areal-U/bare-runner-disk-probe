"""Check the visible Personal name on the linked resource APK and the final APK."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

EXPECTED = 'Bare Personal'
MAIN = 'android.intent.action.MAIN'
LAUNCHER = 'android.intent.category.LAUNCHER'
ANDROID = 'http://schemas.android.com/apk/res/android:'


def manifest_tree(dump):
    # aapt2 xmltree preserves binary attribute values and manifest nesting.
    stack = []
    document = ET.Element('document')
    for line in dump.splitlines():
        item = line.lstrip()
        indent = len(line) - len(item)
        if item.startswith('E: '):
            while stack and stack[-1][0] >= indent:
                stack.pop()
            tag = item[3:].split()[0]
            node = ET.SubElement(stack[-1][1] if stack else document, tag)
            stack.append((indent, node))
        elif item.startswith('A: ') and stack:
            key, _, value = item[3:].partition('=')
            if key.startswith(ANDROID):
                key = key[len(ANDROID):].split('(')[0]
            elif key != 'package':
                continue
            if key in stack[-1][1].attrib:
                raise ValueError(f'duplicate compiled manifest attribute {key}')
            # The first field is the compiled value; the optional Raw text is diagnostic.
            compiled = value.split(' (Raw: ', 1)[0]
            if compiled.startswith('"') and compiled.endswith('"'):
                compiled = compiled[1:-1]
            stack[-1][1].set(key, compiled)
    roots = document.findall('manifest')
    if len(roots) != 1:
        raise ValueError('expected one compiled Android manifest')
    return roots[0]


def alias_labels(alias, target, application):
    # Android 15 ParsedActivityImpl.makeAlias copies both target label fields.
    # ParsedComponentUtils then applies the alias icon and label, in that order.
    target_label = target.get('label', '')
    literal = target_label if not target_label.startswith('@') else ''
    resource = target_label if target_label.startswith('@') else ''
    effective = set()
    for icon in (alias.get('icon'), alias.get('roundIcon') or alias.get('icon')):
        inherited = '' if icon and icon not in ('@null', '@0x00000000') else literal
        override = alias.get('label', '')
        if override.startswith('@'):
            # ComponentInfo.loadUnsafeLabel prefers a surviving nonlocalized literal.
            effective.add(inherited or override)
        else:
            effective.add(override or inherited or resource or application)
    return effective


def launcher_sources(manifest):
    apps = manifest.findall('application')
    if len(apps) != 1 or 'label' not in apps[0].attrib:
        raise ValueError('expected one labelled Android application')
    app = apps[0]
    package = manifest.attrib['package']
    def full_name(name):
        if name.startswith('.'):
            return package + name
        return name if '.' in name else package + '.' + name

    activities = {full_name(a.attrib['name']): a for a in app.findall('activity')}
    if len(activities) != len(app.findall('activity')):
        raise ValueError('duplicate target activity')
    sources = {}
    active = []
    for component in app:
        if component.tag not in ('activity', 'activity-alias'):
            continue
        filters = [f for f in component.findall('intent-filter')
                   if MAIN in [v.get('name') for v in f.findall('action')]
                   and LAUNCHER in [v.get('name') for v in f.findall('category')]]
        if not filters:
            continue
        name = full_name(component.attrib['name'])
        if name in sources:
            raise ValueError('duplicate launchable component: ' + name)
        if component.tag == 'activity-alias':
            target = activities.get(full_name(component.attrib['targetActivity']))
            if target is None:
                raise ValueError('unknown launcher target: ' + name)
            labels = alias_labels(component, target, app.attrib['label'])
        else:
            labels = {component.get('label', app.attrib['label'])}
        sources[name] = labels | {f.attrib['label'] for f in filters if 'label' in f.attrib}
        if (app.get('enabled', 'true') == 'true' and component.get('enabled', 'true') == 'true'
                and component.get('exported', 'true') == 'true'):
            active.append(name)
    if not active:
        raise ValueError('no enabled exported MAIN/LAUNCHER component in the compiled manifest')
    return app.attrib['label'], sources, sorted(active)


def string_values(table, ref, parents=()):
    """Follow numeric or named string references through aapt2's resource table."""
    if ref in parents:
        raise ValueError('cyclic launcher string reference')
    key = ref.removeprefix('@')
    found, selected, default, values = 0, False, False, set()
    table.seek(0)
    for line in table:
        if line.startswith('    resource '):
            _, rid, name, *_ = line.split()
            selected = key in (rid, name) and name.startswith('string/')
            found += selected
        elif selected:
            row = re.fullmatch(r'      \(([^)]*)\) (.+)', line.rstrip('\n'))
            if row:
                cfg, value = row.groups()
                default |= cfg == ''
                values.add(value)
    if found != 1 or not default:
        raise ValueError(f'unresolved or ambiguous launcher string {ref}')
    result = set()
    for value in values:
        if value.startswith('@'):
            result.update(string_values(table, value, parents + (ref,)))
        elif value.startswith('"') and value.endswith('"'):
            result.add(value[1:-1])
        else:
            raise ValueError(f'expected a string value for {ref}')
    return result


def observed_labels(aapt2, apk, badging=None):
    command = [str(aapt2), 'dump']
    if badging is None:
        badging = subprocess.check_output([*command, 'badging', str(apk)], text=True, timeout=120)
    rows = [s for s in badging.splitlines() if s.startswith('application-label')]
    defaults = [s for s in rows if s.startswith('application-label:')]
    if len(defaults) != 1 or any(not re.fullmatch(r"application-label(?:-[^:]+)?:'.*'", s) for s in rows):
        raise ValueError(f'missing or ambiguous default application label: {defaults!r}')
    app_values = {line.partition(':')[2][1:-1] for line in rows}
    xml = subprocess.check_output([*command, 'xmltree', str(apk), '--file', 'AndroidManifest.xml'],
                                  text=True, timeout=120)
    app, sources, active = launcher_sources(manifest_tree(xml))
    names = {app} | {source for group in sources.values() for source in group}
    values = {source: {source} for source in names}
    refs = [source for source in names if source.startswith('@')]
    if refs:
        # Badging lists locale variants but can omit e.g. a night-mode value.
        with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as table:
            subprocess.run([*command, 'resources', str(apk)], stdout=table, timeout=120, check=True)
            for ref in refs:
                values[ref] = string_values(table, ref)
    app_values.update(values[app])
    values[app] = app_values
    effective = {name: sorted(set().union(*(values[s] for s in labels))) for name, labels in sources.items()}
    return dict(application=sorted(app_values), launchers=effective, enabled=active)


def verify_labels(aapt2, apk, badging=None):
    report = observed_labels(aapt2, apk, badging)
    if report['application'] != [EXPECTED] or any(labels != [EXPECTED] for labels in report['launchers'].values()):
        raise ValueError('Unexpected personal launcher label. ' + json.dumps(report, sort_keys=True))
    return report


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('aapt2', type=Path)
    parser.add_argument('apk', type=Path)
    parser.add_argument('--badging', type=Path)
    args = parser.parse_args()
    try:
        result = verify_labels(args.aapt2, args.apk, args.badging.read_text() if args.badging else None)
    except ValueError as error:
        sys.exit(str(error))
    # This tool can run inside the tar-to-age pipeline; stdout is reserved for validated APK bytes.
    print('Verified Bare Personal launcher labels ' + json.dumps(result, sort_keys=True), file=sys.stderr)
