"""Reconstruct additional outputs of the pinned Android Siso handlers from GN."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess

from graph import output_name, sha
from retained import ANDROID_RULES_SHA256, FILEARG_RULES


def configured_outputs(out, rule, command):
    args = shlex.split(command)
    script = '../../build/android/gyp/' + FILEARG_RULES[rule]
    if script not in args[:2]:
        raise ValueError('Unexpected command for a bounded FileArg output')
    specs = [arg.removeprefix('--dex-dest=') for arg in args if arg.startswith('--dex-dest=')] if rule == 'android/proguard' else [
        args[i+1] for i, arg in enumerate(args) if arg == '--output-jars']
    bindings, outputs = {}, set()
    for spec in specs:
        if not (spec.startswith('@FileArg(') and spec.endswith(')')):
            raise ValueError('Unrecognized output binding syntax')
        keys = spec[9:-1].split(':')
        name = keys[0].removesuffix('[]')
        if (len(keys) < 2 or not name.startswith(('gen/', 'obj/')) or not name.endswith('.json') or
                output_name(name, out) != name or any(not re.fullmatch(r'[A-Za-z0-9_-]+', k) for k in keys[1:])):
            raise ValueError('Output binding outside the verified JSON subset')
        path = out / name
        if path.resolve() != path or not path.is_file() or path.stat().st_size > 4*1024**2:
            raise ValueError('Output binding source unavailable or ambiguous')
        data = path.read_bytes()
        value = json.loads(data)
        for key in keys[1:]:
            value = value[key]
        bindings[':'.join([name, *keys[1:]])] = hashlib.sha256(data).hexdigest()
        if isinstance(value, str):
            value = json.loads(value) if value.startswith('[') else [value]
        if not isinstance(value, list) or len(value) > 1024 or not all(isinstance(n, str) for n in value):
            raise ValueError('Unbounded output binding values')
        for item in value:
            dest = item.partition(':')[0]
            if (not dest.startswith(('gen/', 'obj/')) or not dest.endswith(('.jar','.dex','.zip')) or
                    output_name(dest, out) != dest or dest in outputs):
                raise ValueError('Unrecognized or duplicated output path in binding')
            outputs.add(dest)
    if len(bindings) > 64 or len(outputs) > 1024:
        raise ValueError('Unbounded output bindings')
    return outputs, bindings


def desugar_outputs(out, command):
    """Match the fixed dex handler's optional literal path and matching command prefix."""
    args = shlex.split(command)
    if args[:2] != ['../../third_party/cpython3/host/bin/python3', '../../build/android/gyp/dex.py']:
        raise ValueError('Unrecognized DEX handler command')
    positions = [i + 1 for i, arg in enumerate(args) if arg == '--desugar-dependencies']
    if not positions:
        return set()
    if len(positions) != 1 or positions[0] >= len(args):
        raise ValueError('Ambiguous DEX dependency output')
    name = args[positions[0]]
    if not name.endswith('.desugardeps') or output_name(name, out) != name:
        raise ValueError('Unrecognized DEX dependency output')
    return {name}


def runtime_groups(out, rules, planned):
    if not rules:
        return {}, {}
    src = out.parent.parent
    if sha(src / 'build/config/siso/android.star') != ANDROID_RULES_SHA256:
        raise ValueError('Android runtime output policy differs from the verified handler')
    # A fresh, immutable GN graph supplies both command arguments and all static owners,
    # even implicitly declared outputs of clean, unrelated targets. Never execute commands.
    by_primary = {row[1]: edge for edge, row in rules.items()}
    if len(by_primary) != len(rules):
        raise ValueError('Two Android edges have the same first output')
    dynamic, bindings = {}, {}
    need_fileargs = any(row[0] in FILEARG_RULES for row in rules.values())
    need_dex = any(row[0] == 'android/dex' for row in rules.values())
    desugar_counts = {}
    unresolved_dex = False
    binding_counts = {}
    unresolved = False
    declared = set()
    declared_dirs = set()
    siso = src / 'third_party/siso/cipd/siso'
    with subprocess.Popen([siso, 'query', 'graph', '-C', str(out)], stdout=subprocess.PIPE, text=True) as query:
        try:
            for line in query.stdout:
                row = json.loads(line)
                primary = row['output']
                names = [primary, *row.get('extra_outputs', []), *row.get('implicit_outputs', [])]
                declared.update(names)
                declared_dirs.update(n.rstrip('/') for n in names if n.endswith('/'))
                resolved = {}
                command = row.get('command', '')
                if need_dex and '--desugar-dependencies' in command and '../../build/android/gyp/dex.py' in command:
                    try:
                        for name in desugar_outputs(out, command):
                            desugar_counts[name] = desugar_counts.get(name, 0) + 1
                    except (ValueError, TypeError):
                        unresolved_dex = True
                if need_fileargs:
                    for kind, script in FILEARG_RULES.items():
                        if ('../../build/android/gyp/' + script) not in command:
                            continue
                        try:
                            paths, origins = configured_outputs(out, kind, command)
                        except (OSError, ValueError, KeyError, TypeError, IndexError):
                            unresolved = True
                            continue
                        resolved[kind] = (paths, origins)
                        for path in paths:
                            binding_counts[path] = binding_counts.get(path, 0) + 1
                if primary not in by_primary:
                    continue
                edge = by_primary[primary]
                if sorted(names) != planned[edge] or edge in dynamic:
                    raise ValueError('Static edge does not match the planned Android output group')
                kind = rules[edge][0]
                extras = {primary + '.md5.stamp'}
                bindings[edge] = {}
                if kind in FILEARG_RULES:
                    if kind not in resolved:
                        raise ValueError('Cannot bind the Android runtime outputs to their fixed command')
                    extras, bindings[edge] = resolved[kind]
                if kind == 'android/dex':
                    extras.update(desugar_outputs(out, command))
                dynamic[edge] = extras - set(names)
        except BaseException:
            query.kill()
            raise
        if query.wait() or dynamic.keys() != rules.keys():
            raise ValueError('Could not verify the declared Android outputs')
    claimed = set()
    for edge, extras in dynamic.items():
        if any(n.endswith('.desugardeps') and (unresolved_dex or desugar_counts.get(n) != 1) for n in extras):
            raise ValueError('Other DEX dependency output owners cannot be excluded')
        if rules[edge][0] in FILEARG_RULES and extras and (unresolved or any(binding_counts[n] != 1 for n in extras)):
            raise ValueError('Other Android FileArg output owners cannot be excluded')
        if any(n in claimed or n in declared or any(p.as_posix() in declared_dirs for p in Path(n).parents) for n in extras):
            raise ValueError('Ambiguous owner for an Android runtime output')
        claimed.update(extras)
    return dynamic, bindings
