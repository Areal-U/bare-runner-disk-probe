"""Two-host comparison for four public GN source groups in Chromium 157's libyuv.

The hosted field profile adds 96 distinct ICU i18n GN units, selected by source size.
The official Clang/NDK inputs are pinned in prepare.sh. This compact graph does
not include Chromium's PGO, generated modules or libjpeg configuration.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve()
PIN = '1e2e3a35993609da1d89ac170b907719d555f4b3'
ICU_PIN = '2a51536dfb3b448bdf3dae70c782ea2879c90904'
MAX_PAYLOAD = 7 * 1024**2
FLAGS = {'internal': '-ffp-contract=fast', 'neon': '-march=armv8-a+dotprod+i8mm',
         'sve': '-march=armv8.5-a+i8mm+sve2', 'sme': '-march=armv8.5-a+i8mm+sme'}


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, sort_keys=True))


def graph(root):
    gn = (root/'src/BUILD.gn').read_text()
    units = {}
    for group in FLAGS:
        block = gn.split(f'static_library("libyuv_{group}")', 1)[1].split('sources = [', 1)[1].split(']', 1)[0]
        for unit in re.findall(r'"source/([a-z0-9_]+)\.cc"', block):
            if unit in units:
                raise ValueError(f'duplicate GN unit {unit}')
            units[unit] = group
    if len(units) != 51:
        raise ValueError(f'expected pinned source set of 51, got {len(units)}')
    if os.environ.get('NEXT_SPLIT_GROUP') == 'field':
        i18n = (root/'icu/sources.gni').read_text().split('icu18n_sources = [', 1)[1].split(']', 1)[0]
        names = re.findall(r'"source/i18n/([a-z0-9_]+)\.cpp"', i18n)
        if len(names) < 96 or len(names) != len(set(names)):
            raise ValueError('unexpected ICU GN source set')
        ranked = sorted(names, key=lambda n: (-(root/'icu/source/i18n'/(n+'.cpp')).stat().st_size, n))
        units.update({'icu_'+n: 'icu' for n in ranked[:96]})
    return units


def source(group, name):
    if group=='icu': return '../icu/source/i18n/'+name.removeprefix('icu_')+'.cpp'
    return '../src/source/'+name+'.cc'


def execute(out, *args):
    return subprocess.check_output(args, cwd=out, text=True)


def unit_build(out, name):
    mapping = graph(out.parent)
    if name not in mapping:
        raise ValueError('unknown source')
    if (out/'import'/f'{name}.o').exists():
        for ext in ('.o', '.d'):
            shutil.copyfile(out/'import'/(name+ext), out/(name+ext))
        action = 'import'
    else:
        group = mapping[name]
        flags = (['-std=c++20','-DU_I18N_IMPLEMENTATION','-DU_STATIC_IMPLEMENTATION','-I../icu/source/common','-I../icu/source/i18n']
                 if group=='icu' else ['-I../src/include',FLAGS[group]])
        execute(out, '../clang/bin/clang++', '--target=aarch64-linux-android29', '--sysroot=../sysroot',
                '-isystem', '../sysroot/usr/include/aarch64-linux-android', '-isystem', '../sysroot/usr/include/c++/v1',
                '-O2', '-flto=thin', '-fPIC', '-ffile-compilation-dir=.', '-fno-ident',
                '-DNDEBUG', *flags, '-MMD', '-MF', name+'.d', '-c', source(group, name),
                '-o', name+'.o')
        action = 'compile'
    with (out/'actions').open('a') as f:
        f.write(f'{action} {name}\n')


def create(out, units):
    out.mkdir()
    all_objects = ' '.join(name+'.o' for name in sorted(units))
    lines = ['rule cc', f'  command = python3 {HERE} unit $name', '  depfile = $name.d',
             '  deps = gcc', 'rule ar', '  command = ../clang/bin/llvm-ar rcsD $out $in']
    for name in sorted(units):
        lines += [f'build {name}.o: cc {source(units[name],name)} | {HERE} ../src/BUILD.gn ../clang/bin/clang++',
                  f'  name = {name}']
    lines += [f'build cohort.a: ar {all_objects}']
    (out/'build.ninja').write_text('\n'.join(lines)+'\n')


def scope():
    return [PIN, ICU_PIN, os.environ.get('NEXT_SPLIT_GROUP', 'libyuv'), sha(HERE), os.environ.get('GITHUB_RUN_ID', 'local'), os.environ.get('GITHUB_RUN_ATTEMPT', '1'),
            os.environ.get('GITHUB_SHA', 'local')]


def partition(units):
    # Distribute the pinned source groups across both workers with the same rule for every attempt.
    return sorted(units)[1::2]


def collect(out, names):
    return {name+ext: sha(out/(name+ext)) for name in sorted(names) for ext in ('.o', '.d')}


def pack(out, names):
    hashes = collect(out, names)
    with zipfile.ZipFile(out/'shard.zip', 'x', zipfile.ZIP_DEFLATED) as z:
        z.writestr('manifest', json.dumps({'scope': scope(), 'files': hashes}, sort_keys=True))
        for name in hashes:
            z.write(out/name, name)
    if (out/'shard.zip').stat().st_size > MAX_PAYLOAD-16384:
        raise ValueError('oversized shard, stop before upload')


def receive(out, names, path):
    if path.stat().st_size > MAX_PAYLOAD:
        raise ValueError('oversized shard')
    with zipfile.ZipFile(path) as z:
        expected = sorted(name+ext for name in names for ext in ('.o', '.d'))
        if sorted(z.namelist()) != sorted(['manifest', *expected]) or sum(i.file_size for i in z.infolist()) > 24*1024**2:
            raise ValueError('wrong or oversized member set')
        m = json.loads(z.read('manifest'))
        if m['scope'] != scope() or sorted(m['files']) != expected:
            raise ValueError('wrong commit, attempt, trial or output set')
        (out/'import').mkdir()
        for name in expected:
            dest = out/'import'/name
            dest.write_bytes(z.read(name))
            if sha(dest) != m['files'][name]:
                raise ValueError('member payload mismatch')


def actions(out):
    return sorted((out/'actions').read_text().splitlines())


def ninja(out, targets):
    return execute(out, 'ninja', '-d', 'keepdepfile', '-j2', *targets)


def timing(out, role, results):
    write(out/(role+'.json'), results)
    print(json.dumps(results, sort_keys=True), flush=True)


def main():
    mode = sys.argv[1]
    if mode == 'unit':
        unit_build(Path.cwd(), sys.argv[2]); return
    root = Path.cwd()
    units = graph(root)
    right = partition(units)
    role = 'central' if mode == 'join' else mode
    out = root/role
    start = time.monotonic()
    if mode == 'join':
        receive(out, right, root/'shard.zip')
        ninja(out, ['cohort.a'])
        expected = sorted(('import ' if n in right else 'compile ')+n for n in units)
        if actions(out) != expected:
            raise ValueError('central recompiled or missed a unit')
    else:
        create(out, units)
        if mode == 'central':
            names = sorted(set(units)-set(right))
        elif mode == 'peer':
            names = right
        elif mode == 'solo':
            names = units
        else:
            raise ValueError('unknown role')
        ninja(out, ['cohort.a'] if mode=='solo' else [n+'.o' for n in names])
        if actions(out) != sorted('compile '+n for n in names):
            raise ValueError('incomplete independent compilation')
        if mode == 'peer': pack(out, names)
    if mode in ('solo', 'join'):
        before = actions(out)
        if 'no work to do' not in ninja(out, ['cohort.a']) or actions(out)!=before:
            raise ValueError('second build failed to reuse the graph')
        files = collect(out, units)
        digest = hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest()
        timing(out, mode, dict(archive=sha(out/'cohort.a'), objects_and_deps=digest,
                               units=len(units), seconds=time.monotonic()-start, noop=True))
    else:
        timing(out, mode, dict(units=len(names),seconds=time.monotonic()-start))

if __name__ == '__main__':
    main()
