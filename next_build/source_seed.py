"""Import a verified public Chromium Git pack into an empty normal Android source root."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory

# This script may run in isolated Python under the Ubuntu 22.04 builder.
sys.path.insert(0,str(Path(__file__).resolve().parent/'trials'))
import source_reuse as source


def check(receipt, expected):
    spec = receipt['spec']
    source.require(re.fullmatch(r'[0-9a-f]{40}',expected) and
                   spec['url']==source.CHROMIUM and spec['scope']=='chromium' and
                   spec['revision']==spec['CHROMIUM_REV']==expected,
                   'Source receipt is not the selected official Chromium commit')
    source.require(re.fullmatch(r'[0-9a-f]{40}',receipt['tree']) and re.fullmatch(r'[0-9a-f]{64}',receipt['sha256'])
                   and all(type(receipt[k]) is int and receipt[k]>0 for k in ('bytes','files','checkout_bytes'))
                   and receipt['bytes']<=source.CAP['chromium']-source.ZIP_MARGIN,
                   'Malformed or oversized source receipt')


def restore(receipt, pack, dest, expected):
    check(receipt, expected)
    source.require(pack.is_file() and not pack.is_symlink() and not os.path.lexists(dest),
                   'Expected a verified pack and absent target')
    disk=os.statvfs(dest.parent)
    source.require(disk.f_bavail*disk.f_frsize >= 65*1024**3+receipt['bytes'] and
                   disk.f_favail>=2*receipt['files']+20000,'Insufficient builder space for full source and Android dependencies')
    with TemporaryDirectory(dir=dest.parent,prefix='.bare-input-') as work:
        staged=Path(work)/'src'
        source.restore(receipt, pack, staged)
        source.verify(staged, receipt)
        # No artifacts or objects are installed into an existing working copy.
        source.require(not os.path.lexists(dest),'Target appeared during source verification')
        staged.rename(dest)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation',choices=['restore'])
    parser.add_argument('receipt',type=Path)
    parser.add_argument('pack',type=Path)
    parser.add_argument('destination',type=Path)
    parser.add_argument('expected_chromium')
    args=parser.parse_args()
    try:
        restore(json.loads(args.receipt.read_bytes()),args.pack,args.destination,args.expected_chromium)
    except (KeyError,OSError,ValueError,subprocess.SubprocessError) as exc:
        raise SystemExit('Source seed declined: '+str(exc))
