"""Admit cold or exact freshly reverified 2.0.9 recovery input. No old-generation import."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'preflight28/bridge'))
import normal as n
from checkpoint209 import digest, require, valid_hex
from precompile_cold import SELECTOR as COLD_SUCCESSOR, parse_selector

def start():
    genesis = digest(Path(__file__).with_name('upstream-lock.json'))
    require(os.environ['GITHUB_REF'] == 'refs/heads/bare-coexist-v2.0.9' and
            os.environ['GITHUB_RUN_ATTEMPT'] == '1' and os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
            and os.environ['GITHUB_REPOSITORY'] == n.b.REPO and os.environ['GITHUB_ACTOR'] == 'Areal-U',
            'Wrong campaign context')
    os.environ['R209_GENESIS'] = genesis
    raw = os.environ.get('R209_RESUME','')
    first = dict(ordinal=1, parent=genesis, parent_identity=genesis, origin='', manifest='', manifest_sha='')
    v = parse_selector(raw)
    if v and v != COLD_SUCCESSOR:
        i = v['ordinal']
        os.environ.update(R28_PARENT_RUN=str(v['origin_run']), R28_SLOT=str(i+1))
        origin = n.parent_read_run()
        m = n.get_manifest(v['manifest_id'],v['manifest_sha'],i,run_id=origin)
        require(m.get('next_has_headroom') is True, 'Retained predecessor requires a new working-set decision')
        api = n.b.auth_api()
        assets = n.list_private(api)['assets']
        pattern = re.compile(r'r209-'+str(origin)+r'-a1-s([0-9]{2})-manifest\.json(?:-retry1)?')
        require(not any(int(mt[1])>i for row in assets if (mt:=pattern.fullmatch(row['name']))),
                'A newer durable generation already exists')
        h = hashlib.sha256()
        class Sink:
            def write(self, block):
                h.update(block)
        for item in m['parts']:
            api.download(item['id'],item['bytes'],item['sha256'],Sink())
        ids = {v['manifest_id'], *(item['id'] for item in m['parts'])}
        rows = [a for a in assets if a['id'] in ids]
        require(len(rows)==len(ids) and h.hexdigest() == m['sha256'] and
                n.visibility(api, rows, time.time()+600)[0], 'Private predecessor readback incomplete')
        first.update(ordinal=i+1, origin=origin, parent=m['sha256'], parent_identity=m['identity'],
                     manifest=v['manifest_id'],manifest_sha=v['manifest_sha'])
    n.b.output(genesis=genesis, **first)


def certify():
    w = os.environ
    if w['WORKER'] == 'apk':
        via_private = (w.get('PRIVATE_RECEIPT','').isdigit() and valid_hex(w.get('RECEIPT_SHA')) and w.get('CIPHER_ID','').isdigit())
        primary = w['TERMINAL'].isdigit()
        require(primary != via_private and w['PEER'] == 'apk' and w['READBACK'] == 'false',
                'Terminal requires the matching encrypted artifact and publisher stop')
        n.b.output(kind='apk',artifact=w['TERMINAL'] if primary else w['PRIVATE_RECEIPT'])
        print('R209_TERMINAL', 'encrypted Artifact '+w['TERMINAL'] if primary else
              'private Draft receipt '+w['PRIVATE_RECEIPT']+' sha256='+w['RECEIPT_SHA'])
    else:
        require(w['WORKER'] == 'checkpoint' and w['PEER'] == 'candidate' and w['READBACK'] == 'true'
                and w['ADVANCED'] == 'true' and w['HEADROOM'] in ('true','false') and w['HEADROOM'] == w['WRITER_HEADROOM']
                and w['MANIFEST'].isdigit() and
                all(valid_hex(w[k]) for k in ('MANIFEST_SHA','PARENT','IDENTITY')),
                'Checkpoint requires complete independent private receipt')
        n.b.output(kind='checkpoint' if w['HEADROOM']=='true' else 'saved-capacity-limit',manifest=w['MANIFEST'],manifest_sha=w['MANIFEST_SHA'],
                   parent=w['PARENT'],parent_identity=w['IDENTITY'])


if __name__ == '__main__':
    {'start':start, 'certify':certify}[sys.argv[1]]()
