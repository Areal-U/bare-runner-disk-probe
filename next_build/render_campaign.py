#!/usr/bin/env python3
"""Prepare the same Bare 2.0.4, same S2, same private owner destination for a separate campaign."""
import argparse
import difflib
import hashlib
import json
from pathlib import Path
import re
import sys
from tempfile import TemporaryDirectory

import inputs

ORIGINAL = 'bare-personal-204-r28'
ORIGINAL_HEAD = 'f3ed4479912a30959859d81328af3fd4dc6d8d00'
REGISTER = 'preflight28/control/registration.py'
RECOVER = 'preflight28/bridge/owner_recovery.py'
BINDER_TEST = 'preflight28/control/test_registration.py'
RECEIVER_TEST = 'preflight28/bridge/test_normal.py'
STORAGE_TEST = 'preflight28/bridge/test_storage_admission.py'

# This helper is embedded into the rendered registration.py: sparse checkouts already fetch this file.
OWNER_GUARD = '''
def same_owner_as_previous(helper, release, ticket):
    """Check the immutable earlier owner reservation before staging a new physical claim."""
    earlier_name = PREVIOUS_CAMPAIGN + "-collection-registration.json"
    found = [row for row in release["assets"] if row["name"] == earlier_name]
    require(len(found) == 1, "Prior owner ticket missing or ambiguous")
    row = found[0]
    require(type(row["id"]) is int and row["id"] > 0 and row["state"] == "uploaded" and
            0 < row["size"] <= 4096 and row["digest"] == "sha256:" + PREVIOUS_TICKET_SHA and
            all(row["uploader"].get(k) == v for k, v in OWNER.items()), "Unconfirmed prior owner ticket")
    helper.asset_info(release, earlier_name, row["size"], PREVIOUS_TICKET_SHA, row["id"])
    raw = io.BytesIO()
    helper.download(row["id"], row["size"], PREVIOUS_TICKET_SHA, raw)
    require(len(raw.getvalue()) == row["size"] and hashlib.sha256(raw.getvalue()).hexdigest() == PREVIOUS_TICKET_SHA,
            "Prior owner ticket changed")
    prior = json.loads(raw.getvalue())
    fields = dict(schema=1, campaign=PREVIOUS_CAMPAIGN, head=PREVIOUS_HEAD,
                  initial_parent=S2_SHA, repository_id=REPO_ID, release_id=RELEASE_ID,
                  workflow=WORKFLOW, branch=BASE_REF, recipient=RECIPIENT)
    require(all(prior.get(k) == v for k,v in fields.items()) and
            prior["owner_destination_id"] == ticket["owner_destination_id"] and
            prior["registration_nonce"] != ticket["registration_nonce"] and
            prior["collector_registration_id"] != ticket["collector_registration_id"] and
            prior["head"] != ticket["head"], "Changed destination or reused prior owner registration")


'''
ANCHOR = '    service = ticket["collector_registration_id"]\n'
HELPER_BEFORE = 'def checked_ack(helper, release, ticket, created, now):'


def once(data, old, new):
    if data.count(old) != 1:
        raise ValueError('Missing or duplicated reviewed reference: '+old)
    return data.replace(old,new)


def review_namespace(root, head):
    # Reject new static runtime references. Historical protocol names containing the physical run ID
    # remain useful in the same repo and do not select a campaign or an owner.
    result = inputs.git(root,'grep','-l', '-F', ORIGINAL, head, '--','checkpoint.py','build_trial.py',
                        'coexist_inputs.py','.github/workflows/','preflight28/').decode().splitlines()
    found = [x.split(':',1)[1] for x in result]
    live = {p for p in found if not (Path(p).name.startswith('test_') or p.endswith('.md'))}
    if live != {REGISTER,RECOVER}:
        raise ValueError('Campaign binding locations differ: '+repr(sorted(live)))
    for path, sym in [('preflight28/collector/production.py','from registration import CAMPAIGN, CLAIM'),
                      ('preflight28/control/loss_resume.py','LOSS_CLAIM = reg.CAMPAIGN'),
                      ('preflight28/control/owner_witness.py','from registration import CAMPAIGN, CLAIM'),
                      ('preflight28/bridge/terminal_draft.py','owner.CAMPAIGN+"-collection-registration.json"'),
                      ('preflight28/collector/owner_snapshot.py','self.private_hint(p.CLAIM)')]:
        if sym not in inputs.git(root,'show',head+':'+path).decode():
            raise ValueError('Recheck campaign consumer: '+path)


def render(root, head, campaign, locator, out):
    if (not re.fullmatch(r'bare-personal-204-r[1-9][0-9]{1,3}(?:-[a-z0-9]{1,12})?', campaign)
        or campaign == ORIGINAL):
        raise ValueError('A distinct bounded Bare 2.0.4 campaign is required')
    if (locator['head'] != ORIGINAL_HEAD or not re.fullmatch('[a-f0-9]{64}',locator['ticket_sha'])
        or not re.fullmatch('Automation_[0-9a-f]{32}',locator['registration_id'])
        or not re.fullmatch('[A-Za-z0-9_-]{12,200}',locator['owner_destination_id'])):
        raise ValueError('Expected the original R28 owner locator from the private registered ledger')
    inputs.exact(root,head)
    review_namespace(root,head)
    source=lambda p: inputs.git(root,'show',head+':'+p).decode()
    for path, tokens in [('.github/workflows/bare-checkpoint-transfer.yml', [inputs.production.S2_SHA,
                           'bare-coexist-204-45285202990-1-checkpoint-production-s2',inputs.production.apk_seal.RECIPIENT]),
                         ('.github/workflows/bare-arm64-probe.yml',[inputs.production.BARE_REV,inputs.production.CHROMIUM_REV,
                           'expected_code = '+repr('802000415')]),
                         ('preflight28/control/admission.py',[inputs.production.S2_SHA,inputs.production.BASE_REF])]:
        if not all(t in source(path) for t in tokens):
            raise ValueError('Use a separately reviewed route for different version, parent or recipient: '+path)
    pathset=(REGISTER,RECOVER,BINDER_TEST,RECEIVER_TEST,STORAGE_TEST)
    edits={}
    for path in pathset:
        before=source(path)
        if path==REGISTER:
            text=once(before,'CAMPAIGN = "'+ORIGINAL+'"',
                      f'CAMPAIGN = "{campaign}"\nPREVIOUS_CAMPAIGN = "{ORIGINAL}"\nPREVIOUS_HEAD = "{ORIGINAL_HEAD}"\nPREVIOUS_TICKET_SHA = "{locator["ticket_sha"]}"')
            text=once(text,HELPER_BEFORE,OWNER_GUARD+HELPER_BEFORE)
            text=once(text,ANCHOR,'    same_owner_as_previous(helper, release, ticket)\n'+ANCHOR)
        elif path==RECOVER:
            if before.count(ORIGINAL)!=3:
                raise ValueError('Recheck checkpoint recovery original and replacement claim paths')
            text=before.replace(ORIGINAL,campaign)
        elif path==BINDER_TEST:
            # Feed the additional authenticated prior record through the actual guard in all
            # registration tests. Only the prior immutable digest is substituted by its fixture digest.
            needle = '        self.origin = dict(id=81,run_attempt=1,'
            text = once(before,needle,'        from registration import PREVIOUS_CAMPAIGN, PREVIOUS_HEAD\n        self.prior = dict(self.ticket, campaign=PREVIOUS_CAMPAIGN, head=PREVIOUS_HEAD,\n            collector_registration_id="Automation_"+"2"*32, registration_nonce="3"*32)\n'+needle)
            text=once(text,'return json.dumps(self.ticket if n==901 else self.ack).encode()',
                'return json.dumps(self.prior if n==700 else self.ticket if n==901 else self.ack).encode()')
            text=once(text,'dict(self.ack_asset,size=len(self.data(812)))]}',
                'dict(self.ack_asset,size=len(self.data(812))), dict(name=self.prior["campaign"]+"-collection-registration.json",id=700,state="uploaded",uploader=OWNER,size=len(self.data(700)),digest="sha256:"+hashlib.sha256(self.data(700)).hexdigest())]}')
            text=once(text,'aid in (901,812)','aid in (901,812,700)')
            needle='        self.d = OwnerDraft()'
            text=once(text,needle,needle+'\n        prior = patch("registration.PREVIOUS_TICKET_SHA", hashlib.sha256(self.d.data(700)).hexdigest())\n        prior.start()\n        self.addCleanup(prior.stop)')
            text=once(text,'ticket, ack = super().draft(RELEASE_ID)["assets"]',
                      'ticket, ack, prior = super().draft(RELEASE_ID)["assets"]')
            text=once(text,' + [ticket, ack]',' + [ticket, ack, prior]')
            needle='    def test_lease_includes_receiver_private_deposit_and_receipt(self):'
            tests = """    @patch("registration.admit")
    def test_conflicting_predecessor_reservation_cannot_claim(self, claim):
        for change in (dict(owner_destination_id="different_owner_destination"),
                       dict(registration_nonce=self.d.prior["registration_nonce"]),
                       dict(collector_registration_id=self.d.prior["collector_registration_id"])):
            with self.subTest(change=change), patch.dict(self.d.ticket,change), self.assertRaises(ValueError):
                self.enter()
        with patch.dict(self.d.prior,campaign="foreign"), self.assertRaises(ValueError):
            self.enter()
        claim.assert_not_called()

"""
            text=once(text,needle,tests+needle)
        else:
            count={RECEIVER_TEST:3,STORAGE_TEST:2}[path]
            if before.count(ORIGINAL)!=count:
                raise ValueError('Check the original regression fixture: '+path)
            text=before.replace(ORIGINAL,campaign)
        edits[path]=(before,text)
    output=out.resolve()
    checkout=Path(inputs.git(root,'rev-parse','--show-toplevel').decode().strip()).resolve()
    if output.exists() or output==checkout or checkout in output.parents or not output.parent.is_dir():
        raise ValueError('Use a new directory outside the checkout')
    report=dict(campaign=campaign,source_ci_sha=head,dispatch_ready=False,reuses_old_claim=False,
        source=inputs.production.BARE_REV, chromium=inputs.production.CHROMIUM_REV,initial_parent=inputs.production.S2_SHA,
        branch=inputs.production.BASE_REF, owner_dest_rule='match verified earlier owner ticket',
        templates={'ticket':campaign+'-collection-registration.json',
                   'ack':campaign+'-collector-ack-<new-nonce>.json','origin_claim':campaign+'-production-run-claim.json',
                   'replacement_claim':campaign+'-loss-replacement-claim.json',
                   'loss_ticket':campaign+'-loss-<origin-run>.json','loss_evidence':campaign+'-loss-evidence-<origin-run>.json'},
        unresolved=['Exclusive new campaign/name; rule out an existing ticket, claim or pending owner operation.',
                    'Approve the fixed candidate and obtain its final production SHA; reconcile prior ledger and unchanged destination/certificate.',
                    'Register one new private collector, fresh nonce, measured pickup cadence/retry, UTC lease, free ceiling/valid-until.',
                    'Read back its immutable ACK, bind the owner ticket and locator to the final SHA and fresh registration. No new run before that.',
                    'First physical run/attempt/claim ID are discovered by the binder only after a separately authorized dispatch.'])
    common = dict(schema=1,campaign=campaign,branch=inputs.production.BASE_REF,
                  recipient=inputs.production.apk_seal.RECIPIENT,head=None,collector_registration_id=None,
                  owner_destination_id=None,registration_nonce=None,storage_policy="github-public-standard-r28-v1",
                  artifact_ceiling_bytes=None,storage_valid_until=None)
    forms = dict(ticket=dict(common, repository_id=inputs.production.REPO_ID, workflow=inputs.production.WORKFLOW,
                             initial_parent=inputs.production.S2_SHA,release_id=inputs.production.RELEASE_ID,
                             issued_at=None,expires_at=None,collector_ack_sha=None),
                 ack=dict(common,state="collector-read-back-owner-reservation",observed_at=None,
                          valid_until=None,poll_seconds=None,pickup_retry_seconds=None),
                 locator=dict(head=None,ticket_sha=None,registration_id=None,owner_destination_id=None))
    with TemporaryDirectory(dir=output.parent) as tmp:
        stage=Path(tmp)/'files';stage.mkdir()
        patch=[]
        for path,(before,after) in edits.items():
            target=stage/'rendered'/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(after)
            patch.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),'a/'+path,'b/'+path))
        (stage/'campaign.patch').write_text(''.join(patch))
        (stage/'registration-forms.unissued.json').write_text(json.dumps(forms,indent=2)+'\n')
        (stage/'review.json').write_text(json.dumps(report,indent=2)+'\n')
        output.mkdir(mode=0o700)
        for name in ('rendered','campaign.patch','registration-forms.unissued.json','review.json'):
            (stage/name).rename(output/name)
    return report


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prior_locator',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--ci-head',required=True)
    parser.add_argument('--campaign',required=True)
    args=parser.parse_args()
    try:
        row=render(inputs.ROOT,args.ci_head,args.campaign,json.loads(args.prior_locator.read_bytes()),args.output)
        print(json.dumps({'campaign':row['campaign'],'dispatch_ready':False}))
    except (OSError, ValueError, KeyError, inputs.subprocess.SubprocessError) as exc:
        sys.exit('Campaign preview rejected: '+str(exc))
