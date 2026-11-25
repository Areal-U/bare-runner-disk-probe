import base64
from copy import deepcopy
import hashlib
import unittest
from unittest.mock import patch
import trials

B=trials.budget
H="b"*40
NOW=1700000000
F=".github/workflows/bare-disk-probe.yml"
REF=f"{B.BASE}/git/ref/heads/{trials.BRANCH}"
HISTORY=f"{B.BASE}/actions/runs?head_sha={H}&event=workflow_dispatch&per_page=100"
DEFAULT=f"{B.BASE}/contents/{F}?ref=main"

def fixture():
    blob=b"name: Test\non:\n  workflow_dispatch:\n"
    rows={B.BASE:dict(id=B.REPO_ID, full_name=B.REPO, private=False, fork=False, visibility="public",default_branch="main"),
        REF:{"ref":"refs/heads/"+trials.BRANCH, "object":{"type":"commit","sha":H}},
        DEFAULT: dict(type="file",path=F,encoding="base64",content=base64.b64encode(blob).decode(),
                      sha=hashlib.sha1(b"blob "+str(len(blob)).encode()+b"\0"+blob).hexdigest()),
        HISTORY: {"total_count":0, "workflow_runs":[]}}
    for s in B.RUN_STATES:
        rows[f"{B.BASE}/actions/runs?status={s}&per_page=2"] = {"total_count":0, "workflow_runs":[]}
    return dict(schema="bare-next-preflight-reads-v1",started_at=NOW-100,finished_at=NOW-5,head=H,mode="receiver",
                workflow_id=411691930,responses=rows)

def initial(c):
    return trials.connector_gate.initial(c,"receiver",H,branch=trials.BRANCH,workflow=trials.WORKFLOW,
            cost=trials.MODES["receiver"]+B.CONTROL_RESERVE,total_cap=trials.DIAGNOSTIC_TOTAL_CAP,now=NOW)

class AuthenticatedCapture(unittest.TestCase):
    def test_accepts_only_readonly_start_then_in_run_remeasures(self):
        c=fixture()
        e=initial(c)
        self.assertEqual(int(e["ceiling"]),trials.DIAGNOSTIC_TOTAL_CAP)
        from test_trials import api
        bound=trials.check(api,"receiver",H,42,e["ceiling"],e["until"],runner="github-hosted",now=NOW+30)
        self.assertEqual(int(bound["ceiling"]),trials.MODES["receiver"]+B.CONTROL_RESERVE)

    def test_stale_duplicate_or_incomplete_or_previous_run(self):
        c=fixture();rows=c["responses"];row=dict(id=105,event="workflow_dispatch",head_sha=H,workflow_id=411691930,
                                                  display_title=f"Bare next-build trial receiver {H}")
        cases=[]
        for k,v in (("started_at",NOW-121),("finished_at",NOW+1),("head","c"*40),("workflow_id",8)):
            cases.append({**c,k:v})
        for k,v in [(DEFAULT,{**rows[DEFAULT],"sha":"0"*40}),(REF,{"ref":"refs/heads/main","object":{"sha":H}}),
                    (HISTORY,{"total_count":1,"workflow_runs":[row]}),(HISTORY,{"total_count":2,"workflow_runs":[row]}),
                    (f"{B.BASE}/actions/runs?status=pending&per_page=2",{"total_count":1,"workflow_runs":[]})]:
            cases.append({**c,"responses":{**rows,k:v}})
        for x in cases:
            with self.assertRaises(ValueError): initial(x)
        bad=deepcopy(c); del bad["responses"][HISTORY]
        with self.assertRaises(KeyError): initial(bad)
        with patch.dict("os.environ",{"R28_RELAY_BYTE_CEILING":"1"}), self.assertRaises(ValueError):
            initial(c)

if __name__=="__main__":
    unittest.main()
