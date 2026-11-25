import unittest
import os
from unittest.mock import Mock
os.environ.setdefault("RUNNER_TEMP","/tmp")
import artifact_poll as poll
import bridge

RUN=45526428252
REPO="Areal-U/bare-runner-disk-probe"
HEAD="6ac68b6c46dc7e9b60fe243a0f00e2d112ff2025"
NAME=f"r28-thaw-{RUN}-a1-receiver-key"
ROW={"id":14982970974,"name":NAME,"expired":False,"size_in_bytes":2446,
     "digest":"sha256:5742c44a43fd4d55bb9cc2e43d26cf56533ad917c471816b0bb199e74b1b5acd",
     "expires_at":"2026-11-26T01:33:36Z","workflow_run":{"id":RUN,"head_sha":HEAD}}

def page(rows,n=None):return {"total_count":len(rows) if n is None else n,"artifacts":rows}

def lookup(get):return poll.lookup(RUN,NAME,get,repo=REPO,head=HEAD)


class PublicKeyInventory(unittest.TestCase):
    def test_persisted_actual_row(self):
        client=Mock(side_effect=[page([ROW]),page([ROW]),dict(ROW)])
        self.assertEqual(lookup(client),ROW)
        urls=[c.args[0] for c in client.call_args_list]
        self.assertFalse(any("name=" in u for u in urls))
        self.assertEqual(urls[-1],f"/repos/{REPO}/actions/artifacts/14982970974")

    def test_eventual_inventory_is_never_absence_or_duplicate_proof(self):
        for replay in ([page([ROW],0)],[page([],1)],[page([]),page([ROW])],
                       [page([ROW]),page([ROW]),bridge.ScopedHTTPError(404)],
                       [page([ROW]),page([ROW]),{**ROW,"size_in_bytes":20}]):
            with self.subTest(replay=replay), self.assertRaises(poll.UnstableInventory):
                lookup(Mock(side_effect=replay))
        self.assertIsNone(lookup(Mock(side_effect=[page([]),page([])])))
        with self.assertRaisesRegex(ValueError,"Multiple distinct"):
            lookup(Mock(return_value=page([ROW,{**ROW,"id":10}])))
        with self.assertRaisesRegex(ValueError,"Foreign"):
            lookup(Mock(return_value=page([{**ROW,"workflow_run":{"id":0x123,"head_sha":HEAD}}])))
        with self.assertRaisesRegex(ValueError,"expired"):
            row={**ROW,"expired":True}
            lookup(Mock(side_effect=[page([row]),page([row]),row]))

    def test_all_pages_and_boundaries(self):
        rest=[{**ROW,"id":1000+i,"name":"unrelated"+str(i)} for i in range(100)]
        first=page(rest,101);last=page([ROW],101)
        self.assertEqual(lookup(Mock(side_effect=[first,last,first,last,ROW])),ROW)
        with self.assertRaises(poll.UnstableInventory):
            lookup(Mock(side_effect=[first,page([ROW],102)]))
        with self.assertRaises(poll.UnstableInventory):
            lookup(Mock(side_effect=[first,page([rest[0]],101)]))

if __name__=="__main__":unittest.main()
