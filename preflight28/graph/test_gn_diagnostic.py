"""No compiler is invoked. Ninja parses the archived graph using its query tool."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import retained
from test_retained import ArchiveTest


class DiagnosticTest(unittest.TestCase):
    write = ArchiveTest.write
    log = (retained.GN_HEADER + "\n\n### siso.gni ###\nuse_siso=true\n"
           "#### get_concurrent_links.py ####\n").encode()

    def audit(self, old, new):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = {"gn_logs.txt":self.log+b"memory=16\n", "obj/a":b"prior",
                   "build.ninja":b"subninja rules.ninja\n",
                   "rules.ninja":b"build chrome_public_apk: phony obj/b.o\n", **old}
            new = {**old, "gn_logs.txt":self.log+b"memory=17\n", "obj/b.o":b"B", **new}
            old = {k:v for k,v in old.items() if v is not None}
            new = {k:v for k,v in new.items() if v is not None}
            parent, ps = self.write(root, "parent", old)
            body = {k:retained.record(0o644,len(v),hashlib.sha256(v).hexdigest())
                    for k,v in new.items() if isinstance(v, bytes) and not retained.meta(k)}
            for k,v in new.items():
                if v == "symlink":
                    body[k] = retained.link_record("a")
            proof = {"format":"bare-28-apk-frontier-2","target":"chrome_public_apk","target_path":"obj/b.o",
                     "outputs":{"obj/b.o":[1,hashlib.sha256(b"B").hexdigest()]},
                     "child_content":retained.commitment(body)}
            child, cs = self.write(root, "child", new, proof)
            receipt = root / "diff.json"
            with patch.object(retained,"S2",ps):
                try:
                    retained.archives(parent,child,ps,cs,report_path=receipt)
                except ValueError:
                    if not receipt.is_file():
                        raise
            r = json.loads(receipt.read_text())
            self.assertEqual(r["child_content"], proof["child_content"])
            return r

    def test_exact_root_log_only_and_original_hash_preserved(self):
        r = self.audit({}, {})
        self.assertEqual(r["status"], "passed", r["issues"])
        self.assertEqual(r["counts"]["gn_diagnostic"], 1)
        diag, = r["diagnostics"]
        self.assertEqual(diag["evidence"]["changed_sections"], ["get_concurrent_links.py"])
        self.assertNotEqual(diag["parent"], diag["child"])
        self.assertEqual(diag["evidence"]["parent"]["manifest_content"]["files"], 2)
        self.assertEqual(r["counts"]["unchanged"], 3)
        self.assertEqual(r["counts"]["added"], 1)

    def test_every_unknown_change_and_missing_input_reported(self):
        r = self.audit({"obj/gn_logs.txt":b"other","required.o":b"required","renamed-log.txt":b"a"},
                       {"obj/gn_logs.txt":b"unrelated change","required.o":None,"renamed-log.txt":b"b"})
        self.assertEqual(r["status"], "rejected")
        self.assertEqual(r["counts"]["gn_diagnostic"], 1)
        rows = {x["path"]:x for x in r["differences"]}
        self.assertEqual(rows["obj/gn_logs.txt"]["classification"], "unclassified")
        self.assertEqual(rows["required.o"]["classification"], "removed")
        self.assertEqual(rows["renamed-log.txt"]["classification"], "unclassified")
        self.assertIsNone(rows["required.o"]["child"])

    def test_graph_expansion_source_headers_failure_and_missing_log(self):
        graph = b"x = gn_\ny = logs.txt\nbuild chrome_public_apk: phony ${x}${y}\n"
        for old, new in [
            ({"rules.ninja":graph}, {}),
            ({"graph.d":b"obj/b.o: gn_logs.txt\n"}, {}),
            ({"sensitive.rsp":b"gn_logs.txt"}, {}),
            ({}, {"gn_logs.txt":b"not from gn"}),
            ({}, {"gn_logs.txt":None}),
            ({}, {"gn_logs.txt":"symlink"}),
            ({"build.ninja":b"include missing.ninja\n"}, {}),
        ]:
            with self.subTest(old=old,new=new):
                self.assertEqual(self.audit(old,new)["status"],"rejected")


if __name__ == "__main__":
    unittest.main()
