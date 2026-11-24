"""Regression controls for the producer ledger and the cross-UID receipt interface."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from trial_provenance import (CORE, EXPORTS, FILE, FORMAT, LEGACY, S2, WORKFLOW,
                              encoded, expected, export, finish, sha)


class TrialProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.checkout=self.root/"source"
        self.checkout.mkdir()
        self.workflow=self.checkout/WORKFLOW
        self.workflow.parent.mkdir(parents=True)
        self.workflow.write_text("jobs: {}\n")
        self.actual={}
        for path in CORE:
            f=self.checkout/path
            f.parent.mkdir(parents=True,exist_ok=True)
            f.write_bytes(("fixed "+path+"\n").encode()); self.actual[path]=f.read_bytes()
        for args in (["init","-q"],["add","."],["-c","user.name=Fixture","-c","user.email=x@example.invalid","commit","-qm","local receipt fixture"]):
            subprocess.run(["git","-C",str(self.checkout),*args],check=True)
        self.head=subprocess.check_output(["git","-C",str(self.checkout),"rev-parse","HEAD"],text=True).strip()

    def test_immutable_full_program_set(self):
        data=expected(self.checkout,self.head,"final-spliced-command",{"jobs":{}},[])
        self.assertEqual(data["trial_workflow"]["sha256"],sha(self.workflow.read_bytes()))
        self.assertEqual(set(data["inputs"]),set(CORE))
        self.assertEqual(data["effective_script_sha256"],sha(b"final-spliced-command"))
        (self.checkout/CORE[1]).write_bytes(b"unexpected substitution")
        with self.assertRaisesRegex(ValueError,"Staged implementation differs"):
            expected(self.checkout,self.head,"final-spliced-command",{"jobs":{}},[])
        self.workflow.write_text("replaced")
        with self.assertRaisesRegex(ValueError,"Workflow differs"):
            expected(self.checkout,self.head,"final-spliced-command",{"jobs":{}},[])

    def test_archived_inputs_rechecked_in_receiver(self):
        ex=self.root/"exchange"; ex.mkdir()
        base=self.root/"out";base.mkdir()
        tmp=ex/"checkpoint"; tmp.mkdir()
        hashes={}
        for n in LEGACY:
            raw=("frozen "+n).encode()
            (ex/n).write_bytes(raw);hashes[n]=sha(raw)
        for name in CORE[:4]:
            (ex/Path(name).name).write_bytes(self.actual[name])
        data={"format":FORMAT,"source_revision":self.head,"legacy_ci":hashes,"graph_format":"bare-28-apk-frontier-2",
              "inputs":{k:sha(v) for k,v in self.actual.items()}}
        (ex/"trial-inputs.json").write_bytes(encoded(data))
        (base/"checkpoint-round28-graph.json").write_bytes(encoded({"format":data["graph_format"]}))
        ident={"ci_revision":self.head}
        (base/"checkpoint-provenance.json").write_bytes(encoded({"identity":ident,"identity_sha256":sha(encoded(ident).rstrip())}))
        with patch.dict(os.environ, TRIAL_SHA=self.head), patch("trial_provenance.LEGACY",hashes):
            finish(base,ex,"produce")
            self.assertEqual({p.name for p in tmp.iterdir()},EXPORTS)
            self.assertEqual((tmp/"trial-provenance-sha.txt").read_text().strip(),sha((base/FILE).read_bytes()))
            for path in tmp.iterdir():path.unlink()
            finish(base,ex,"receive")
            for path in tmp.iterdir():path.unlink()
            bad=json.loads((base/FILE).read_bytes());bad["child_identity"]="0"*64;(base/FILE).write_bytes(encoded(bad))
            with self.assertRaisesRegex(ValueError,"Archived trial provenance differs"):
                finish(base,ex,"receive")
            self.assertEqual(list(tmp.iterdir()),[])
        with self.assertRaises(ValueError):export(tmp/"unapproved",b"test")
        (tmp/"graph-sha.txt").symlink_to(base/"checkpoint-provenance.json")
        with self.assertRaises(FileExistsError):export(tmp/"graph-sha.txt",b"test")


if __name__=="__main__":
    unittest.main()
