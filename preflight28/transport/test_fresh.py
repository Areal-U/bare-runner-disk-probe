"""Exercise the split ordinary/writer handoff with real CMS, real zstd, and a local receiver."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import fresh as f


def raw(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":")).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


class FreshTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.top=Path(self.tmp.name)
        self.src=self.top/"src"
        self.dst=self.top/"dst"
        self.project=self.top/"project"
        (self.project/f.WORKFLOW).parent.mkdir(parents=True)
        (self.project/f.WORKFLOW).write_text("name: test\n")
        self.head="c"*40
        self.env=patch.dict(os.environ,GITHUB_REPOSITORY=f.b.REPO,GITHUB_RUN_ID="81",GITHUB_RUN_ATTEMPT="1",
            TRIAL_SHA=self.head,GITHUB_JOB="produce",FRESH_ARTIFACT_ID="40",R28_CAMPAIGN=f.CAMPAIGN,GITHUB_OUTPUT=str(self.top/"outputs"))
        self.env.start();self.addCleanup(self.env.stop)
        self.old={"ci_revision":f.PARENT_REV,"chromium":"123","input":"local"}
        self.new={**self.old,"ci_revision":self.head}
        self.original_identity=f.canonical(self.old)
        def apply(p):
            p.start();self.addCleanup(p.stop)
        apply(patch.object(f,"PROJECT",self.project))
        apply(patch.object(f.b,"PARENT_IDENTITY",self.original_identity))
        apply(patch.object(f.b,"disk"))
        self.job=types.SimpleNamespace(CAMPAIGN=f.CAMPAIGN,send=self.record)
        apply(patch.dict(sys.modules,exchange=self.job))
        self.commits=[]
        self.visible={"full":self.artifact("full",40)}
        self.succeeded=True
        self.audited=True
        apply(patch.object(f.b,"api_json",side_effect=self.service))
        apply(patch.object(f.b,"inventory",side_effect=lambda:list(self.visible.values())))
        for d in (self.src,self.dst):
            (d/"r28-split/incoming").mkdir(parents=True)
        self.move(self.dst)
        f.b.keygen()
        shutil.copyfile(f.b.ROOT/"public.pem",self.src/"r28-split/incoming/public.pem")

    def artifact(self,mode,i):
        return {"id":i,"size_in_bytes":12543,"expired":False,"expires_at":"tomorrow",
                "name":f.artifact_name({"full":"cipher","delta":"delta","key":"key"}[mode]),
                "workflow_run":{"id":81,"head_sha":self.head}}

    def service(self,path):
        if "/jobs?" in path:
            return {"total_count":1,"jobs":[{"name":f.PRODUCER_NAME,"status":"completed","id":631,
                            "conclusion":"success" if self.succeeded else "failure",
                            "steps":[{"name":f.AUDIT_NAME,"conclusion":"success" if self.audited else "skipped"}]}]}
        name=path.split("?name=",1)[1].split("&")[0]
        rows=[r for r in self.visible.values() if r["name"]==name]
        return {"total_count":len(rows),"artifacts":rows}

    def move(self,d):
        f.TEMP=d
        f.b.ROOT=d/"r28-split"
        os.environ["GITHUB_JOB"]="produce" if d==self.src else "send"

    def record(self):
        out=f.TEMP/"bare-official/exchange/checkpoint"
        self.commits.append(((out/"child-provenance.json").read_bytes(),(out/"graph-sha.txt").read_text().strip(),
            (out/"trial-provenance-sha.txt").read_text().strip(),f.b.digest(f.TEMP/"r28-child.tar.zst")))

    def make(self, mutation=None):
        self.move(self.src)
        def provenance(identity):
            return {"format":"bare-checkpoint-provenance","version":2,"identity":identity,
                    "identity_sha256":f.canonical(identity)}
        obj="obj/blink/new.o";data=b"newly built bytes"
        outs={obj:[len(data),digest(data)]}
        index=f.canonical(sorted(outs))
        graph=dict(format="bare-28-apk-frontier-2",target="chrome_public_apk",target_path=obj,outputs=outs,
                   graph_sha256="3"*64,parent_pending=[index,"b"*64],successor_pending=["b"*64],
                   parent_content={"files":6,"sha256":"4"*64},child_content={"files":7,"sha256":"5"*64})
        g=raw(graph)
        n=dict(format="bare-r28-trial-provenance-v1",source_revision=self.head,s2_producer_revision=f.PARENT_REV,
               s2_archive_sha256=f.b.PARENT_SHA,graph_sha256=digest(g),graph_format=graph["format"],
               child_identity=f.canonical(self.new),effective_script_sha256="e"*64,
               trial_workflow={"path":f.WORKFLOW,"sha256":f.b.digest(self.project/f.WORKFLOW)})
        members={f.CHILD:raw(provenance(self.new)),f.PARENT:raw(provenance(self.old)),f.GRAPH:g,f.TRIAL:raw(n),
                 obj:data}
        if mutation:
            mutation(members)
        out=f.TEMP/"bare-official/exchange/checkpoint";out.mkdir(parents=True)
        (out/"graph-sha.txt").write_text(digest(members[f.GRAPH])+"\n")
        (out/"trial-provenance-sha.txt").write_text(digest(members[f.TRIAL])+"\n")
        (out/"child-provenance.json").write_bytes(raw({"identity_sha256":f.canonical(self.new),"identity":{"ci_revision":self.head}}))
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name,content in members.items():
                t=tarfile.TarInfo("out/Bare/"+name);t.size=len(content)
                tar.addfile(t,io.BytesIO(content))
        plain=f.TEMP/"r28-child.tar.zst"
        plain.write_bytes(subprocess.run(["zstd","-q","-9","-T2","-c"],input=buf.getvalue(),
                          stdout=subprocess.PIPE,check=True).stdout)
        self.sha=f.b.digest(plain)
        f.seal()
        for name in (f.CIPHER,f.RECEIPT):
            shutil.copyfile(f.b.ROOT/name,self.dst/"r28-split/incoming"/name)
        self.move(self.dst)

    def test_true_split(self):
        self.make();f.send()
        self.assertEqual(self.commits[0][-1],self.sha)
        self.assertEqual(f.b.digest(f.TEMP/"r28-child.tar.zst"),self.sha)

    def test_altered_object_cannot_publish(self):
        self.make(lambda members:members.__setitem__("obj/blink/new.o",b"old or incomplete"))
        with self.assertRaisesRegex(ValueError,"Archived new object differs"):
            f.send()
        self.assertEqual(self.commits,[])

    def test_unknown_recipe_cannot_publish(self):
        self.make()
        (self.project/f.WORKFLOW).write_text("changed recipe")
        with self.assertRaisesRegex(ValueError,"bound effective trial"):
            f.send()
        self.assertEqual(self.commits,[])

    def test_cannot_publish_terminal(self):
        self.make(lambda members:members.__setitem__("apks/cHroMePUblic.apk",b"APK"))
        with self.assertRaisesRegex(ValueError,"Terminal APK"):
            f.send()
        self.assertEqual(self.commits,[])

    def simulate_reconstruction(self):
        os.environ["FRESH_MODE"]="delta"
        self.visible={"delta":self.artifact("delta",40)}
        (f.b.ROOT/"incoming"/f.CIPHER).unlink()
        for n in ("delta.cms","delta.json"):
            (f.b.ROOT/"incoming"/n).write_bytes(b"test delta reader consumed this")
        shutil.copyfile(self.src/"r28-child.tar.zst",self.dst/"r28-child.tar.zst")

    def test_full_candidate_after_delta_reader(self):
        self.make();self.simulate_reconstruction();f.send()
        self.assertEqual(self.commits[0][-1],self.sha)

    def test_changed_reconstruction_blocks_upload(self):
        self.make();self.simulate_reconstruction()
        file=self.dst/"r28-child.tar.zst"
        old=file.read_bytes();file.write_bytes(b"x"+old[1:])
        with self.assertRaisesRegex(ValueError,"Incomplete private reconstruction"):
            f.send()
        self.assertEqual(self.commits,[])

    def add_alternate(self, same):
        self.visible["delta"]=self.artifact("delta",41)
        os.environ.update(FRESH_OTHER_ID="41",FRESH_PEER_NAME=f.PRODUCER_NAME)
        other=f.b.ROOT/"alternate";other.mkdir()
        (other/f.RECEIPT).write_bytes((f.b.ROOT/"incoming"/f.RECEIPT).read_bytes() if same else b"{}")

    def test_equal_alternate_publishes_once(self):
        self.make();self.add_alternate(True);f.wait("cipher")
        outputs=(self.top/"outputs").read_text()
        self.assertIn("id=40\nmode=full\nother_id=41",outputs)
        f.send();self.assertEqual(len(self.commits),1)

    def test_mismatched_alternate(self):
        self.make();self.add_alternate(False)
        with self.assertRaisesRegex(ValueError,"alternative|alternate"):f.send()
        self.assertEqual(self.commits,[])

    def test_late_alternate(self):
        self.make();self.visible["delta"]=self.artifact("delta",41)
        with self.assertRaisesRegex(ValueError,"Late alternative"):f.send()
        self.assertEqual(self.commits,[])

    def test_original_audit_required(self):
        self.make();self.audited=False
        with self.assertRaisesRegex(ValueError,"final retained-byte audit"):f.send()
        self.assertEqual(self.commits,[])

    def test_wrong_generation(self):
        self.make();os.environ["GITHUB_RUN_ATTEMPT"]="2"
        with self.assertRaisesRegex(ValueError,"generation"):
            f.send()
        self.assertEqual(self.commits,[])

if __name__=="__main__":
    unittest.main()
