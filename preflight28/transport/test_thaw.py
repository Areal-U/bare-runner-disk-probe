"""Recover an already-sealed object using real OpenSSL, a historical git reader and idempotent private I/O."""
import gzip
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
from urllib.parse import parse_qs,urlsplit
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP","/tmp")
import thaw as t


def raw(data):
    return json.dumps(data,sort_keys=True,separators=(",",":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Private:
    API="api.github.com";BASE="/repos/"+t.b.REPO;UPLOAD="uploads.github.com"
    def __init__(self):
        self.assets=[];self.data={};self.writes=0;self.lost=True
    def draft(self,release):
        assert release==t.b.RELEASE
        return {"assets":self.assets}
    def asset_info(self,release,name,size,digest,id_):
        result=[a for a in release["assets"] if a["name"]==name and a["id"]==id_ and a["size"]==size
                and a["state"]=="uploaded" and a["digest"]=="sha256:"+digest]
        if len(result)!=1:raise ValueError("changed immutable evidence")
        return result[0]
    def anonymous_status(self,*args):return None
    def request(self,host,op,path,**kwargs):
        assert host==self.UPLOAD and op=="POST" and kwargs["auth"] and str(t.ORIGINAL_RUN) in path
        data=kwargs["body"].read();assert len(data)==kwargs["length"]
        name=parse_qs(urlsplit(path).query)["name"][0]
        row={"id":181+self.writes,"state":"uploaded","name":name,"size":len(data),"digest":"sha256:"+sha(data),
             "browser_download_url":"https://github.com/"+t.b.REPO+"/releases/download/private/"+name}
        assert all(r["name"]!=name for r in self.assets)
        self.writes+=1;self.assets.append(row);self.data[row["id"]]=data
        if self.lost:self.lost=False;raise ConnectionResetError("after commit")
        return io.BytesIO(),types.SimpleNamespace(status=201,read=lambda _:b"")
    def download(self,id_,size,digest,out):
        data=self.data[id_]
        assert len(data)==size and sha(data)==digest
        out.write(data)


class ThawTest(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.recover=self.root/"recover";self.recover.mkdir()
        self.src=self.root/"original";self.src.mkdir()
        self.cipher=self.root/"original-artifact";self.cipher.mkdir()
        self.keys=self.root/"writer-artifact";self.keys.mkdir()
        self.keyfile=self.root/"escrow.pem"
        self.parent=self.root/"S2.tar.gz"
        self.output=self.root/"outputs"
        def override(ctx):
            ctx.start();self.addCleanup(ctx.stop)
        override(patch.dict(os.environ,GITHUB_JOB="recover",GITHUB_RUN_ID="165",GITHUB_RUN_ATTEMPT="1",
            GITHUB_REPOSITORY=t.b.REPO,TRIAL_SHA="4"*40,PRIOR_SHA="3"*40,RUNNER_TEMP=str(self.recover),
            THAW_KEY_PEM=str(self.keyfile),THAW_SOURCE_TREE=str(self.src),THAW_CIPHER_DIR=str(self.cipher),
            THAW_KEY_ARTIFACT_DIR=str(self.keys),THAW_PARENT=str(self.parent),GITHUB_OUTPUT=str(self.output)))
        override(patch.object(t,"TEMP",self.recover))
        override(patch.object(t.b,"ROOT",self.keys));override(patch.object(t.b,"disk"))
        self.private=Private()
        override(patch.object(t,"private",return_value=self.private))
        self.gate=unittest.mock.Mock()
        override(patch.object(t,"gate",self.gate))
        for name in t.ORIGINAL_FILES:
            p=self.src/name;p.parent.mkdir(parents=True,exist_ok=True)
            if name.endswith(".yml"):p.write_text("name: test prior workflow\n")
            else:shutil.copyfile(t.PROJECT/name,p)
        def git(*cmd):
            return subprocess.check_output(["git","-C",str(self.src),*cmd],stderr=subprocess.PIPE)
        git("init","-q");git("add",".");git("-c","user.name=fixture","-c","user.email=fixture@example.invalid","commit","-qm","immutable")
        self.head=git("rev-parse","HEAD").decode().strip()
        override(patch.object(t,"ORIGINAL_HEAD",self.head))
        t.b.keygen();(self.keys/"key.pem").rename(self.keyfile);self.keyfile.chmod(0o600)
        (self.keys/"writer-key.age").write_bytes(b"fixture encrypted original disposable key")
        override(patch.object(t,"WRAP_SHA",t.b.digest(self.keys/"writer-key.age")))
        self.parent.write_bytes(gzip.compress(b"fixture physical basis"))
        original_ci="bf70ddbf474f3390a62220a076b8c43347fecc64"
        before={"ci_revision":original_ci,"input":"source"}
        after={**before,"ci_revision":self.head}
        def provenance(obj):
            return {"format":"bare-checkpoint-provenance","version":2,"identity":obj,"identity_sha256":sha(raw(obj))}
        path="obj/example.o";data=b"real local fixture bytes"
        selected={path:[len(data),sha(data)]}
        proof={"format":"bare-28-apk-frontier-2","target":"chrome_public_apk","target_path":path,"outputs":selected,
            "graph_sha256":"9"*64,"parent_pending":[sha(raw(sorted(selected))),"7"*64],"successor_pending":["7"*64],
            "parent_content":{"files":1,"sha256":"1"*64},"child_content":{"files":2,"sha256":"2"*64}}
        graph=raw(proof);ident=sha(raw(after))
        wf=".github/workflows/bare-r28-s2-recovery.yml"
        trial=raw({"format":"bare-r28-trial-provenance-v1","source_revision":self.head,"s2_producer_revision":original_ci,
            "s2_archive_sha256":t.b.PARENT_SHA,"graph_format":proof["format"],"graph_sha256":sha(graph),
            "child_identity":ident,"effective_script_sha256":"6"*64,
            "trial_workflow":{"path":wf,"sha256":t.b.digest(self.src/wf)}})
        payload={path:data,"checkpoint-provenance.json":raw(provenance(after)),
            "checkpoint-round28-parent-provenance.json":raw(provenance(before)),
            "checkpoint-round28-graph.json":graph,"checkpoint-round28-trial-provenance.json":trial}
        buf=io.BytesIO()
        with tarfile.open(fileobj=buf,mode="w") as tar:
            for n,d in payload.items():
                m=tarfile.TarInfo("out/Bare/"+n);m.size=len(d);tar.addfile(m,io.BytesIO(d))
        original=self.root/"original.zst"
        original.write_bytes(subprocess.run(["zstd","-q","-9","-c"],input=buf.getvalue(),capture_output=True,check=True).stdout)
        self.original=original.read_bytes();enc=self.cipher/"checkpoint.cms"
        t.frames.seal(self.keys/"public.pem",original,enc,sha(self.original))
        self.rec={**t.REC,"head":self.head,"parent_identity":sha(raw(before)),"identity":ident,"graph_sha":sha(graph),
              "trial_provenance_sha":sha(trial),"recipient_fpr":t.b.fingerprint(self.keys/"public.pem"),
              "sha256":sha(self.original),"bytes":len(self.original),"sealed_sha":t.b.digest(enc),"sealed_bytes":enc.stat().st_size}
        override(patch.object(t,"REC",self.rec))
        override(patch.object(t,"HISTORY",{**t.HISTORY,"source_sha":self.head,"sha256":sha(self.original),
            "bytes":len(self.original),"identity":ident,"parent_identity":self.rec["parent_identity"],
            "graph_sha":sha(graph),"trial_provenance_sha":sha(trial)}))
        (self.cipher/"cipher-receipt.json").write_bytes(raw(self.rec))

    def audited(self):
        import thaw_claim
        from test_thaw_claim import report as full_report
        check=patch.object(thaw_claim,"CHILD",self.rec["sha256"])
        check.start()
        self.addCleanup(check.stop)
        report=full_report()
        t.report_path().write_bytes(raw(report))
        t.stamp("r28-thaw-audited.json",{**t.physical(),"report_sha256":t.checked_report()})

    def test_actual_open_manifest_and_clean_read(self):
        t.open_source()
        with self.assertRaises(FileNotFoundError):t.publish()
        self.assertEqual(self.private.writes,0)
        self.audited();t.publish();t.publish()
        self.assertEqual(self.private.writes,2)
        self.assertEqual([c.args for c in self.gate.call_args_list],[("authorize",),("authorize",)])
        os.environ["GITHUB_JOB"]="issue"
        t.TEMP=self.root/"fresh-runner";t.TEMP.mkdir()
        t.receive_source()
        self.assertEqual((t.TEMP/"r28-child.tar.zst").read_bytes(),self.original)
        recovered=json.loads((t.TEMP/"r28-child.json").read_bytes())
        self.assertEqual(recovered["producer_run"],t.ORIGINAL_RUN)
        self.assertEqual(recovered["source_sha"],self.head)
        self.assertEqual(self.private.writes,2)
        self.gate.assert_called_with("verify")

    def test_existing_source_without_original_cipher_or_key(self):
        t.open_source();self.audited();t.publish()
        count=self.private.writes
        reference=self.private.assets[-1]["id"]
        old=self.recover
        t.TEMP=self.root/"new-recovery";t.TEMP.mkdir()
        os.environ["THAW_ORIGINAL_MANIFEST_ID"]=str(reference)
        self.keyfile.unlink()
        (self.cipher/"checkpoint.cms").unlink()
        with patch.object(t,"existing_permit") as allowed:
            t.existing()
            allowed.assert_called_once_with(self.private,reference)
        self.assertEqual(self.private.writes,count)
        self.assertEqual((t.TEMP/"r28-child.tar.zst").read_bytes(),self.original)
        with self.assertRaises(FileNotFoundError):t.publish()
        self.audited();t.publish()
        self.assertEqual(self.private.writes,count)

    def test_failed_audit_refuses_publication(self):
        t.open_source();self.audited()
        p=t.report_path();r=json.loads(p.read_bytes());r["counts"]["unclassified"]=1;p.write_bytes(raw(r))
        with self.assertRaisesRegex(ValueError,"[Uu]nresolved|[Ii]nvalid|[Uu]nexpected"):t.publish()
        self.assertEqual(self.private.writes,0)

    def test_conflicting_completed_part_rejected(self):
        t.open_source();self.audited();t.publish()
        self.private.assets[0]["digest"]="sha256:"+"9"*64
        with self.assertRaisesRegex(ValueError,"changed"):t.publish()
        self.assertEqual(self.private.writes,2)

    def test_tamper(self):
        p=self.cipher/"cipher-receipt.json";d=json.loads(p.read_bytes());d["run"]+=1;p.write_bytes(raw(d))
        with self.assertRaisesRegex(ValueError,"original source receipt"):t.open_source()
        self.assertFalse((t.TEMP/"r28-child.tar.zst").exists())

    def test_key_and_role(self):
        self.keyfile.chmod(0o644)
        with self.assertRaisesRegex(ValueError,"key file permissions"):t.open_source()
        os.environ["GITHUB_RUN_ATTEMPT"]="2"
        with self.assertRaisesRegex(ValueError,"role"):t.open_source()

if __name__=="__main__":unittest.main()
