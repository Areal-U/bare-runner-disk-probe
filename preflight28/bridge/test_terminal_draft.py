import hashlib
import json
import os
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

os.environ.setdefault("RUNNER_TEMP", "/tmp")
import terminal_draft as d


class Draft:
    def __init__(self):
        self.assets = {}
        self.data = {}
    def inventory(self, _):
        return {"assets": list(self.assets.values())}
    def put(self, suffix, file, offset, length, digest, *, origin_prefix=None):
        name = (origin_prefix or d.normal.stem())+"-"+suffix
        file.seek(offset)
        data = file.read(length)
        self.data.setdefault(name, data)
        if self.data[name] != data or digest != hashlib.sha256(data).hexdigest():
            raise ValueError("conflicting immutable asset")
        row = self.assets.setdefault(name, {"id":len(self.assets)+1, "name":name, "state":"uploaded","size":length,"digest":"sha256:"+digest})
        return dict(id=row["id"],name=name,bytes=length,sha256=digest)
    def download(self, i, length, digest, dest):
        name, = [n for n, r in self.assets.items() if r["id"] == i]
        data = self.data[name]
        if len(data) != length or hashlib.sha256(data).hexdigest() != digest: raise ValueError("bad bytes")
        if dest is not None: dest.write(data)


class TerminalDraft(unittest.TestCase):
    def test_legacy_entry_uses_legacy_keys_and_only_the_original_single_file_cache_version(self):
        import yaml
        source = Path(__file__).resolve().parents[2]/".github/workflows/bare-checkpoint-transfer.yml"
        jobs = yaml.safe_load(source.read_text())["jobs"]
        legacy=jobs["recover-encrypted-apk"]
        self.assertIn("inputs.loss_origin_run == ''",legacy["if"])
        steps=legacy["steps"]
        lookups=[s for s in steps if s.get("uses","").startswith("actions/cache/restore@")]
        self.assertEqual(len(lookups),1)
        self.assertEqual(lookups[0]["with"]["path"],"${{ runner.temp }}/bare-apk-delivery/"+d.apk_seal.CIPHER_FILE)
        verify=next(s["run"] for s in steps if s["name"]=="Check the exact encrypted APK receipt")
        for suffix,ok in (("",True),("-s2",True),("-s1",False),("-s3",False),("-s12",False),("-s13",False)):
            env=dict(os.environ,EXPECTED_KEY="bare-coexist-204-apk-v1-45285202990-1"+suffix,EXPECTED_SHA="a"*64,EXPECTED_BYTES="32")
            self.assertEqual(subprocess.run(["bash","-eu","-c",verify],env=env).returncode==0,ok)
        rescue=jobs["deliver-recovered-cached-apk"]
        current=[s for s in rescue["steps"] if s.get("uses","").startswith("actions/cache/restore@")]
        self.assertEqual(current[0]["with"]["path"],"${{ runner.temp }}/bare-apk-delivery")
        self.assertFalse(any("upload-artifact@" in s.get("uses","") for s in rescue["steps"]))

    def test_transfer_only_authorization_refuses_foreign_cache_and_existing_artifact(self):
        import sys
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"collector"))
        from contextlib import ExitStack
        from unittest.mock import Mock
        import production as owner
        class Api:
            request = staticmethod(lambda *args,**kwargs: None)
            def draft(self,_): return {"assets":[]}
        with TemporaryDirectory() as temp, ExitStack() as ss:
            head="a"*40
            env=dict(GITHUB_REPOSITORY=d.b.REPO,GITHUB_REF="refs/heads/"+owner.BASE_REF,GITHUB_EVENT_NAME="workflow_dispatch",
                     GITHUB_RUN_ATTEMPT="1",GITHUB_RUN_ID="77",GITHUB_JOB="deliver-recovered-cached-apk",
                     GITHUB_ACTOR="Areal-U",GITHUB_SHA=head,GITHUB_EVENT_PATH=temp+"/event")
            key="bare-coexist-204-apk-v1-9-1-s2"
            inputs=dict(mode="recover-encrypted-apk",loss_origin_run="9",checkpoint_key=key,checkpoint_sha="c"*64,encrypted_apk_bytes="100")
            def save():
                Path(env["GITHUB_EVENT_PATH"]).write_text(json.dumps(dict(inputs=inputs,repository={"id":owner.REPO_ID},sender=owner.OWNER)))
            save()
            def physical(path):
                run=int(path.split("/")[2])
                return json.dumps(dict(id=run,run_attempt=1,path=owner.WORKFLOW,head_sha=head,event="workflow_dispatch",head_branch=owner.BASE_REF,
                                  repository={"id":owner.REPO_ID},head_repository={"id":owner.REPO_ID},actor=owner.OWNER,status="completed" if run==9 else "in_progress"))
            ss.enter_context(patch.object(owner,"PagedOwnerDraft",lambda a:a))
            ss.enter_context(patch.object(owner,"private_row",return_value={"id":4,"digest":"sha256:"+"e"*64}))
            ss.enter_context(patch.object(owner,"private_document",return_value={"owner_destination_id":"owner","collector_registration_id":"registered"}))
            ss.enter_context(patch.object(owner,"bind",return_value=(9,9,22,d.recover.ChainStart())))
            ss.enter_context(patch.object(d.recover,"get",side_effect=physical))
            ss.enter_context(patch.object(d.recover,"inventory",return_value=[]))
            ss.enter_context(patch.object(d.recover,"slot_chain",return_value=[]))
            out=dict(status="inspect-terminal",ordinal=2,accepted_parent="d"*64,cipher_cache=key,cipher_cache_id="987",
                     cipher_id="",cipher_sha=inputs["checkpoint_sha"],cipher_bytes=100)
            ss.enter_context(patch.object(d.recover,"terminal_source",return_value=out))
            capture=ss.enter_context(patch.object(d.b,"output"))
            d.authorize_rescue(env,Api())
            self.assertEqual((capture.call_args.kwargs["source_run"],capture.call_args.kwargs["cache_id"]),(9,"987"))
            for k,bad in (("loss_origin_run","55"),("checkpoint_key",key+"-fake"),("checkpoint_sha","f"*64)):
                orig=inputs[k]; inputs[k]=bad; save()
                with self.assertRaises(ValueError): d.authorize_rescue(env,Api())
                inputs[k]=orig
            save()
            out["cipher_id"]="37"
            with self.assertRaises(ValueError): d.authorize_rescue(env,Api())
            self.assertEqual(capture.call_count,1)

    def test_checked_cache_only_and_idempotent_retry(self):
        with TemporaryDirectory() as temp:
            root=Path(temp)
            payload=b"age-encryption.org/v1\nfixture ciphertext"
            checksum=hashlib.sha256(payload).hexdigest()
            key="bare-coexist-204-apk-v1-9-1-s2"
            env=dict(GITHUB_RUN_ID="9",R28_SLOT="2",GITHUB_REPOSITORY=d.b.REPO,GITHUB_REF="refs/heads/bare-coexist-v2.0.4",
                  GITHUB_EVENT_NAME="workflow_dispatch",GITHUB_RUN_ATTEMPT="1",GITHUB_JOB="deliver-cached-apk",GITHUB_ACTOR="Areal-U",
                  R28_COLLECTION_CLAIM="5",CACHE_KEY=key,CACHE_MATCH=key,CACHE_HIT="true",GITHUB_SHA="a"*40,
                  R28_PARENT_SHA="b"*64,CIPHER_SHA=checksum,CIPHER_BYTES=str(len(payload)))
            (root/d.apk_seal.CIPHER_FILE).write_bytes(payload)
            seal_env=dict(env,SEGMENT_ORDINAL="2",APK_RECIPIENT=d.apk_seal.RECIPIENT,SEALED_SHA=checksum,SEALED_BYTES=str(len(payload)))
            self.assertEqual(d.apk_seal.write(root/"seal.json",seal_env),"r28-9-a1-s02-apk-seal")
            with self.assertRaises(FileExistsError): d.apk_seal.write(root/"seal.json",seal_env)
            with self.assertRaises(ValueError): d.apk_seal.write(root/"seal.json",dict(seal_env,GITHUB_RUN_ATTEMPT="2"))
            api=Draft()
            with patch.dict(os.environ,env), patch.object(d.normal,"list_private",api.inventory),patch.object(d.normal,"put",api.put):
                a=d.publish(root,env,api)
                self.assertEqual(d.publish(root,env,api),a)
                self.assertEqual(len(api.assets),2)
                with self.assertRaises(ValueError): d.publish(root,dict(env,CACHE_MATCH="other"),api)
                with self.assertRaises(ValueError): d.publish(root,dict(env,R28_PARENT_SHA="f"*64),api)
                with self.assertRaises(ValueError): d.publish(root,dict(env,CIPHER_BYTES="1"),api)
                rescue=dict(env,GITHUB_JOB="deliver-recovered-cached-apk",R28_SOURCE_RUN="9",GITHUB_RUN_ID="12",CACHE_ID="77")
                with patch.object(d.recover,"current_caches",return_value=[dict(key=key,ref=env["GITHUB_REF"],id=77)]):
                    with patch.dict(os.environ,rescue):
                        self.assertEqual(d.publish(root,rescue,api),a)
                        self.assertEqual(len(api.assets),2)
                        with self.assertRaises(ValueError): d.publish(root,dict(rescue,CACHE_ID="78"),api)
                api.assets["dup"]=dict(id=17,name=d.normal.stem()+"-apk.age-retry1",state="uploaded")
                with self.assertRaises(ValueError): d.publish(root,env,api)

if __name__ == "__main__":
    unittest.main()
