"""Exercise private release alias matching with synthetic tag names and the original claim bytes."""
import contextlib
import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT=Path(__file__).resolve().parents[2]
OLD="test-original-release-alias"
NEW="test-rotated-release-alias"


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m);return m


class AliasTests(unittest.TestCase):
    def setUp(self):
        self.stack=contextlib.ExitStack();self.addCleanup(self.stack.close)
        work=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        env=dict(os.environ,RUNNER_TEMP=str(work),GITHUB_WORKSPACE=str(ROOT))
        subprocess.run([sys.executable,str(ROOT/"preflight28/transport/prepare.py"),"tools"],env=env,
                       check=True,capture_output=True)
        self.stack.enter_context(patch.object(sys,"path",[str(work),*sys.path]))
        self.anchor=load("r28_verified_draft",work/"r28_verified_draft.py")
        self.stack.enter_context(patch.dict(sys.modules,r28_verified_draft=self.anchor))
        self.helper=load("transfer",work/"transfer.py")
        self.stack.enter_context(patch.object(self.helper,"DRAFT_TAG_SHA256",hashlib.sha256(OLD.encode()).hexdigest()))
        self.stack.enter_context(patch.object(self.anchor,"TAG_SHA",hashlib.sha256(NEW.encode()).hexdigest()))
        h=self.helper
        self.claim_bytes={ident:(Path(__file__).with_name("fixtures")/f"claim-{ident}.json").read_bytes()
                          for _,ident,_,_ in self.anchor.CLAIMS}
        owner=dict(id=h.OWNER_ID,login=h.OWNER)
        def asset(name,aid,size,sha):
            return dict(name=name,id=aid,size=size,state="uploaded",digest="sha256:"+sha,uploader=owner)
        self.assets=[asset(h.SAMPLE,769833795,h.PROBE_BYTES,h.PROBE_SHA),asset("checkpoint-25-s2.tar.gz",770240309,2042700560,
                    "dd2177a80c72db7d0d6b558bec1fbd2c0acf448b28144d02dd26796104315413"),*(asset(*c) for c in self.anchor.CLAIMS)]
        self.release=dict(name=h.DRAFT_TITLE,id=h.RELEASE_ID,draft=True,published_at=None,author=owner,
                          target_commitish="main",assets=self.assets)
        def metadata(path):
            if path.endswith("/"+str(h.RELEASE_ID)):return self.release
            if path.endswith("/assets?per_page=100&page=1"):return self.assets
            raise AssertionError(path)
        self.stack.enter_context(patch.object(h,"metadata",side_effect=metadata))
        self.get=self.stack.enter_context(patch.object(h,"download",side_effect=lambda aid,n,d,dest:dest.write(self.claim_bytes[aid])))
        self.lookup=lambda:h.draft(h.RELEASE_ID)
    def url(self,tag):
        self.release.update(tag_name=tag,html_url="https://github.com/"+self.helper.REPO+"/releases/tag/"+tag)

    def test_both_aliases_require_original_private_anchors_and_exact_bytes(self):
        self.url(OLD);self.lookup();self.get.assert_not_called()
        self.url(NEW);self.lookup();self.assertEqual(self.get.call_count,2)
        self.release["tag_name"]="";self.lookup();self.assertEqual(self.get.call_count,2)
        self.release["assets"]=self.assets[:2];self.lookup()
        self.assets[-1]["digest"]="sha256:"+"1"*64
        with self.assertRaises(self.helper.Invalid):self.lookup()
    def test_wrong_bytes_id_delete_moved_title_retarget_publication_owner_or_unobserved_url(self):
        self.url(NEW)
        original=self.claim_bytes[self.anchor.CLAIMS[0][1]]
        self.claim_bytes[self.anchor.CLAIMS[0][1]]=b"other"
        with self.assertRaises(ValueError):self.lookup()
        self.claim_bytes[self.anchor.CLAIMS[0][1]]=original
        invalid=[dict(tag_name="other"),dict(html_url="https://github.com/other"),
                 dict(name="other"),dict(target_commitish="somewhere"),dict(author={"id":1,"login":"Areal-U"}),
                 dict(draft=False),dict(published_at="2026-11-25"),dict(id=self.helper.RELEASE_ID+1)]
        for override in invalid:
            with self.subTest(override=override),patch.dict(self.release,override),self.assertRaises((ValueError,self.helper.Invalid)):
                self.lookup()
        with patch.dict(self.assets[0],id=67),self.assertRaises(self.helper.Invalid):self.lookup()
        with patch.dict(self.assets[-1],id=78),self.assertRaises(self.helper.Invalid):self.lookup()


if __name__=="__main__":unittest.main()
