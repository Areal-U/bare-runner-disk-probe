import hashlib
import io
import json
import tarfile
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import production as p


class PrivateDocs:
    def __init__(self):
        self.files = {}
        self.rows = []
    def write(self, name, obj, owner=False):
        data = json.dumps(obj, sort_keys=True).encode()
        i = len(self.rows) + 1
        row = dict(id=i, name=name, digest="sha256:"+hashlib.sha256(data).hexdigest(),
                   size=len(data), state="uploaded", uploader=p.OWNER if owner else {})
        self.rows.append(row)
        self.files[i] = data
        return row
    def download(self, i, size, digest, output):
        output.write(self.files[i])


class Production(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.head = "a"*40
        self.data = b"age-encryption.org/v1\nunit-test; inert"
        self.seal = dict(schema=p.apk_seal.SCHEMA, run=9, attempt=1, ordinal=1, producer_sha=self.head,
                         accepted_parent=p.S2_SHA, recipient=p.apk_seal.RECIPIENT,
                         sha=hashlib.sha256(self.data).hexdigest(), bytes=len(self.data))

    def test_ordinary_meta_inf_is_part_of_signed_payload(self):
        receipt = {"signer_sha256": "a" * 64}
        owner = {"final_certificate_sha256": "b" * 64}
        original, alternate = self.path / "original.apk", self.path / "alternate.apk"
        for path, data in ((original, b"one"), (alternate, b"two")):
            with ZipFile(path, "w") as archive:
                archive.writestr("META-INF/MANIFEST.MF", b"ordinary application manifest")
                archive.writestr("META-INF/service-provider", data)
        receipt.update(bytes=original.stat().st_size, sha256=p.digest(original))
        with patch.object(p, "verify_signer"):
            self.assertEqual(p.compare_signing_payload(original, receipt, original, owner, None)["matched_entries"], 2)
            with self.assertRaisesRegex(ValueError, "APK entry bytes changed: META-INF/service-provider"):
                p.compare_signing_payload(original, receipt, alternate, owner, None)

    def test_jar_signature_exception_rejects_ambiguous_or_custom_manifest(self):
        for block, manifest, reason in (
            ("SECOND.RSA", b"Manifest-Version: 1.0", "Unexpected JAR signer"),
            ("FIRST.RSA", b"Manifest-Version: 1.0\nCustom: app data", "outside the signing-only format"),
        ):
            with self.subTest(reason=reason):
                path = self.path / "jar-envelope.apk"
                with ZipFile(path, "w") as archive:
                    for name, content in (("FIRST.SF", b"fixture"), (block, b"fixture"), ("MANIFEST.MF", manifest)):
                        archive.writestr("META-INF/" + name, content)
                with ZipFile(path) as archive, self.assertRaisesRegex(ValueError, reason):
                    p.signing_entries(archive, "a" * 64, None)

    def test_archive_and_exclusive_idempotent_retrieval(self):
        with ZipFile(self.path/"a.zip", "w") as z:
            z.writestr("seal.json", json.dumps(self.seal))
            z.writestr(p.apk_seal.CIPHER_FILE, self.data)
        z = self.path/"a.zip"
        row = dict(size_in_bytes=z.stat().st_size,digest="sha256:"+p.digest(z))
        out = self.path/"a.age"
        binding = dict(run=9,ordinal=1,head=self.head,parent=p.S2_SHA)
        self.assertEqual(p.unwrap(z,row,out,**binding),self.seal)
        final = self.path/"delivered.age"
        p.install(out, final)
        p.install(out, final)
        bad = self.path/"bad"
        bad.write_bytes(b"different")
        with self.assertRaises(ValueError): p.install(bad,final)
        with self.assertRaises(ValueError): p.unwrap(z,row,self.path/"2",**{**binding,"run":10})
        with self.assertRaises(ValueError): p.unwrap(z,{**row,"digest":"sha256:"+"b"*64},self.path/"3",**binding)
        with ZipFile(z, "a") as archive: archive.writestr("extra", b"unexpected")
        with self.assertRaises(ValueError):
            p.unwrap(z,dict(size_in_bytes=z.stat().st_size,digest="sha256:"+p.digest(z)),self.path/"4",**binding)

    def test_original_and_single_admitted_replacement_discovered_without_run_id(self):
        api = PrivateDocs()
        common = dict(schema=1,campaign=p.CAMPAIGN,repository_id=p.REPO_ID,workflow=p.WORKFLOW,branch=p.BASE_REF,
                      head=self.head,recipient=p.apk_seal.RECIPIENT,release_id=p.RELEASE_ID)
        service="Automation_"+"b"*32
        ticket = dict(**common,initial_parent=p.S2_SHA,owner_destination_id="owner-private-file",collector_registration_id=service)
        t=api.write(p.TICKET_NAME,ticket,owner=True)
        locator=dict(ticket_asset_id=t["id"],ticket_sha=t["digest"][7:],head=self.head,registration_id=service,owner_destination_id=ticket["owner_destination_id"])
        g=api.write(p.CLAIM,dict(**common,initial_parent=p.S2_SHA,run_id=9,producer_attempt=1,registration_id=service,ticket_asset_id=t["id"],ticket_sha=t["digest"][7:]))
        self.assertEqual(p.bind(api,api.rows,locator)[:3],(9,9,g["id"]))
        key=dict(origin_run=9,ordinal=2,original_claim_id=g["id"],owner_destination_id=locator["owner_destination_id"])
        evidence=api.write(p.CAMPAIGN+"-loss-evidence-9.json",dict(**common,**key,parent_sha="c"*64,owner_copy="confirmed-absent",
                           pending_writes=0,state="ledger-closed-no-durable-output",collector_registration_id=service),owner=True)
        evidence_ids=dict(evidence_asset_id=evidence["id"],evidence_sha=evidence["digest"][7:])
        l=api.write(p.CAMPAIGN+"-loss-9.json",dict(**common,**key,**evidence_ids,state="original-operation-closed-no-durable-output",collector_registration_id=service),owner=True)
        r=api.write(p.REPLACEMENT,dict(**common,**key,**evidence_ids,run_id=12,producer_attempt=1,registration_id=service,ticket_asset_id=l["id"],ticket_sha=l["digest"][7:],
                    initial_parent="c"*64,parent_sha="c"*64,parent_identity="d"*64))
        self.assertEqual(p.bind(api,api.rows,locator)[:3],(9,12,r["id"]))
        with self.assertRaises(ValueError): p.bind(api,api.rows,{**locator,"owner_destination_id":"operator-only"})
        with self.assertRaises(ValueError): p.bind(api,api.rows+[dict(r,id=98)],locator)
        api.files[evidence["id"]]=b"{}"
        with self.assertRaises(ValueError): p.bind(api,api.rows,locator)

    def test_numbered_draft_only_delivery_with_no_cache_or_artifact_left(self):
        start="2026-11-25T00:00:00Z"
        end="2026-11-25T00:10:00Z"
        job=dict(name="Bounded build segment 1 / "+p.DRAFT_JOB,id=30,run_id=9,run_attempt=1,head_sha=self.head,
                 conclusion="success",status="completed",completed_at=end,
                 steps=[dict(name=p.DRAFT_STEP,conclusion="success",started_at=start,completed_at=end)])
        row=dict(name="r28-9-a1-s01"+p.RECEIPT_SUFFIX,id=24,digest="sha256:"+"a"*64,state="uploaded",created_at=end)
        n,parent,outcome,artifact,private=p.decide([job],[],[row],[],9,self.head,p.recover.ChainStart())
        self.assertEqual((n,parent,artifact,private["id"]),(1,p.S2_SHA,None,24))
        p.private_depositor({"depositor_run":9}, row, [job], 9,self.head,1)
        with self.assertRaises(ValueError): p.private_depositor({"depositor_run":9}, row, [dict(job,run_attempt=2)],9,self.head,1)
        run=dict(id=12,run_attempt=1,path=p.WORKFLOW,head_sha=self.head,event="workflow_dispatch",head_branch=p.BASE_REF,
                 repository=dict(id=p.REPO_ID),head_repository=dict(id=p.REPO_ID),actor=p.OWNER)
        rescue=dict(job,name="Transfer the original cached ciphertext to its registered owner",run_id=12,
                    steps=[*job["steps"],dict(name="Bind the exact original cache to its registered owner",conclusion="success")])
        with patch.object(p.recover,"get",return_value=json.dumps(run)),patch.object(p.recover,"inventory",return_value=[rescue]):
            p.private_depositor({"depositor_run":12},row,[],9,self.head,1)
            with self.assertRaises(ValueError): p.private_depositor({"depositor_run":13},row,[],9,self.head,1)
        with self.assertRaises(ValueError): p.decide([job],[],[row,dict(row,name=row["name"]+"-retry1",id=25)],[],9,self.head,p.recover.ChainStart())

    def test_clear_bound_to_accepted_revision_and_CI_bytes(self):
        app=b"stand-in for functional code-signing tests"
        meta=dict(apk="ChromePublic.apk",package="org.barebrowser.personal",version_name="2.0.4",
                  version_code="802000415",abi="arm64-v8a",signer_sha256=p.CI_CERT,
                  embedded_ublock_origin_sha256=p.UBO_SHA,bare_revision=p.BARE_REV,chromium_revision=p.CHROMIUM_REV,
                  ci_revision=self.head,bytes=len(app),sha256=hashlib.sha256(app).hexdigest())
        tar=self.path/"decrypted.tar"
        with tarfile.open(tar,"w") as t:
            for name,data in (("ChromePublic.apk",app),("apk-metadata.json",json.dumps(meta).encode())):
                m=tarfile.TarInfo(name); m.size=len(data); t.addfile(m,io.BytesIO(data))
        pickup=dict(campaign=p.CAMPAIGN,source_run=9,seal=self.seal)
        with patch.object(p,"verify_application") as content, patch.object(p,"verify_signer") as verify:
            self.assertEqual(p.clear_bundle(tar,pickup,self.path/"owned","aapt","jar"),meta)
            self.assertEqual(verify.call_args.args[1],p.CI_CERT)
            self.assertEqual(content.call_count,1)
            with self.assertRaises(ValueError):
                p.clear_bundle(tar,dict(pickup,seal=dict(self.seal,producer_sha="b"*40)),self.path/"wrong","aapt","jar")
        with tarfile.open(tar,"a") as t:
            t.addfile(tarfile.TarInfo("unexpected"))
        with self.assertRaises(ValueError): p.clear_bundle(tar,pickup,self.path/"other","aapt","jar")

    def test_final_owner_access_cert_version(self):
        f=self.path/"apk"; f.write_bytes(b"test signed content")
        cert="c"*64
        ticket=dict(owner_destination_id="fixed",final_certificate_sha256=cert,account_id="personal",reserved_version=1,final_path="/owner/app.apk")
        item=dict(library_file_id="fixed",surface="library",kind="file",version_id="2",file_id="file-2",path=ticket["final_path"],size_bytes=f.stat().st_size)
        publication=dict(library_file_id="fixed",certificate_sha256=cert,file_id="file-2",version=2,signed_sha256=p.digest(f))
        with patch.object(p.subprocess,"check_output",return_value="Number of signers: 1\nSigner #1 certificate SHA-256 digest: "+cert+"\n"):
            self.assertEqual(p.owner_check(ticket,{"surface":"library","items":[item]},publication,f,"kit.jar")["state"],"delivered")
            for wrong in (dict(item,is_shared=True),dict(item,version_id=1),dict(item,library_file_id="operator-only-id")):
                with self.assertRaises(ValueError): p.owner_check(ticket,{"surface":"library","items":[wrong]},publication,f,"kit.jar")
            with self.assertRaises(ValueError): p.owner_check(ticket,{"surface":"library","items":[item]},dict(publication,signed_sha256="f"*64),f,"kit.jar")

if __name__ == "__main__":
    unittest.main()
