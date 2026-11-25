"""Exercise offline recovery after both contributing Actions runners are gone."""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

os.environ.setdefault("RUNNER_TEMP", "/tmp")
import bridge
import normal
import owner_recovery


ARTIFACT = 77881
CLAIM = 72410
RUN = 97001
HEAD = "c" * 40
VALIDATION_ERRORS = (ValueError, subprocess.CalledProcessError, FileExistsError)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def generate_identity(path):
    subprocess.run(["age-keygen", "-o", str(path)], check=True, capture_output=True)
    return subprocess.check_output(["age-keygen", "-y", str(path)], text=True).strip()


def checkpoint_archive(folder):
    """Build a bounded private tar carrying the real validator's provenance, descriptor and proof."""
    ckfile = Path(normal.__file__).resolve().parents[2] / "checkpoint.py"
    spec = importlib.util.spec_from_file_location("checkpoint_fixture_validator", ckfile)
    checkpoint = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checkpoint)
    build = folder / "out/Bare"
    (build / "apks").mkdir(parents=True)
    (build / "apks/Trichrome.ssargs").write_text("--fixture\n")
    (build / "build.ninja.d").write_text("build.ninja.stamp: apks/Trichrome.ssargs ../../DEPS\n")
    marker = os.urandom(1024)
    (build / "current.o").write_bytes(marker)
    identity = {"ci_revision": HEAD}
    ih = checkpoint.canonical_hash(identity)
    provenance = {"format": checkpoint.PROVENANCE_FORMAT, "version": checkpoint.CHECKPOINT_VERSION,
                  "identity": identity, "identity_sha256": ih}
    (build / "checkpoint-provenance.json").write_text(json.dumps(provenance))
    proof = {"format": "bare-apk-segment-frontier-v2", "target": "chrome_public_apk",
             "parent_sha256": normal.PARENT["sha"], "before": ["1" * 64, "2" * 64],
             "after": ["2" * 64], "witnesses": [{"current.o": [len(marker), sha(marker)]}]}
    graph = build / "checkpoint-segment-frontier.json"
    graph.write_text(json.dumps(proof))
    archive = folder / "new.tar.zst"
    subprocess.run(["tar", "--zstd", "-C", str(folder), "-cf", str(archive), "out/Bare"], check=True)
    return archive, ih, sha(graph.read_bytes()), marker


class OwnerRecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.stack = ExitStack()
        cls.addClassCleanup(cls.stack.close)
        cls.work = Path(cls.stack.enter_context(tempfile.TemporaryDirectory()))
        cls.good_key, cls.other_key = cls.work / "test.agekey", cls.work / "other.agekey"
        recipient = generate_identity(cls.good_key)
        generate_identity(cls.other_key)
        cls.stack.enter_context(patch.object(owner_recovery, "RECIPIENT", recipient))
        cls.stack.enter_context(patch.dict(os.environ, GITHUB_JOB="draft-publisher",
            GITHUB_REPOSITORY=bridge.REPO, GITHUB_RUN_ID=str(RUN), GITHUB_RUN_ATTEMPT="1",
            R28_HEAD_SHA=HEAD, R28_PARENT_SHA=normal.PARENT["sha"], R28_SLOT="1",
            R28_PARENT_IDENTITY=normal.PARENT["identity"], R28_OWNER_RECIPIENT=recipient,
            R28_COLLECTION_CLAIM=str(CLAIM)))
        builder, writer = cls.work / "compiler", cls.work / "limited"
        writer.mkdir(mode=0o700)
        builder.mkdir(mode=0o700)
        with patch.object(bridge, "ROOT", writer):
            bridge.keygen()
            context = normal.context()
            wrapped = owner_recovery.wrap(writer, context, recipient, CLAIM)
            cls.foreign_wrapper = owner_recovery.wrap(
                writer, dict(context, run=RUN+1, key=f"bare-coexist-204-{RUN+1}-1-checkpoint-production-s1"),
                recipient, CLAIM)
            cls.private_pem = (writer / "key.pem").read_bytes()
            shutil.copyfile(writer / "public.pem", builder / "writer.pem")
        archive, ih, proof_sha, cls.marker = checkpoint_archive(builder)
        cls.checkpoint_bytes = archive.read_bytes()
        (builder / "input.json").write_text(json.dumps({**context, "owner_recovery": wrapped}))
        with patch.object(bridge, "ROOT", builder), patch.object(normal, "ROOT", builder), patch.object(bridge, "disk"):
            normal.seal(archive, ih, proof_sha)
        cls.record = json.loads((builder / "outcome.json").read_bytes())
        cls.cipher = (builder / "checkpoint.cms").read_bytes()
        cls.original_zip, cls.receipt = cls.make_zip("original", cls.record)
        shutil.rmtree(builder)
        shutil.rmtree(writer)

    @classmethod
    def make_zip(cls, name, record, cipher=None):
        file = cls.work / (name + ".zip")
        with zipfile.ZipFile(file, "w", compression=zipfile.ZIP_STORED) as z:
            z.writestr("outcome.json", json.dumps(record))
            z.writestr("checkpoint.cms", cls.cipher if cipher is None else cipher)
        expires = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        service_row = {
            "name": f"r28-{RUN}-a1-s01-outcome", "expired": False, "expires_at": expires,
            "id": ARTIFACT, "digest": "sha256:" + sha(file.read_bytes()), "size_in_bytes": file.stat().st_size,
            "workflow_run": {"id": RUN, "head_sha": HEAD},
        }
        receipt = owner_recovery.service_record(service_row, RUN, 1, HEAD, normal.PARENT["sha"], CLAIM,
                                                expect_id=ARTIFACT)
        return file, receipt

    def recover(self, dest, *, archive=None, receipt=None, key=None, **overrides):
        bound = dict(artifact_id=ARTIFACT, run=RUN, ordinal=1, head=HEAD,
                     parent_sha=normal.PARENT["sha"], claim_id=CLAIM)
        owner_recovery.open_saved(archive or self.original_zip, receipt or self.receipt,
                                  key or self.good_key, dest, **{**bound, **overrides})

    def test_only_ciphertext_and_checked_idempotent_recovery(self):
        with zipfile.ZipFile(self.original_zip) as z:
            self.assertEqual(set(z.namelist()), {"outcome.json", "checkpoint.cms"})
            upload = z.read("outcome.json") + z.read("checkpoint.cms")
        self.assertNotIn(self.private_pem, upload)
        self.assertNotIn(b"PRIVATE KEY-----", upload)
        self.assertNotIn(b"AGE-SECRET-KEY-", upload)
        self.assertNotIn(self.marker, upload)
        self.assertIn("owner_recovery", self.record)
        dest = self.work / "verified.tar.zst"
        self.recover(dest)
        before = dest.stat()
        self.assertEqual(dest.read_bytes(), self.checkpoint_bytes)
        self.recover(dest)
        after = dest.stat()
        self.assertEqual((before.st_ino, before.st_mtime_ns), (after.st_ino, after.st_mtime_ns))

    def test_wrong_owner_cannot_open(self):
        dest = self.work / "wrong-owner.zst"
        with self.assertRaises(VALIDATION_ERRORS):
            self.recover(dest, key=self.other_key)
        self.assertFalse(dest.exists())

    def test_other_service_identity_or_generation_cannot_open(self):
        for key, value in {"artifact_id": ARTIFACT+1, "run": RUN+1, "ordinal": 2,
                           "head": "9"*40, "claim_id": CLAIM+1, "parent_sha": "e"*64}.items():
            with self.subTest(key=key):
                dest = self.work / ("bad-" + key)
                with self.assertRaises(VALIDATION_ERRORS):
                    self.recover(dest, **{key: value})
                self.assertFalse(dest.exists())
        for key,value in {"zip_sha256": "e"*64, "name": f"r28-{RUN}-a1-s02-outcome"}.items():
            with self.subTest(receipt=key):
                dest = self.work / ("bad-receipt-" + key)
                with self.assertRaises(VALIDATION_ERRORS):
                    self.recover(dest, receipt={**self.receipt, key:value})
                self.assertFalse(dest.exists())

    def test_genuine_wrapper_from_another_run_cannot_be_mixed(self):
        # Relabel the public wrapper to look like the current generation while retaining
        # the genuine age ciphertext, fingerprint, and digest from the other run.
        inner_mismatch = {**self.record["owner_recovery"],
                          "age": self.foreign_wrapper["age"], "sha256": self.foreign_wrapper["sha256"]}
        for label, wrapper in (("mixed", self.foreign_wrapper), ("relabeled", inner_mismatch)):
            with self.subTest(label=label):
                file, receipt = self.make_zip(label, {**self.record, "owner_recovery": wrapper})
                dest = self.work / (label + ".tar.zst")
                with self.assertRaises(VALIDATION_ERRORS):
                    self.recover(dest, archive=file, receipt=receipt)
                self.assertFalse(dest.exists())

    def test_tampered_payload_and_archive_proof_cannot_be_released(self):
        for label, record, cipher in (
            ("cipher", self.record, self.cipher[:-1] + bytes([self.cipher[-1] ^ 1])),
            ("proof", {**self.record, "proof_sha": "3"*64}, self.cipher),
        ):
            with self.subTest(label=label):
                file, receipt = self.make_zip("bad-payload-" + label, record, cipher)
                dest = self.work / ("bad-payload-" + label + ".tar.zst")
                with self.assertRaises(VALIDATION_ERRORS):
                    self.recover(dest, archive=file, receipt=receipt)
                self.assertFalse(dest.exists())

    def test_existing_conflicting_file_never_replaced(self):
        dest = self.work / "existing.tar.zst"
        dest.write_bytes(b"existing unrelated private file")
        with self.assertRaises(VALIDATION_ERRORS):
            self.recover(dest)
        self.assertEqual(dest.read_bytes(), b"existing unrelated private file")


if __name__ == "__main__":
    unittest.main()
