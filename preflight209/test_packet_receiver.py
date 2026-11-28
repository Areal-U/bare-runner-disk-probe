"""Private staging and existing final acceptance with small physical CMS bytes and a local service double."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import unittest
from unittest.mock import patch

import test_outcome_transport as original
import packet_receiver as receiver


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Service:
    """Represent the remote cache service, separate from both local transfer directories."""
    def __init__(self, root, outcome, sealed, packet_bytes):
        self.root, self.outcome, self.cap = root, outcome, packet_bytes
        self.rows, self.blobs, self.deleted, self.acks = {}, {}, [], []
        self.count = max(1, (len(sealed) + self.cap - 1) // self.cap)
        for kind in ("packet", "receipt"):
            self.folder(kind).mkdir()
        for index in range(self.count):
            chunk = sealed[index*self.cap:(index+1)*self.cap]
            piece = dict(schema="test-piece", claim=97, index=index, count=self.count,
                         bytes=len(chunk), sha256=sha(chunk), offset=index*self.cap, outcome=outcome)
            k = self.key(index)
            self.blobs[k] = {"piece.json": receiver.raw(piece), "piece.sig": b"test-signature", "piece.bin": chunk}
            self.rows[k] = self.row(k, index+1)

    def folder(self, kind):
        return self.root / kind

    def key(self, i, kind="packet"):
        return f"fixture-{kind}-{i}"

    def row(self, key, id_):
        return dict(id=id_, key=key, ref=os.environ["GITHUB_REF"], version="a"*64, size_in_bytes=300)

    def exact(self, key, deadline):
        return self.rows.get(key)

    def restore(self, kind, index, row, deadline):
        key = self.key(index, kind)
        assert self.rows[key] == row
        for name, content in self.blobs[key].items():
            (self.folder(kind)/name).write_bytes(content)

    def read_piece(self, i):
        piece = json.loads((self.folder("packet")/"piece.json").read_bytes())
        data = (self.folder("packet")/"piece.bin").read_bytes()
        if sha(data) != piece["sha256"]:
            raise ValueError("damaged transport")
        return piece

    def make_receipt(self, piece, row, stage):
        (self.folder("receipt")/"receipt.json").write_bytes(receiver.raw(dict(index=piece["index"], id=row["id"],
                                                                            asset=stage)))
        (self.folder("receipt")/"receipt.sig").write_bytes(b"signed-test-receipt")

    def save(self, kind, index, deadline, size):
        assert kind == "receipt"
        k = self.key(index, kind)
        if k not in self.rows:
            self.rows[k] = self.row(k, 1000+index)
            self.blobs[k] = {f.name:f.read_bytes() for f in self.folder(kind).iterdir()}
        self.acks.append(index)
        return self.rows[k]

    def delete(self, api, i, saved, deadline):
        key = self.key(i)
        if key in self.rows:
            assert self.rows[key] == saved
            del self.rows[key]
            self.deleted.append(i)


class Receive(unittest.TestCase):
    setUp = original.OutcomeTransport.setUp
    command = original.OutcomeTransport.command
    make_candidate = original.OutcomeTransport.make_candidate

    def wire(self, outcome, sealed, *, cap, draft):
        svc = Service(self.tmp, outcome, sealed, cap)
        for method in ("key", "exact", "restore", "read_piece", "make_receipt", "save", "folder"):
            self.enterContext(patch.object(receiver.packets, method, getattr(svc, method)))
        self.enterContext(patch.object(receiver.packets, "PACKET_BYTES", cap))
        self.enterContext(patch.object(receiver.packets, "archive_bound", lambda n:n+2*1024**2))
        self.enterContext(patch.dict(os.environ, GITHUB_JOB="draft-publisher"))
        self.enterContext(patch.object(receiver.packets, "before_delete"))
        self.enterContext(patch.object(receiver, "delete_exact", svc.delete))
        self.enterContext(patch.object(original.bridge, "auth_api", return_value=draft))
        return svc

    def control(self, status="no-progress"):
        out = dict(original.normal.context(), status=status)
        (self.normal / "input.json").write_text(json.dumps(dict(original.normal.context(),
             **original.normal.sender_times(int(time.time()), 23))))
        draft = original.LocalDraft()
        return out, draft, self.wire(out, b"", cap=32, draft=draft)

    def test_control_and_immutable_recovery_after_delete(self):
        out, draft, svc = self.control()
        self.assertTrue(receiver.Receiver().poll())
        self.assertEqual(svc.deleted, [0])
        self.assertEqual(json.loads((self.normal/"incoming"/"outcome.json").read_bytes()),out)
        (self.normal/"incoming"/"outcome.json").unlink()
        self.assertTrue(receiver.Receiver().poll())
        self.assertEqual(svc.deleted, [0])
        original.normal.publish()
        self.assertIn("checkpoint_advanced=false", self.outputs.read_text())

    def test_foreign_run_retains_cache_and_does_not_ack(self):
        out, draft, svc = self.control()
        blob = svc.blobs[svc.key(0)]
        piece = json.loads(blob["piece.json"])
        piece["outcome"]["run"] += 1
        blob["piece.json"] = receiver.raw(piece)
        with self.assertRaisesRegex(ValueError, "Foreign packet outcome"):
            receiver.Receiver().poll()
        self.assertEqual((svc.deleted, svc.acks, draft.assets), ([], [], []))

    def test_missing_piece_and_negative_private_readback_do_not_ack(self):
        out, draft, svc = self.control()
        key, row = svc.key(0), svc.rows.pop(svc.key(0))
        obj = receiver.Receiver()
        self.assertFalse(obj.poll())
        svc.rows[key] = row
        with patch.object(draft,"download",side_effect=ValueError("bad private bytes")):
            with self.assertRaisesRegex(ValueError, "bad private bytes"):
                obj.poll()
        self.assertEqual((svc.deleted, svc.acks), ([], []))

    def test_wrong_existing_ack_prevents_cleanup(self):
        out, draft, svc = self.control()
        key=svc.key(0, "receipt")
        svc.rows[key] = svc.row(key, 900)
        svc.blobs[key] = {"receipt.json":b"{}", "receipt.sig":b"foreign ack"}
        with self.assertRaisesRegex(ValueError, "Wrong or incomplete packet ACK"):
            receiver.Receiver().poll()
        self.assertEqual(svc.deleted, [])

    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'requires age and age-keygen')
    def test_real_package_confirmed_across_separate_reads_and_published(self):
        _, sender, _, draft = self.make_candidate()
        outcome = json.loads((self.normal/"outcome.json").read_bytes())
        sealed = (self.normal/"checkpoint.cms").read_bytes()
        shutil.copyfile(self.normal/"input.json",sender/"input.json")
        svc = self.wire(outcome, sealed, cap=(len(sealed)+2)//3, draft=draft)
        with patch.object(original.normal,"ROOT",sender), patch.object(original.bridge,"ROOT",sender):
            obj=receiver.Receiver()
            self.assertFalse(obj.poll())
            # A new process reconstructs its first segment after exact-owned cache deletion.
            (sender/"checkpoint-packets.partial").unlink()
            obj=receiver.Receiver()
            self.assertFalse(obj.poll())
            self.assertFalse(obj.poll())
            k=svc.key(2)
            last=svc.blobs[k]["piece.bin"]
            svc.blobs[k]["piece.bin"] = bytes([last[0] ^ 1]) + last[1:]
            with self.assertRaisesRegex(ValueError,"damaged transport"):
                obj.poll()
            self.assertEqual(svc.deleted,[0,1])
            svc.blobs[k]["piece.bin"]=last
            self.assertTrue(obj.poll())
            self.assertEqual((sender/"incoming"/"checkpoint.cms").read_bytes(), sealed)
            original.normal.publish()
            self.assertIn("private_readback_verified=true", self.outputs.read_text())
        self.assertEqual(svc.deleted,[0,1,2])


    @unittest.skipUnless(shutil.which('age') and shutil.which('age-keygen'), 'requires age and age-keygen')
    def test_signed_packets_and_signed_ack_between_separate_keys(self):
        archive, publisher, _, draft = self.make_candidate()
        normal, bridge, packet = original.normal, original.bridge, receiver.packets
        sealed = (self.normal/"checkpoint.cms").read_bytes()
        outcome = json.loads((self.normal/"outcome.json").read_bytes())
        bridge.keygen()  # The ordinary job's key; the fixed private receiver already has its own.
        (publisher/"incoming").mkdir()
        shutil.copyfile(self.normal/"public.pem",publisher/"incoming"/"public.pem")
        shutil.copyfile(self.normal/"input.json",publisher/"input.json")
        workspace = self.tmp/"cache-runtime"
        workspace.mkdir()
        self.enterContext(patch.dict(os.environ, GITHUB_WORKSPACE=str(workspace), GITHUB_JOB="draft-publisher"))
        self.enterContext(patch.object(packet, "PACKET_BYTES", (len(sealed)+1)//2))
        rows, data = {}, {}
        def deposit(kind, index, deadline=None, whole_bytes=None):
            key = packet.key(index,kind)
            snapshot = {p.name:p.read_bytes() for p in packet.folder(kind).iterdir()}
            if key in data:
                self.assertEqual(data[key],snapshot)
            else:
                data[key] = snapshot
                rows[key] = dict(id=len(rows)+1, key=key, ref=os.environ["GITHUB_REF"], version=packet.version(kind),
                                 size_in_bytes=sum(map(len,snapshot.values())))
            return rows[key]
        def restore(kind,index,row,deadline):
            self.assertEqual(row,rows[packet.key(index,kind)])
            packet.reset(kind)
            for name, value in data[row["key"]].items():
                (packet.folder(kind)/name).write_bytes(value)
        def delete(api,index,row,deadline):
            self.assertEqual(rows.pop(packet.key(index)),row)
        for method, replacement in (("exact",lambda key,deadline:rows.get(key)), ("save",deposit), ("restore",restore),
                                    ("before_delete",lambda piece,row,deadline:None)):
            self.enterContext(patch.object(packet,method,replacement))
        self.enterContext(patch.object(receiver,"delete_exact",delete))
        issued = []
        for i, offset in enumerate(range(0,len(sealed),packet.PACKET_BYTES)):
            payload=sealed[offset:offset+packet.PACKET_BYTES]
            record=dict(schema="r209-checkpoint-piece-v1",claim=97,index=i,count=2,offset=offset,bytes=len(payload),
                        sha256=sha(payload),outcome=outcome,meter_barrier=i==1)
            packet.reset("packet")
            folder=packet.folder("packet")
            (folder/"piece.bin").write_bytes(payload)
            (folder/"piece.json").write_bytes(packet.data(record))
            packet.signature(folder,"piece",normal.ROOT/"key.pem")
            issued.append((record,deposit("packet",i)))
        with patch.object(normal,"ROOT",publisher), patch.object(bridge,"ROOT",publisher):
            obj=receiver.Receiver()
            self.assertFalse(obj.poll())
            self.assertTrue(obj.poll())
            self.assertEqual((publisher/"incoming"/"checkpoint.cms").read_bytes(),sealed)
            normal.publish()
            self.assertEqual((publisher/"candidate.tar.zst").read_bytes(),archive.read_bytes())
        for i, (record, row) in enumerate(issued):
            restore("receipt",i,rows[packet.key(i,"receipt")],None)
            confirmed = packet.verify_receipt(record,row)
            self.assertEqual(confirmed["source"],row)
            with self.assertRaisesRegex(ValueError,"Unmatched"):
                packet.verify_receipt(record,dict(row,id=999999))


class ExactDelete(unittest.TestCase):
    def test_replacement_before_delete_is_never_touched(self):
        ref="refs/heads/bare-coexist-v2.0.9"
        row=dict(id=111,key="fixture-packet-0",ref=ref,version="a"*64,size_in_bytes=1)
        from unittest.mock import Mock
        api=Mock()
        with patch.dict(os.environ, GITHUB_REF=ref), patch.object(receiver.packets,"key",return_value=row["key"]), \
             patch.object(receiver.packets,"exact",return_value=dict(row,id=112)):
            with self.assertRaisesRegex(ValueError,"changed before exact cleanup"):
                receiver.delete_exact(api,0,row,time.time()+60)
        api.request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
