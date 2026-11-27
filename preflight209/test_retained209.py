import copy
import hashlib
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import retained209 as r


class Retained(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.out = self.base / "out/Bare"
        (self.out / ".r209").mkdir(parents=True)
        self.before = [[["a.o", "headers/side.h"], "action"], [["b.o"], "cxx"], [["c.so"], "link"]]
        self.after = self.before[1:]
        for name in [".siso_deps", ".siso_fs_state", ".ninja_log", "args.gn", "build.ninja",
                     "a.o", "headers/side.h", ".r209/inputs.gz", "not-a-goal.witness"]:
            self.write(name, name.encode())
        patcher = patch.object(r, "GN_SHA", self.sha("args.gn"))
        patcher.start()
        self.addCleanup(patcher.stop)

    def write(self, name, data):
        p = self.out / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def sha(self, name):
        return hashlib.sha256((self.out / name).read_bytes()).hexdigest()

    def trial(self, phase):
        state = self.out / ".siso_fs_state"
        return dict(format="bare-apk-trial", version=1, phase=phase, reason="time-limit",
                    target="chrome_public_apk", failed_steps=[], failed_step_count=0, forced_kill=False,
                    ready_for_restore_test=True, artifact_ready=False, container_quiescence_verified=True,
                    command=["autoninja", "-C", "out/Bare", "-j", "2", "-metrics_json",
                             "/exchange/slot209/siso-metrics-" + phase + ".json", "chrome_public_apk"],
                    close=dict(saved=True, journal_ready=False, errors=[],
                               state=dict(size=state.stat().st_size, sha256=self.sha(state.name))))

    def create(self, before=None, after=None, phase="seed"):
        before = before or self.before
        after = after or self.after
        trial = self.trial(phase)
        self.write("checkpoint-trial-restore.json", r.canonical(trial))
        self.write(".r209/frontier.json", r.canonical(after))
        retained = r.create(self.out, before, after, trial)
        proof = dict(retained=retained, graph=r.graph_id(r.source_rows(self.out)),
                     before=len(before), remaining=len(after), ordinal=1 if phase == "seed" else 2)
        self.write(r.PROOF, r.canonical(proof))
        closed = json.loads((self.out / r.CLOSED).read_bytes())
        return proof, closed, after, trial

    def receive(self, proof, closed, after, trial):
        tarpath = self.base / "checkpoint.tar"
        with tarfile.open(tarpath, "w") as t:
            t.add(self.out, "out/Bare")
        rows = {}
        with tarfile.open(tarpath, "r|") as t:
            for m in t:
                kind = "dir" if m.isdir() else "link" if m.issym() else "file"
                value = (None if m.isdir() else m.linkname if m.issym() else r.digest_stream(t.extractfile(m)))
                r.add(rows, m.name, m.mode, kind, m.size, value)
        r.verify(rows, proof, closed, after, trial)

    def test_two_slots_and_lost_earlier_implicit_output(self):
        self.receive(*self.create())
        self.write("b.o", b"real output")
        saved = self.create(self.after, self.after[1:], "restore")
        self.receive(*saved)
        (self.out / "headers/side.h").unlink()
        with self.assertRaisesRegex(ValueError, "Retained tree differs"):
            self.receive(*saved)
        with self.assertRaisesRegex(ValueError, "Missing completed Siso output"):
            r.require_outputs(r.source_rows(self.out), r.group_map(saved[1]["previous"]))

    def test_missing_slot_output(self):
        (self.out / "headers/side.h").unlink()
        with self.assertRaisesRegex(ValueError, "Missing completed Siso output"):
            self.create()

    def test_all_payload_content_mode_and_paths(self):
        saved = self.create()
        self.receive(*saved)
        p = self.out / "not-a-goal.witness"
        with self.subTest("same length replacement"):
            data = p.read_bytes()
            p.write_bytes(b"X" * len(data))
            with self.assertRaisesRegex(ValueError, "Retained tree differs"):
                self.receive(*saved)
            p.write_bytes(data)
        with self.subTest("empty directory"):
            p = self.out / "sneaked"
            p.mkdir()
            with self.assertRaisesRegex(ValueError, "Retained tree differs"):
                self.receive(*saved)
            p.rmdir()
        with self.subTest("mode"):
            p = self.out / "a.o"
            p.chmod(stat.S_IMODE(p.stat().st_mode) ^ 0o100)
            with self.assertRaisesRegex(ValueError, "Retained tree differs"):
                self.receive(*saved)

    def test_wrong_graph_state_gn_and_command(self):
        saved = self.create()
        bad = copy.deepcopy(saved)
        bad[0]["graph"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "GN or Personal"):
            self.receive(*bad)
        with patch.object(r, "GN_SHA", "0" * 64), self.assertRaisesRegex(ValueError, "GN or Personal"):
            self.receive(*saved)
        for field, value in [("command", ["unrelated"]), ("ready_for_restore_test", False)]:
            bad = dict(saved[-1], **{field: value})
            self.write("checkpoint-trial-restore.json", r.canonical(bad))
            with self.assertRaisesRegex(ValueError, "Invalid interrupted target"):
                self.again(bad)
        self.write(".siso_fs_state", b"wrong")
        self.write("checkpoint-trial-restore.json", r.canonical(saved[-1]))
        with self.assertRaisesRegex(ValueError, "Siso state differs"):
            self.again(saved[-1])

    def again(self, trial):
        (self.out / r.CLOSED).unlink(missing_ok=True)
        return r.create(self.out, self.before, self.after, trial)


if __name__ == "__main__":
    unittest.main()
