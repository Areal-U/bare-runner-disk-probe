import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import metrics_evidence as m


NM = "siso_metrics.json"
STEP = {"step_id": "ff45c33d-05f4-432b-8003-09477915bad8", "action": "ok",
        "outputs": ["foo"], "duration_nanos": 41, "exec_start_nanos": -100,
        "spans": [{"name": "step:ok", "start_ns": 10, "duration_ns": 23}]}
SUMMARY = {"build_id": "e60c90ce-cefa-476a-96f1-e95ac3aef584", "duration_nanos": 52}


def data(*rows):
    return b"".join(json.dumps(row, separators=(",", ":")).encode() + b"\n" for row in rows)


def read(raw, **opts):
    return m.inspect_metrics(opts.pop("name", NM), opts.pop("mode", 0o644),
                             opts.pop("size", len(raw)), io.BytesIO(raw), **opts)


class SchemaTest(unittest.TestCase):
    def test_exact_members(self):
        names = [NM, *("siso_metrics.%d.json" % i for i in range(10))]
        for name in names:
            self.assertTrue(m.metrics_name(name))
        for name in ["a/" + NM, "out/Bare/" + NM, "./" + NM, "siso_metrics.10.json",
                     "siso_metrics.00.json", "siso_metrics.９.json", NM + ".0", NM + "\n"]:
            self.assertFalse(m.metrics_name(name))
            with self.assertRaises(ValueError):
                read(b"", name=name)

    def test_original_bytes_and_type(self):
        for raw, steps, builds in [(b"", 0, 0), (data(STEP), 1, 0), (data(SUMMARY), 0, 1),
                                   (data(dict(STEP, err=True), dict(SUMMARY, err=True)), 1, 1)]:
            row = read(raw, mode=stat.S_IFREG | 0o640)
            self.assertEqual((row["size"], row["sha256"], row["mode"]),
                             (len(raw), hashlib.sha256(raw).hexdigest(), 0o640))
            self.assertEqual((row["step_rows"], row["summary_rows"]), (steps, builds))
        for options in [{"regular": False}, {"mode": stat.S_IFLNK | 0o644}, {"mode": 0o755},
                        {"mode": 0o4644}, {"size": 1}, {"size": m.MAX_BYTES + 1}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                read(b"", **options)

    def test_rejects_unknown_or_partial_frames(self):
        for raw in [b"\n", data({}), data({"outputs": ["fake"]}), data(STEP)[:-1],
                    data(dict(STEP, copied_input="bogus")), data(dict(STEP, is_local=1)),
                    data(dict(STEP, outputs=["x\x00y"])), data(dict(STEP, inputs=True)),
                    data(dict(STEP, digest=[])), data(dict(STEP, spans=[{"name": "oops"}])),
                    data(dict(SUMMARY, err=1)), data(dict(SUMMARY, build_id="bogus")),
                    data(SUMMARY, dict(SUMMARY, build_id="25d59b8e-02fc-47fb-af27-a69b87685bfd")),
                    data(SUMMARY, dict(SUMMARY, duration_nanos=51)), data(SUMMARY, SUMMARY),
                    data(STEP).replace(b'"action":', b'"action":"a","action":'),
                    b"{" + (b"z" * m.MAX_ROW) + b"}\n", b"\xff\n"]:
            with self.subTest(raw=raw[:80]), self.assertRaises(ValueError):
                read(raw)

    @unittest.skipUnless(os.environ.get("SISO"), "set SISO to Chromium's pinned binary")
    def test_manifest_rebuild_phases_share_one_stream(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gclient").touch()
            (root / "input").touch()
            out = root / "out/Bare"
            out.mkdir(parents=True)
            (out / "build.ninja").write_text(
                "rule regen\n  command = touch build.ninja\n  generator = 1\n"
                "rule ok\n  command = touch $out\nbuild build.ninja: regen ../../input\nbuild foo: ok\n")
            for args, steps in [(["foo"], 1), (["foo"], 0), (["-n", "foo"], 0)]:
                subprocess.run([os.environ["SISO"], "ninja", "-load=", "-C", str(out), *args],
                               cwd=root, env=dict(os.environ, GOMAXPROCS="2"), check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                raw = (out / NM).read_bytes()
                rows = [json.loads(line) for line in raw.splitlines()]
                result = read(raw)
                self.assertEqual(len({row["build_id"] for row in rows if "build_id" in row}), 1)
                self.assertEqual((result["step_rows"], result["summary_rows"]), (steps, 3))
                self.assertEqual(result["last_summary_nanos"], rows[-1]["duration_nanos"])
                if not steps:
                    self.assertGreaterEqual(len(raw), 225)
                    self.assertLess(len(raw), 260)

    @unittest.skipUnless(os.environ.get("SISO"), "set SISO to Chromium's pinned binary")
    def test_pinned_writer_bytes_zero_rotations_and_failure(self):
        exe = os.environ["SISO"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gclient").touch()
            out = root / "out/Bare"
            out.mkdir(parents=True)
            (out / "build.ninja").write_text("rule ok\n  command = touch $out\nrule bad\n"
                                              "  command = false\nbuild foo: ok\nbuild broken: bad\n")
            emitted = []
            for args, status, steps, summaries in [
                    (["-n", "foo"], 0, 1, 1), (["foo"], 0, 1, 1), (["missing"], 1, 0, 0),
                    (["broken"], 1, 1, 1), *[(["foo"], 0, 0, 1)] * 10]:
                p = subprocess.run([exe, "ninja", "-load=", "-C", str(out), *args], cwd=root,
                                   env=dict(os.environ, GOMAXPROCS="2"), stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, timeout=30)
                self.assertEqual(p.returncode, status)
                path = out / NM
                raw = path.read_bytes()
                info = read(raw, mode=path.stat().st_mode)
                self.assertEqual((info["step_rows"], info["summary_rows"]), (steps, summaries))
                self.assertEqual(info["error_steps"], int("broken" in args))
                self.assertEqual(info["build_error"], bool(status) if summaries else None)
                for i, prior in enumerate(reversed(emitted[-10:])):
                    rotated = out / f"siso_metrics.{i}.json"
                    self.assertEqual(rotated.read_bytes(), prior)
                    self.assertEqual(read(prior, name=rotated.name)["sha256"], hashlib.sha256(prior).hexdigest())
                emitted.append(raw)
            self.assertEqual({p.name for p in out.glob("siso_metrics*")},
                             {NM, *(f"siso_metrics.{i}.json" for i in range(10))})


if __name__ == "__main__":
    unittest.main()
