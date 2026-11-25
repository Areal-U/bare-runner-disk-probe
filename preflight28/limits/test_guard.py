"""Boundary checks for the exact module used in the trial producer/receiver."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import time

import guard


class GuardTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_size_cli(self):
        path = self.root / 'file'
        for kind, limit in guard.BYTE_CAPS.items():
            for n, status in ((limit-1, 0), (limit, 0), (limit+1, 65), (0, 66)):
                with self.subTest(kind=kind, size=n), path.open('wb') as out:
                    out.truncate(n)
                    cp = subprocess.run([sys.executable, guard.__file__, 'size', kind, str(path)], capture_output=True)
                    self.assertEqual(cp.returncode, status)
                    entry = json.loads(cp.stdout or cp.stderr)
                    self.assertEqual(entry['size'], n)
                    if n > limit:
                        self.assertFalse(entry['retry'])
        path.unlink()
        path.symlink_to(__file__)
        with self.assertRaisesRegex(guard.GuardError, 'invalid-file'):
            guard.check_size('apk', path)

    def test_retained_generations(self):
        fixed_parent = {'physical_id': 'cache:11016400308', 'bytes': 2742685925}
        current = [fixed_parent, {'physical_id':'other-four', 'bytes':9846677792-2742685925}]
        # Reference to basis is the same physical item; do not count twice.
        current.append(fixed_parent.copy())
        for n, expected in enumerate((447035995, 137549270, -171937455), start=1):
            current.append({'physical_id': f'pending:segment-{n}', 'bytes':309486725})
            if expected < 0:
                with self.assertRaises(guard.GuardError) as e:
                    guard.cache_budget(current)
                self.assertEqual(e.exception.record['headroom'], expected)
            else:
                self.assertEqual(guard.cache_budget(current)['headroom'], expected)
        with self.assertRaises(ValueError):
            guard.cache_budget([fixed_parent, dict(fixed_parent, bytes=2)])

    def test_stream_vs_two_raw_copies(self):
        free = {'free_bytes': 42*guard.GIB, 'free_inodes': 570000}
        guard.reserve(free, 22*guard.GIB, 550000)
        for fs, wanted, nodes in [(free, 32*guard.GIB, 550000),
                                  (dict(free, free_bytes=free['free_bytes']-1), 22*guard.GIB,550000),
                                  (free, 22*guard.GIB,550001)]:
            with self.assertRaisesRegex(guard.GuardError, 'insufficient-space'):
                guard.reserve(fs, wanted, nodes)
        self.assertGreater(17 * guard.GIB * 21 // 100, guard.BYTE_CAPS['checkpoint'])

    def test_r20_burst_and_thresholds(self):
        delta_out = 509147136
        delta_free = 511643648
        g = guard.GIB
        sample = {'estimate':guard.OUT_CAP-4*g, 'entries':200000}
        fs = {'free_bytes':guard.FLOOR+4*g, 'free_inodes':1000000}
        self.assertEqual(guard.pressure(sample,fs,False),('normal',30))
        self.assertEqual(guard.pressure(sample,fs,True),('fast',5))
        sample['estimate'] = guard.OUT_CAP-guard.FAST_MARGIN
        self.assertEqual(guard.pressure(sample,fs,False),('fast',5))
        sample['estimate'] = guard.OUT_CAP-guard.STOP_MARGIN-1
        fs['free_bytes'] = guard.FLOOR+guard.STOP_MARGIN+1
        # Place known burst immediately after a scan; a second, equal burst during quiescence.
        sample['estimate'] += delta_out
        fs['free_bytes'] -= delta_free
        self.assertEqual(guard.pressure(sample,fs,False),('stop',5))
        self.assertLess(sample['estimate']+delta_out,guard.OUT_CAP)
        self.assertGreater(fs['free_bytes']-delta_free,guard.FLOOR)
        self.assertEqual(guard.pressure(dict(sample, estimate=0),
                         dict(fs, free_bytes=100*g, free_inodes=guard.INODE_FLOOR+9999),False),('stop',5))

    def test_budget(self):
        self.assertEqual(guard.compile_seconds(100,100+35*60+47),274*60+13)
        self.assertEqual(guard.compile_seconds(100,100+35*60+56),274*60+4)
        self.assertEqual(guard.compile_seconds(100,100+310*60),0)
        for args in [(100,99), (100,100,351), (100,100,40)]:
            with self.assertRaises(ValueError):
                guard.compile_seconds(*args)

    def test_monitor_has_real_subprocess_measurements(self):
        # Only statvfs headroom is simulated; measurement and subprocess execution are real.
        out = self.root / 'out'
        out.mkdir()
        args=SimpleNamespace(cmd=['--',sys.executable,'-c',
                                 'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"test")',str(out/'x')],
                             output=out,jsonl=self.root/'records',terminal=True,job_start=time.time(),job_minutes=350)
        fake_disk={'device':1234,'free_bytes':50*guard.GIB,'free_inodes':1000000}
        with patch.object(guard,'disk',return_value=fake_disk):
            self.assertEqual(guard.monitor(args)['status'],'completed')
        entries=[json.loads(s) for s in args.jsonl.read_text().splitlines()]
        self.assertEqual(entries[0]['interval'],5)
        self.assertTrue(entries[-1]['ok'])
        self.assertEqual(entries[-1]['entries'],1)
        self.assertGreaterEqual(entries[-1]['peak_estimate'],4+2048)
        args.jsonl=self.root/'blocked'
        with patch.object(guard,'disk',return_value=dict(fake_disk, free_bytes=guard.FLOOR)), \
                self.assertRaisesRegex(guard.GuardError,'compile-not-started'):
            guard.monitor(args)


if __name__ == '__main__':
    unittest.main(verbosity=2)
