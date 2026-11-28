import os
import unittest
from unittest.mock import patch

import packet_space as space


class Disk(unittest.TestCase):
    def setUp(self):
        self.enterContext(patch.dict(os.environ, RUNNER_TEMP="/tmp/runner", GITHUB_WORKSPACE="/tmp/work"))

    def disk(self, temp_bytes, work_bytes=None, inodes=20020):
        def read(path):
            temp = str(path) == "/tmp/runner"
            return dict(device=1 if temp or work_bytes is None else 2, free_inodes=inodes,
                        free_bytes=space.guard.FLOOR + (temp_bytes if temp or work_bytes is None else work_bytes))
        return patch.object(space.guard, "disk", read)

    def test_precompile_accounts_for_archive_ciphertext_staging_and_compressor(self):
        x=space.MIB
        peak=10*x+11*x+2*(2*x+space.METADATA)+space.ARCHIVE_OVERHEAD+space.ALLOCATION
        with self.disk(peak):
            self.assertEqual(space.before_compile(10*x,11*x,2*x),space.guard.FLOOR+peak)
        with self.disk(peak-1),self.assertRaises(space.guard.GuardError):
            space.before_compile(10*x,11*x,2*x)

    def test_highly_compressible_restore_needs_both_full_expanded_allocations(self):
        compressed, expanded = 97, 256*space.MIB+space.METADATA
        peak=compressed+2*expanded+space.TAR_PADDING+space.ALLOCATION
        with self.disk(peak-1),self.assertRaises(space.guard.GuardError):
            space.before_restore(compressed,expanded)
        with self.disk(peak):
            space.before_restore(compressed,expanded)
        with self.disk(peak,expanded-1),self.assertRaises(space.guard.GuardError):
            space.before_restore(compressed,expanded)

    def test_controller_stops_before_consuming_its_reserved_transfer_floor(self):
        high = space.guard.FLOOR + 7 * 1024**3
        state = dict(free_bytes=high + space.guard.STOP_MARGIN, free_inodes=1_000_000)
        sample = dict(estimate=4096, entries=5)
        self.assertEqual(space.guard.pressure(sample,state,False,high), ("stop",5))
        self.assertEqual(space.guard.pressure(sample,state,False), ("normal",30))
        with self.assertRaises(ValueError):
            space.guard.pressure(sample,state,True,space.guard.FLOOR-1)

    def test_distinct_devices_keep_both_floors_and_inode_limits(self):
        x, extra=space.MIB,space.ALLOCATION
        with self.disk(2*x+space.TAR_PADDING+extra,x+extra):
            space.before_restore(x,x)
        with self.disk(2*x+space.TAR_PADDING+extra,x+extra,inodes=20019),self.assertRaises(space.guard.GuardError):
            space.before_restore(x,x)

    def test_stage_and_archive_write_recheck_only_incremental_bytes(self):
        x, extra = space.MIB,space.ALLOCATION
        peak=2*(x+space.METADATA)+space.ARCHIVE_OVERHEAD+extra
        with self.disk(peak-1),self.assertRaises(space.guard.GuardError):
            space.before_piece(x)
        with self.disk(x+space.METADATA+space.ARCHIVE_OVERHEAD+extra):
            space.before_save(x+space.METADATA)
        with self.disk(x+extra):
            space.before_assembly(3*x,2*x)
        with self.disk(x+extra-1),self.assertRaises(space.guard.GuardError):
            space.before_assembly(3*x,2*x)


if __name__ == "__main__":
    unittest.main()
