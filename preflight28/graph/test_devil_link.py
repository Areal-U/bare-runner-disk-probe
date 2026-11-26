"""The fixed Linux developer-tool link is a valid whole-edge witness."""
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from retained import DEVIL_LINK, DEVIL_TARGET, devil_link_record


class DevilLinkTest(unittest.TestCase):
    def test_required_link_text_and_live_executable(self):
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            target = out / DEVIL_TARGET
            target.parent.mkdir()
            target.write_bytes(b'host executable')
            target.chmod(0o755)
            link = out / DEVIL_LINK
            link.symlink_to(DEVIL_TARGET)
            self.assertEqual(devil_link_record(out), ['symlink', DEVIL_TARGET])
            target.chmod(0o644)
            with self.assertRaises(ValueError):
                devil_link_record(out)
            target.unlink()
            with self.assertRaises(ValueError):
                devil_link_record(out)
            other = out / 'other'
            other.write_bytes(b'other executable')
            other.chmod(0o755)
            target.symlink_to(other)
            with self.assertRaises(ValueError):
                devil_link_record(out)
            target.unlink()
            os.link(other, target)
            link.unlink()
            link.symlink_to('other')
            with self.assertRaises(ValueError):
                devil_link_record(out)
            link.unlink()
            link.write_bytes(b'host executable')
            with self.assertRaises(ValueError):
                devil_link_record(out)
