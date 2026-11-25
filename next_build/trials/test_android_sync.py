import json
from pathlib import Path
import subprocess
import unittest

import android_sync
import source_reuse


class PinnedAndroidTest(unittest.TestCase):
    def test_exact_normal_settings_and_no_build_hooks(self):
        normal=source_reuse.PIN_FILE.read_text()
        builder,bootstrap,sync = android_sync.shell_material(normal)
        self.assertIn('bash builder.sh build',builder)
        self.assertIn('UBUNTU_SNAPSHOT_URL',builder)
        self.assertIn('gclient sync --no-history --nohooks --revision "src@$CHROMIUM_REV" --jobs 4',sync)
        self.assertIn("'name': 'src'",bootstrap)
        self.assertIn("target_os = ['linux', 'android']",bootstrap)
        self.assertNotIn('runhooks',bootstrap+sync)
        for part in (builder,bootstrap,sync):
            subprocess.run(['bash','-n'],input=part,text=True,check=True)
        with self.assertRaises(ValueError): android_sync.shell_material(normal.replace(' --jobs 4',' --jobs 1'))

    def test_real_fixture_bound_to_current_pins(self):
        r=json.loads((Path(__file__).parent/'android-source-receipt.json').read_text());p=source_reuse.pins()
        self.assertEqual(r['spec']['revision'],p['CHROMIUM_REV'])
        self.assertEqual(r['spec']['DEPOT_REV'],p['DEPOT_REV'])
        self.assertEqual(r['artifact']['workflow_run'],45590664108)
        self.assertGreater(r['artifact']['size_in_bytes'],r['bytes'])
