from pathlib import Path
import tempfile
import unittest

import source_reuse as trial


class SourceComparisonTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        origin = self.root / 'origin'
        trial.fresh(origin)
        for version in ('old', 'new'):
            (origin / 'source').write_text(version)
            trial.git(origin, 'add', 'source')
            trial.git(origin, '-c', 'user.name=trial', '-c', 'user.email=trial@example.invalid', 'commit', '-qm', version)
        self.spec = {'url': origin.as_uri(), 'revision': trial.value(origin, 'rev-parse', 'HEAD')}
        self.work = self.root / 'producer'
        self.work.mkdir()

    def test_complete_shallow_tree_and_commit(self):
        report = trial.pack(self.spec, self.work, trial.CAP['v8'])
        dest = self.root / 'received'
        trial.restore(report, self.work / 'source.pack', dest)
        trial.verify(dest, report)
        self.assertEqual((dest / 'source').read_text(), 'new')
        self.assertEqual(report['checkout_bytes'], 3)
        self.assertEqual(report['files'], 1)
        self.assertEqual(trial.value(dest, 'rev-list', '--count', 'HEAD'), '1')

    def test_corrupt_pack_stops_before_checkout(self):
        report = trial.pack(self.spec, self.work, trial.CAP['v8'])
        wrong = self.root / 'source.pack'
        material = (self.work / 'source.pack').read_bytes()
        wrong.write_bytes(material[:-1] + bytes([material[-1] ^ 1]))
        with self.assertRaisesRegex(ValueError, 'SHA'):
            trial.restore(report, wrong, self.root / 'received')
        self.assertFalse((self.root / 'received').exists())

    def test_budget_and_amortization(self):
        with self.assertRaisesRegex(ValueError, 'cap exceeded'):
            trial.pack(self.spec, self.work, trial.ZIP_MARGIN + 1)
        result = trial.decision({'seeded_s': 4, 'direct_s': 10}, {'make_s': 10}, 2, 2, 3)
        self.assertEqual(result['min_uses_to_save_time'], 4)
        self.assertEqual(result['net_s_over_planned_uses'], 0)
        self.assertIsNone(trial.decision({'seeded_s': 8, 'direct_s': 10}, {'make_s': 1}, 1, 2, 2)['min_uses_to_save_time'])

    def test_new_pins_replace_both_without_using_a_branch_name(self):
        source = self.root / 'pins.yml'
        template = ''.join(f'      {key}: {digit * 40}\n' for key, digit in [('BARE_REV', '1'), ('CHROMIUM_REV', '2'), ('DEPOT_REV', '3')])
        source.write_text(template)
        self.assertEqual(trial.pins(source)['CHROMIUM_REV'], '2' * 40)
        source.write_text(template.replace('2' * 40, 'main'))
        with self.assertRaisesRegex(ValueError, 'CHROMIUM_REV'):
            trial.pins(source)


if __name__ == '__main__':
    unittest.main()
