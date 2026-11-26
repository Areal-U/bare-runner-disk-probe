"""Build genuine resource APKs for label gate comparisons: AAPT2=/... ANDROID_JAR=/... python -m unittest."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from launcher_labels import verify_labels


@unittest.skipUnless(os.environ.get('AAPT2') and os.environ.get('ANDROID_JAR'), 'Android build tools required')
class CompiledLaunchers(unittest.TestCase):
    def check(self, *, app='@string/personal', target='', alias='', alternate='', ja='', night='', split=False, icon=''):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            values = root / 'res/values'
            values.mkdir(parents=True)
            (values / 'brands.xml').write_text('''<resources><string name="personal">Bare Personal</string>
                <string name="other">Bare</string><item type="string" name="through">@string/personal</item>
                </resources>''')
            for config, text in [('ja', ja), ('night', night)]:
                if text:
                    translated = root / ('res/values-' + config)
                    translated.mkdir()
                    (translated/'brands.xml').write_text(
                        f'<resources><string name="personal">{text}</string></resources>')
            def attr(value):
                return f' android:label="{value}"' if value else ''
            filters = ('<intent-filter><action android:name="android.intent.action.MAIN"/>'
                       + ('</intent-filter><intent-filter>' if split else '') +
                       '<category android:name="android.intent.category.LAUNCHER"/></intent-filter>')
            extra = (f'<activity-alias android:name=".Dark" android:enabled="false" android:exported="true"'
                     f' android:targetActivity=".Browser"{attr(alternate)}>{filters}</activity-alias>'
                     if alternate else '')
            manifest = root / 'AndroidManifest.xml'
            manifest.write_text(
                '<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.barebrowser.personal">'
                f'<application{attr(app)}><activity android:name=".Browser" android:exported="true"{attr(target)}/>'
                f'<activity-alias android:name=".Main" android:targetActivity=".Browser" android:exported="true"'
                f'{attr(alias)} {icon}>{filters}</activity-alias>{extra}</application></manifest>')
            tool = os.environ['AAPT2']
            resources, apk = root / 'res.zip', root / 'resources.ap_'
            subprocess.run([tool, 'compile', '--dir', root / 'res', '-o', resources], check=True)
            subprocess.run([tool, 'link', '-I', os.environ['ANDROID_JAR'], '--manifest', manifest,
                            resources, '-o', apk], check=True)
            badging = subprocess.check_output([tool, 'dump', 'badging', apk], text=True)
            # The pinned AAPT2 omits launchable-activity for these activity-alias manifests.
            self.assertNotIn('launchable-activity:', badging)
            if night:
                self.assertIn("application-label:'Bare Personal'", badging.splitlines())
                self.assertNotIn("application-label:'Bare'", badging.splitlines())
            return verify_labels(tool, apk, badging)

    def test_main_and_alternate_inherit_application(self):
        result = self.check(alternate='Bare Personal')
        self.assertEqual(['org.barebrowser.personal.Main'], result['enabled'])
        self.assertEqual({'org.barebrowser.personal.Main': ['Bare Personal'],
                          'org.barebrowser.personal.Dark': ['Bare Personal']}, result['launchers'])

    def test_shared_value_via_distinct_target_resource(self):
        self.assertEqual(['Bare Personal'], self.check(target='@string/through')['application'])

    def test_alias_overrides_target(self):
        self.assertEqual(['Bare Personal'], self.check(target='Bare', alias='Bare Personal')['application'])

    def test_bad_application_and_inherited_alias(self):
        with self.assertRaisesRegex(ValueError, '"application": .+"Bare"'):
            self.check(app='@string/other')

    def test_alias_resource_does_not_hide_inherited_literal(self):
        with self.assertRaisesRegex(ValueError, 'Main": .+"Bare"'):
            self.check(target='Bare', alias='@string/personal')

    def test_alias_icon_clears_inherited_literal(self):
        result = self.check(target='Bare', alias='@string/personal', icon='android:icon="@android:drawable/ic_menu_view"')
        self.assertEqual(['Bare Personal'], result['launchers']['org.barebrowser.personal.Main'])

    def test_round_icon_may_leave_inherited_literal(self):
        with self.assertRaisesRegex(ValueError, 'Main": .+"Bare"'):
            self.check(target='Bare', alias='@string/personal', icon='android:roundIcon="@android:drawable/ic_menu_view"')

    def test_good_app_wrong_alias(self):
        with self.assertRaisesRegex(ValueError, 'Main": .+"Bare"'):
            self.check(alias='@string/other')

    def test_good_app_wrong_target_even_when_alias_has_no_label(self):
        with self.assertRaisesRegex(ValueError, 'Main": .+"Bare"'):
            self.check(target='@string/other')

    def test_wrong_localized_name(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected personal launcher label'):
            self.check(ja='Bare')

    def test_wrong_night_mode_name_hidden_by_badging(self):
        with self.assertRaisesRegex(ValueError, 'Unexpected personal launcher label'):
            self.check(night='Bare')

    def test_switchable_icon_also_has_correct_label(self):
        with self.assertRaisesRegex(ValueError, 'Dark": .+"Bare"'):
            self.check(alternate='Bare')

    def test_action_and_category_in_different_filters(self):
        with self.assertRaisesRegex(ValueError, 'no enabled exported MAIN/LAUNCHER'):
            self.check(split=True)

    def test_missing_app_label(self):
        with self.assertRaisesRegex(ValueError, 'application label|labelled Android application'):
            self.check(app='')


if __name__ == '__main__':
    unittest.main()
