import json
from pathlib import Path
import subprocess
import unittest
from tempfile import TemporaryDirectory

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

    def test_signed_package_bootstrap(self):
        fixture = Path(__file__).with_name('bootstrap_pool.sh')
        script = '''source "$1"
apt-get() { cat "$SOURCES"; }
signed_indices() { cat "$PACKAGES"; }
make_plan "$2" -y --no-install-recommends git
'''
        import os
        with TemporaryDirectory() as temp:
            target=Path(temp)
            source=target/'sources'
            records=target/'packages'
            archive='pool/main/b/bare/bare_1.0+test_amd64.deb'
            size='42'
            sha='ab'*32
            uri='https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/'+archive.replace('+','%2b')
            source.write_text("'"+uri+"' bare_1%3a1.0%2btest_amd64.deb "+size+" MD5Sum:unused\n")
            record=f'Filename: {archive}\nSize: {size}\nSHA256: {sha}\n\n'
            env={**os.environ,'SOURCES':str(source),'PACKAGES':str(records)}
            def run():
                return subprocess.run(['bash','-c',script,'test',str(fixture),temp],env=env,capture_output=True,text=True)
            records.write_text(record)
            result=run()
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((target/'plan').read_text().split(),[archive,uri,'bare_1%3a1.0%2btest_amd64.deb',size,sha])
            for invalid in ('',record.replace('Size: 42','Size: 43'),record+record.replace(sha,'cd'*32)):
                records.write_text(invalid)
                self.assertNotEqual(run().returncode,0)
            source.write_text(source.read_text().replace('snapshot.ubuntu.com','unrelated.invalid'))
            records.write_text(record)
            self.assertNotEqual(run().returncode,0)

    def test_only_bootstrap_transport_changes(self):
        start='RUN --mount=type=bind,source=bare-ci-apt-ca.pem,target=/tmp/bare-ci-apt-ca.pem '
        update='apt-get -o Acquire::Retries=3 -o Acquire::https::CAInfo=/tmp/bare-ci-apt-ca.pem update'
        install=update.removesuffix('update')+'install -y --no-install-recommends git'
        original=start+update+' && '+install
        result=android_sync.use_signed_pool(original)
        self.assertIn(update,result)
        self.assertIn('bash /tmp/bare-bootstrap-pool.sh -y --no-install-recommends git',result)
        with self.assertRaises(ValueError):
            android_sync.use_signed_pool(original.replace('-y --no-install-recommends','-y'))

    def test_host_mode_reports_separately(self):
        import os
        import unittest.mock as mock
        import io
        import contextlib
        # Use a fresh temporary root and the actual after() checks; no Android binaries are run.
        with TemporaryDirectory() as name:
            root=Path(name)
            src=root/'chromium/src'
            sdk=src/'third_party/android_sdk/public/build-tools/37.0.0/aapt2'
            sdk.parent.mkdir(parents=True); sdk.touch();sdk.chmod(0o755)
            ndk=src/'third_party/android_toolchain/ndk/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/android/api-level.h'
            ndk.parent.mkdir(parents=True);ndk.touch()
            dep={'src':'public','src/v8':'v8',**{f'src/dep{i}':'git' for i in range(120)}}
            (src.parent/'.gclient_entries').write_text('entries = '+repr(dep))
            ref=json.loads((Path(__file__).parent/'android-source-receipt.json').read_text())
            def git(src,*args):
                return ref['spec']['revision'] if src.name=='src' and args[-1]=='HEAD' else ref['tree'] if args[-1]=='HEAD^{tree}' else 'a'*40
            original=Path.read_text
            def contents(path,*args,**kwargs):
                return 'VERSION_ID="24.04"' if path==Path('/etc/os-release') else original(path,*args,**kwargs)
            buf=io.StringIO()
            with mock.patch.dict(os.environ,{'BARE_HOST_SOURCE_ROOT':name}),mock.patch.object(Path,'read_text',contents), \
                 mock.patch.object(os,'getuid',return_value=1000),mock.patch.object(android_sync,'git',git), \
                 mock.patch.object(android_sync,'stat_disk',return_value={'free':85_000_000_000,'inodes':12_000_000}),contextlib.redirect_stdout(buf):
                for phase in ('boot','pre','before','after'): android_sync.stage(phase)
            self.assertIn('BARE_ANDROID_HOST_SOURCE_RESULT ',buf.getvalue())
            self.assertNotIn('BARE_ANDROID_SOURCE_RESULT ',buf.getvalue())
