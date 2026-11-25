import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import inputs
import render_input_assertions as renderer


class RenderingTests(unittest.TestCase):
    def setUp(self):
        self.before = dict(bare=inputs.production.BARE_REV,chromium=inputs.production.CHROMIUM_REV,patches=313,
                           extension='third_party/ublock_origin/uBlockOrigin-1.75.0.crx',
                           extension_sha256=inputs.production.UBO_SHA,package='org.barebrowser.personal',
                           abi='arm64-v8a',version_name='2.0.4',version_code=802000415,
                           upstream_gn_sha256=inputs.coexist_inputs.UPSTREAM_ARM64_ARGS_SHA256)
        self.candidate=dict(self.before,version_name='2.0.6',version_code=802000615,patches=330,
                            bare='f'*40,chromium='e'*40,upstream_gn_sha256='9'*64)

    def test_same_is_exact_and_foreign_anchors_are_rejected(self):
        for path in (renderer.PRODUCER, renderer.COLLECTOR, renderer.COEXIST):
            with self.subTest(path=path):
                raw = (inputs.ROOT/path).read_text()
                self.assertEqual(renderer.render_text(path,raw,self.before,self.before),raw)
                for altered in (raw + raw, raw.replace('802000415','802000416') if
                                path != renderer.COEXIST else raw.replace('pinned Bare','changed Bare')):
                    with self.assertRaises(ValueError):
                        renderer.render_text(path, altered, self.before, self.candidate)

    def test_branch_and_lease_names_and_signer_are_unchanged(self):
        raw = (inputs.ROOT/renderer.PRODUCER).read_text()
        after = renderer.render_text(renderer.PRODUCER,raw,self.before,self.candidate)
        for text in ('refs/heads/bare-coexist-v2.0.4','R28_COLLECTION_CLAIM:', 'Bare-Personal-2.0.4-arm64-v8a.tar.age',
                     "        expected_cert = '", 'runs-on:'):
            self.assertGreater(raw.count(text),0)
            self.assertEqual([s for s in raw.splitlines() if text in s],[s for s in after.splitlines() if text in s])
        self.assertIn('BARE_REV: '+self.candidate['bare'], after)
        self.assertIn('CHROMIUM_REV: '+self.candidate['chromium'], after)
        self.assertIn("expected_version = '2.0.6'",after)
        self.assertIn("expected_code = '802000615'",after)
        self.assertIn('== 330 ]]',after)


def check_real(output, bare_git):
    """Run rendered GN selection and the rendered collector's package/ABI/ELF/CRX checks."""
    report=json.loads((output/'review.json').read_bytes())
    row=report['product_inputs']
    assert report['dispatch_ready'] is False
    tree=output/'rendered'
    with tempfile.TemporaryDirectory() as directory:
        work=Path(directory)
        docs=work/'docs'
        docs.mkdir()
        (docs/'build-from-source.md').write_bytes(inputs.git(bare_git,'show',row['bare']+':docs/build-from-source.md'))
        checked=work/'args.gn'
        subprocess.run([sys.executable, str(tree/renderer.COEXIST),'gn','--bare-root',str(work),'--output',str(checked)],
                       check=True,timeout=10)
        assert checked.read_bytes() == (output/'args.gn').read_bytes()
        assert hashlib.sha256(checked.read_bytes()).hexdigest() == row['personal_gn_sha256']
        fixture=work/'fixture.apk'
        with ZipFile(fixture,'w') as z:
            z.writestr('assets/bare/ublock_origin.crx',inputs.git(bare_git,'show',row['bare']+':'+row['extension']))
            z.writestr('lib/arm64-v8a/libchrome.so',b'\x7fELF\x02\x01'+bytes(12)+b'\xb7\x00')
        spec=importlib.util.spec_from_file_location('rendered_private_checks',tree/renderer.COLLECTOR)
        reader=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(reader)
        assert (reader.BARE_REV,reader.CHROMIUM_REV) == (row['bare'],row['chromium'])
        def badging(code):
            return (f"package: name='{row['package']}' versionName='{row['version_name']}' versionCode='{code}'\n"
                    "application-label:'Bare Personal'\nnative-code: 'arm64-v8a'\n")
        with patch.object(reader.subprocess,'check_output',return_value=badging(row['version_code'])):
            reader.verify_application(fixture,Path('fixture-aapt2'))
        with patch.object(reader.subprocess,'check_output',return_value=badging(row['version_code']+1)):
            with unittest.TestCase().assertRaisesRegex(ValueError,'Incorrect Bare Personal application'):
                reader.verify_application(fixture,Path('fixture-aapt2'))
        producer=(tree/renderer.PRODUCER).read_text()
        for key,target in [('expected_version',row['version_name']),('expected_code',row['version_code']),
                           ('expected_crx',row['extension_sha256'])]:
            assert producer.count(f"        {key} = '{target}'\n") == 1
        assert f'== {row["patches"]} ]]' in producer
    print(json.dumps(dict(version=row['version_name'],code=row['version_code'],patches=row['patches'],
                          collector_accepted_expected_and_rejected_other=True, test_badging='fixture',
                          checked_gn_sha256=row['personal_gn_sha256'],dispatch_ready=False)))


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='verify-preview':
        parser=argparse.ArgumentParser()
        parser.add_argument('output',type=Path)
        parser.add_argument('bare_git',type=Path)
        a=parser.parse_args(sys.argv[2:])
        check_real(a.output, a.bare_git)
    else:
        unittest.main()
