import hashlib
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


HERE = Path(__file__).resolve().parent
BOOTSTRAP = HERE / "apt_bootstrap.sh"


class PackageRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        work = Path(cls.temp.name)
        template = HERE.parent / "preflight28/transport/recipes/install_six.sh"
        subprocess.run(["bash", str(template)], check=True, env=dict(os.environ, RUNNER_TEMP=str(work)))
        output = work / "install-transaction.py"
        subprocess.run(["python3", "-I", str(HERE / "builder_environment.py"), "installer",
                        str(work / "round26-pool-install.py"), str(output)], check=True)
        cls.installer = runpy.run_path(str(output))

    def test_downstream_pinned_tuple_and_official_urls(self):
        acquire = self.installer["acquire"]
        self.assertEqual(len(self.installer["LIBRARIAN"]), 8)
        for path, (size, sha, obj) in self.installer["LIBRARIAN"].items():
            filename = path.rsplit("/", 1)[1]
            name, version, arch = filename.removesuffix(".deb").split("_")
            record = (name, version, arch, size, sha)
            with self.subTest(path=path):
                self.assertEqual(self.installer["librarian_path"](path, record), f"/{obj}/{filename}")
                fetch = Mock(side_effect=["HTTP 404", "HTTP 404", "HTTP 503", "verified"])
                with patch.dict(acquire.__globals__, download=fetch):
                    self.assertIsNone(acquire((path, record, Path("fixture.deb"))))
                    self.assertEqual([call.args[0] for call in fetch.call_args_list],
                                     ["archive.ubuntu.com", "security.ubuntu.com", "snapshot.ubuntu.com",
                                      "launchpadlibrarian.net"])
                for i, wrong in enumerate(("other", "0.0", "other", size+1, "0"*64)):
                    altered = list(record)
                    altered[i] = wrong
                    with patch.dict(acquire.__globals__, download=Mock(side_effect=AssertionError)):
                        with self.assertRaises(ValueError):
                            acquire((path, tuple(altered), Path("fixture.deb")))

    def test_downstream_four_failures_are_not_accepted(self):
        path, (size, digest, _) = next(iter(self.installer["LIBRARIAN"].items()))
        record = (*Path(path).name.removesuffix(".deb").split("_"), size, digest)
        acquire = self.installer["acquire"]
        with patch.dict(acquire.__globals__, download=Mock(return_value="HTTP 503")):
            failure = acquire((path, record, Path("unused.deb")))
        self.assertEqual(failure[-1], "launchpadlibrarian.net=HTTP 503")
        self.assertEqual(len(failure), 5)

    def test_downstream_librarian_redirect_is_not_followed(self):
        connection = Mock()
        response = connection.return_value.getresponse.return_value
        response.status = 302
        path, (size, digest, obj) = next(iter(self.installer["LIBRARIAN"].items()))
        file = Path(path).name
        record = (*file.removesuffix(".deb").split("_"), size, digest)
        with tempfile.TemporaryDirectory() as td, patch("http.client.HTTPSConnection", connection):
            result = self.installer["download"]("launchpadlibrarian.net", path, record, Path(td)/"item")
        self.assertEqual(result, "HTTP 302")
        self.assertEqual(connection.call_count, 1)
        self.assertEqual(connection.return_value.request.call_args.args[:2], ("GET", f"/{obj}/{file}"))
        response.read.assert_not_called()

    def test_unlisted_signed_package_remains_on_three_hosts(self):
        acquire = self.installer["acquire"]
        fetch = Mock(return_value="HTTP 404")
        with patch.dict(acquire.__globals__, download=fetch):
            failure = acquire(("pool/main/p/pkg/pkg_1_amd64.deb", ("pkg","1","amd64",1,"0"*64), Path("unused")))
        self.assertEqual(len(failure), 4)
        self.assertEqual(fetch.call_count, 3)

    def test_bootstrap_missing_all_sources(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td)
            (cache/"partial").mkdir()
            helper = cache / "unavailable"
            helper.write_text('#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\nexit 1\n')
            helper.chmod(0o700)
            log = cache / "calls"
            cmd = ['bash','-c','source "$1"; apt_helper=$2; shift 2; fetch_one "$@"',
                   'test',str(BOOTSTRAP),str(helper),str(cache),
                   'pool/main/e/expat/libexpat1_2.4.7-1ubuntu0.9_amd64.deb',
                   'libexpat1','2.4.7-1ubuntu0.9','amd64','96926',
                   '0ee31596316d2275ab351d11290c63e7547fff0ecd7f431e56855cb7c5f18588',
                   'libexpat1_2.4.7-1ubuntu0.9_amd64.deb']
            def check(count):
                if log.exists():
                    log.unlink()
                result = subprocess.run(cmd, capture_output=True, env=dict(os.environ, CALLS=str(log)))
                self.assertNotEqual(result.returncode, 0)
                calls = log.read_text().splitlines()
                self.assertEqual(len(calls),count)
                self.assertTrue(all('AllowRedirect=false' in line for line in calls))
                self.assertFalse((cache/cmd[-1]).exists())
                return calls
            self.assertIn('https://launchpadlibrarian.net/877865687/',check(4)[-1])
            cmd[-2] = '0'*64
            self.assertTrue(all('librarian' not in line for line in check(3)))
            cmd[-7:] = [
                "pool/main/libs/libssh/libssh-4_0.9.6-2ubuntu0.22.04.8_amd64.deb",
                "libssh-4", "0.9.6-2ubuntu0.22.04.8", "amd64", "188616",
                "ebeff6b7c3777c5ae0a2fd4200c3a946f3e866d102d7c56d46c997af8ebc2138",
                "libssh-4_0.9.6-2ubuntu0.22.04.8_amd64.deb"]
            self.assertIn('https://launchpadlibrarian.net/874600094/',check(4)[-1])
            cmd[-3] = '188617'
            self.assertTrue(all('librarian' not in line for line in check(3)))

    def test_cached_deb_requires_matching_bytes_and_metadata(self):
        with tempfile.TemporaryDirectory() as td:
            cache = Path(td)
            control = cache / "pkg/DEBIAN/control"
            control.parent.mkdir(parents=True)
            control.write_text("Package: fixture\nVersion: 1\nArchitecture: all\n"
                               "Maintainer: Fixture <fixture@example.invalid>\nDescription: test\n")
            blob = cache / "fixture_1_all.deb"
            subprocess.run(["dpkg-deb", "-b", str(cache/"pkg"), str(blob)], check=True, capture_output=True)
            values = [str(blob), "fixture", "1", "all", str(blob.stat().st_size),
                      hashlib.sha256(blob.read_bytes()).hexdigest(), "fixture"]
            cmd = ['bash','-c','source "$1"; shift; verify_deb "$@"','test',str(BOOTSTRAP)]
            self.assertEqual(subprocess.run(cmd+values).returncode, 0)
            for field in range(1,6):
                altered = values.copy()
                altered[field] += '0'
                self.assertNotEqual(subprocess.run(cmd+altered,capture_output=True).returncode,0)


if __name__ == "__main__":
    unittest.main()
