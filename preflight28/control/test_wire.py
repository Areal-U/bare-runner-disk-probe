"""Exercise the pinned, *actually staged* sender through both APIs, entirely in memory."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import admission


ROOT = Path(__file__).resolve().parents[2]


def load_module(name, source):
    spec = importlib.util.spec_from_file_location(name, source)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class Reply(io.BytesIO):
    def __init__(self, status, data=b"", location=None):
        super().__init__(data)
        self.status = status
        self.location = location

    def getheader(self, name, default=None):
        return self.location if name == "Location" else default


class WireTests(unittest.TestCase):
    def test_pinned_sender_http_signatures_and_hdrs(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.ExitStack() as stack:
            tmp = Path(folder)
            recipe_dir = ROOT / ".github/workflows"
            if not (recipe_dir / "bare-round26-transport-check.yml").exists():
                recipe_dir = ROOT / "r28-prep"
            recipes = tmp / "repo/.github/workflows"
            recipes.mkdir(parents=True)
            shutil.copy2(recipe_dir / "bare-round26-transport-check.yml", recipes)
            stack.enter_context(patch.dict(os.environ, RUNNER_TEMP=folder, GH_TOKEN="unit-test-only",
                               GITHUB_WORKSPACE=str(tmp / "repo"), GITHUB_RUN_ID="71",
                               TRIAL_SHA="f" * 40, GITHUB_RUN_ATTEMPT="1",
                               GITHUB_OUTPUT=str(tmp / "outputs")))
            subprocess.run([sys.executable, str(ROOT/"preflight28/transport/prepare.py"), "tools"],
                           check=True, capture_output=True)
            stack.enter_context(patch.object(sys, "path", [folder, *sys.path]))
            helper = load_module("transfer", tmp/"transfer.py")
            stack.enter_context(patch.dict(sys.modules, transfer=helper))
            exchange = load_module("exchange", ROOT/"preflight28/transport/exchange.py")
            self.assertEqual(helper.UPLOAD, "uploads.github.com")
            stack.enter_context(patch.object(helper, "DRAFT_TAG_SHA256", hashlib.sha256(b"unit").hexdigest()))
            owner = {"id": helper.OWNER_ID, "login": helper.OWNER}
            blobs = {}
            def asset(name, n, size, digest):
                return {"name": name, "id": n, "state": "uploaded", "size": size,
                        "digest": "sha256:" + digest, "uploader": owner,
                        "browser_download_url": "https://github.com/" + helper.REPO + "/releases/download/unit/" + name}
            assets = [asset(helper.SAMPLE, 769833795, helper.PROBE_BYTES, helper.PROBE_SHA),
                      asset("checkpoint-25-s2.tar.gz", 770240309, 2042700560,
                            "dd2177a80c72db7d0d6b558bec1fbd2c0acf448b28144d02dd26796104315413")]
            release = {"name": helper.DRAFT_TITLE, "author": owner, "id": helper.RELEASE_ID, "draft": True,
                       "published_at": None, "tag_name": "unit", "target_commitish": "main", "assets": assets}
            posts = []
            gets = []
            def dispatch(host, method, path, body, headers):
                parsed = urlsplit(path)
                if "Authorization" in headers:
                    self.assertIn(host, {helper.API, helper.UPLOAD})
                    self.assertEqual(headers["Authorization"], "Bearer unit-test-only")
                elif host in {"github.com", helper.API}:
                    gets.append(("anonymous", host))
                    return Reply(404)
                if host == helper.UPLOAD:
                    self.assertEqual((method, parsed.path), ("POST", f"{helper.BASE}/releases/{helper.RELEASE_ID}/assets"))
                    name = parse_qs(parsed.query)["name"][0]
                    self.assertNotIn(name, posts)
                    raw = body if isinstance(body, bytes) else body.read()
                    self.assertEqual(str(len(raw)), headers["Content-Length"])
                    n = len(assets)+1111
                    assets.append(asset(name, n, len(raw), hashlib.sha256(raw).hexdigest()))
                    blobs[n] = raw
                    posts.append(name)
                    return Reply(201, b"{}")
                self.assertEqual(method, "GET")
                if parsed.path == f"{helper.BASE}/releases/{helper.RELEASE_ID}":
                    return Reply(200, json.dumps(release).encode())
                if parsed.path == f"{helper.BASE}/actions/caches":
                    row = {"key": exchange.PARENT_KEY, "ref": "refs/heads/bare-coexist-v2.0.4",
                           "id": 11016400308, "size_in_bytes": 2742685925, "version": "fixture"}
                    return Reply(200, json.dumps({"total_count":1,"actions_caches":[row]}).encode())
                n = int(parsed.path.split("/")[-1])
                if host == helper.API:
                    return Reply(302, location="https://release-assets.githubusercontent.com/test/" + str(n))
                self.assertEqual(host, "release-assets.githubusercontent.com")
                self.assertNotIn("Authorization", headers)
                return Reply(200, blobs[n])

            class Connection:
                def __init__(self, host, **kw):
                    self.host = host
                def request(self, method, path, body, headers):
                    self.reply = dispatch(self.host, method, path, body, headers)
                def getresponse(self):
                    return self.reply
                def close(self):
                    pass

            stack.enter_context(patch.object(helper.http.client, "HTTPSConnection", Connection))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            holder = {"run": 71, "attempt": 1}
            self.assertEqual(admission.admit("compute", holder, helper), admission.admit("recover", holder, helper))
            candidate = b"fixture zstd transfer bytes"
            (tmp/"r28-child.tar.zst").write_bytes(candidate)
            evidence = tmp/"bare-official/exchange/checkpoint"
            evidence.mkdir(parents=True)
            (evidence/"child-provenance.json").write_text(json.dumps({"identity_sha256":"1"*64}))
            (evidence/"graph-sha.txt").write_text("2"*64)
            exchange.send()
            (tmp/"r28-child.tar.zst").unlink()
            exchange.receive()
            self.assertEqual((tmp/"r28-child.tar.zst").read_bytes(), candidate)
            self.assertEqual(len(posts), 3)  # claim, one part, manifest
            self.assertEqual(gets.count(("anonymous", helper.API)), 2)
            self.assertEqual(gets.count(("anonymous", "github.com")), 2)
            self.assertIn("manifest_id=", (tmp/"outputs").read_text())


if __name__ == "__main__":
    unittest.main()
