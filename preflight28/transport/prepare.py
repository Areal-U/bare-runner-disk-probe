"""Stage the byte-pinned R26 helpers used by the normal build and private sender."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys

TEMP = Path(os.environ["RUNNER_TEMP"])
RECIPES = Path(__file__).resolve().with_name("recipes")
# Exact shell bodies selected from the previously verified R26 package and transfer recipes.
RECIPE_SHA256 = {
    "archive_helpers.sh": "7d2961a280e073246c1364e338969337e4693e2245270a454112bd2ea059ccc0",
    "draft_transfer.sh": "fc20cadfa04f38a958a3af710fe25ef62ccebacad7162989b3b3d4e7db1de618",
    "fetch_six.sh": "1c2e72e59cc16811bc07e7e15b9126575028ceb6fd3db636379cfb605ac7b28d",
    "install_six.sh": "0f47bd06fbfebd08c7cac1ff0990437e674bcfbfabc19dca7749c7dfa476fc73"
}


def recipe(name):
    data = (RECIPES / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != RECIPE_SHA256[name]:
        raise ValueError("Changed pinned build recipe: " + name)
    return data.decode("utf-8")


def shell(script, *, label="fixed setup step", **env):
    # Preserve command input semantics while keeping the entire embedded CI and
    # transport program out of exceptions. No command body or token in failures.
    result = subprocess.run(["bash", "-euo", "pipefail", "-c", script], env={**os.environ, **env})
    if result.returncode:
        raise SystemExit(f"{label} failed (exit {result.returncode}); inspect the preceding stage diagnostic")


def once(script, old, new):
    if script.count(old) != 1:
        raise ValueError("Original fixed recipe splice failed: " + old[:50])
    return script.replace(old, new, 1)


def stage_tools():
    for name in ("archive_helpers.sh", "draft_transfer.sh"):
        shell(recipe(name))
    # GitHub assigns another temporary permalink when the owner saves an untagged Draft.
    transfer_source = TEMP / "transfer.py"
    old_gate = '''    require(pinned_tag(tag) or (tag in (None, "") and pinned_tag(permalink_tag)),
            "Draft tag or permalink differs from the independently verified owner draft")'''
    alias_gate = '''    generation_209 = os.environ.get("BARE_GENERATION") == "2.0.9"
    observed_sha = os.environ.get("R209_DRAFT_ALIAS_SHA")
    require(generation_209 or not observed_sha, "Owner Draft dispatch digest supplied for a different generation")
    if generation_209 or not (pinned_tag(tag) or (tag in (None, "") and pinned_tag(permalink_tag))):
        from r28_verified_draft import validate
        record = validate(record, release_id, tag, permalink_tag, BASE, metadata, asset_info, download,
                          generation_209=generation_209, observed_alias_sha=observed_sha)'''
    transfer_source.write_text(once(transfer_source.read_text(), old_gate, alias_gate))
    (TEMP / "r28_verified_draft.py").write_bytes(Path(__file__).with_name("draft_anchor.py").read_bytes())
    import importlib
    import inspect
    sys.path.insert(0, str(TEMP))
    helper = importlib.import_module("transfer")
    if (not Path(helper.__file__).resolve().samefile(TEMP / "transfer.py")
            or helper.UPLOAD != "uploads.github.com" or helper.API != "api.github.com"
            or helper.RELEASE_ID != 452114666 or helper.BASE != "/repos/Areal-U/bare-runner-disk-probe"):
        raise ValueError("Owner helper does not match the pinned writer/reader contract")
    for name, args in {"draft": (helper.RELEASE_ID,), "asset_info": ({}, "x", 1, "0"*64, 1),
                       "download": (1, 1, "0"*64, None), "anonymous_status": (helper.API, "/", "api"),
                       "metadata": ("/",), "sha256_file": (TEMP / "transfer.py",)}.items():
        inspect.signature(getattr(helper, name)).bind(*args)
    inspect.signature(helper.request).bind(helper.UPLOAD, "POST", "/test", auth=True,
                                           body=b"", length=0, content_type="application/octet-stream")
    print("Verified full producer, receiver, private read and anonymous check interfaces")


if __name__ == "__main__":
    if sys.argv[1:] != ["tools"]:
        raise SystemExit("Expected tools")
    stage_tools()
