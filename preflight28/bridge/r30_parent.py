"""The immutable cross-run input for the R30 S1 independent retest and continuation."""
import json
from pathlib import Path

RUN = 45771045621
PRODUCER = "9869f9af1ba14eeb943e6ef38af7dc77456f4ec3"
MANIFEST = 795559195
MANIFEST_SHA = "f48700364b590b28188715d565d564b1afba5d5d90df1e4b98efa5cef04971c8"
SHA = "fa44728d39b61c25d4116579e6da2c63ca7898cec24ada0e7ae453548bbd73bf"
IDENTITY = "8f6e0fc60ac76d6558ff3f7f593a8db5a3a5c2da523b251b3847fb594fa2e3be"
KEY = f"bare-coexist-204-{RUN}-1-checkpoint-production-s1"
PROOF = "27b52991ec81306daf99437ba9c0488a5a510180e75bc3d3e3be9cfa32cc482a"
SIZE = 2308658666
S2 = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"
TRIAL_REF = "refs/heads/bare-r30-s1-restore-20261126"
PRODUCTION_REF = "refs/heads/bare-coexist-v2.0.4"


def authorized(env):
    if env.get("R28_PARENT_RUN") != str(RUN):
        return False
    event = json.loads(Path(env["GITHUB_EVENT_PATH"]).read_text())
    common = {
        "GITHUB_REPOSITORY": "Areal-U/bare-runner-disk-probe", "GITHUB_ACTOR": "Areal-U",
        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
        "R28_SLOT": "2", "R28_PARENT_BACKEND": "draft", "R28_EXPECTED_PARENT_KEY": KEY,
        "R28_PARENT_SHA": SHA, "R28_PARENT_IDENTITY": IDENTITY, "R28_PARENT_MANIFEST": str(MANIFEST),
        "R28_PARENT_MANIFEST_SHA": MANIFEST_SHA,
    }
    if (not all(env.get(k) == v for k, v in common.items()) or
            env.get("GITHUB_RUN_ID") == str(RUN) or env["GITHUB_SHA"] != env["R28_HEAD_SHA"] or
            event.get("sender", {}).get("id") != 292261483 or event.get("repository", {}).get("id") != 1450926240):
        return False
    mode = (event.get("inputs") or {}).get("mode")
    route = (env["GITHUB_REF"], mode, env.get("R28_PARENT_READBACK_ONLY"))
    return route in ((TRIAL_REF, "verify-r30-s1", "true"), (PRODUCTION_REF, "build-apk", "false"))
