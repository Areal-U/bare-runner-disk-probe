"""Bind one sealed ciphertext to its production commit, original run, and accepted parent."""
import argparse
import json
import os
from pathlib import Path
import re

RECIPIENT = "age1t69raxytlqula36e8w0tm6p3ezt49ztwnrtz8k57h6mvpwfguy7sjmr4yx"
CIPHER_FILE = "Bare-Personal-2.0.4-arm64-v8a.tar.age"
CIPHER_CAP = 451 * 1024**2
SCHEMA = "bare-r28-apk-seal-v1"


def validate(value, *, run, ordinal, head, parent):
    fields = {"schema", "run", "attempt", "ordinal", "producer_sha", "accepted_parent",
              "recipient", "sha", "bytes"}
    if not (isinstance(value, dict) and value.keys() == fields
            and type(run) is int and run > 0 and type(ordinal) is int and 1 <= ordinal <= 12
            and re.fullmatch(r"[0-9a-f]{40}", head) and re.fullmatch(r"[0-9a-f]{64}", parent)
            and value["schema"] == SCHEMA and type(value["run"]) is int and value["run"] == run
            and type(value["attempt"]) is int and value["attempt"] == 1
            and type(value["ordinal"]) is int and value["ordinal"] == ordinal
            and value["producer_sha"] == head and value["accepted_parent"] == parent
            and value["recipient"] == RECIPIENT and isinstance(value["sha"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["sha"])
            and type(value["bytes"]) is int and 0 < value["bytes"] <= CIPHER_CAP):
        raise ValueError("Terminal ciphertext seal differs from the original production slot")
    return value


def write(path, env):
    if (env["GITHUB_REF"] != "refs/heads/bare-coexist-v2.0.4" or env["GITHUB_EVENT_NAME"] != "workflow_dispatch"
            or env["GITHUB_REPOSITORY"] != "Areal-U/bare-runner-disk-probe" or env["GITHUB_RUN_ATTEMPT"] != "1"):
        raise ValueError("Only the original production runner may seal the ciphertext")
    run, ordinal = int(env["GITHUB_RUN_ID"]), int(env["SEGMENT_ORDINAL"])
    head, parent = env["GITHUB_SHA"], env["R28_PARENT_SHA"]
    record = dict(schema=SCHEMA, run=run, attempt=1, ordinal=ordinal, producer_sha=head,
                  accepted_parent=parent, recipient=env["APK_RECIPIENT"],
                  sha=env["SEALED_SHA"], bytes=int(env["SEALED_BYTES"]))
    validate(record, run=run, ordinal=ordinal, head=head, parent=parent)
    file = path.with_name(CIPHER_FILE)
    if path.name != "seal.json" or not file.is_file() or file.is_symlink() or file.stat().st_size != record["bytes"]:
        raise ValueError("The seal must accompany the exact original ciphertext")
    with path.open("x", encoding="ascii") as output:
        json.dump(record, output, separators=(",", ":"), sort_keys=True)
        output.write("\n")
    return f"r28-{run}-a1-s{ordinal:02}-apk-seal"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    print(write(args.path, os.environ))
