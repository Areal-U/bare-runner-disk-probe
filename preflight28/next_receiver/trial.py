"""Bounded hosted comparison of two ephemeral checkpoint receiver start policies."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bridge"))
import artifact_poll
import bridge
import frames
import storage_admission
import rest_zip

SAMPLE = [".github/workflows/bare-arm64-probe.yml", "preflight28/bridge"]
MAX_SAMPLE = 1024**2
CONTROL_LIMIT = 64 * 1024
ENVELOPE_LIMIT = 2 * 1024**2
WAIT_SECONDS = 180
STAGE_SECONDS = 20
ROOT = Path(os.environ["RUNNER_TEMP"]) / "bare-next-receiver"
bridge.ROOT = ROOT / "private"


def write(path, obj):
    path.parent.mkdir(exist_ok=True, parents=True)
    with path.open("x") as out:
        json.dump(obj, out, sort_keys=True)


def stamp():
    return round(time.time(), 3)


def binding(mode):
    run, attempt = bridge.env_int("GITHUB_RUN_ID"), bridge.env_int("GITHUB_RUN_ATTEMPT")
    sha = os.environ["GITHUB_SHA"]
    bridge.require(mode in ("baseline", "delayed") and attempt == 1 and
                   os.environ["GITHUB_REPOSITORY"] == bridge.REPO and
                   os.environ["GITHUB_REF"] == "refs/heads/bare-next-build-prep-20261125" and
                   os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch" and
                   os.environ.get("GITHUB_ACTOR") == "Areal-U" and
                   subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip() == sha,
                   "Wrong diagnostic run, actor, ref, attempt or checkout")
    return dict(run=run, attempt=attempt, head=sha, mode=mode)


def art(mode, kind):
    return f"bare-next-rx-{os.environ['GITHUB_RUN_ID']}-a1-{mode}-{kind}"


def directory(kind):
    p = ROOT / kind
    p.mkdir(mode=0o700, exist_ok=True, parents=True)
    return p


def init(mode):
    ctx = binding(mode)
    directory("private")
    bridge.output(root=ROOT, **{kind: art(mode, kind) for kind in ("ticket", "key", "envelope", "receipt")})
    write(ROOT / "local.json", dict(ctx=ctx, started=stamp()))


def read(path):
    with path.open() as f:
        return json.load(f)


def sample(output):
    # Materialize exactly the same non-private, immutable Bare files on each VM.
    with output.open("xb") as f:
        subprocess.run(["git", "archive", "--format=tar", os.environ["GITHUB_SHA"], "--", *SAMPLE],
                       stdout=f, check=True, timeout=20)
    size = output.stat().st_size
    bridge.require(0 < size <= MAX_SAMPLE, "Fixture exceeds its one-MiB input budget")
    return dict(bytes=size, sha=bridge.digest(output))


def ticket(mode):
    fixed = sample(ROOT / "reference.tar")
    write(directory("ticket") / "ticket.json", dict(ctx=binding(mode), file=fixed, issued=stamp()))


def claim_ticket(mode):
    t = read(ROOT / "ticket" / "ticket.json")
    actual = sample(ROOT / "input.tar")
    bridge.require(t["ctx"] == binding(mode) and t["file"] == actual, "Foreign ticket or altered parent")
    write(ROOT / "ready.json", dict(ready=stamp(), file=actual, ticket_issued=t["issued"]))


def key(mode):
    bridge.keygen()
    p = directory("key")
    shutil.copyfile(bridge.ROOT / "public.pem", p / "public.pem")
    write(p / "key.json", dict(ctx=binding(mode), issued=stamp(), fingerprint=bridge.fingerprint(p / "public.pem")))


def checked_key(mode):
    record = read(ROOT / "key" / "key.json")
    cert = ROOT / "key" / "public.pem"
    bridge.require(record["ctx"] == binding(mode) and record["fingerprint"] == bridge.fingerprint(cert),
                   "Unbound receiver certificate")
    return cert, record


def seal(mode):
    cert, record = checked_key(mode)
    ready = read(ROOT / "ready.json")
    acquired = stamp()
    output = directory("envelope") / "payload.cms"
    frames.seal(cert, ROOT / "input.tar", output, ready["file"]["sha"])
    bridge.require(output.stat().st_size < ENVELOPE_LIMIT - CONTROL_LIMIT, "Sealed data too large")
    write(output.parent / "envelope.json", dict(ctx=binding(mode), file=ready["file"],
          fingerprint=record["fingerprint"], cipher_sha=bridge.digest(output), ticket_issued=ready["ticket_issued"],
          producer_started=read(ROOT / "local.json")["started"], early_ready=ready["ready"],
          key_received=acquired, sealed=stamp()))


def receive(mode):
    data = read(ROOT / "envelope" / "envelope.json")
    _, record = checked_key(mode)
    input_file = ROOT / "envelope" / "payload.cms"
    sample_file = ROOT / "expected.tar"
    expected = sample(sample_file)
    bridge.require(data["ctx"] == binding(mode) and data["file"] == expected and
                   record["fingerprint"] == data["fingerprint"] and bridge.digest(input_file) == data["cipher_sha"],
                   "Wrong payload, generation or certificate")
    path = ROOT / "private" / "verified.tar"
    frames.receive(input_file, path, expected["bytes"], expected["sha"])
    receipt = dict(data, decoded=stamp(), sha=bridge.digest(path), cipher_bytes=input_file.stat().st_size,
                   receiver_started=read(ROOT / "local.json")["started"], key_issued=record["issued"])
    bridge.require(receipt["sha"] == expected["sha"], "Wrong received archive")
    write(directory("receipt") / "receipt.json", receipt)


def lookup(mode, kind, wait=WAIT_SECONDS, lookup_artifact=artifact_poll.lookup,
           read_zip=rest_zip.read_zip, expected_id=None, pause=4.0):
    b = binding(mode)
    tag = art(mode, kind)
    deadline = time.monotonic() + wait
    get = bridge.api_before(deadline)
    expected = None
    while time.monotonic() < deadline:
        try:
            row = lookup_artifact(b["run"], tag, get, repo=bridge.REPO, head=b["head"])
        except (bridge.TransientReadError, artifact_poll.UnstableInventory):
            row = None
        if row is not None and time.monotonic() < deadline:
            ceiling = ENVELOPE_LIMIT if kind == "envelope" else CONTROL_LIMIT
            valid_until = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
            bridge.require(0 < row["size_in_bytes"] <= ceiling and valid_until > datetime.now(timezone.utc),
                           "Peer artifact exceeds size/deadline")
            key = artifact_poll.identity(row)
            bridge.require((expected_id is None or row["id"] == expected_id) and
                           (expected is None or expected == key), "Artifact identity changed after discovery")
            expected = key
            try:
                data = read_zip(row, deadline)
            except bridge.TransientReadError:
                pass
            else:
                bridge.require(time.monotonic() <= deadline and valid_until > datetime.now(timezone.utc),
                               "Artifact download expired before receipt")
                dest = ROOT / (mode if kind == "receipt" else kind)
                rest_zip.unpack(data, dest, MEMBERS[kind], ceiling)
                print(f"Received Artifact ID={row['id']} bytes={len(data)} {row['digest']}", flush=True)
                return
        time.sleep(max(0, min(pause, deadline - time.monotonic())))
    raise TimeoutError(f"No verified {tag} within {wait}s; no calculation retry")


MEMBERS = {"key": {"public.pem", "key.json"}, "ticket": {"ticket.json"},
           "envelope": {"payload.cms", "envelope.json"}, "receipt": {"receipt.json"}}


def admit(mode, kind, get=bridge.api_json):
    binding(mode)
    root = ROOT / kind
    paths = list(root.iterdir())
    bridge.require(not root.is_symlink() and {p.name for p in paths} == MEMBERS[kind] and
                   all(not p.is_symlink() and p.is_file() for p in paths),
                   "Unexpected or linked diagnostic transfer member")
    # At most two short ASCII member names, compression=0 and no nested directories.
    bound = sum(p.stat().st_size for p in paths) + 8192
    bridge.require(8192 < bound <= (ENVELOPE_LIMIT if kind == "envelope" else CONTROL_LIMIT),
                   "Local ZIP candidate is outside the diagnostic limit")
    result = storage_admission.admit(get, os.environ, bound, 1, stage="control",
                                     exact_name=art(mode, kind))
    bridge.require(result == "admitted", "The original named Artifact exists; preserve it and inspect its receipt")


def occupancy(rows):
    def timestamp(value):
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    jobs = {}
    for mode, roles in (("baseline", ["producer", "receiver"]), ("delayed", ["producer", "receiver", "ticket"])):
        for role in roles:
            name = "RX " + mode + " " + role
            hits = [r for r in rows if r["name"].split(" / ")[-1] == name]
            bridge.require(len(hits) == 1 and hits[0]["conclusion"] == "success", "Missing or duplicate hosted role " + name)
            r = hits[0]
            jobs[mode, role] = dict(id=r["id"], created=timestamp(r["created_at"]),
                                    start=timestamp(r["started_at"]), end=timestamp(r["completed_at"]))
    return jobs


def summarize(jobs):
    results = {}
    for mode in ("baseline", "delayed"):
        b = binding(mode)
        payload = read(ROOT / mode / "receipt.json")
        bridge.require(payload["ctx"] == b and payload["sha"] == payload["file"]["sha"] and
                       payload["cipher_bytes"] < ENVELOPE_LIMIT and payload["key_received"] >= payload["early_ready"],
                       "Unbound receipt")
        roles = {role: row for (m, role), row in jobs.items() if m == mode}
        p, r = roles["producer"], roles["receiver"]
        # Reapply the production 350-minute clock and 60 / 35-minute reserves.
        gain = min(p["start"] + 290*60, r["start"] + 255*60) - (p["start"] + 255*60)
        results[mode] = dict(sha=payload["sha"], raw_bytes=payload["file"]["bytes"],
            cipher_bytes=payload["cipher_bytes"], receipt_readback=True, jobs=roles,
            key_wait_s=round(payload["key_received"] - payload["early_ready"], 3),
            total_wall_s=max(j["end"] for j in roles.values()) - min(j["start"] for j in roles.values()),
            vm_seconds=sum(j["end"] - j["start"] for j in roles.values()),
            receiver_start_delta_s=r["start"] - p["start"], projected_compile_budget_delta_s=gain)
    bridge.require(results["baseline"]["sha"] == results["delayed"]["sha"], "Different inputs invalidated pairing")
    baseline, delayed = results["baseline"], results["delayed"]
    gain = delayed["projected_compile_budget_delta_s"] - baseline["projected_compile_budget_delta_s"]
    extra_wait = delayed["key_wait_s"] - baseline["key_wait_s"]
    results["comparison"] = dict(actual_earliest_finish_wait_delta_s=round(extra_wait, 3),
           projected_deadline_gain_s=gain, runner_seconds_delta=delayed["vm_seconds"] - baseline["vm_seconds"],
           useful_for_deadline_bound_intervals=(delayed["receiver_start_delta_s"] > 0 and gain > 0),
           early_finish_break_even_fraction=(gain/(gain+max(0, extra_wait)) if gain > 0 else None),
           full_size_free_route_verified=False)
    return results


def collect():
    run = binding("baseline")["run"]
    resp = bridge.api_json(f"/repos/{bridge.REPO}/actions/runs/{run}/attempts/1/jobs?per_page=100")
    bridge.require(resp["total_count"] == len(resp["jobs"]), "Partial job inventory")
    results = summarize(occupancy(resp["jobs"]))
    content = json.dumps(results, indent=2)
    print(content)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as f:
        print("### Bare checkpoint receiver timing\n\n```json\n" + content + "\n```", file=f)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["init", "ticket", "claim-ticket", "key", "seal", "receive", "lookup", "admit", "pause", "collect"])
    parser.add_argument("mode", choices=["baseline", "delayed"])
    parser.add_argument("kind", nargs="?", choices=sorted(MEMBERS))
    a = parser.parse_args()
    if a.operation == "admit":
        bridge.require(a.kind is not None, "Artifact kind is required")
        admit(a.mode, a.kind)
    elif a.operation == "lookup":
        bridge.require(a.kind is not None, "Artifact kind is required")
        expected_id = bridge.env_int("RECEIPT_ID") if a.kind == "receipt" else None
        lookup(a.mode, a.kind, expected_id=expected_id)
    elif a.operation == "pause":
        time.sleep(STAGE_SECONDS)
    elif a.operation == "collect":
        collect()
    else:
        {"init": init, "ticket": ticket, "claim-ticket": claim_ticket,
         "key": key, "seal": seal, "receive": receive}[a.operation](a.mode)


if __name__ == "__main__":
    main()
