"""Reuse the byte-pinned, previously successful PR9 environment and owner-Draft helpers."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

READ = ("bare-round26-zstd-six-receiver.yml", "8f74cb7a6c871e77fa6e58232b0f3d863124c74652f132d4e024570839de9c7d", "zstd_read")
ARCHIVE = ("bare-round26-transport-check.yml", "39ee444aaf7a9c9d7ee92706b29b8b801077ac001aba2a1bb32a9d90aa017f57", "archive_send")
ROOT = Path(os.environ.get("GITHUB_WORKSPACE", Path.cwd()))
TEMP = Path(os.environ["RUNNER_TEMP"])
OLD = "bf70ddbf474f3390a62220a076b8c43347fecc64"
IDENTITY = "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
S2_SHA = "4381b248b26a7d12443241192c27d00311abaeb5b7d1839c7a5a17d088f736cf"


def parse_recipe(data):
    try:
        import yaml
        payload = yaml.safe_load(data)
    except ModuleNotFoundError:
        # Ruby/Psych is part of the hosted Linux image; no package acquisition.
        result = subprocess.run(["ruby", "-ryaml", "-rjson", "-e",
                                 "puts JSON.generate(YAML.safe_load(STDIN.read, aliases: true))"],
                                input=data, stdout=subprocess.PIPE, check=True)
        payload = json.loads(result.stdout)
    return payload


def commands(pin):
    name, want, job = pin
    data = (ROOT / ".github" / "workflows" / name).read_bytes()
    if hashlib.sha256(data).hexdigest() != want:
        raise ValueError("Reviewed environment recipe does not match " + name)
    return {step["name"]: step.get("run") for step in parse_recipe(data)["jobs"][job]["steps"]}


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
    archive = commands(ARCHIVE)
    for name in ["Prepare checkpoint_parts.py", "Prepare transfer.py"]:
        shell(archive[name])
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


def build_recipe(steps):
    script = steps["Verify producer provenance, Ninja reuse and fresh compile progress"]
    start = script.index("# These exact APK graph objects")
    script = script[:start] + (ROOT / "preflight28/transport/build-tail.sh").read_text()
    script = once(script, 'set -- "$RUNNER_TEMP/bare-zstd-trial/checkpoint.tar.zst"', 'set -- "$R28_ARCHIVE"')
    script = once(script, ' && ! -e $RUNNER_TEMP/bare-official &&', ' &&')
    script = once(script, "export EXPECTED_IDENTITY=" + IDENTITY, 'export EXPECTED_IDENTITY="$INPUT_IDENTITY"')
    script = once(script, 'cp "$ci/"*.py "$ci/"*.yml exchange/', '''cp "$ci/"*.py "$ci/"*.yml exchange/
install -m 644 "$GITHUB_WORKSPACE/preflight28/graph/graph.py" exchange/graph.py
install -m 644 "$GITHUB_WORKSPACE/preflight28/graph/retained.py" exchange/retained.py
install -m 644 "$GITHUB_WORKSPACE/preflight28/limits/guard.py" exchange/guard.py
install -m 644 "$GITHUB_WORKSPACE/preflight28/transport/trial_provenance.py" exchange/trial_provenance.py
install -m 644 "$RUNNER_TEMP/r28-trial-inputs.json" exchange/trial-inputs.json''')
    # The build UID alone writes exchange/checkpoint. The hosted runner reads
    # three explicitly exported scalar receipts through a traversable directory.
    script = once(script, "chmod 777 exchange/checkpoint", """sudo -n chown 1000:1000 exchange/checkpoint
sudo -n chmod 0755 exchange/checkpoint
[[ $(stat -c %a exchange/checkpoint) == 755 ]]
""")
    # Legacy gzip omitted GN packaging descriptors. Private v2 preserves them.
    script = once(script, "gn gen out/Bare\ncmp -- /exchange/args.gn", 'if [[ $R28_ROLE == produce ]]; then gn gen out/Bare; fi\ncmp -- /exchange/args.gn')
    # No command can execute on the readback VM, including the inherited
    # marker checks prior to the graph-specific verifier.
    marker = 'autoninja -C out/Bare -j 2 -v '
    if script.count(marker) != 3:
        raise ValueError("Unexpected legacy marker command count")
    script = script.replace(marker, 'autoninja "${read_mode[@]}" -C out/Bare -j 2 -v ')
    script = once(script, 'object=out/Bare/obj/base/third_party/cityhash/cityhash/city.o',
                  'read_mode=()\n[[ $R28_ROLE != receive ]] || read_mode=(-n)\nobject=out/Bare/obj/base/third_party/cityhash/cityhash/city.o')
    # The 26-minute timeout was for legacy restore-only assertions. The new bounded
    # graph planner and one edge run inside the per-job guard and a 95-minute cap.
    i = script.index("zstd -qdc -M128MB")
    script = script[:i] + once(script[i:], 'zstd -qdc -M128MB -- "$asset" | docker compose exec', '''decode_input() {
  if [[ $R28_ROLE == produce ]]; then gzip -dc -- "$asset"; else zstd -qdc -M128MB -- "$asset"; fi
}
decode_input | docker compose exec''')
    i = script.index("decode_input |")
    script = script[:i] + once(script[i:], '-e "CI_REVISION=$PRODUCER_REV"', '''-e "CI_REVISION=$INPUT_REVISION" -e TRIAL_SHA -e R28_ROLE -e JOB_STARTED''')
    script = script[:i] + once(script[i:], 'timeout --kill-after=2m 26m', 'timeout --kill-after=2m 95m')
    return script


def uid_preflight():
    runner = os.getuid()
    if runner == 0:
        raise ValueError("A non-root runner is required to test read denials")
    writer = 1000 if runner != 1000 else 65534
    # Isolate this synthetic cross-UID fixture; no chmod of private source,
    # existing cache, archive or signer material.
    with tempfile.TemporaryDirectory(prefix="bare28-export-check-",dir="/tmp") as name:
        path=Path(name)
        path.chmod(0o755)
        script=path/"fixture.py"
        script.write_bytes((ROOT/"preflight28/transport/trial_provenance.py").read_bytes())
        script.chmod(0o644)
        folder=path/"builder"
        folder.mkdir(mode=0o755)
        subprocess.run(["sudo","-n","chown",f"{writer}:{writer}",str(folder)],check=True)
        try:
            subprocess.run(["sudo","-n","-u",f"#{writer}","python3","-I",str(script),"fixture-write",str(folder)],check=True)
            subprocess.run(["python3","-I",str(script),"fixture-read",str(folder)],check=True)
        finally:
            # Restore ownership of the synthetic directory to permit normal
            # TemporaryDirectory cleanup. No other object is touched.
            subprocess.run(["sudo","-n","chown",f"{runner}:{os.getgid()}",str(folder)],check=True)


def setup(stage):
    uid_preflight()
    steps = commands(READ)
    shell(steps["Acquire all six pinned payloads before the cache and source checkout"])
    shell(steps["Stage the reviewed fixed-index Ubuntu package verifier"])
    dual = steps["Prepare the reviewed dual-format reader and metadata checks"]
    dual = once(dual, "cat > \"$RUNNER_TEMP/dual-reader.patch\"", 'install -m 0644 checkpoint.py frozen-checkpoint.py\ncat > "$RUNNER_TEMP/dual-reader.patch"')
    shell(dual, SOURCE_REV=OLD, label="stage dual reader")
    data = json.loads((TEMP / "r28-child.json").read_text()) if stage == "receive" else {}
    archive = TEMP / ("r28-child.tar.zst" if stage == "receive" else "bare-official/exchange/checkpoint/checkpoint.tar.gz")
    sha = data["sha256"] if data else S2_SHA
    revision = data["source_sha"] if data else OLD
    identity = data["identity"] if data else IDENTITY
    if stage == "receive" and revision != os.environ["TRIAL_SHA"]:
        raise ValueError("Successor was produced by a different PR revision")
    check = TEMP / "bare-zstd-tools/checkpoint.py"
    env = {**os.environ, "BARE_R26_TAR_CEILING": str(21 * 1024**3)}
    if stage == "produce" and archive.stat().st_size != 2753879385:
        raise ValueError("Wrong immutable parent size")
    subprocess.run(["sha256sum", "--strict", "--check"], check=True,
                   input=f"{sha}  {archive}\n", text=True)
    for action, args in [("validate-archive", []), ("verify-continuation", ["--expected-identity", identity, "--ci-revision", revision])]:
        prefix = [str(check)] if stage == "produce" else [str(ROOT/"preflight28/bridge/check_archive.py"), str(check.with_name("frozen-checkpoint.py"))]
        subprocess.run([sys.executable, "-I", *prefix, action, str(archive), "--production", *args], check=True, env=env)
    script = build_recipe(steps)
    from trial_provenance import WORKFLOW, encoded, expected
    workflow=ROOT/WORKFLOW
    inputs=expected(ROOT, os.environ["TRIAL_SHA"], script, parse_recipe(workflow.read_bytes()), [READ[:2], ARCHIVE[:2]])
    (TEMP/"r28-trial-inputs.json").write_bytes(encoded(inputs))
    shell(script, label="S2 "+stage, R28_ROLE=stage, R28_ARCHIVE=str(archive), INPUT_REVISION=revision,
          INPUT_IDENTITY=identity, ZSTD_SHA=sha, BARE_R26_TAR_CEILING=env["BARE_R26_TAR_CEILING"])


if __name__ == "__main__":
    cmd, = sys.argv[1:]
    if cmd == "tools":
        stage_tools()
    elif cmd in {"produce", "receive"}:
        setup(cmd)
    else:
        raise SystemExit("Unknown stage")
