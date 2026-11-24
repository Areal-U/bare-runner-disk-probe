# Runs inside the same validated builder as the existing no-op checks.
proof=out/Bare/checkpoint-round28-graph.json
if [[ $R28_ROLE == produce ]]; then
  [[ ! -e "$proof" ]]
  python3 /exchange/guard.py monitor --output out/Bare --jsonl /exchange/checkpoint/resource-events.jsonl \
    --job-start "$JOB_STARTED" --job-minutes 215 -- \
    python3 /exchange/graph.py produce --out out/Bare --proof "$proof"
  python3 /exchange/checkpoint.py verify-reuse-markers "$record" > /exchange/checkpoint/after-advance.json
  cmp /exchange/checkpoint/production-before.json /exchange/checkpoint/after-advance.json
  date +%s > /exchange/checkpoint/pack-start.epoch
  cp out/Bare/checkpoint-provenance.json out/Bare/checkpoint-round28-parent-provenance.json
  python3 /exchange/checkpoint.py record-provenance out/Bare/checkpoint-provenance.json \
    --ci-revision "$TRIAL_SHA" --base-image "$BASE_IMAGE"
  python3 /exchange/checkpoint.py canonicalize-logs --scale
  python3 /exchange/checkpoint.py record-inputs out/Bare/checkpoint-inputs.jsonl.gz
else
  python3 - <<'PY'
import json, os, hashlib
from pathlib import Path
base = Path("out/Bare")
old = json.loads((base/"checkpoint-round28-parent-provenance.json").read_text())
new = json.loads((base/"checkpoint-provenance.json").read_text())
assert old["identity_sha256"] == "a11dd3df7bccafb011f90f562e997b4601fa8a200f85c39d09d6fc962de8a3dc"
assert old["identity"]["ci_revision"] == "bf70ddbf474f3390a62220a076b8c43347fecc64"
expected = dict(old["identity"], ci_revision=os.environ["TRIAL_SHA"])
assert new["identity"] == expected
payload = json.dumps(old["identity"], sort_keys=True, separators=(",", ":")).encode()
assert hashlib.sha256(payload).hexdigest() == old["identity_sha256"]
PY
  python3 /exchange/graph.py receive --out out/Bare --proof "$proof"
fi
python3 /exchange/checkpoint.py check-gn-packaging out/Bare
cp out/Bare/checkpoint-provenance.json /exchange/checkpoint/child-provenance.json
sha256sum "$proof" | cut -d' ' -f1 > /exchange/checkpoint/graph-sha.txt
CONTAINER
cd "$RUNNER_TEMP/bare-official"
if [[ $R28_ROLE == produce ]]; then
  tail -n 1 exchange/checkpoint/resource-events.jsonl
  container=chromium-android-builder
  volume=$(docker inspect "$container" --format '{{range .Mounts}}{{if eq .Destination "/work"}}{{.Name}}{{end}}{{end}}')
  [[ -n $volume ]]
  mapfile -t users < <(docker ps --filter "volume=$volume" --format '{{.Names}}')
  [[ ${#users[@]} == 1 && ${users[0]} == "$container" ]]
  docker stop --time 20 "$container"
  [[ $(docker inspect "$container" --format '{{.State.Running}}') == false ]]
  docker start "$container"
  docker compose exec -T chromium-builder true
  start=$(cat exchange/checkpoint/pack-start.epoch)
  python3 "$GITHUB_WORKSPACE/preflight28/limits/guard.py" space "$RUNNER_TEMP" --bytes $((7 * 1024**3 / 2)) --inodes 2
  docker compose exec -T chromium-builder bash -euc '
    cd /work/chromium/src
    tar --format=posix --pax-option=delete=atime,delete=ctime --exclude=out/Bare/apks \
      --exclude="*.[aA][pP][kK]" --exclude="*.[aA][pP]_" --exclude="*.[aA][aA][bB]" \
      --exclude="*.[aA][pP][kK][sS]" -cf - out/Bare
  ' | zstd -q -T2 -9 -c | python3 "$GITHUB_WORKSPACE/preflight28/transport/stream.py" "$RUNNER_TEMP/r28-child.tar.zst"
  file="$RUNNER_TEMP/r28-child.tar.zst"
  python3 "$GITHUB_WORKSPACE/preflight28/limits/guard.py" size checkpoint "$file"
  identity=$(jq -er .identity_sha256 exchange/checkpoint/child-provenance.json)
  revision=$(jq -er .identity.ci_revision exchange/checkpoint/child-provenance.json)
  [[ $revision == "$TRIAL_SHA" ]]
  python3 -I "$RUNNER_TEMP/bare-zstd-tools/checkpoint.py" validate-archive "$file" --production
  python3 -I "$RUNNER_TEMP/bare-zstd-tools/checkpoint.py" verify-continuation "$file" --production \
     --expected-identity "$identity" --ci-revision "$revision"
  echo "packed_validated_seconds=$(($(date +%s)-start)) bytes=$(stat -c%s "$file") input_identity=$identity"
  df -B1 -- "$RUNNER_TEMP"
  df -Pi -- "$RUNNER_TEMP"
else
  [[ $(cat exchange/checkpoint/graph-sha.txt) == "$(jq -er .graph_sha "$RUNNER_TEMP/r28-child.json")" ]]
fi
# These containers receive no GitHub credentials. Shut them down before a scoped
# writer step receives the token for exactly one fixed owner Draft.
docker compose stop --timeout 20
[[ -z $(docker compose ps --status running -q) ]]
