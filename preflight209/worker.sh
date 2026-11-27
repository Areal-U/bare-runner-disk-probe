#!/usr/bin/env bash
# Ordinary, read-only compiler VM; only encrypted transfer material leaves it.
set -euo pipefail
repo=$PWD
work=$RUNNER_TEMP/bare-official
ex=$work/exchange
stage=$ex/slot209
cd "$work"
umask 077
mkdir -m 0700 "$stage"
builder_uid=$(docker compose exec -T chromium-builder id -u)
runner_uid=$(id -u)
runner_gid=$(id -g)
[[ $builder_uid =~ ^[1-9][0-9]*$ && $runner_uid != "$builder_uid" ]]
cp -R "$repo/preflight28" "$ex/"
cp "$repo/checkpoint.py" "$repo/build_trial.py" "$repo/preflight28/limits/guard.py" "$ex/"
chmod -R a+rX "$ex/preflight28"
chmod a+r "$ex/checkpoint.py" "$ex/build_trial.py" "$ex/guard.py"
if ! command -v age >/dev/null; then
  sudo apt-get -qq -o Acquire::Retries=2 update
  sudo apt-get -qq --no-install-recommends install -y age
fi
install -m 0755 "$(command -v age)" "$ex/age"
export DEPOT_TOOLS_UPDATE=0 DEPOT_TOOLS_METRICS=0 PYTHONDONTWRITEBYTECODE=1
ctx=(docker compose exec -T -w /work/chromium/src -e DEPOT_TOOLS_UPDATE -e DEPOT_TOOLS_METRICS -e PYTHONDONTWRITEBYTECODE
     -e GITHUB_RUN_ID -e R28_SLOT -e R28_HEAD_SHA -e R28_PARENT_SHA -e R209_GENESIS -e R28_COLLECTION_CLAIM -e R209_SENDER_UNTIL)
args=()
if (( R28_SLOT > 1 )); then
  python3 -c 'import json,sys; json.dump(json.load(open(sys.argv[1]))["source"],sys.stdout)' "$RUNNER_TEMP/r28-normal/input.json" > "$stage/parent.json"
  mv "$RUNNER_TEMP/r28-normal/checkpoint.tar.zst" "$stage/parent.tar.zst"
  args=(--record /exchange/slot209/parent.json)
fi
sudo chown -R --no-dereference "$builder_uid:$runner_gid" "$stage"
sudo chmod 0710 "$stage"
"${ctx[@]}" chromium-builder python3 /exchange/r209/segment.py prepare "${args[@]}"
# Both VMs' actual hosted starts bound the tail. Never take packing, upload
# retry, acquisition or independent full readback minutes for compilation.
worker_start=$(cat "$RUNNER_TEMP/bare-probe-start")
end=$(( worker_start + (350 - 60)*60 ))
peer_end=$(( R209_SENDER_UNTIL - 60*60 ))
(( end <= peer_end )) || end=$peer_end
remaining=$(( end - $(date +%s) ))
(( remaining >= 600 ))
phase=seed
(( R28_SLOT == 1 )) || phase=restore
echo "R209_CONTROLLER_START slot=$R28_SLOT utc=$(date -u +%FT%TZ) allowed_seconds=$remaining command=autoninja target=chrome_public_apk"
"${ctx[@]}" -e "COMPILE_STOP_EPOCH=$end" chromium-builder python3 /exchange/build_trial.py --phase "$phase" \
    --result /exchange/slot209/trial.json --log /exchange/slot209/trial.log --production --jobs 2 \
    --seconds "$remaining" --max-output-bytes "$((18*1024**3))"
container=$(docker compose ps -q chromium-builder)
[[ -n $container ]]
volume=$(docker inspect "$container" --format '{{range .Mounts}}{{if eq .Destination "/work"}}{{.Name}}{{end}}{{end}}')
[[ -n $volume ]]
mapfile -t users < <(docker ps --filter "volume=$volume" --format '{{.ID}}')
[[ ${#users[@]} == 1 && $container == "${users[0]}"* ]]
docker stop --time 20 "$container" >/dev/null
[[ $(docker inspect "$container" --format '{{.State.Running}}') == false ]]
docker start "$container" >/dev/null
"${ctx[@]}" chromium-builder python3 /exchange/r209/segment.py close
sudo chown -h "$runner_uid:$runner_gid" "$stage/kind"
case "$(cat "$stage/kind")" in
  checkpoint)
    sudo chown -h "$runner_uid:$runner_gid" "$stage/next.tar.zst" "$stage/proof.json"
    chmod 0600 "$stage/next.tar.zst" "$stage/proof.json"
    cd "$repo"
    python3 -c 'import json,sys; print("next_has_headroom="+str(json.load(open(sys.argv[1]))["next_has_headroom"]).lower())' "$stage/proof.json" >> "$GITHUB_OUTPUT"
    id=$(sha256sum "$stage/proof.json" | cut -d' ' -f1)
    python3 preflight28/bridge/normal.py seal "$stage/next.tar.zst" --identity "$id" --proof-sha "$id"
    ;;
  apk)
    "${ctx[@]}" chromium-builder bash -euc '
      export JAVA_HOME="$PWD/third_party/jdk/current" PATH="/exchange:$PWD/third_party/jdk/current/bin:$PATH"
      sdk=third_party/android_sdk/public/build-tools/37.0.0
      python3 /exchange/r209/owner_apk.py seal --apk out/Bare/apks/ChromePublic.apk --report /exchange/slot209/trial.json \
          --sdk "$sdk" --run "$GITHUB_RUN_ID" --head "$R28_HEAD_SHA" --slot "$R28_SLOT" \
          --parent "$R28_PARENT_SHA" --claim "$R28_COLLECTION_CLAIM" --out /exchange/slot209/owner'
    sudo chown -h "$runner_uid:$runner_gid" "$stage/owner"
    sudo chown -h "$runner_uid:$runner_gid" "$stage/owner/seal.json" "$stage/owner/Bare-Personal-2.0.9-arm64-v8a.tar.age"
    chmod 0700 "$stage/owner"
    chmod 0600 "$stage/owner/"*
    ;;
  *) exit 1 ;;
esac
echo "kind=$(cat "$stage/kind")" >> "$GITHUB_OUTPUT"
