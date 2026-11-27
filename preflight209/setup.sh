#!/usr/bin/env bash
# Prepare a new, fixed Bare Android source tree on the standard hosted runner.
# The segment controller owns out/Bare and restores only this campaign's checkpoints.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=${RUNNER_TEMP:?}/bare-official
[[ ${RUNNER_ENVIRONMENT:-} == github-hosted && ${RUNNER_ARCH:-} == X64 ]]
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 && ! -e $work ]]

# This is an ephemeral VM. The Android SDK subsequently used comes from Chromium DEPS.
for path in /usr/local/lib/android /usr/local/share/boost /usr/share/dotnet /usr/share/swift \
            /usr/local/.ghcup /opt/ghc /usr/lib/google-cloud-sdk; do
    if [[ -d $path && $(realpath -- "$path") == "$path" ]] && ! mountpoint -q -- "$path"; then
        sudo -n rm -rf --one-file-system -- "$path"
    fi
done
docker_root=$(docker info --format '{{.DockerRootDir}}')
[[ $docker_root == /* ]]
df -B1 "$docker_root"
df -i "$docker_root"
awk '/^(MemTotal|MemAvailable|SwapTotal):/' /proc/meminfo

# Both the upstream inputs and the container run without repository credentials.
lock=$repo/preflight209/upstream-lock.json
bare=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["bare_commit"])' "$lock")
chromium=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["chromium_commit"])' "$lock")
depot=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["depot_tools_commit"])' "$lock")
[[ $bare == 019a612f7bb758da20c33ecf43c086e696391aec && $chromium == 52bdd21723d5db0c9ab11716d38feac74828cf84 && $depot =~ ^[0-9a-f]{40}$ ]]
mkdir -m 0755 "$work"
cd "$work"
git init -q
git -c credential.helper= fetch --no-tags --depth=1 https://github.com/BareBrowser/bare-browser.git "$bare"
git checkout --quiet --detach FETCH_HEAD
[[ $(git rev-parse HEAD) == "$bare" ]]
python3 -I "$repo/preflight209/upstream.py" verify-bare --bare-root "$work"
python3 -I "$repo/preflight209/upstream.py" gn --bare-root "$work" --output "$work/exchange/args.gn"
cp -a patches exchange/
install -m 0644 third_party/ublock_origin/uBlockOrigin-1.75.0.crx exchange/ublock_origin.crx
cp -R "$repo/preflight209" exchange/r209
chmod -R a+rX exchange/r209

# Re-read the six older packages from their authenticated published sources. The
# remainder is selected by the current Chromium package resolver, not an old list.
python3 "$repo/preflight28/transport/normal_deps.py"
install -d -m 0755 exchange/verified-six
install -m 0644 "$RUNNER_TEMP"/verified-six/{*.deb,receipts.json,receive_six.py} exchange/verified-six/
python3 -I "$repo/preflight209/builder_environment.py" installer \
    "$RUNNER_TEMP/round26-pool-install.py" exchange/install-transaction.py
install -m 0644 /etc/ssl/certs/ca-certificates.crt docker/bare-ci-apt-ca.pem
python3 -I "$repo/preflight209/builder_environment.py" dockerfile docker/Dockerfile docker/Dockerfile
bash builder.sh build
bash builder.sh start
bash "$repo/preflight209/transfer_access.sh" probe
docker compose exec -T chromium-builder bash -seu <<'UBUNTU'
set -o pipefail
[[ $(id -un) == builder && $(uname -m) == x86_64 ]]
[[ ! -e /work/chromium ]]
sudo install -d -m 0755 -o builder -g builder /work/chromium
test -w /work/chromium
[[ $(df -B1 --output=avail /work | tail -1) -ge 100000000000 ]]
[[ $(df --output=iavail /work | tail -1) -ge 1033934 ]]
sudo dpkg --add-architecture i386
sudo apt-get -o Acquire::Retries=3 -o APT::Update::Error-Mode=any -o Acquire::AllowInsecureRepositories=false update
python3 -I /exchange/verified-six/receive_six.py index /exchange/verified-six
UBUNTU

docker compose exec -T -e "DEPOT_REV=$depot" -e "CHROMIUM_REV=$chromium" \
    -e GIT_TERMINAL_PROMPT=0 chromium-builder bash -seu <<'SOURCE'
set -o pipefail
export DEPOT_TOOLS_UPDATE=0 DEPOT_TOOLS_METRICS=0
git init -q "$HOME/depot_tools"
git -C "$HOME/depot_tools" fetch --no-tags --depth=1 https://chromium.googlesource.com/chromium/tools/depot_tools.git "$DEPOT_REV"
git -C "$HOME/depot_tools" checkout -q --detach FETCH_HEAD
[[ $(git -C "$HOME/depot_tools" rev-parse HEAD) == "$DEPOT_REV" ]]
"$HOME/depot_tools/ensure_bootstrap"
cd /work/chromium
cat > .gclient <<'GCLIENT'
solutions = [{
    'name': 'src', 'url': 'https://chromium.googlesource.com/chromium/src.git',
    'deps_file': 'DEPS', 'managed': False, 'custom_deps': {}, 'custom_vars': {},
}]
target_os = ['linux', 'android']
cache_dir = None
GCLIENT
gclient sync --no-history --nohooks --revision "src@$CHROMIUM_REV" --jobs 4
cd src
[[ $(git rev-parse HEAD) == "$CHROMIUM_REV" ]]
python3 -I /exchange/r209/builder_environment.py verify-resolver build/install-build-deps.py
python3 -I /exchange/install-transaction.py
for pkg in libc6:amd64 libc6:i386 libc6-dev:amd64; do
    [[ $(dpkg-query -W -f='${Version}' "$pkg") == 2.35-0ubuntu3.15 ]]
done
gclient runhooks
cd /work/chromium
python3 src/v8/tools/builtins-pgo/download_profiles.py download \
    --depot-tools src/third_party/depot_tools --check-v8-revision --quiet
test -s src/v8/tools/builtins-pgo/profiles/x64.profile
cd src
python3 -I /exchange/r209/upstream.py verify-chromium --chromium-src "$PWD" --depot-tools "$HOME/depot_tools"
# These are the extracted Linux executables in the fixed Clang GCS archive
# and Siso CIPD instance. Check the installed bytes before starting the graph.
sha256sum --strict --check <<'TOOLS'
39b2e8892e0dccc9618a2d5fc21d912a86917111078fb30cd024098896f670d8  third_party/llvm-build/Release+Asserts/bin/clang
19733a6faf64ad02594b19d5d4a08c7271e57e44a90934a37ef246ebe3c81d9d  third_party/siso/cipd/siso
TOOLS
[[ $(cat third_party/llvm-build/Release+Asserts/cr_build_revision) == llvmorg-24-init-14453-ge063be79-1 ]]
third_party/llvm-build/Release+Asserts/bin/clang --version
third_party/siso/cipd/siso version
sdk=third_party/android_sdk/public/build-tools/37.0.0
[[ -x $sdk/aapt2 && -x $sdk/apksigner && -x third_party/jdk/current/bin/java ]]
git apply --index /exchange/patches/*.patch
python3 -I /exchange/r209/upstream.py label --chromium-src "$PWD"
install -D -m 0644 /exchange/ublock_origin.crx chrome/browser/resources/bare/ublock_origin.crx
[[ ! -e out/Bare ]]
df -B1 /work
df -i /work
SOURCE
