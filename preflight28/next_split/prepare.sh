#!/usr/bin/env bash
# Fresh GitHub-hosted VM, public and immutable inputs only. Extract the NDK headers only.
set -euo pipefail
mkdir -p "$RUNNER_TEMP/next-split"
cd "$RUNNER_TEMP/next-split"
[[ ! -e src && $(df -PB1 . | awk 'NR==2{print $4}') -ge 3221225472 ]]
git init -q src
git -C src fetch --no-tags --depth=1 https://chromium.googlesource.com/libyuv/libyuv.git 1e2e3a35993609da1d89ac170b907719d555f4b3
git -C src checkout -q --detach FETCH_HEAD
[[ $(git -C src rev-parse HEAD) == 1e2e3a35993609da1d89ac170b907719d555f4b3 ]]
if [[ ${NEXT_SPLIT_GROUP:-libyuv} == field ]]; then
  git init -q icu
  git -C icu fetch --no-tags --filter=blob:none --depth=1 https://chromium.googlesource.com/chromium/deps/icu.git 2a51536dfb3b448bdf3dae70c782ea2879c90904
  git -C icu sparse-checkout init --cone
  git -C icu sparse-checkout set source/i18n source/common
  git -C icu checkout -q --detach FETCH_HEAD
  [[ $(git -C icu rev-parse HEAD) == 2a51536dfb3b448bdf3dae70c782ea2879c90904 ]]
fi
curl -fsSL --retry 2 --max-time 300 -o clang.txz https://commondatastorage.googleapis.com/chromium-browser-clang/Linux_x64/clang-llvmorg-24-init-7747-g62397f8b-67.tar.xz
printf '%s  %s\n' ab8ec1e75c7f74565e9f893212262780abc9174363ce5f1ff670c415e9cd4147 clang.txz | sha256sum -c -
mkdir clang
tar -xJf clang.txz -C clang
curl -fsSL --retry 2 --max-time 360 -o ndk.zip https://dl.google.com/android/repository/android-ndk-r30-linux.zip
printf '%s  %s\n' 753611f410d002cfcd3f3dc2ef49aad532089d3180b436c060a90bf0fcb64df2 ndk.zip | sha256sum -c -
unzip -q ndk.zip 'android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/include/*'
ln -s android-ndk-r30/toolchains/llvm/prebuilt/linux-x86_64/sysroot sysroot
command -v ninja
