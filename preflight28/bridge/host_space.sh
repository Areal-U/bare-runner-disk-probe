#!/usr/bin/env bash
# Prepare only a disposable GitHub-hosted runner. No retained object is removed.
set -euo pipefail
[[ ${RUNNER_ENVIRONMENT:?} == github-hosted && ${RUNNER_OS:?} == Linux && ${RUNNER_ARCH:?} == X64 ]]
# Same preinstalled SDK allowlist used by the existing Bare standard-runner job.
for dir in /usr/local/lib/android /usr/local/share/boost /usr/share/dotnet /usr/share/swift /usr/local/.ghcup /opt/ghc /usr/lib/google-cloud-sdk; do
  if [[ -d $dir && $(realpath -- "$dir") == "$dir" ]] && ! mountpoint -q -- "$dir"; then
    sudo -n rm -rf --one-file-system -- "$dir"
  fi
done
# The encrypted outcome Artifact, expanded zip, and decrypted archive may
# briefly coexist on the same filesystem during the publisher handoff.
python3 preflight28/limits/guard.py space "$RUNNER_TEMP" --bytes "$((3 * 3758096384 + 96 * 1024 * 1024))" --inodes 10
