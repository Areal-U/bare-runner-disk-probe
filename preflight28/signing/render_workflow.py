#!/usr/bin/env python3
"""Generate a single guarded PR workflow without giving the job repository credentials."""
import ast
from pathlib import Path
import re
import sys
import textwrap

base=Path(__file__).resolve().parent
before=sys.argv[1]
if not re.fullmatch("[0-9a-f]{40}",before): raise ValueError("exact predecessor SHA required")
guard=(base.parent/"limits"/"guard.py").read_text()
nodes={getattr(n,'name',None):n for n in ast.parse(guard).body}
path_checks="\n\n".join(ast.get_source_segment(guard,nodes[name]) for name in ["GuardError","check_size"])
size_cli="""import json, stat, sys
from pathlib import Path
MIB = 1024**2
BYTE_CAPS = {'apk':450*MIB,'cipher':451*MIB}
""" + path_checks + """
if len(sys.argv) != 4 or sys.argv[1] != 'size': sys.exit(66)
try:
    print(json.dumps(check_size(sys.argv[2], Path(sys.argv[3])), sort_keys=True))
except GuardError as exc:
    print(json.dumps(exc.record,sort_keys=True),file=sys.stderr)
    sys.exit(65 if exc.record['status']=='size-exceeded' else 66)
"""
header="""name: R28 preflight private test delivery
run-name: r28-preflight-s2-20261125-v1
on:
  pull_request:
    types: [synchronize]
    branches: [bare-coexist-v2.0.4]
    paths:
      - '.github/workflows/bare-r28-delivery-preflight.yml'
permissions: {}
cache-mode: none
jobs:
  deliver-test-artifact:
    name: Create encrypted test-only APK
    if: >-
      github.repository == 'Areal-U/bare-runner-disk-probe' &&
      github.event.sender.id == 292261483 &&
      github.event.pull_request.base.sha == 'bf70ddbf474f3390a62220a076b8c43347fecc64' &&
      github.event.pull_request.number == 9 &&
      github.event.pull_request.head.repo.full_name == github.repository &&
      github.event.pull_request.head.ref == 'work-bare-27-storage-check' &&
      github.event.action == 'synchronize' &&
      github.event.before == 'PREDECESSOR' &&
      github.run_attempt == '1'
    cache-mode: none
    runs-on: ubuntu-24.04
    timeout-minutes: 18
    env:
      TRIAL_HEAD: ${{ github.event.pull_request.head.sha }}
    steps:
      - name: Prepare standard runner tools
        shell: bash
        run: |
          set -euo pipefail
          if ! command -v age >/dev/null; then
            sudo apt-get -qq -o Acquire::Retries=2 update
            sudo apt-get -qq -o Acquire::Retries=2 --no-install-recommends install age
          fi
          age --version
          java -version
      - name: Build, check and seal the synthetic no-code APK
        shell: bash
        run: |
""".replace("PREDECESSOR",before)
body="""set -euo pipefail
umask 077
trial_dir="$RUNNER_TEMP/bare-r28-delivery-test"
mkdir "$trial_dir"
cd "$trial_dir"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:?}}"
tools=$(find "$sdk/build-tools" -maxdepth 2 -name aapt2 -type f | sort -V | tail -n 1)
export AAPT2="$tools" SIGN_JAR="$(dirname "$tools")/lib/apksigner.jar" ANDROID_JAR="$sdk/platforms/android-35/android.jar"
test -x "$AAPT2" && test -s "$SIGN_JAR" && test -s "$ANDROID_JAR"
"$AAPT2" version
java -jar "$SIGN_JAR" version
"""
for name,source in [('guard.py',size_cli),('AndroidManifest.xml',(base/'AndroidManifest.xml').read_text())]:
    body += f"cat > {name} <<'R28_FILE'\n"+source.rstrip()+"\nR28_FILE\n"
body += (base/'produce.sh').read_text()
footer="""      - name: Upload only owner-test ciphertext
        id: upload
        uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: r28-preflight-s2-20261125-v1-delivery-${{ github.run_id }}-${{ github.run_attempt }}
          path: ${{ runner.temp }}/bare-r28-delivery-test/test-apk.tar.age
          if-no-files-found: error
          compression-level: 0
          retention-days: 3
      - name: Publish exact ID for the assigned private receiver
        shell: bash
        env:
          AID: ${{ steps.upload.outputs.artifact-id }}
        run: |
          set -euo pipefail
          [[ "$AID" =~ ^[1-9][0-9]*$ ]]
          echo "C1_ARTIFACT id=$AID run=$GITHUB_RUN_ID attempt=$GITHUB_RUN_ATTEMPT head_sha=$TRIAL_HEAD"
"""
(base/'bare-r28-delivery-preflight.yml').write_text(header+textwrap.indent(body,' '*10)+footer)
