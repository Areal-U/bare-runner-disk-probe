#!/usr/bin/env bash
set -euo pipefail
umask 077
: "${GITHUB_RUN_ID:?}" "${GITHUB_RUN_ATTEMPT:?}" "${TRIAL_HEAD:?}" "${AAPT2:?}" "${ANDROID_JAR:?}" "${SIGN_JAR:?}"
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ && "$GITHUB_RUN_ATTEMPT" == 1 && "$TRIAL_HEAD" =~ ^[0-9a-f]{40}$ ]]
campaign=r28-preflight-s2-20261125-v1
pub=age1ndr7f7txhcjqfxdjzrlf7m7za0sfa7yhzm4gg9404pfl5jtq4geqgcu466
"$AAPT2" link --manifest AndroidManifest.xml -I "$ANDROID_JAR" -o unsigned.apk
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 -days 7 -subj '/CN=R28 Preflight Ephemeral CI Test Signer/O=Test Only/' -keyout ci.pem -out ci.crt >/dev/null 2>&1
openssl pkcs8 -topk8 -nocrypt -in ci.pem -outform DER -out ci.pk8
java -jar "$SIGN_JAR" sign --key ci.pk8 --cert ci.crt --v4-signing-enabled false --out ci-test.apk unsigned.apk
java -jar "$SIGN_JAR" verify --verbose --print-certs ci-test.apk | grep -F 'certificate SHA-256 digest:'
"$AAPT2" dump badging ci-test.apk | grep -F "package: name='org.barebrowser.r28preflight.testonly' versionCode='1' versionName='1.0-preflight'"
python3 guard.py size apk ci-test.apk
CI_CERT=$(openssl x509 -in ci.crt -outform DER | sha256sum | cut -d' ' -f1)
export CI_CERT
python3 - <<'PY'
import hashlib, json, os
from pathlib import Path
p = Path('ci-test.apk')
record = dict(operation='r28-preflight-s2-20261125-v1', run_id=int(os.environ['GITHUB_RUN_ID']),
              attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), head_sha=os.environ['TRIAL_HEAD'],
              ci_cert_sha256=os.environ['CI_CERT'], clear_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
              clear_bytes=p.stat().st_size)
Path('receipt.json').write_text(json.dumps(record,sort_keys=True)+'\n')
PY
tar -cf - ci-test.apk receipt.json | "${AGE:-age}" -r "$pub" -o test-apk.tar.age
python3 guard.py size cipher test-apk.tar.age
python3 - <<'PY'
import hashlib,json
from pathlib import Path
p=Path('test-apk.tar.age')
r=json.loads(Path('receipt.json').read_text())
r.update(cipher_bytes=p.stat().st_size,cipher_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
print('C1_RECEIPT '+json.dumps(r,sort_keys=True))
PY
