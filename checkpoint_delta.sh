#!/usr/bin/env bash
# Fixed-base transport for a verified GNU gzip -1 or -6 checkpoint on Linux.
# create BASE.gz TARGET.gz DELTA EXPECTED_BASE_SHA EXPECTED_TARGET_SHA
# apply  BASE.gz DELTA TARGET.gz EXPECTED_BASE_SHA EXPECTED_TARGET_SHA
set -euo pipefail
umask 077
[[ $# == 6 ]]
mode=$1
basis=$2
input=$3
output=$4
base_sha=$5
target_sha=$6
[[ $mode == create || $mode == apply ]]
[[ $base_sha =~ ^[0-9a-f]{64}$ && $target_sha =~ ^[0-9a-f]{64}$ ]]
[[ -f $basis && ! -L $basis && -f $input && ! -L $input ]]
[[ ! -e $output && ! -L $output ]]
full_cap=$((7 * 1024**3 / 2))
raw_cap=$((24 * 1024**3))
delta_cap=1900000000
verify() {
  printf '%s  %s\n' "$1" "$2" | sha256sum --check --strict --status
}
verify "$base_sha" "$basis"
(( $(stat -c %s -- "$basis") <= full_cap ))
work=$(mktemp -d -- "$(dirname -- "$output")/delta.XXXXXXXX")
trap 'rm -rf --one-file-system -- "$work"' EXIT
if [[ $mode == create ]]; then
  (( $(stat -c %s -- "$input") <= full_cap ))
  verify "$target_sha" "$input"
  # GNU gzip uses XFL 4 for -1 and XFL 0 for -6. These are the producer's two levels.
  case $(od -An -tu1 -j8 -N1 -- "$input" | tr -d ' ') in
    4) level=1 ;;
    0) level=6 ;;
    *) echo 'Unsupported checkpoint gzip parameters.' >&2; exit 1 ;;
  esac
  # Confirm that the hosted consumer’s compressor reproduces the builder's exact stream before saving.
  digest=$(gzip -dc -- "$input" | gzip -n "-$level" -c | sha256sum)
  [[ ${digest%% *} == "$target_sha" ]]
  # The complete successor and basis have passed the production verifier.
  gzip -dc -- "$basis" | rdiff --block-size=4096 -- signature - "$work/signature"
  (
    ulimit -f "$(((delta_cap + 1023) / 1024))"
    # A standard zstd skippable frame stores the gzip level; zstd -dc still emits only the rdiff bytes.
    python3 -I -c 'import struct,sys; sys.stdout.buffer.write(struct.pack("<III",0x184d2a50,4,int(sys.argv[1])))' "$level" > "$work/output"
    gzip -dc -- "$input" | rdiff -- delta "$work/signature" | zstd -q -T2 -3 -c >> "$work/output"
  )
  count=$(stat -c %s -- "$work/output")
  (( count > 0 && count <= delta_cap ))
else
  count=$(stat -c %s -- "$input")
  (( count > 0 && count <= delta_cap ))
  level=$(python3 -I -c '
import struct, sys
with open(sys.argv[1], "rb") as f:
    magic, size, level = struct.unpack("<III", f.read(12))
if (magic, size) != (0x184d2a50, 4) or level not in (1, 6):
    raise SystemExit("Invalid checkpoint delta header")
print(level)' "$input")
  # GNU gzip -l reports the low 32 bits for large gzip streams.
  raw_bytes=$(gzip -dc -- "$basis" | wc -c)
  (( raw_bytes > 0 && raw_bytes <= raw_cap ))
  free=$(df -B1 --output=avail -- "$work" | tail -1)
  (( free >= raw_bytes + full_cap + 512 * 1024**2 ))
  (
    ulimit -f "$(((raw_bytes + 1023) / 1024))"
    gzip -dc -- "$basis" > "$work/basis.tar"
  )
  [[ $(stat -c %s -- "$work/basis.tar") == "$raw_bytes" ]]
  (
    ulimit -f "$((full_cap / 1024))"
    zstd -q -d -M128MB -c -- "$input" |
      head -c "$raw_cap" |
      rdiff -- patch "$work/basis.tar" |
      head -c "$raw_cap" |
      gzip -n "-$level" -c > "$work/output"
  )
  verify "$target_sha" "$work/output"
fi
chmod 0644 "$work/output"
ln -- "$work/output" "$output"
