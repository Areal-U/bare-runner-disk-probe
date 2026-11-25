#!/bin/bash
# Passed only the pinned Bare Dockerfile's original apt install arguments.
# The signed snapshot's own Packages records select bytes even when read from another Ubuntu pool.
set -euo pipefail
export LC_ALL=C
snapshot=https://snapshot.ubuntu.com/ubuntu/20261112T093000Z/
ca=/tmp/bare-ci-apt-ca.pem

# Only read package indexes admitted by the same authenticated APT transaction.
signed_indices() {
  local temp=$1 kind trust index_url file
  apt-get indextargets --format '$(IDENTIFIER) $(TRUSTED) $(URI) $(FILENAME)' > "$temp/targets"
  while read -r kind trust index_url file; do
    [[ $kind == Packages ]] || continue
    [[ $trust == yes && $index_url == "$snapshot"dists/* && $file == /var/lib/apt/lists/* && -f $file ]]
    /usr/lib/apt/apt-helper cat-file "$file"
    printf '\n'
  done < "$temp/targets"
}

# APT's installer uses the selected Packages stanzas and its own archive filenames.
# Print one four-column tab-separated record per requested archive, matching the signed
# record by path and byte count, not by the leaf filename or the display version.
make_plan() {
  local temp=$1
  shift
  apt-get -qq --print-uris --download-only install "$@" > "$temp/uris"
  local uri name size hash path
  while read -r uri name size hash; do
    [[ $uri == \'*\' ]] || continue
    uri=${uri#\'}; uri=${uri%\'}
    [[ $uri == "$snapshot"pool/* && $uri != *'?'* && $uri != *'#'* ]]
    [[ $name =~ ^[a-zA-Z0-9.+~_%:-]+\.deb$ && $size =~ ^[1-9][0-9]*$ ]]
    path=${uri#"$snapshot"}
    # Percent encodings produced by APT are decoded solely for signed Filename lookup.
    [[ $path != *'\'* && $path != *'..'* ]]
    path=$(printf '%b' "${path//%/\\x}")
    [[ $path =~ ^pool/(main|universe|restricted|multiverse)/[a-z0-9]+/[a-z0-9.+-]+/[a-zA-Z0-9.+~_:-]+\.deb$ ]]
    printf '%s\t%s\t%s\t%s\n' "$path" "$uri" "$name" "$size"
  done < "$temp/uris" > "$temp/required"
  [[ -s $temp/required && $(wc -l < "$temp/required") -le 160 ]]
  [[ $(cut -f3 "$temp/required" | sort -u | wc -l) == $(wc -l < "$temp/required") ]]
  signed_indices "$temp" | awk -v wanted="$temp/required" '
    BEGIN {
      while ((getline line < wanted)>0) {
        split(line,a,"\t"); if (a[1] in lines) exit 2
        lines[a[1]]=line; sizes[a[1]]=a[4]; n++
      }
    }
    /^Filename: / {path=$2} /^Size: / {bytes=$2} /^SHA256: / {hash=$2}
    /^$/ {
      if (path in lines) {
        if (bytes != sizes[path] || length(hash)!=64 || hash !~ /^[0-9a-f]+$/ || (path in hashes && hash!=hashes[path])) exit 3
        hashes[path]=hash
      }
      path=bytes=hash=""
    }
    END {
      for (p in lines) {if (!(p in hashes)) exit 4; print lines[p] "\t" hashes[p]}
      if (n<1) exit 5
    }' > "$temp/plan"
  awk -F '\t' '{n++; bytes+=$4} END {if(n<1 || bytes>256*1024*1024) exit 10; printf "BARE_SIGNED_BOOTSTRAP packages=%d bytes=%.0f\n",n,bytes}' "$temp/plan"
}

read_one() {
  local temp=$1 path=$2 original=$3 name=$4 size=$5 sha=$6 host uri actual
  local part="$temp/$name" final="/var/cache/apt/archives/$name"
  for host in archive.ubuntu.com security.ubuntu.com snapshot.ubuntu.com; do
    if [[ $host == snapshot.ubuntu.com ]]; then uri=$original; else uri="https://$host/ubuntu/${original#"$snapshot"}"; fi
    if /usr/lib/apt/apt-helper -o "Acquire::https::CAInfo=$ca" -o Acquire::Retries=0 -o Acquire::https::Timeout=25 download-file "$uri" "$part" "SHA256:$sha" >/dev/null; then
      actual=$(sha256sum -- "$part")
      [[ ${actual%% *} == "$sha" && $(stat -c %s -- "$part") == "$size" ]]
      mv -- "$part" "$final"
      return 0
    fi
    rm -f -- "$part"
  done
  printf 'Unable to acquire signed package %s\n' "$path" >&2
  return 1
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return; fi
if [[ ${1-} == --read-one ]]; then shift; read_one "$@"; exit; fi
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
# Let apt-helper use _apt as its sandbox user when downloading into this private staging directory.
chown _apt:root "$work"
make_plan "$work" "$@"
xargs -r -P 8 -n 5 bash "$0" --read-one "$work" < "$work/plan"
apt-get -o "Acquire::https::CAInfo=$ca" --no-download install "$@"
