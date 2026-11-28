#!/usr/bin/env bash
# The pinned Jammy base does not have Python or CA certificates installed yet.
set -euo pipefail
export LC_ALL=C
snapshot=https://snapshot.ubuntu.com/ubuntu/20261112T093000Z
apt_helper=/usr/lib/apt/apt-helper
transport=(-o Acquire::https::CAInfo=/tmp/bare-ci-apt-ca.pem -o Acquire::https::AllowRedirect=false
           -o Acquire::http::AllowRedirect=false -o Acquire::Retries=1 -o Acquire::https::Timeout=40)

die() { echo "Bare bootstrap: $*" >&2; exit 1; }

verify_deb() {
    local file=$1 package=$2 version=$3 arch=$4 size=$5 sha=$6 origin=$7 info
    [[ -f $file && ! -L $file && $(stat -c '%s' "$file") == "$size" ]] || die "wrong size or type at $origin"
    printf '%s  %s\n' "$sha" "$file" | sha256sum --check --status || die "wrong SHA-256 at $origin"
    info=$(dpkg-deb --show --showformat='in ${Package} ${Version} ${Architecture}' "$file")
    [[ $info == "in $package $version $arch" ]] || die "wrong deb metadata at $origin"
}

# Rows have already been matched to the trusted APT transaction. Even a
# successful HTTP response is unusable until all content checks pass.
fetch_one() {
    local cache=$1 path=$2 package=$3 version=$4 arch=$5 size=$6 sha=$7 name=$8
    local tmp url
    if [[ -e $cache/$name || -L $cache/$name ]]; then
        verify_deb "$cache/$name" "$package" "$version" "$arch" "$size" "$sha" "$name"
        return
    fi
    local -a urls=("https://archive.ubuntu.com/ubuntu/$path"
                   "https://security.ubuntu.com/ubuntu/$path" "$snapshot/$path")
    case "$path $package $version $arch $size $sha" in
        "pool/main/e/expat/libexpat1_2.4.7-1ubuntu0.9_amd64.deb libexpat1 2.4.7-1ubuntu0.9 amd64 96926 0ee31596316d2275ab351d11290c63e7547fff0ecd7f431e56855cb7c5f18588")
            urls+=("https://launchpadlibrarian.net/877865687/${path##*/}");;
        "pool/main/libs/libssh/libssh-4_0.9.6-2ubuntu0.22.04.8_amd64.deb libssh-4 0.9.6-2ubuntu0.22.04.8 amd64 188616 ebeff6b7c3777c5ae0a2fd4200c3a946f3e866d102d7c56d46c997af8ebc2138")
            urls+=("https://launchpadlibrarian.net/874600094/${path##*/}");;
    esac
    for url in "${urls[@]}"; do
        tmp=$(mktemp -d "$cache/partial/bare.XXXXXXXX")
        if "$apt_helper" "${transport[@]}" download-file "$url" "$tmp/item.deb"; then
            verify_deb "$tmp/item.deb" "$package" "$version" "$arch" "$size" "$sha" "$url"
            mv -- "$tmp/item.deb" "$cache/$name"
            rmdir -- "$tmp"
            echo "Bare bootstrap verified $package $version $arch from $url"
            return
        fi
        rm -f -- "$tmp/item.deb" "$tmp/item.deb.FAILED"
        rmdir -- "$tmp"
    done
    die "all official paths failed for $path"
}

# Produce the signed pool records and APT's cache filenames from this exact
# base image. apt-cache reads the authenticated indexes used by this resolver.
plan() {
    local work=$1 uri name size supplied path package t trusted source index
    shift
    apt-get indextargets --format '$(IDENTIFIER)|$(TRUSTED)|$(URI)|$(FILENAME)' 'Identifier: Packages' > "$work/targets"
    [[ -s $work/targets ]] || die "no signed Packages indexes"
    while IFS='|' read -r t trusted source index; do
        [[ $t == Packages && $trusted == yes && $source == "$snapshot/dists/"* &&
            ${index%/*} == /var/lib/apt/lists && -f $index ]] || die "unexpected Packages index: $source"
    done < "$work/targets"
    mkdir -p "$work/empty/partial"
    apt-get -o "Dir::Cache::archives=$work/empty" --yes --no-install-recommends --download-only --print-uris install "$@" > "$work/uris"
    local -a names=()
    while read -r uri name size supplied; do
        [[ ${uri:0:1} == "'" ]] || continue
        [[ $uri == "'$snapshot/pool/"*"'" && $name =~ ^[a-zA-Z0-9.+~_%:-]+\.deb$ &&
            $size =~ ^[1-9][0-9]*$ ]] || die "unexpected package URI"
        path=${uri:1:${#uri}-2}
        path=${path#"$snapshot/"}
        [[ $path =~ ^[a-zA-Z0-9.+~_%:/-]+$ ]] || die "unsafe pool path"
        printf -v path '%b' "${path//%/\\x}"
        [[ $path =~ ^pool/(main|universe|restricted|multiverse)/[a-z0-9]+/[a-z0-9.+-]+/[a-zA-Z0-9.+~_:-]+\.deb$ ]] || die "invalid pool path"
        package=${name%%_*}
        [[ $package =~ ^[a-z0-9][a-z0-9.+-]+$ ]] || die "invalid package name"
        names+=("$package")
        printf '%s\t%s\t%s\n' "$path" "$size" "$name"
    done < "$work/uris" > "$work/requested"
    [[ ${#names[@]} == 95 ]] || die "expected 95 packages, got ${#names[@]}"
    apt-cache show "${names[@]}" > "$work/packages"
    awk -F '\t' '
        NR==FNR { if ($1 in sizes || $3 in used) exit 10; sizes[$1]=$2; names[$1]=$3; used[$3]=1; next }
        function emit(  row) {
            if (f["Filename"] in sizes) {
                if (f["Size"] != sizes[f["Filename"]] || !f["SHA256"] || !f["Package"] || !f["Version"] || !f["Architecture"]) exit 11
                row=f["Filename"] "\t" f["Package"] "\t" f["Version"] "\t" f["Architecture"] "\t" f["Size"] "\t" f["SHA256"] "\t" names[f["Filename"]]
                if (f["Filename"] in rows && rows[f["Filename"]] != row) exit 12
                rows[f["Filename"]]=row
            }
            delete f
        }
        /^$/ { emit(); next }
        /^(Filename|Size|SHA256|Package|Version|Architecture): / { k=$0; sub(/:.*/, "", k); f[k]=substr($0,length(k)+3) }
        END { emit(); if(length(rows)!=95) exit 13; for(k in rows) print rows[k] }
    ' "$work/requested" "$work/packages" | sort > "$work/plan"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then return; fi
if [[ ${1:-} == fetch-one ]]; then shift; fetch_one "$@"; exit; fi
if [[ ${1:-} == plan ]]; then shift; plan "$@"; exit; fi
[[ ${1:-} == -y && ${2:-} == --no-install-recommends ]] || die "unexpected upstream install options"
shift 2
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
plan "$work" "$@"
# Compare the complete transaction, including the authenticated SHA-256 of every package.
cut -f1-6 "$work/plan" > "$work/records"
printf '%s  %s\n' '8f61bd514fc81c0f5abce29fb31cb4d308b41f9148b41bd407973af0f5615f1c' "$work/records" | sha256sum --check --status ||
    die "pinned 95-package transaction changed"
mkdir -p /var/cache/apt/archives/partial
tr '\t\n' '\0\0' < "$work/plan" |
    xargs -0 -r -n 7 -P 6 /bin/bash "$0" fetch-one /var/cache/apt/archives
apt-get --no-download --yes --no-install-recommends -o APT::Get::AllowUnauthenticated=false install "$@"
while IFS=$'\t' read -r path package version arch size sha name; do
    query=$package
    [[ $arch == all ]] || query="$package:$arch"
    installed=$(dpkg-query -W -f='${db:Status-Status} ${Version} ${Architecture}' "$query")
    [[ $installed == "installed $version $arch" ]] || die "package state differs: $query"
done < "$work/plan"
audit=$(dpkg --audit)
[[ -z $audit ]] || die "dpkg audit reported incomplete installation"
echo "Bare bootstrap installed and verified the 95 locked packages."
