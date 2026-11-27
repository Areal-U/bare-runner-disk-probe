#!/usr/bin/env bash
# Use real host and container UIDs on this disposable VM. Never make owner
# plaintext, transfer keys, credentials, or its retained checkpoint public.
set -euo pipefail
cd "${RUNNER_TEMP:?}/bare-official"
umask 077
host_user=$(id -u)
host_group=$(id -g)
builder_user=$(docker compose exec -T chromium-builder id -u)
[[ $builder_user =~ ^[1-9][0-9]*$ && $host_user != "$builder_user" ]]

give_input() {
    sudo chown -R --no-dereference "$builder_user:$host_group" "$1"
    sudo chmod 0710 "$1"
}
take_file() {
    sudo chown -h "$host_user:$host_group" "$1"
    [[ -f $1 && ! -L $1 ]]
    chmod 0600 "$1"
}
take_directory() {
    sudo chown -h "$host_user:$host_group" "$1"
    [[ -d $1 && ! -L $1 ]]
    chmod 0700 "$1"
}

case "${1-}" in
    input)
        give_input exchange/slot209 ;;
    result)
        for item in "${@:2}"; do
            case "$item" in kind|proof.json|next.tar.zst) take_file "exchange/slot209/$item" ;; *) exit 2 ;; esac
        done ;;
    sealed)
        take_directory exchange/slot209/owner
        take_file exchange/slot209/owner/seal.json
        take_file exchange/slot209/owner/Bare-Personal-2.0.9-arm64-v8a.tar.age ;;
    probe)
        tmp=$(mktemp -d exchange/uid-check-XXXXXX)
        # Both owners may have made private directories when an assertion fails.
        trap 'sudo rm -rf -- "$tmp"' EXIT
        printf 'ordinary source' > "$tmp/in"
        give_input "$tmp"
        docker compose exec -T -e "UID_TEST=/${tmp}" chromium-builder sh -eu -c '
          umask 077
          test "$(cat "$UID_TEST/in")" = "ordinary source"
          mkdir "$UID_TEST/sealed"
          printf "sealed evidence" > "$UID_TEST/sealed/digest"
        '
        [[ ! -r $tmp/sealed/digest ]]
        take_directory "$tmp/sealed"
        take_file "$tmp/sealed/digest"
        [[ $(cat "$tmp/sealed/digest") == 'sealed evidence' ]]
        echo "R209_PRIVATE_MOUNT host_uid=$host_user builder_uid=$builder_user two_way_verified=true" ;;
    *) exit 2 ;;
esac
