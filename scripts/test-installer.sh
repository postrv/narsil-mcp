#!/usr/bin/env bash
# Exercise release discovery without downloading or installing anything.
set -eu

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
installer="$script_dir/../install.sh"
# Load only this function: sourcing the installer would run installation.
discovery=$(sed -n '/^get_latest_version() {$/,/^}$/p' "$installer")
test -n "$discovery"

check_version() {
    local name="$1" response="$2" expected="$3" curl_status="${4:-0}" actual
    actual=$(RELEASE_RESPONSE="$response" CURL_STATUS="$curl_status" bash -c '
        curl() {
            printf "%s\n" "$RELEASE_RESPONSE"
            return "$CURL_STATUS"
        }
        eval "$1"
        get_latest_version
    ' bash "$discovery")
    if [ "$actual" != "$expected" ]; then
        printf 'FAIL %s: expected <%s>, got <%s>\n' "$name" "$expected" "$actual" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

check_version formatted $'{\n  "tag_name": "v1.7.1",\n  "draft": false\n}' v1.7.1
check_version compact '{"tag_name":"v1.7.1","draft":false}' v1.7.1
check_version whitespace '{"tag_name" :  "v1.7.1"}' v1.7.1
check_version missing-tag '{"message":"Not Found"}' ''
check_version failed-request '' '' 22
