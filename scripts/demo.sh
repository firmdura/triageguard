#!/bin/sh
# Run the synthetic walkthrough without modifying checked-in inputs.
set -eu

if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'This walkthrough requires Linux (Go 1.27.4 and GNU coreutils).' >&2
    exit 2
fi
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GONOPROXY=none GOWORK=off
if [ "$(go env GOVERSION)" != go1.27.4 ]; then
    printf '%s\n' 'Use the pinned Go 1.27.4 toolchain; prepare dependencies before this offline run.' >&2
    exit 2
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/triageguard-demo.XXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 2' HUP INT TERM
cd "$repo"

snapshot_inputs() {
    find examples/firmware testdata/demo -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    find examples/firmware testdata/demo -printf '%p %m %s %T@\n' | LC_ALL=C sort
}
snapshot_inputs > "$work/inputs.before"
sha256sum --check testdata/demo/known-bytes.sha256 > "$work/known-bytes.log"
go build -mod=readonly -trimpath -buildvcs=false -o "$work/triageguard" ./cmd/triageguard

for case_name in unchanged feature-enabled missing-evidence; do
    case_root="$work/$case_name"
    mkdir "$case_root"
    cp -R examples/firmware/evidence/. "$case_root/"
    case "$case_name" in
        unchanged) want_exit=0 ;;
        feature-enabled|missing-evidence)
            cp testdata/demo/feature-enabled.json "$case_root/build-config.json"
            want_exit=1
            if [ "$case_name" = missing-evidence ]; then
                rm "$case_root/src/parser.c"
                want_exit=2
            fi
            ;;
    esac
    for report_format in json markdown; do
        extension=$report_format
        if [ "$report_format" = markdown ]; then extension=md; fi
        actual="$work/$case_name.$extension"
        actual_exit=0
        "$work/triageguard" check --manifest examples/firmware/decisions.yaml \
            --root "$case_root" --format "$report_format" > "$actual" 2> "$work/stderr" || actual_exit=$?
        if [ "$actual_exit" -ne "$want_exit" ]; then
            cat "$work/stderr" >&2
            printf '%s\n' "$case_name/$report_format: expected exit $want_exit, got $actual_exit" >&2
            exit 1
        fi
        if [ -s "$work/stderr" ]; then
            cat "$work/stderr" >&2
            exit 1
        fi
        cmp "testdata/demo/expected/$case_name.$extension" "$actual"
    done
    printf '%s\n' "$case_name: exit $want_exit; JSON and Markdown match expected reports"
done
snapshot_inputs > "$work/inputs.after"
cmp "$work/inputs.before" "$work/inputs.after"
printf '%s\n' 'Original fixture bytes, modes, sizes and mtimes are unchanged.'
