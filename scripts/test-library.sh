#!/bin/sh
# Compile an external consumer that imports only the public TriageGuard facade.
set -eu

if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'This smoke test requires Linux (Go 1.27.4 and GNU coreutils).' >&2
    exit 2
fi
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GONOPROXY=none GOWORK=off
if [ "$(go env GOVERSION)" != go1.27.4 ]; then
    printf '%s\n' 'Use the pinned Go 1.27.4 toolchain; prepare dependencies before this offline run.' >&2
    exit 2
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
work=$(mktemp -d "${TMPDIR:-/tmp}/triageguard-library.XXXXXX")
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
mkdir "$work/consumer"
cp examples/go-check/main.go "$work/consumer/main.go"
cp go.sum "$work/consumer/go.sum"
printf '%s\n' 'module example.com/triageguard-consumer' '' 'go 1.27.0' '' \
    'require github.com/firmdura/triageguard v0.0.0' > "$work/consumer/go.mod"
(
    cd "$work/consumer"
    go mod edit "-replace=github.com/firmdura/triageguard=$repo"
    go build -mod=mod -trimpath -buildvcs=false -o "$work/library-check" .
)

check_run() {
    run_label=$1
    run_want=$2
    run_expected=$3
    shift 3
    run_exit=0
    "$@" > "$work/$run_label.out" 2> "$work/$run_label.err" || run_exit=$?
    if [ "$run_exit" -ne "$run_want" ]; then
        cat "$work/$run_label.err" >&2
        printf '%s\n' "$run_label: expected exit $run_want, got $run_exit" >&2
        exit 1
    fi
    if [ -s "$work/$run_label.err" ]; then
        cat "$work/$run_label.err" >&2
        exit 1
    fi
    cmp "$run_expected" "$work/$run_label.out"
}

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
        expected="testdata/demo/expected/$case_name.$extension"
        check_run "$case_name-$extension-cli" "$want_exit" "$expected" \
            "$work/triageguard" check --manifest examples/firmware/decisions.yaml \
            --root "$case_root" --format "$report_format"
        check_run "$case_name-$extension-api" "$want_exit" "$expected" \
            "$work/library-check" examples/firmware/decisions.yaml "$case_root" "$report_format"
        cmp "$work/$case_name-$extension-cli.out" "$work/$case_name-$extension-api.out"
    done
    printf '%s\n' "$case_name: external module and CLI agree; exit $want_exit, JSON and Markdown"
done
snapshot_inputs > "$work/inputs.after"
cmp "$work/inputs.before" "$work/inputs.after"
printf '%s\n' 'External-module import passed; original fixture bytes and metadata are unchanged.'
