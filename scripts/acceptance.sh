#!/bin/sh
# End-to-end acceptance of the already-built CLI and a real public API consumer.
set -eu
if [ "$(uname -s)" != Linux ]; then
    printf '%s\n' 'Acceptance requires Linux; use ./scripts/verify-linux.sh.' >&2
    exit 2
fi
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GONOPROXY=none GOWORK=off GOENV=off
if [ "$(go env GOVERSION)" != go1.27.4 ]; then
    printf '%s\n' 'Acceptance requires the pinned Go 1.27.4 toolchain and prepared dependencies.' >&2
    exit 2
fi
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo"
binary="$repo/bin/triageguard"
if [ ! -x "$binary" ]; then
    printf '%s\n' 'Build the CLI first: go build -o bin/triageguard ./cmd/triageguard' >&2
    exit 2
fi
work=$(mktemp -d "${TMPDIR:-/tmp}/triageguard-acceptance.XXXXXX")
trap 'rm -rf "$work"' 0
trap 'exit 2' HUP INT TERM

snapshot() {
    find "$1" -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum
    find "$1" -printf '%p %m %s %T@\n' | LC_ALL=C sort
}
snapshot examples > "$work/original.before"
snapshot testdata >> "$work/original.before"
sha256sum --check testdata/demo/known-bytes.sha256 > "$work/known-bytes.log"

mkdir "$work/consumer"
cp examples/go-check/main.go "$work/consumer/main.go"
cp go.sum "$work/consumer/go.sum"
printf '%s\n' 'module example.com/triageguard-acceptance' '' 'go 1.27.0' '' \
    'require github.com/firmdura/triageguard v0.0.0' > "$work/consumer/go.mod"
(
    cd "$work/consumer"
    go mod edit "-replace=github.com/firmdura/triageguard=$repo"
    go build -mod=mod -trimpath -buildvcs=false -o "$work/api-check" .
)

run_report() {
    label=$1
    want=$2
    shift 2
    actual_exit=0
    "$@" > "$work/$label.out" 2> "$work/$label.err" || actual_exit=$?
    if [ "$actual_exit" -ne "$want" ] || [ -s "$work/$label.err" ]; then
        cat "$work/$label.err" >&2
        printf '%s\n' "$label: expected exit $want with report-only stdout, got $actual_exit" >&2
        exit 1
    fi
    test -s "$work/$label.out"
}

for case_name in unchanged feature-enabled missing-evidence malformed-export; do
    evidence="$work/$case_name"
    mkdir "$evidence"
    cp -R examples/firmware/evidence/. "$evidence/"
    case "$case_name" in
        unchanged) want=0 ;;
        feature-enabled|missing-evidence)
            cp testdata/demo/feature-enabled.json "$evidence/build-config.json"
            want=1
            if [ "$case_name" = missing-evidence ]; then
                rm "$evidence/src/parser.c"
                want=2
            fi
            ;;
        malformed-export)
            printf '%s\n' '{"FEATURE_X":"n","FEATURE_X":"n"}' > "$evidence/build-config.json"
            want=2
            ;;
    esac
    snapshot "$evidence" > "$work/evidence.before"
    for format in json markdown; do
        extension=$format
        if [ "$format" = markdown ]; then extension=md; fi
        run_report "$case_name-$format-first" "$want" "$binary" check \
            --manifest examples/firmware/decisions.yaml --root "$evidence" --format "$format"
        run_report "$case_name-$format-repeat" "$want" "$binary" check \
            --manifest examples/firmware/decisions.yaml --root "$evidence" --format "$format"
        run_report "$case_name-$format-api" "$want" "$work/api-check" \
            examples/firmware/decisions.yaml "$evidence" "$format"
        cmp "$work/$case_name-$format-first.out" "$work/$case_name-$format-repeat.out"
        cmp "$work/$case_name-$format-first.out" "$work/$case_name-$format-api.out"
        if [ "$case_name" != malformed-export ]; then
            cmp "testdata/demo/expected/$case_name.$extension" "$work/$case_name-$format-first.out"
        fi
    done
    if [ "$case_name" = malformed-export ]; then
        grep -q '"reason": "invalid-export"' "$work/$case_name-json-first.out"
        grep -q '"status": "unverifiable"' "$work/$case_name-json-first.out"
    fi
    snapshot "$evidence" > "$work/evidence.after"
    cmp "$work/evidence.before" "$work/evidence.after"
    printf '%s\n' "$case_name: exit $want; deterministic JSON/Markdown; CLI/API parity; inputs unchanged"
done

printf '%s\n' 'schema_version: 1' 'decisions: []' > "$work/invalid.yaml"
actual_exit=0
"$binary" check --manifest "$work/invalid.yaml" --root examples/firmware/evidence \
    > "$work/invalid.out" 2> "$work/invalid.err" || actual_exit=$?
if [ "$actual_exit" -ne 2 ] || [ -s "$work/invalid.out" ] || [ ! -s "$work/invalid.err" ]; then
    printf '%s\n' 'Invalid whole manifest did not return diagnostic-only exit 2.' >&2
    exit 1
fi
snapshot examples > "$work/original.after"
snapshot testdata >> "$work/original.after"
cmp "$work/original.before" "$work/original.after"
printf '%s\n' 'Acceptance passed; checked-in input bytes and metadata are unchanged.'
