#!/usr/bin/env bash
# Build versioned local distribution archives from one clean committed source.
# No tags, releases, pushes, or repository visibility changes are performed.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=linux-common.sh
source "$repo/scripts/linux-common.sh"
cd "$repo"
version=${1:-v1.0.0}
output=${2:-"$repo/dist/$version"}
if [ "$#" -gt 2 ] || [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s\n' 'Usage: ./scripts/build-release.sh [v1.0.0 [OUTPUT_DIRECTORY]]' >&2
    exit 2
fi
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then
    printf '%s\n' 'Release packaging requires a clean committed worktree; verification can use pending source.' >&2
    exit 2
fi
git ls-tree -r --name-only -z HEAD | while IFS= read -r -d '' path; do
    case "/$path" in
        */AGENTS.md|*/SKILL.md|*/CLAUDE.md|*/GEMINI.md|*/copilot-instructions.md|*.instructions.md|\
        */.agents/*|*/.codex/*|/bin/*|/dist/*)
            printf '%s\n' "Refusing distribution containing local instructions/artifacts: $path" >&2
            exit 2 ;;
    esac
done
tg_require_prepared
if [ -e "$output" ] && { [ ! -d "$output" ] || [ -n "$(ls -A "$output")" ]; }; then
    printf '%s\n' 'Release output directory must be absent or empty.' >&2
    exit 2
fi
commit=$(git rev-parse HEAD)
epoch=$(git show -s --format=%ct HEAD)
name="triageguard-${version#v}"
work=$(mktemp -d "${TMPDIR:-/tmp}/triageguard-release.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM
git archive --format=tar --prefix="$name/" HEAD > "$work/source.tar"

tg_container none bash -ec '
    set -euo pipefail
    version=$1 commit=$2 epoch=$3 name=$4
    cat > /tmp/source.tar
    gzip -n -c /tmp/source.tar > /tmp/source.tar.gz
    mkdir /tmp/source /tmp/artifacts
    tar -xf /tmp/source.tar -C /tmp/source
    cd "/tmp/source/$name"
    test "$(go env GOVERSION)" = go1.27.4
    go mod verify >&2
    cmp licenses/go/LICENSE "$(go env GOROOT)/LICENSE"
    cmp licenses/go/PATENTS "$(go env GOROOT)/PATENTS"
    cmp licenses/yaml/LICENSE "$(go env GOMODCACHE)/go.yaml.in/yaml/v3@v3.0.4/LICENSE"
    cmp licenses/yaml/NOTICE "$(go env GOMODCACHE)/go.yaml.in/yaml/v3@v3.0.4/NOTICE"
    for arch in arm64 amd64; do
        package="$name-linux-$arch"
        stage="/tmp/$package"
        mkdir "$stage"
        CGO_ENABLED=0 GOOS=linux GOARCH="$arch" GOAMD64=v1 GOARM64=v8.0 GOEXPERIMENT= \
            go build -mod=readonly -trimpath -buildvcs=false \
            -ldflags="-s -w -buildid= -X main.version=$version" \
            -o "$stage/triageguard" ./cmd/triageguard
        cp LICENSE THIRD_PARTY_NOTICES.md "$stage/"
        cp -R licenses "$stage/licenses"
        printf "%s\n" "TriageGuard $version for Linux/$arch" \
            "Run ./triageguard --help to see the options and exit codes." \
            "To run it as triageguard, copy the executable into a directory on your PATH." \
            "An unchanged result means only that the recorded assumptions still match." \
            "It does not establish whether a CVE affects a product, whether a fix works," \
            "or whether the product is secure or compliant." \
            "Keep all inputs unchanged while a check runs. Review reports before sharing;" \
            "they can contain sensitive configuration values and review details." \
            "Source, documentation, and synthetic examples are in $name-source.tar.gz." \
            > "$stage/README.txt"
        printf "%s\n" "version=$version" "commit=$commit" "toolchain=go1.27.4" \
            "target=linux/$arch" "CGO_ENABLED=0" "GOAMD64=v1" "GOARM64=v8.0" \
            "flags=-mod=readonly -trimpath -buildvcs=false -s -w -buildid=" \
            > "$stage/BUILD-INFO.txt"
        chmod 0755 "$stage/triageguard"
        find "$stage" -type d -exec chmod 0755 {} +
        find "$stage" -type f ! -name triageguard -exec chmod 0644 {} +
        if [ "$arch" = arm64 ]; then
            test "$("$stage/triageguard" --version)" = "triageguard $version"
        fi
        tar --sort=name --mtime="@$epoch" --owner=0 --group=0 --numeric-owner \
            -C /tmp -cf - "$package" | gzip -n > "/tmp/artifacts/$package.tar.gz"
    done
    cp /tmp/source.tar.gz "/tmp/artifacts/$name-source.tar.gz"
    cd /tmp/artifacts
    sha256sum "$name-linux-amd64.tar.gz" "$name-linux-arm64.tar.gz" "$name-source.tar.gz" > SHA256SUMS
    sha256sum --check SHA256SUMS >&2
    tar -cf - .
' bash "$version" "$commit" "$epoch" "$name" < "$work/source.tar" > "$work/artifacts.tar"
mkdir -p "$output"
tar -xf "$work/artifacts.tar" -C "$output"
printf '%s\n' "Local $version distributions prepared from $commit in $output"
printf '%s\n' 'No release has been published; independently rebuild and verify checksums before delivery.'
