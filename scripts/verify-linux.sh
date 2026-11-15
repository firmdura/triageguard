#!/usr/bin/env bash
# Prepare explicitly with networking, then verify current source offline.
set -euo pipefail
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
# shellcheck source=linux-common.sh
source "$repo/scripts/linux-common.sh"
cd "$repo"

mode=${1:-check}
if [ "$#" -gt 1 ] || { [ "$mode" != prepare ] && [ "$mode" != check ]; }; then
    printf '%s\n' 'Usage: ./scripts/verify-linux.sh [prepare|check]' >&2
    exit 2
fi

if [ "$mode" = prepare ]; then
    docker pull --platform "$tg_platform" "$tg_image"
    docker volume create "$tg_cache_volume" >/dev/null
    docker run --rm --pull=never --platform "$tg_platform" --network=none \
        --mount "type=volume,src=$tg_cache_volume,dst=/cache" \
        "$tg_image" sh -ec 'mkdir -p /cache/gocache /cache/gomod /cache/gopath; chown -R "$1:$2" /cache' \
        sh "$(id -u)" "$(id -g)"
    COPYFILE_DISABLE=1 tar --no-xattrs -cf - go.mod go.sum | tg_container bridge sh -ec '
        mkdir /tmp/source
        tar -xf - -C /tmp/source
        cd /tmp/source
        go mod download
        go mod verify
    '
    printf '%s\n' 'Pinned image and dependency cache prepared. Offline verification: ./scripts/verify-linux.sh'
    exit 0
fi

tg_require_prepared
work=$(mktemp -d "${TMPDIR:-/tmp}/triageguard-verify.XXXXXX")
trap 'rm -rf "$work"' EXIT
trap 'exit 2' HUP INT TERM

# Include pending source changes during development. Git supplies the inventory,
# but the file bytes come from the worktree, never a possibly older HEAD archive.
# Local instruction/coordination files and generated artifacts are never sent.
git ls-files --cached --others --exclude-standard -z | while IFS= read -r -d '' path; do
    case "/$path" in
        */AGENTS.md|*/SKILL.md|*/CLAUDE.md|*/GEMINI.md|*/copilot-instructions.md|*.instructions.md|\
        */.git/*|*/.agents/*|*/.codex/*|/bin/*|/dist/*) continue ;;
    esac
    printf '%s\0' "$path"
done > "$work/source.list"
printf '%s\n' 'Verifying current worktree source in pinned Linux/arm64; network disabled.'
COPYFILE_DISABLE=1 tar --no-xattrs --null -T "$work/source.list" -cf - | tg_container none sh -ec '
    mkdir /tmp/source
    tar -xf - -C /tmp/source
    cd /tmp/source
    test "$(go env GOVERSION)" = go1.27.4
    go test ./... -count=1
    go test -race ./... -count=1
    go vet ./...
    go build -o bin/triageguard ./cmd/triageguard
    ./scripts/acceptance.sh
    ./scripts/test-library.sh
    ./scripts/demo.sh
'
printf '%s\n' 'Pinned offline Linux verification passed.'
