#!/usr/bin/env bash
# Shared pinned runtime settings for verification and local release packaging.

tg_image='golang@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea'
tg_platform='linux/arm64'
tg_cache_volume=${TRIAGEGUARD_CACHE_VOLUME:-triageguard-go1.27.4-cache}

tg_require_prepared() {
    if ! docker image inspect "$tg_image" >/dev/null 2>&1; then
        printf '%s\n' 'Pinned Linux image is not present. Run ./scripts/verify-linux.sh prepare first.' >&2
        return 2
    fi
    if ! docker volume inspect "$tg_cache_volume" >/dev/null 2>&1; then
        printf '%s\n' 'Prepared dependency cache is not present. Run ./scripts/verify-linux.sh prepare first.' >&2
        return 2
    fi
}

tg_container() {
    local network=$1 proxy=off sumdb=off
    shift
    if [ "$network" = bridge ]; then
        proxy=https://proxy.golang.org
        sumdb=sum.golang.org
    fi
    docker run --rm -i --pull=never --platform "$tg_platform" --network="$network" \
        --user "$(id -u):$(id -g)" \
        --mount "type=volume,src=$tg_cache_volume,dst=/cache" \
        -e GOTOOLCHAIN=local -e GOENV=off -e GOWORK=off -e GOFLAGS= \
        -e GOPROXY="$proxy" -e GOSUMDB="$sumdb" -e GONOPROXY=none -e GONOSUMDB= -e GOPRIVATE= \
        -e GOCACHE=/cache/gocache -e GOMODCACHE=/cache/gomod -e GOPATH=/cache/gopath \
        "$tg_image" "$@"
}
