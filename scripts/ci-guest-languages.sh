#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
# Rebuild experimental bindings and test fresh consumers on the real host.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out=$root/.cache/guest-languages
mkdir -p "$out"
. deploy/ci/images.env
rust=rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f
wasi=ghcr.io/webassembly/wasi-sdk:wasi-sdk-25@sha256:fdebde86990902087ecc470bf993ffec4d646e8fbd2e68c290a44120437622d0
scratch=$(mktemp -d)
cleanup() {
    docker run --rm -v "$scratch:/out" "$wasi" chown -R "$(id -u):$(id -g)" /out
    rm -rf -- "$scratch"
}
trap cleanup EXIT

docker run --rm --init --cpus 3 --memory 5g \
    -v "$root:/src:ro" -v "$scratch:/out" -w /src "$wasi" bash -ceu '
    export PATH=/opt/wasi-sdk/bin:$PATH
    clang --version
    clang --target=wasm32-wasip1 -Oz -s -Wall -Werror \
        -o /out/guest_c.wasm pkg/debuglet/testdata/guest_c/main.c
    mkdir /out/c-consumer
    cp examples/debuglets/c/common/debuglet_api.h LICENSE /out/c-consumer/
    sed '\''s|../../../../examples/debuglets/c/common/debuglet_api.h|debuglet_api.h|'\'' \
        pkg/debuglet/testdata/guest_c/main.c > /out/c-consumer/main.c
    clang --target=wasm32-wasip1 -Oz -s -Wall -Werror \
        -o /out/consumer_c.wasm /out/c-consumer/main.c
    '
docker run --rm --init --cpus 3 --memory 5g \
    -v "$root:/src:ro" -v "$scratch:/out" -w /src "$rust" bash -ceu '
    rustc --version
    rustup target add wasm32-wasip1
    export CARGO_TARGET_DIR=/out/target
    export RUSTFLAGS=--remap-path-prefix=/src/=
    cargo build --release --locked --target wasm32-wasip1 \
        --manifest-path pkg/debuglet/testdata/guest_rust/Cargo.toml
    cp /out/target/wasm32-wasip1/release/guest_rust.wasm /out/
    cargo package --allow-dirty --no-verify \
        --manifest-path examples/debuglets/rust/debuglet/Cargo.toml
    mkdir /out/package
    tar -xf /out/target/package/debuglet-0.1.0.crate -C /out/package
    cmp LICENSE /out/package/debuglet-0.1.0/LICENSE
    cargo new --bin --vcs none /out/rust-consumer
    cp pkg/debuglet/testdata/guest_rust/src/main.rs /out/rust-consumer/src/main.rs
    printf '\''debuglet = { path = "/out/package/debuglet-0.1.0" }\n'\'' >> /out/rust-consumer/Cargo.toml
    cargo build --release --target wasm32-wasip1 --manifest-path /out/rust-consumer/Cargo.toml
    cp /out/target/wasm32-wasip1/release/rust-consumer.wasm /out/consumer_rust.wasm
    '
for language in c rust; do
    cmp "$scratch/guest_$language.wasm" "pkg/debuglet/testdata/guest_$language/guest_$language.wasm"
    cp "$scratch/consumer_$language.wasm" "$out/"
done
cp "$scratch/target/package/debuglet-0.1.0.crate" "$out/"
tar -czf "$out/debuglet-c-source.tar.gz" -C "$scratch/c-consumer" debuglet_api.h LICENSE
docker run --rm --init --cpus 3 --memory 5g \
    -v "$root:/src" -w /src -e GOTOOLCHAIN=local -e GOMAXPROCS=3 \
    -e DEBUGLET_FOREIGN_CONSUMER_DIR=/src/.cache/guest-languages \
    -v debuglet-ci-go-mod:/go/pkg/mod -v debuglet-ci-go-build:/go/build-cache \
    -e GOCACHE=/go/build-cache "${DEBUGLET_CI_BASE_IMAGE}@${DEBUGLET_CI_BASE_DIGEST}" \
    go test -json ./pkg/debuglet -run 'TestForeignGuestsOnCurrentHost|TestBuiltForeignConsumersOnCurrentHost' \
        -count=1 -timeout=120s > "$out/tests.json"
sha256sum "$out"/*.wasm "$out"/*.crate "$out"/*.tar.gz > "$out/artifacts.sha256"
cat "$out/artifacts.sha256"
