#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
# Linux amd64: Docker, curl, gzip, sha256sum and Python 3 are required.
set -euo pipefail
cd "$(dirname "$0")/.."
root=$PWD
out=$root/.cache/guest-measure
mkdir -p "$out"
. deploy/ci/images.env
bash scripts/guest-measure-inputs.sh "$out/inputs"
start=$(date +%s%N)
"$out/inputs/javy" build -o "$out/javascript.wasm" examples/debuglets/javascript/hello.js
printf 'javascript\t%d\n' "$((($(date +%s%N)-start)/1000000))" > "$out/build-ms.tsv"
docker run --rm --init --cpus 3 --memory 5g \
    -v "$out:/out" ghcr.io/webassembly/wasi-sdk:wasi-sdk-25@sha256:fdebde86990902087ecc470bf993ffec4d646e8fbd2e68c290a44120437622d0 \
    /opt/wasi-sdk/bin/llvm-strip --strip-all -o /out/python.wasm /out/inputs/python/python.wasm
# This mount is a diagnostic comparison only; executor guests have no filesystem.
mkdir -p "$out/stdlib-root/usr/local"
cp -R "$out/inputs/python/lib" "$out/stdlib-root/usr/local/"
docker run --rm --init --cpus 3 --memory 5g \
    -v "$root:/src" -w /src -e GOTOOLCHAIN=local -e GOMAXPROCS=3 \
    -v debuglet-ci-go-mod:/go/pkg/mod -v debuglet-ci-go-build:/go/build-cache \
    -e GOCACHE=/go/build-cache "${DEBUGLET_CI_BASE_IMAGE}@${DEBUGLET_CI_BASE_DIGEST}" bash -ceu '
    out=.cache/guest-measure
    go version > "$out/toolchain.txt"
    go list -m github.com/tetratelabs/wazero >> "$out/toolchain.txt"
    go build -buildvcs=false -o "$out/measure" ./tools/guest-measure
    for kind in cold warm; do
        start=$(date +%s%N)
        GOCACHE=/tmp/guest-go-cache GOOS=wasip1 GOARCH=wasm \
            go build -buildvcs=false -trimpath -o "$out/go.wasm" ./examples/debuglets/go/hello-local
        printf "go-%s\t%d\n" "$kind" "$((($(date +%s%N)-start)/1000000))" >> "$out/build-ms.tsv"
    done
    for i in 1 2 3 4 5; do
        "$out/measure" "$out/go.wasm" > "$out/go-$i.json"
        "$out/measure" "$out/javascript.wasm" > "$out/javascript-$i.json"
        if "$out/measure" "$out/python.wasm" python -c "print('\''Hello from Debuglet! (Python)'\'')" > "$out/python-$i.json"; then
            echo "Python unexpectedly started without its standard library" >&2; exit 1
        else
            test "$?" -eq 1
        fi
    done
    for i in 1 2 3; do
        "$out/measure" -stdlib-root "$out/stdlib-root" "$out/python.wasm" \
            python -c "print('\''Hello from Debuglet! (Python)'\'')" > "$out/python-filesystem-$i.json"
    done
    sha256sum "$out"/*.wasm > "$out/modules.sha256"
    '
python3 - "$out" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
for name in ('go', 'javascript', 'python', 'python-filesystem'):
    for i in range(1, 4 if name == 'python-filesystem' else 6):
        result = json.loads((out / f'{name}-{i}.json').read_text())
        assert result['filesystem_mounted'] == (name == 'python-filesystem'), result
        assert not result['non_wasi_imports'], result
        if name == 'python':
            assert result['error'] == 'module closed with exit_code(1)', result
            assert 'Fatal Python error: Failed to import encodings module' in result['stderr'], result
            assert not result['stdout'] and result['first_stdout_ms'] is None, result
        else:
            assert not result['error'] and 'Hello from Debuglet!' in result['stdout'], result
            assert result['first_stdout_ms'] is not None, result
    print(name, result['bytes'], 'bytes;', result['maxrss_kib'], 'KiB peak RSS')
PY
printf 'Measurements: %s\n' "$out"
