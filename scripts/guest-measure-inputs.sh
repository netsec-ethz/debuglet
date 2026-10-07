#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 ETH Zurich
# Fetch the exact experimental runtimes measured in docs/development/guest-languages.md.
set -euo pipefail
out=${1:?usage: guest-measure-inputs.sh OUTPUT_DIRECTORY}
mkdir -p "$out"
curl --fail --location --retry 2 --max-time 120 \
    https://github.com/bytecodealliance/javy/releases/download/v9.1.0/javy-x86_64-linux-v9.1.0.gz \
    -o "$out/javy.gz"
curl --fail --location --retry 2 --max-time 120 \
    https://github.com/brettcannon/cpython-wasi-build/releases/download/v3.14.7/python-3.14.7-wasi_sdk-24.zip \
    -o "$out/python.zip"
(cd "$out" && sha256sum --check <<'SUMS'
a68b122d48eb3dfc1b801d4e14c39271fde3638243d3272d206e376ac9189e39  javy.gz
2e064d3fb8172471d39d741348efa722349c40b96301f69968dff714999c584b  python.zip
SUMS
)
gzip -dc "$out/javy.gz" > "$out/javy"
chmod +x "$out/javy"
python3 -m zipfile -e "$out/python.zip" "$out/python"
