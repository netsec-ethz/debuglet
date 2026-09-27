# TCP throughput example

This debuglet sends fixed-size chunks to a TCP sink for a chosen time and prints the bytes sent. It measures application-level throughput; it does not prove link capacity or packet-level enforcement.

## Run locally

Start a local sink in one terminal:

```sh
socat -u TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork OPEN:/dev/null
```

Build and submit in another:

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/throughput
dbl run --wasm examples/debuglets/go/throughput/debuglet.wasm \
  --allow 127.0.0.1 --duration 25s --wait \
  -- -addr 127.0.0.1:8080 -secs 20 -chunk 128
```

Keep the debuglet duration shorter than the submitted job budget. Stop the sink when finished.
