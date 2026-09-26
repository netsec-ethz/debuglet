# TCP throughput sample

The guest connects to `-addr`, writes fixed-size chunks for `-secs` seconds, and prints the bytes sent and elapsed time. It needs a raw TCP sink that accepts bytes until the guest closes. It is not an iperf protocol client.

## Build

From the repository root:

```sh
make wasm SAMPLE_DIR=examples/debuglets/go/throughput
```

## Local example

Use an already configured local dispatcher and executor. For the simplest setup, configure the executor to use the `fallback` packet counter. In a separate terminal, run a loopback sink with `socat`:

```sh
socat -u TCP-LISTEN:8080,bind=127.0.0.1,reuseaddr,fork OPEN:/dev/null
```

Then submit to an ID from `dbl nodes`:

```sh
dbl --timeout 30s run \
  --wasm examples/debuglets/go/throughput/debuglet.wasm \
  --executor EXECUTOR_ID --allow 127.0.0.1 \
  --floor-bps 20000 --ceil-bps 100000 --duration 25s --wait \
  -- -addr 127.0.0.1:8080 -secs 20 -chunk 128
```

Replace `EXECUTOR_ID`; add `--endpoint` before the command if needed. Stop the sink when finished. Choose a guest duration shorter than the job budget and a client timeout long enough to observe completion.

A chunk larger than 8192 bytes is split across host calls, so `-chunk` changes
how many calls the guest makes rather than how much reaches the sink.

The output is application-level throughput for this setup. It does not establish eBPF packet enforcement or link capacity. Kernel measurements require an isolated test network, suitable privileges, and separate packet-level verification.
