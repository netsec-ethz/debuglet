# Testing Throughput

Connects to `-addr` and sends fixed-size chunks for `-secs` seconds, then reports the achieved throughput. Pair it with any TCP sink (e.g. an iperf server, or `nc -l -k <port> >/dev/null`).

## Build

```sh
make wasm SAMPLE_DIR=local/wasm_samples/go/throughput
```

## Test Locally

To use the sample locally, it is important to take note of HOW the executor is running. If the executor has root permissions and EBPF enabled, it will
indicate so in the logs:

```sh
Initialized packet counter	{"type": "ebpf"}
```

Having the EBPF implementation work correctly locally extra steps are required. Head to [EBPF Setup](#ebpf-setup) for instructions on how to setup the local system so that packets are routed correctly and ratelimited accordingly.

If it was disabled or there was a failure, the executor won't use EBPF and fallback to a Go implementation:

```sh
Initialized packet counter	{"type": "fallback"}
```

## EBPF Setup

The local loopback (`lo`) network interface behaves differently for EBPF and does not correctly handle all packets. Instead, create a virtual network interface which can be used to bypass any of the issues:

```sh
# Create a new network namespace and a virtual ethernet pair
sudo ip netns add ebpf-test
sudo ip link add veth-host type veth peer name veth-ns
sudo ip link set veth-ns netns ebpf-test
sudo ip addr add 192.168.100.1/24 dev veth-host
sudo ip netns exec ebpf-test ip addr add 192.168.100.2/24 dev veth-ns
sudo ip link set veth-host up
sudo ip netns exec ebpf-test ip link set veth-ns up
sudo ip netns exec ebpf-test ip link set lo up

# Clean up and delete the namespace and interfaces afterwards
sudo ip link delete veth-host
sudo ip netns del ebpf-test
```

This also means the executor has to be configured to attach any EBPF hooks on the `veth-host` interface. Add the following to the `executor.toml` config:

```toml
# executor.toml
network_interface = "veth-host"
```

**IMPORTANT:** Launch the executor using `make e EBPF=1` .

### Listener

We start a very simple listener which will listen on `192.168.100.2` and report the throughput it receives.

```sh
sudo ip netns exec ebpf-test sh -c "socat -u TCP-LISTEN:8080,bind=192.168.100.2,reuseaddr,fork - | pv -i 1 -f -F '%t %r %b\n' > /dev/null"
```

### Start debuglet

```sh
go run ./cmd/user \
    -wasm local/wasm_samples/go/throughput/debuglet.wasm \
    -addr 192.168.100.2 \
    -floor 20000 \
    -ceil 100000 \
    -- -addr 192.168.100.2:8080 -secs 20 -chunk 128
```

## Non-EBPF Fallback

The fallback does not directly interact with the network interface, so it is not necessary to create a virtual network interface. The executor can be launched without root privileges using `make e`.

### Listener

The listener can be started on the loopback interface:

```sh
sudo sh -c "socat -u TCP-LISTEN:8080,reuseaddr,fork - | pv -i 1 -f -F '%t %r %b\n' > /dev/null"
```

### Start debuglet

```sh
go run ./cmd/user \
    -wasm local/wasm_samples/go/throughput/debuglet.wasm \
    -addr 127.0.0.1 \
    -floor 20000 \
    -ceil 100000 \
    -- -addr 127.0.0.1:8080 -secs 20 -chunk 128
```
