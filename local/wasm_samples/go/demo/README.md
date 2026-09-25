# Demo guest

This guest is packaged as `share/debuglet/demo.wasm` and run by `dbl demo`. It takes exactly two arguments, `[targetAddr, nonce]`, directly as WASI `os.Args` without a program-name element. The nonce is 16 random bytes encoded as 32 lowercase hexadecimal characters.

The guest connects through `pkg/debuglet` to the demo's loopback TCP target. It accumulates fragmented reads with a 4096-byte buffer and a 128-byte line limit, requires exactly `DEBUGLET/1 <nonce>\n`, and writes `ACK <nonce>\n`. After the target closes normally with no trailing data, it prints `DEBUGLET_DEMO_OK <nonce>\n`. A wrong reply, premature EOF, or socket failure exits unsuccessfully without that marker.

The package build compiles this source with Go 1.25.11, `CGO_ENABLED=0 GOOS=wasip1 GOARCH=wasm`, `-mod=readonly`, and `-trimpath`. The complete installed demo needs no compiler or checkout.
