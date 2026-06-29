// throughput — TCP throughput sender, written with the Debuglet Go SDK.
//
// Connects to `-addr` and sends fixed-size chunks for `-secs` seconds, then
// reports the achieved throughput in Mbps. Pair it with any TCP sink (e.g. an
// iperf server, or `nc -l -k <port> >/dev/null`).
//
// Build:
//
//	make wasm SAMPLE_DIR=local/wasm_samples/go/throughput
//
// Run:
//
//	go run ./cmd/user -wasm local/wasm_samples/go/throughput/debuglet.wasm -- -addr 127.0.0.1:5201 -secs 5
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"debuglet/pkg/debuglet"
)

var (
	addr  = flag.String("addr", "127.0.0.1:5201", "TCP sink to send to (host:port)")
	secs  = flag.Int("secs", 5, "duration to send for, in seconds")
	chunk = flag.Int("chunk", 4096, "send buffer size in bytes")
)

func main() {
	flag.CommandLine.Parse(os.Args)

	fmt.Printf("[*] throughput: sending to %s for %ds (chunk=%dB)\n", *addr, *secs, *chunk)

	conn, err := debuglet.ConnectTCP(*addr)
	if err != nil {
		fmt.Printf("[-] %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	buf := make([]byte, *chunk)
	for i := range buf {
		buf[i] = 'A'
	}

	deadline := time.Now().Add(time.Duration(*secs) * time.Second)
	var sent int64
	for time.Now().Before(deadline) {
		if err := conn.Send(buf); err != nil {
			fmt.Printf("[-] send failed after %d bytes: %v\n", sent, err)
			os.Exit(1)
		}
		sent += int64(len(buf))
	}

	elapsed := float64(*secs)
	mbps := float64(sent) * 8.0 / (elapsed * 1e6)
	fmt.Printf("[+] sent %d bytes in %.0fs (%.2f Mbps)\n", sent, elapsed, mbps)
}
