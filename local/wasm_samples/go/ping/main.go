// ping — ICMPv4 latency probe, written with the Debuglet Go SDK.
//
// Sends `-iter` ICMP echo requests to `-addr` (one per second) and prints the
// round-trip time of each reply. Build with:
//
//	make wasm SAMPLE_DIR=local/wasm_samples/go/ping
//
// Run (args after `--` are passed verbatim to the guest):
//
//	dbl run --wasm local/wasm_samples/go/ping/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 1.1.1.1 --wait -- -addr 1.1.1.1 -iter 5
//
// ICMP needs a raw socket, so the executor must be allowed to open one; on an
// executor without that permission the connect call ends the job. The address
// must also be in the job's --allow list, and only addresses you are
// authorized to probe belong there.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var (
	addr = flag.String("addr", "1.1.1.1", "IPv4 address to ping")
	iter = flag.Int("iter", 5, "number of echo requests to send")
)

func main() {
	// WASI argv has no program name, so parse os.Args as-is.
	flag.CommandLine.Parse(os.Args)

	for seq := 0; seq < *iter; seq++ {
		rtt, err := ping(1, uint16(seq))
		if err != nil {
			fmt.Printf("icmp_seq=%d  error: %v\n", seq, err)
		} else {
			fmt.Printf("icmp_seq=%d  time=%v\n", seq, rtt)
		}
		// Pace at roughly one ping per second.
		time.Sleep(time.Second - min(time.Second, rtt))
	}
}

// echoPacket builds a minimal ICMP echo request (type 8) with the checksum set.
func echoPacket(id, seq uint16, size int) []byte {
	p := make([]byte, size)
	p[0] = 8 // type: echo request
	binary.BigEndian.PutUint16(p[4:6], id)
	binary.BigEndian.PutUint16(p[6:8], seq)
	binary.BigEndian.PutUint16(p[2:4], checksum(p))
	return p
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func ping(id, seq uint16) (time.Duration, error) {
	conn, err := debuglet.ConnectICMP4(*addr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	start := time.Now()
	if err := conn.Write(echoPacket(id, seq, 64)); err != nil {
		return 0, err
	}

	buf := make([]byte, 100)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil {
		return 0, err
	}
	if n < 20 {
		return 0, fmt.Errorf("short reply: %d bytes (missing IP header)", n)
	}
	return rtt, nil
}
