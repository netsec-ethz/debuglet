// throughput — TCP throughput sender, written with the Debuglet Go SDK.
//
// Read the respective README.md for more information on how to use this sample.
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

type Bitrate uint64

func (b Bitrate) Bytes() uint64 { return (uint64(b) + 7) / 8 }
func FromBytes(b int64) Bitrate { return Bitrate(b * 8) }

func (b Bitrate) String() string {
	bytes := b.Bytes()
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%.1fGiB", float64(bytes)/float64(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%.1fMiB", float64(bytes)/float64(1<<20))
	case bytes >= 1<<10:
		return fmt.Sprintf("%.1fKiB", float64(bytes)/float64(1<<10))
	default:
		return fmt.Sprintf("%dB", uint64(bytes))
	}
}

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
	start := time.Now()
	for time.Now().Before(deadline) {
		if err := conn.Write(buf); err != nil {
			fmt.Printf("[-] send failed after %d bytes: %v\n", sent, err)
			os.Exit(1)
		}
		sent += int64(len(buf))
	}

	fmt.Printf("[+] sent %s in %s (%s/s)\n", FromBytes(sent), time.Since(start).Round(time.Millisecond), FromBytes(sent/int64(*secs)))
}
