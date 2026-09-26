// latency — TCP round-trip latency, written with the Debuglet Go SDK.
//
// Opens one TCP connection per round trip to -addr, sends -probe, waits for the
// first reply bytes and reports the elapsed time. The target must answer with at
// least one byte; a line-oriented echo service is enough.
//
// Build and run:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/latency
//	dbl run --wasm examples/debuglets/go/latency/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 127.0.0.1 --wait -- -addr 127.0.0.1:8080 -count 3
//
// The destination must be in the job's --allow list; a destination outside it
// ends the job without guest output past the connect line.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var (
	addr  = flag.String("addr", "127.0.0.1:8080", "TCP target that echoes a reply (host:port)")
	count = flag.Int("count", 3, "number of round trips")
	probe = flag.String("probe", "PING\n", "bytes to send on each round trip")
)

func main() {
	// WASI argv carries no program name, so os.Args is parsed as-is.
	flag.CommandLine.Parse(os.Args)

	fmt.Printf("target=%s count=%d\n", *addr, *count)

	var samples []time.Duration
	for seq := 0; seq < *count; seq++ {
		rtt, n, err := roundTrip()
		if err != nil {
			fmt.Printf("rtt seq=%d error=%v\n", seq, err)
			continue
		}
		samples = append(samples, rtt)
		fmt.Printf("rtt seq=%d bytes=%d ms=%.3f\n", seq, n, milliseconds(rtt))
	}
	if len(samples) == 0 {
		fmt.Println("no round trip completed")
		os.Exit(1)
	}

	low, high, total := samples[0], samples[0], time.Duration(0)
	for _, rtt := range samples {
		if rtt < low {
			low = rtt
		}
		if rtt > high {
			high = rtt
		}
		total += rtt
	}
	fmt.Printf("summary samples=%d min_ms=%.3f avg_ms=%.3f max_ms=%.3f\n",
		len(samples), milliseconds(low), milliseconds(total/time.Duration(len(samples))), milliseconds(high))
}

// roundTrip measures connect, send and first reply as one round trip.
func roundTrip() (time.Duration, int, error) {
	start := time.Now()
	conn, err := debuglet.ConnectTCP(*addr)
	if err != nil {
		return 0, 0, err
	}
	defer conn.Close()

	if err := conn.Write([]byte(*probe)); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	rtt := time.Since(start)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, 0, err
	}
	if n == 0 {
		return 0, 0, errors.New("target closed the connection without replying")
	}
	return rtt, n, nil
}

func milliseconds(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
