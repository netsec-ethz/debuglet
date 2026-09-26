// http_get — plaintext HTTP/1.0 request, written with the Debuglet Go SDK.
//
// Sends one GET over a TCP connection and reports the status line and the sizes
// of the response. It speaks just enough HTTP to be readable; it is not an HTTP
// client library. Use ConnectTLS for HTTPS, which needs a target with a
// certificate the executor's system roots trust.
//
// Build and run:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/http_get
//	dbl run --wasm examples/debuglets/go/http_get/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 127.0.0.1 --wait -- -addr 127.0.0.1:8080 -path /
//
// The destination must be in the job's --allow list. "Connection: close" makes
// the server end the stream, which the guest reads as a normal io.EOF.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var (
	addr = flag.String("addr", "127.0.0.1:8080", "HTTP server (host:port)")
	path = flag.String("path", "/", "request path")
	host = flag.String("host", "", "Host header (defaults to -addr)")
)

func main() {
	flag.CommandLine.Parse(os.Args)

	header := *host
	if header == "" {
		header = *addr
	}
	fmt.Printf("GET %s from %s\n", *path, *addr)

	conn, err := debuglet.ConnectTCP(*addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	request := fmt.Appendf(nil, "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", *path, header)
	start := time.Now()
	if err := conn.Write(request); err != nil {
		fmt.Printf("write error=%v\n", err)
		os.Exit(1)
	}

	// Read returns io.EOF when the server closes, so ReadAll terminates.
	response, err := io.ReadAll(conn)
	elapsed := time.Since(start)
	if err != nil {
		fmt.Printf("read error=%v\n", err)
		os.Exit(1)
	}
	if len(response) == 0 {
		fmt.Println("empty response")
		os.Exit(1)
	}

	status, rest, _ := bytes.Cut(response, []byte("\r\n"))
	head, body, split := bytes.Cut(rest, []byte("\r\n\r\n"))
	if !split {
		fmt.Println("response has no header terminator")
		os.Exit(1)
	}
	fmt.Printf("status=%s\n", status)
	fmt.Printf("header_bytes=%d body_bytes=%d\n", len(head), len(body))
	fmt.Printf("elapsed_ms=%.3f\n", float64(elapsed)/float64(time.Millisecond))
}
