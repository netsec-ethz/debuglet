// listen_tcp — inbound TCP echo server, written with the Debuglet Go SDK.
//
// Publishes the job's TCP listener address, serves -count connections and
// echoes the first chunk each client sends. The job must request a TCP listener
// and the executor must have a public host and port range configured;
// otherwise the listener address is unavailable and the guest exits.
//
// Build:
//
//	make wasm SAMPLE_DIR=local/wasm_samples/go/listen_tcp
//
// A listener is requested through the policy of a submission, which `dbl run`
// does not expose: submit this guest with the Go client SDK (client.Policy's
// ListenTCP) or through the dispatcher API.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var count = flag.Int("count", 1, "number of connections to serve before exiting")

func main() {
	flag.CommandLine.Parse(os.Args)

	addr, err := debuglet.ListenAddr()
	if err != nil {
		fmt.Printf("listener error=%v\n", err)
		os.Exit(1)
	}
	// Clients connect to this address; print it before blocking on Accept.
	fmt.Printf("listening on %s\n", addr)

	for seq := 0; seq < *count; seq++ {
		if err := serve(seq); err != nil {
			fmt.Printf("connection seq=%d error=%v\n", seq, err)
			os.Exit(1)
		}
	}
	fmt.Printf("served=%d\n", *count)
}

// serve accepts one connection, echoes its first chunk and closes.
func serve(seq int) error {
	conn, err := debuglet.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()

	if remote, err := conn.RemoteAddr(); err == nil {
		fmt.Printf("client seq=%d remote=%s\n", seq, remote)
	}
	buf := make([]byte, 4096)
	// A clean close by the client is io.EOF with no bytes, not a failure.
	n, err := conn.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	fmt.Printf("received seq=%d bytes=%d\n", seq, n)
	if n == 0 {
		return nil
	}
	return conn.Write(buf[:n])
}
