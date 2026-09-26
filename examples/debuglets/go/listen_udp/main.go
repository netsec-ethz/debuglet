// listen_udp — inbound UDP receiver, written with the Debuglet Go SDK.
//
// Publishes the job's UDP listener address and reports -count datagrams with
// their senders. The job must request a UDP listener and the executor must have
// a public host and port range configured.
//
// Build:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/listen_udp
//
// A listener is requested through the policy of a submission, which `dbl run`
// does not expose: submit this guest with the Go client SDK (client.Policy's
// ListenUDP) or through the dispatcher API.
//
// ReadFromUDP has no deadline of its own: with no datagram to read, the guest
// waits until the job's execution budget ends it.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var count = flag.Int("count", 1, "number of datagrams to report before exiting")

func main() {
	flag.CommandLine.Parse(os.Args)

	addr, err := debuglet.ListenUDPAddr()
	if err != nil {
		fmt.Printf("listener error=%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("listening on %s\n", addr)

	buf := make([]byte, 2048)
	for seq := 0; seq < *count; seq++ {
		n, from, err := debuglet.ReadFromUDP(buf)
		if err != nil {
			fmt.Printf("datagram seq=%d error=%v\n", seq, err)
			os.Exit(1)
		}
		fmt.Printf("received seq=%d bytes=%d from=%s\n", seq, n, from)
	}
	fmt.Printf("received=%d\n", *count)
}
