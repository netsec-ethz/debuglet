// send_udp — UDP sender, written with the Debuglet Go SDK.
//
// Sends -count datagrams to -addr on a connected UDP socket. No reply is read,
// so the output only reports what the guest handed to the host.
//
// Build and run:
//
//	make wasm SAMPLE_DIR=examples/debuglets/go/send_udp
//	dbl run --wasm examples/debuglets/go/send_udp/debuglet.wasm \
//	  --executor EXECUTOR_ID --allow 127.0.0.1 --wait -- -addr 127.0.0.1:9000 -count 5
//
// The destination must be in the job's --allow list.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var (
	addr    = flag.String("addr", "127.0.0.1:9000", "UDP destination (host:port)")
	count   = flag.Int("count", 5, "number of datagrams to send")
	payload = flag.String("payload", "hello", "datagram payload")
)

func main() {
	flag.CommandLine.Parse(os.Args)

	conn, err := debuglet.ConnectUDP(*addr)
	if err != nil {
		fmt.Printf("connect error=%v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	for seq := 0; seq < *count; seq++ {
		if err := conn.Write([]byte(*payload)); err != nil {
			fmt.Printf("send seq=%d error=%v\n", seq, err)
			os.Exit(1)
		}
	}
	fmt.Printf("sent=%d bytes=%d to=%s\n", *count, *count*len(*payload), *addr)
}
