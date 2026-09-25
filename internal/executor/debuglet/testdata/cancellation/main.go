// This real Go/WASI fixture is built from tracked source by lifecycle tests.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

var result uint64

func main() {
	mode := flag.String("mode", "", "cpu, read or output")
	addr := flag.String("addr", "", "owned loopback peer")
	if err := flag.CommandLine.Parse(os.Args); err != nil {
		panic(err)
	}
	switch *mode {
	case "cpu":
		fmt.Println("CPU READY")
		for {
			result++
		}
	case "read":
		conn, err := debuglet.ConnectTCP(*addr)
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		if err := conn.Write([]byte("READ READY\n")); err != nil {
			panic(err)
		}
		_, err = conn.Read(make([]byte, 1))
		panic(fmt.Sprintf("read unexpectedly returned: %v", err))
	case "output":
		fmt.Println("OUTPUT READY")
		for {
			fmt.Println("OUTPUT BLOCK")
		}
	default:
		panic("missing mode")
	}
}
