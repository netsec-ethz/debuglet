package main

import (
	"debuglet/pkg/debuglet"
	"flag"
	"os"
)

var (
	addr = flag.String("addr", "google.com:80", "address and port to contact")
)

func main() {
	flag.CommandLine.Parse(os.Args)

	conn, err := debuglet.ConnectUDP(*addr)
	if err != nil {
		panic(err)
	}

	for range 5 {
		conn.Write([]byte("hello"))
	}
}
