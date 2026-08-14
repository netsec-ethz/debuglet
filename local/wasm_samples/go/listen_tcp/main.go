package main

import (
	"debuglet/pkg/debuglet"
)

//go:wasmimport env accept_tcp
func accept_tcp() int32

func main() {
	for {
		conn, err := debuglet.AcceptTCP()
		if err != nil {
			panic(err)
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}
		println("received", n, "bytes")
		conn.Close()
	}
}
