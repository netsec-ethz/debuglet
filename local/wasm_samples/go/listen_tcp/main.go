package main

import (
	"fmt"

	"debuglet/pkg/debuglet"
)

func main() {
	addr, err := debuglet.ListenAddr()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("listening on", addr)

	for {
		conn, err := debuglet.AcceptTCP()
		if err != nil {
			panic(err)
		}
		if remote, err := conn.RemoteAddr(); err == nil {
			fmt.Println("client:", remote)
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
