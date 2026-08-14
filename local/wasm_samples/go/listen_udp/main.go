package main

import (
	"fmt"

	"debuglet/pkg/debuglet"
)

func main() {
	addr, err := debuglet.ListenUDPAddr()
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("listening on", addr)

	buf := make([]byte, 2048)
	for {
		n, from, err := debuglet.ReadFromUDP(buf)
		if err != nil {
			panic(err)
		}
		fmt.Println("received", n, "bytes from", from)
	}
}
