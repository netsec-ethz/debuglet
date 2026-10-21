// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func require(ok bool, args ...any) {
	if !ok {
		panic(fmt.Sprint(args...))
	}
}

func main() {
	buf := make([]byte, 4)
	for _, timeout := range []time.Duration{-1, 10 * time.Millisecond} {
		_, err := debuglet.ReceiveUDPTimeout(buf, timeout)
		require(errors.Is(err, debuglet.ErrTimeout), err)
	}
	if os.Args[0] == "timeout" {
		fmt.Println("UDP timeout recovered")
		return
	}
	address, err := debuglet.ListenUDPAddr()
	require(err == nil, err)
	fmt.Println("ready", address)
	for i := 0; i < 3; i++ {
		packet, err := debuglet.ReceiveUDPTimeout(buf, 5*time.Second)
		require(err == nil, err)
		if i == 0 {
			require(packet.N == 4 && packet.Size == 10 && packet.Truncated && string(buf) == "LONG", packet, string(buf))
		}
		if i == 1 {
			require(packet.N == 0 && packet.Size == 0 && !packet.Truncated, packet)
		}
		if i == 2 {
			require(packet.N == 4 && packet.Size == 4 && !packet.Truncated && string(buf) == "PING", packet, string(buf))
		}
		reply := []byte("PONG")
		if i == 1 {
			reply = nil
		}
		n, err := debuglet.ReplyUDPTimeout(packet.From, reply, time.Second)
		require(err == nil && n == len(reply), n, err)
	}
	_, err = debuglet.ReceiveUDPTimeout(nil, time.Millisecond)
	require(errors.Is(err, debuglet.ErrTimeout), err)
	fmt.Println("UDP truncation, empty datagram and same-port replies passed")
}
