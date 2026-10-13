// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func require(ok bool, values ...any) {
	if !ok {
		panic(fmt.Sprint(values...))
	}
}

func main() {
	for _, timeout := range []time.Duration{-1, 30 * time.Millisecond, 30 * time.Millisecond} {
		conn, err := debuglet.AcceptTCPTimeout(timeout)
		require(conn == nil && errors.Is(err, debuglet.ErrTimeout), conn, err)
	}
	if os.Args[0] == "no-input" {
		fmt.Println("bounded no-input exit")
		return
	}
	address, err := debuglet.ListenAddr()
	require(err == nil, err)
	fmt.Println("ready", address)
	conn, err := debuglet.AcceptTCPTimeout(3 * time.Second)
	require(err == nil, err)
	defer conn.Close()
	buf := make([]byte, 4)
	require(conn.SetReadDeadline(time.Now().Add(30*time.Millisecond)) == nil)
	n, err := conn.Read(buf)
	require(n == 0 && errors.Is(err, debuglet.ErrTimeout), n, err)
	require(conn.SetReadDeadline(time.Time{}) == nil)
	require(conn.SetWriteDeadline(time.Now().Add(time.Second)) == nil)
	n, err = conn.Write([]byte("PING"))
	require(n == 4 && err == nil, n, err)
	n, err = io.ReadFull(conn, buf)
	require(n == 4 && err == nil && string(buf) == "PONG", n, err, string(buf))
	require(conn.Close() == nil)
	n, err = conn.Read(buf)
	require(n == 0 && errors.Is(err, debuglet.ErrClosed), n, err)

	// The expired bounded accepts must not leave a deadline on the listener
	// used by the unchanged legacy API.
	fmt.Println("legacy", address)
	legacy, err := debuglet.AcceptTCP()
	require(err == nil, err)
	defer legacy.Close()
	n, err = io.ReadFull(legacy, buf)
	require(n == 4 && err == nil && string(buf) == "PING", n, err, string(buf))
	require(legacy.Write([]byte("PONG")) == nil)
	fmt.Println("bounded accept recovered and closed")
}
