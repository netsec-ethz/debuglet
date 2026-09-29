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
	mode, address := os.Args[0], os.Args[1]
	if mode == "refused" || mode == "connect-timeout" || mode == "connect-reset" || mode == "denied" {
		network, want := "tcp", debuglet.ErrRefused
		if mode == "connect-timeout" {
			network, want = "tls", debuglet.ErrTimeout
		}
		if mode == "connect-reset" {
			network, want = "tls", debuglet.ErrReset
		}
		if mode == "denied" {
			want = debuglet.ErrDenied
		}
		_, err := debuglet.DialTimeout(network, address, 100*time.Millisecond)
		require(errors.Is(err, want), err)
		fmt.Println("handled", mode)
		return
	}
	network := "tcp"
	if mode == "datagram" {
		network = "udp"
	}
	s, err := debuglet.Dial(network, address)
	require(err == nil, err)
	defer s.Close()
	buf := make([]byte, 16)
	switch mode {
	case "datagram":
		n, err := s.Write(make([]byte, debuglet.MaxIOBytes+1))
		require(n == 0 && errors.Is(err, debuglet.ErrTooLarge), n, err)
		n, err = s.Write([]byte("PING"))
		require(n == 4 && err == nil, n, err)
		n, err = s.Write(nil)
		require(n == 0 && err == nil, n, err)
		n, err = s.Read(buf)
		require(n == 0 && err == nil, n, err)
	case "scripted":
		n, err := s.Read(buf)
		require(n == 3 && string(buf[:n]) == "abc" && errors.Is(err, debuglet.ErrReset), n, err)
		n, err = s.Read(buf)
		require(n == 2 && string(buf[:n]) == "ok" && errors.Is(err, io.EOF), n, err)
		n, err = s.Write([]byte("PING"))
		require(n == 2 && errors.Is(err, debuglet.ErrTimeout), n, err)
		n, err = s.Write([]byte("PONG"))
		require(n == 4 && err == nil, n, err)
	case "deadline":
		require(s.SetReadDeadline(time.Now().Add(-time.Second)) == nil)
		n, err := s.Read(buf)
		require(n == 0 && errors.Is(err, debuglet.ErrTimeout), n, err)
		require(s.SetReadDeadline(time.Time{}) == nil)
		require(s.SetWriteDeadline(time.Now().Add(-time.Second)) == nil)
		n, err = s.Write([]byte("FAIL"))
		require(n == 0 && errors.Is(err, debuglet.ErrTimeout), n, err)
		require(s.SetWriteDeadline(time.Time{}) == nil)
		n, err = s.Write([]byte("PING"))
		require(n == 4 && err == nil, n, err)
		n, err = io.ReadFull(s, buf[:4])
		require(n == 4 && err == nil && string(buf[:n]) == "PONG", n, err)
	case "reset":
		n, err := s.Read(buf)
		require(n == 0 && errors.Is(err, debuglet.ErrReset), n, err)
	default:
		panic("unknown mode")
	}
	require(s.Close() == nil)
	n, err := s.Read(buf)
	require(n == 0 && errors.Is(err, debuglet.ErrClosed), n, err)
	n, err = s.Write([]byte("x"))
	require(n == 0 && errors.Is(err, debuglet.ErrClosed), n, err)
	fmt.Println("handled", mode, "and closed; guest continues")
}
