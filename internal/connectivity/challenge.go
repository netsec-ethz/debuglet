// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package connectivity implements fixed-size reachability challenges. Target
// selection belongs to trusted operator configuration, never measurement input.
package connectivity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

const TokenSize = 32
const ProbeTimeout = 400 * time.Millisecond

// ServeTCP owns the already-bound sample until stop is called. It handles one
// fixed-size challenge at a time and joins before returning from stop.
func ServeTCP(listener *net.TCPListener, token []byte) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(ProbeTimeout))
			challenge := make([]byte, TokenSize)
			if _, err := io.ReadFull(conn, challenge); err == nil {
				_, _ = conn.Write(answer(token, challenge))
			}
			_ = conn.Close()
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { _ = listener.Close(); <-done }) }
}

// ServeUDP never sends more bytes than it receives and ignores wrong lengths.
func ServeUDP(conn *net.UDPConn, token []byte) func() {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, TokenSize+1)
		for {
			n, peer, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n == TokenSize {
				_, _ = conn.WriteToUDP(answer(token, buf[:n]), peer)
			}
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { _ = conn.Close(); <-done }) }
}

func answer(token, challenge []byte) []byte {
	mac := hmac.New(sha256.New, token)
	_, _ = mac.Write(challenge)
	return mac.Sum(nil)
}

// Check tests one previously approved literal endpoint. It sends one 32-byte
// challenge and requires proof of the report's token, so an unrelated open
// service is not reported as the executor's listener.
func Check(ctx context.Context, transport, endpoint string, token []byte) error {
	if transport != "tcp" && transport != "udp" || len(token) != TokenSize {
		return errors.New("invalid connectivity challenge")
	}
	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, transport, endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	challenge := make([]byte, TokenSize)
	if _, err := rand.Read(challenge); err != nil {
		return err
	}
	if _, err := conn.Write(challenge); err != nil {
		return err
	}
	response := make([]byte, TokenSize)
	if _, err := io.ReadFull(conn, response); err != nil {
		return err
	}
	if !hmac.Equal(response, answer(token, challenge)) {
		return errors.New("listener challenge mismatch")
	}
	return nil
}
