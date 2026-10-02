// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// latency measures nonce-matched UDP echoes. The same source runs natively
// for the local baseline and as a debuglet using the recoverable I/O extension.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

const payloadBytes = 1024

type reply struct {
	Sequence int   `json:"sequence"`
	Sent     int64 `json:"sent_unix_ns"`
	Received int64 `json:"received_unix_ns"`
	RTT      int64 `json:"rtt_ns"`
}
type measurement struct {
	Sent        int     `json:"sent"`
	Replies     []reply `json:"replies"`
	Elapsed     int64   `json:"elapsed_ns"`
	SendElapsed int64   `json:"send_elapsed_ns"`
	Late        int     `json:"late"`
}
type report struct {
	Version      int          `json:"version"`
	Nonce        string       `json:"nonce"`
	PayloadBytes int          `json:"payload_bytes"`
	Latency      measurement  `json:"latency"`
	Burst        *measurement `json:"burst,omitempty"`
	Error        string       `json:"error,omitempty"`
}

func main() {
	args := os.Args
	if runtime.GOOS != "wasip1" {
		args = args[1:]
	}
	if len(args) != 3 || (args[2] != "latency" && args[2] != "both") {
		fmt.Fprintln(os.Stderr, "usage: latency TARGET NONCE latency|both")
		os.Exit(2)
	}
	nonce, err := hex.DecodeString(args[1])
	if err != nil || len(nonce) != 16 {
		fmt.Fprintln(os.Stderr, "nonce must be 32 hex characters")
		os.Exit(2)
	}
	result := report{Version: 1, Nonce: args[1], PayloadBytes: payloadBytes}
	result.Latency, err = probe(args[0], nonce, 12, false)
	if err == nil && args[2] == "both" {
		var burst measurement
		burst, err = probe(args[0], nonce, 32, true)
		result.Burst = &burst
	}
	if err != nil {
		result.Error = err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		os.Exit(1)
	}
}

type socket interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func probe(address string, nonce []byte, count int, burst bool) (measurement, error) {
	var conn socket
	var err error
	if runtime.GOOS == "wasip1" {
		conn, err = debuglet.Dial("udp", address)
	} else {
		conn, err = net.Dial("udp", address)
	}
	result := measurement{Replies: []reply{}}
	if err != nil {
		return result, err
	}
	defer conn.Close()
	data, buffer := make([]byte, payloadBytes), make([]byte, payloadBytes+1)
	copy(data, nonce)
	if burst {
		data[16] = 1
	}
	started := time.Now()
	if err := conn.SetWriteDeadline(started.Add(12 * time.Second)); err != nil {
		return result, err
	}
	times := make([]time.Time, count)
	seen := make([]bool, count)
	send := func(i int) error {
		binary.BigEndian.PutUint32(data[17:21], uint32(i))
		times[i] = time.Now()
		n, err := conn.Write(data)
		if err == nil && n != len(data) {
			err = errors.New("short UDP write")
		}
		if err == nil {
			result.Sent++
		}
		return err
	}
	receive := func(want int, deadline time.Time) (bool, error) {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return false, err
		}
		for {
			n, err := conn.Read(buffer)
			received := time.Now()
			if err != nil {
				var timeout interface{ Timeout() bool }
				if errors.As(err, &timeout) && timeout.Timeout() {
					return false, nil
				}
				return false, err
			}
			if n != payloadBytes || !bytes.Equal(buffer[:16], nonce) || buffer[16] != data[16] {
				return false, errors.New("incorrect echo identity or length")
			}
			i := int(binary.BigEndian.Uint32(buffer[17:21]))
			if i >= count {
				return false, errors.New("incorrect echo sequence")
			}
			if seen[i] || (want >= 0 && i != want) {
				result.Late++
				continue
			}
			seen[i] = true
			result.Replies = append(result.Replies, reply{i, times[i].UnixNano(), received.UnixNano(), received.Sub(times[i]).Nanoseconds()})
			return true, nil
		}
	}
	if burst {
		for i := 0; i < count; i++ {
			if err = send(i); err != nil {
				return result, err
			}
		}
		result.SendElapsed = time.Since(started).Nanoseconds()
		deadline := started.Add(10 * time.Second)
		for len(result.Replies) < count {
			var received bool
			received, err = receive(-1, deadline)
			if err != nil {
				return result, err
			}
			if !received {
				break
			}
		}
	} else {
		for i := 0; i < count; i++ {
			if err = send(i); err != nil {
				return result, err
			}
			if _, err = receive(i, times[i].Add(400*time.Millisecond)); err != nil {
				return result, err
			}
		}
	}
	result.Elapsed = time.Since(started).Nanoseconds()
	return result, nil
}
