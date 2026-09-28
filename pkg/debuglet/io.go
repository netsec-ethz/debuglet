// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"fmt"
	"io"
	"time"

	"github.com/netsec-ethz/debuglet/internal/guestio"
)

// IOError is a stable transport outcome from the debuglet_io_v1 extension.
// Use errors.Is(err, ErrTimeout), for example, to handle a wrapped outcome.
type IOError uint32

const (
	ErrTimeout     IOError = guestio.Timeout
	ErrReset       IOError = guestio.Reset
	ErrClosed      IOError = guestio.Closed
	ErrRefused     IOError = guestio.Refused
	ErrDenied      IOError = guestio.Denied
	ErrIO          IOError = guestio.Failure
	ErrCanceled    IOError = guestio.Canceled
	ErrUnsupported IOError = guestio.Unsupported
)

func (e IOError) Error() string {
	switch e {
	case ErrTimeout:
		return "network operation timed out"
	case ErrReset:
		return "connection reset or broken pipe"
	case ErrClosed:
		return "socket is closed"
	case ErrRefused:
		return "connection refused"
	case ErrDenied:
		return "destination or transport is not permitted"
	case ErrCanceled:
		return "network operation canceled"
	case ErrUnsupported:
		return "socket operation is unsupported"
	default:
		return "network I/O failed"
	}
}

func (e IOError) Timeout() bool   { return e == ErrTimeout }
func (e IOError) Temporary() bool { return e == ErrTimeout }

func ioOutcome(result uint64) (int, error) {
	n, status := int(uint32(result)), uint32(result>>32)
	switch status {
	case guestio.OK:
		return n, nil
	case guestio.EOF:
		return n, io.EOF
	case guestio.NoProgress:
		return n, io.ErrNoProgress
	case guestio.ShortWrite:
		return n, io.ErrShortWrite
	default:
		return n, IOError(status)
	}
}

// Socket is an io.ReadWriteCloser with recoverable transport errors. Unlike
// Conn, its Write method returns a byte count. It requires debuglet_io_v1;
// existing Connect* functions and compiled guests keep their legacy behavior.
type Socket struct {
	handle int32
	stream bool
}

// Dial connects using "tcp", "tls", "udp" or "ip4:icmp". Policy and resource
// admission are identical to Connect*. The run's lifetime bounds the call.
func Dial(network, address string) (*Socket, error) {
	return DialTimeout(network, address, 0)
}

// DialTimeout also bounds resolution, connection and TLS handshake. Zero uses
// the run's remaining lifetime; a negative timeout expires immediately.
func DialTimeout(network, address string, timeout time.Duration) (*Socket, error) {
	var transport uint32
	switch network {
	case "tcp":
		transport = 0
	case "tls":
		transport = 1
	case "ip4:icmp":
		transport = 2
	case "udp":
		transport = 3
	default:
		return nil, fmt.Errorf("%w: unsupported network %q", ErrConnect, network)
	}
	if address == "" {
		return nil, fmt.Errorf("%w: empty address", ErrConnect)
	}
	return dialSocket(transport, address, timeout)
}
