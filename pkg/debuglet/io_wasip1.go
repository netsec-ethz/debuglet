// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

import (
	"fmt"
	"io"
	"time"
)

//go:wasmimport debuglet_io_v1 dial
func socketDial(transport, ptr, length uint32, timeout int64) uint64

//go:wasmimport debuglet_io_v1 read
func socketRead(handle int32, ptr, length uint32) uint64

//go:wasmimport debuglet_io_v1 write
func socketWrite(handle int32, ptr, length uint32) uint64

//go:wasmimport debuglet_io_v1 close
func socketClose(handle int32) uint64

//go:wasmimport debuglet_io_v1 deadline
func socketDeadline(handle int32, write uint32, unixNano int64) uint64

func dialSocket(transport uint32, address string, timeout time.Duration) (*Socket, error) {
	handle, err := ioOutcome(socketDial(transport, strPtr(address), uint32(len(address)), int64(timeout)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrConnect, err)
	}
	if handle < 0 || handle > 1<<31-1 {
		return nil, fmt.Errorf("debuglet: invalid socket handle")
	}
	return &Socket{handle: int32(handle), stream: transport < 2}, nil
}

// Read returns any received bytes together with their error, including EOF.
// Process b[:n] before handling err. An empty datagram is (0, nil); an empty
// input buffer returns (0, nil) without calling the host.
func (s *Socket) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	n, err := ioOutcome(socketRead(s.handle, bytePtr(b), uint32(len(b))))
	if n < 0 || n > min(len(b), MaxIOBytes) {
		return 0, fmt.Errorf("debuglet: invalid read count")
	}
	return n, err
}

// Write preserves the count on failure. Large stream writes use bounded host
// calls; an error stops the operation without retrying or resending bytes.
// UDP/ICMP writes use one call and reject oversized datagrams before sending.
func (s *Socket) Write(b []byte) (int, error) {
	if !s.stream && len(b) > MaxIOBytes {
		return 0, ErrTooLarge
	}
	if !s.stream && len(b) == 0 {
		n, err := ioOutcome(socketWrite(s.handle, 0, 0))
		if n != 0 {
			return 0, fmt.Errorf("debuglet: invalid write count")
		}
		return 0, err
	}
	written := 0
	for len(b) != 0 {
		chunk := b[:min(len(b), MaxIOBytes)]
		n, err := ioOutcome(socketWrite(s.handle, bytePtr(chunk), uint32(len(chunk))))
		if n < 0 || n > len(chunk) {
			return written, fmt.Errorf("debuglet: invalid write count")
		}
		written += n
		if err != nil {
			return written, err
		}
		if n != len(chunk) {
			return written, io.ErrShortWrite
		}
		b = b[n:]
	}
	return written, nil
}

// Close releases this socket. Further operations report ErrClosed.
func (s *Socket) Close() error {
	_, err := ioOutcome(socketClose(s.handle))
	return err
}

// SetReadDeadline bounds underlying reads. A zero time clears the deadline;
// clearing it never extends the run's lifetime.
func (s *Socket) SetReadDeadline(t time.Time) error { return s.deadline(t, 0) }

// SetWriteDeadline bounds underlying writes. A zero time clears the deadline.
func (s *Socket) SetWriteDeadline(t time.Time) error { return s.deadline(t, 1) }

func (s *Socket) deadline(t time.Time, write uint32) error {
	var nanos int64
	if !t.IsZero() {
		nanos = t.UnixNano()
	}
	_, err := ioOutcome(socketDeadline(s.handle, write, nanos))
	return err
}
