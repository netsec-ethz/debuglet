// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"bytes"
	"context"
	"errors"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"testing"
)

func TestOutputWriterChunksBeforeCopy(t *testing.T) {
	input := bytes.Repeat([]byte("x"), 3*pb.MaxOutputFrameBytes+7)
	queue := make(chan []byte, 4)
	w := &chanWriter{ctx: t.Context(), ch: queue}
	n, err := w.Write(input)
	if err != nil || n != len(input) {
		t.Fatalf("write=%d,%v", n, err)
	}
	input[0] = 'y'
	var got []byte
	for len(queue) > 0 {
		chunk := <-queue
		if len(chunk) > pb.MaxOutputFrameBytes {
			t.Fatal("unbounded chunk")
		}
		got = append(got, chunk...)
	}
	if len(got) != n || got[0] != 'x' {
		t.Fatal("guest bytes were aliased or lost")
	}
	if n, err := w.Write(nil); n != 0 || err != nil || len(queue) != 0 {
		t.Fatal("zero write created output")
	}
}

func TestOutputWriterCancelsAfterAcceptedPrefix(t *testing.T) {
	ctx, cancel := context.WithCancelCause(t.Context())
	queue := make(chan []byte)
	w := &chanWriter{ctx: ctx, ch: queue}
	cause := errors.New("producer canceled")
	done := make(chan struct{})
	var n int
	var err error
	go func() { defer close(done); n, err = w.Write(make([]byte, 3*pb.MaxOutputFrameBytes)) }()
	if chunk := <-queue; len(chunk) != pb.MaxOutputFrameBytes {
		t.Fatal("first chunk")
	}
	cancel(cause)
	joinRuntimeTest(t, done)
	if n != pb.MaxOutputFrameBytes || !errors.Is(err, cause) {
		t.Fatalf("accepted prefix=%d,%v", n, err)
	}
}
