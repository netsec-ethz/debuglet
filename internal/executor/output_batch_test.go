// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"testing"
)

func TestQueuedOutputCoalescesWithoutChangingBytesOrFrameBound(t *testing.T) {
	input := make(chan []byte, outputQueueFrames)
	chunks := [][]byte{[]byte("first\n"), []byte("second\n"), bytes.Repeat([]byte("x"), pb.MaxOutputFrameBytes), []byte("last\n")}
	for _, chunk := range chunks[1:] {
		input <- chunk
	}
	close(input)
	var frames [][]byte
	coalesceOutput(input, chunks[0], func(data []byte) {
		if len(data) > pb.MaxOutputFrameBytes {
			t.Fatal("oversized frame")
		}
		frames = append(frames, append([]byte(nil), data...))
	})
	// A full frame ends this bounded drain; process any remaining queued suffix.
	for chunk := range input {
		coalesceOutput(input, chunk, func(data []byte) { frames = append(frames, append([]byte(nil), data...)) })
	}
	if len(frames) != 3 || !bytes.Equal(bytes.Join(frames, nil), bytes.Join(chunks, nil)) {
		t.Fatalf("frames lost order or bytes: %d", len(frames))
	}
}
func TestQueuedOutputDoesNotWaitForAnotherWrite(t *testing.T) {
	input := make(chan []byte, outputQueueFrames)
	calls := 0
	coalesceOutput(input, []byte("live result"), func(data []byte) {
		calls++
		if string(data) != "live result" {
			t.Fatal("changed bytes")
		}
	})
	if calls != 1 {
		t.Fatalf("live output was held: %d", calls)
	}
}
