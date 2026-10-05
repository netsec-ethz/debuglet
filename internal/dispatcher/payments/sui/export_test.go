// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package sui

import (
	"context"

	v2 "github.com/block-vision/sui-go-sdk/pb/sui/rpc/v2"
)

// CatchUpRange runs one catch-up over a known tip, without the chain's ledger
// service.
func (l *Listener) CatchUpRange(ctx context.Context, after, tip uint64) error {
	return l.catchUpRange(ctx, after, tip)
}

// CatchUpTo runs the catch-up of Start over a known tip.
func (l *Listener) CatchUpTo(ctx context.Context, cursor *uint64, tip uint64) (*uint64, error) {
	return l.catchUpTo(ctx, cursor, tip)
}

// Stream is one subscription's handling of streamed checkpoints.
type Stream struct {
	l  *Listener
	st streamState
}

// NewStream starts a subscription after the stored cursor.
func (l *Listener) NewStream(cursor *uint64) *Stream {
	return &Stream{l: l, st: streamState{cursor: cursor}}
}

// Checkpoint handles one streamed checkpoint, as the stream loop does.
func (s *Stream) Checkpoint(ctx context.Context, cp *v2.Checkpoint) error {
	return s.l.streamCheckpoint(ctx, &s.st, cp)
}

// Cursor is the cursor the stream loop holds.
func (s *Stream) Cursor() *uint64 {
	return s.st.cursor
}
