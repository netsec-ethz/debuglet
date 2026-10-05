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

// ProcessCheckpoint handles one streamed checkpoint.
func (l *Listener) ProcessCheckpoint(ctx context.Context, cp *v2.Checkpoint) error {
	return l.processCheckpoint(ctx, cp)
}

// StreamCheckpoint handles one streamed checkpoint after cursor, as the
// stream loop does.
func (l *Listener) StreamCheckpoint(ctx context.Context, cursor *uint64, cp *v2.Checkpoint) (uint64, error) {
	return l.streamCheckpoint(ctx, cursor, cp)
}
