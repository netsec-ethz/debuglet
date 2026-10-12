// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"context"
	"errors"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UploadFailureFields records the boundary that failed, not a guessed root
// cause or admission outcome. Stage is a constant from the upload handler;
// error text and request contents must not be included in these normal logs.
func UploadFailureFields(ctx context.Context, stage string, err error, elapsed time.Duration) []zap.Field {
	code := status.Code(err)
	// Match the RPC boundary's classification of local context errors. The
	// incoming context can still be live when a nested SQL budget expires.
	if errors.Is(err, context.Canceled) {
		code = codes.Canceled
	} else if errors.Is(err, context.DeadlineExceeded) {
		code = codes.DeadlineExceeded
	}
	return []zap.Field{
		zap.String("upload_stage", stage),
		zap.String("grpc_code", code.String()),
		zap.Int64("elapsed_ms", elapsed.Milliseconds()),
		zap.String("context_code", status.FromContextError(ctx.Err()).Code().String()),
	}
}
