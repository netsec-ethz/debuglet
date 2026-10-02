// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Diagnostic is bounded, single-line text for the opt-in private Debug sink.
// Callers redact known credentials before using it; it is not a secret detector.
func Diagnostic(err error) string {
	if err == nil {
		return ""
	}
	var b strings.Builder
	for _, r := range err.Error() {
		if unicode.IsControl(r) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > 2048 {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

func rpcFailure(ctx context.Context, logger *zap.Logger, method string, err error) error {
	if err == nil {
		return nil
	}
	// Locally classified context errors retain their standard wire status.
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, "request cancelled")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	}
	if credential, readErr := controlrpc.Read(ctx); readErr == nil {
		err = credential.RedactError(err)
	}
	st := status.Convert(err)
	switch st.Code() {
	case codes.Canceled:
		return status.Error(codes.Canceled, "request cancelled")
	case codes.DeadlineExceeded:
		return status.Error(codes.DeadlineExceeded, "request deadline exceeded")
	case codes.Unknown, codes.Internal, codes.DataLoss:
		fields := []zap.Field{zap.String("method", Identifier(method)), zap.String("code", st.Code().String())}
		if logger != nil {
			logger.Warn("RPC failed", fields...)
			logger.Debug("Private RPC diagnostic", append(fields, zap.String("error", Diagnostic(err)))...)
		}
		return status.Error(st.Code(), "operation failed; operator diagnostics have the details")
	default:
		// Explicit validation, ownership, availability and capacity messages are
		// constructed by handlers. Preserve typed negotiation/status details and
		// existing credential redaction, while bounding the readable message.
		projected := st.Proto()
		projected.Message = Diagnostic(errors.New(st.Message()))
		return status.FromProto(projected).Err()
	}
}

func UnaryErrors(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		out, err := handler(ctx, req)
		return out, rpcFailure(ctx, logger, info.FullMethod, err)
	}
}
func StreamErrors(logger *zap.Logger) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		return rpcFailure(stream.Context(), logger, info.FullMethod, handler(srv, stream))
	}
}
