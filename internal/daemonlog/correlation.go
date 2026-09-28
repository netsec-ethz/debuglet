// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package daemonlog

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"go.uber.org/zap"
)

type requestIDKey struct{}

// WithRequestID attaches a server-generated identifier to local request work.
func WithRequestID(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, requestIDKey{}, id.String())
}

func RequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey{}).(string); ok {
		return id
	}
	return "unknown"
}

// Identifier keeps non-secret identifiers bounded and safe in text logs too.
// Oversized or non-printable identifiers use a stable digest, not a prefix
// that could make two different executors appear to be the same one.
func Identifier(value string) string {
	if value == "" {
		return "unknown"
	}
	safe := len(value) <= 128 && value != "unknown" && !strings.HasPrefix(value, "sha256:")
	for i := 0; safe && i < len(value); i++ {
		safe = value[i] >= 0x21 && value[i] <= 0x7e
	}
	if safe {
		return value
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value)))
}

func SessionFields(executorID string, binding controlsession.Binding) []zap.Field {
	return []zap.Field{
		zap.String("executor_id", Identifier(executorID)),
		zap.String("dispatcher_incarnation", Identifier(binding.Incarnation)),
		zap.String("session_id", Identifier(binding.SessionID)),
	}
}

// RunFields joins HTTP and dispatcher events through request_id, and dispatcher
// and executor events through the run and control binding. No durable attempt
// identity is currently available; absence is not evidence of a first attempt.
func RunFields(ctx context.Context, id uuid.UUID, executorID string, binding controlsession.Binding) []zap.Field {
	return append(SessionFields(executorID, binding),
		zap.String("request_id", RequestID(ctx)), zap.String("run_id", id.String()), zap.String("attempt", "unknown"))
}
