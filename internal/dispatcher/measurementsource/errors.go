// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package measurementsource

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
)

var (
	ErrNotFound       = errors.New("debuglet not found")
	ErrPayloadDeleted = errors.New("measurement payload was deleted; run identity and outcome remain available")
)

// ValidationError distinguishes malformed source from a conflicting attachment.
type ValidationError struct {
	Message  string
	Conflict bool
}

func (e *ValidationError) Error() string { return e.Message }
func invalid(message string) error       { return &ValidationError{Message: message} }
func conflict(message string) error      { return &ValidationError{Message: message, Conflict: true} }

// RetentionError distinguishes a failed retention lookup from a deleted payload.
type RetentionError struct{ Cause error }

func (e *RetentionError) Error() string { return "failed to inspect payload retention" }
func (e *RetentionError) Unwrap() error { return e.Cause }

func requireRetainedPayload(ctx context.Context, q *database.Queries, id uuid.UUID) error {
	_, err := q.GetPayloadTombstone(ctx, id)
	if err == nil {
		return ErrPayloadDeleted
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return &RetentionError{Cause: err}
}
