// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package storageheadroom preserves an advisory margin for SQLite control and
// terminal records by refusing payload writes before available space is spent.
package storageheadroom

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
)

const DefaultReserveBytes int64 = 16 << 20

var ErrLowSpace = errors.New("storage control reserve reached")

// Queryer is satisfied by a transaction or its owned connection. Call Check
// within the payload writer's existing serialization, before its first write.
type Queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func Check(ctx context.Context, q Queryer, reserve, payload int64) error {
	if reserve <= 0 || payload < 0 || payload > (math.MaxInt64-reserve-(64<<10))/4 {
		return errors.New("invalid storage headroom budget")
	}
	// Room for both database and journal growth plus B-tree/accounting updates.
	// SQLite's exact growth depends on its pages; this is deliberately a margin,
	// not a guarantee against unrelated writers, device failure or a growing WAL.
	required := reserve + 4*payload + (64 << 10)
	var pageSize, pageCount, maxPages, freePages int64
	for _, read := range []struct {
		name  string
		value *int64
	}{{"page_size", &pageSize}, {"page_count", &pageCount}, {"max_page_count", &maxPages}, {"freelist_count", &freePages}} {
		if err := q.QueryRowContext(ctx, "PRAGMA main."+read.name).Scan(read.value); err != nil {
			return err
		}
	}
	availablePages := maxPages - pageCount + freePages
	if pageSize <= 0 || availablePages < 0 || availablePages <= (required-1)/pageSize {
		return ErrLowSpace
	}
	rows, err := q.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return err
	}
	var path string
	for rows.Next() {
		var sequence int
		var name, file string
		if err = rows.Scan(&sequence, &name, &file); err != nil {
			break
		}
		if name == "main" {
			path = file
		}
	}
	err = errors.Join(err, rows.Err(), rows.Close())
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	} // An in-memory database has no disk allocation.
	available, err := availableBytes(path)
	if err != nil {
		return fmt.Errorf("inspect storage headroom: %w", err)
	}
	if available < uint64(required) {
		return ErrLowSpace
	}
	return nil
}
