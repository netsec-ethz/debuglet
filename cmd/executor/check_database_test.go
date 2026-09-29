package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/storagecheck"
)

// TestCheckDatabaseStatus keeps the exit status of -check-database telling a
// current database, an upgrade that keeps the data, an upgrade that drops the
// recorded runs and every other refusal apart.
func TestCheckDatabaseStatus(t *testing.T) {
	absent := storagecheck.Check(context.Background(), storagecheck.Executor, filepath.Join(t.TempDir(), "executor.sqlite"))
	for _, tc := range []struct {
		name string
		err  error
		want int
	}{
		{name: "current", err: nil, want: 0},
		{name: "outdated", err: fmt.Errorf("%w: version 8", storagecheck.ErrOutdated), want: 3},
		{name: "outdated with data loss", err: fmt.Errorf("%w: version 2; %w", storagecheck.ErrOutdated, storagecheck.ErrDataLoss), want: 4},
		{name: "data loss alone", err: storagecheck.ErrDataLoss, want: 1},
		{name: "absent", err: absent, want: 1},
		{name: "unknown", err: storagecheck.ErrUnknown, want: 1},
		{name: "unreadable", err: storagecheck.ErrUnreadable, want: 1},
		{name: "newer", err: storagecheck.ErrNewer, want: 1},
		{name: "incomplete", err: storagecheck.ErrIncomplete, want: 1},
		{name: "other", err: errors.New("resolve path"), want: 1},
	} {
		if got := checkDatabaseStatus(tc.err); got != tc.want {
			t.Errorf("%s (%v): status %d, want %d", tc.name, tc.err, got, tc.want)
		}
	}
	if !errors.Is(absent, storagecheck.ErrAbsent) {
		t.Fatalf("absent database: %v", absent)
	}
}
