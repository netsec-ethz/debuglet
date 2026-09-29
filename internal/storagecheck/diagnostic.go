package storagecheck

import (
	"context"
	"database/sql"
)

// CheckDB verifies an already-open database against this policy. The caller
// owns the handle and its read-only or offline snapshot semantics.
func (p Policy) CheckDB(ctx context.Context, db *sql.DB) error {
	return p.verify(ctx, db, "configured database")
}
