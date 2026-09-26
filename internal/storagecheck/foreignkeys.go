package storagecheck

import (
	"context"
	"fmt"
	"sort"
)

// ForeignKeyViolation counts the rows of Table that reference a missing row
// of Parent.
type ForeignKeyViolation struct {
	Table  string
	Parent string
	Rows   int
}

func (v ForeignKeyViolation) String() string {
	return fmt.Sprintf("%d row(s) of %s reference a missing %s row", v.Rows, v.Table, v.Parent)
}

// ForeignKeyViolations reports the rows of the database at path whose
// references PRAGMA foreign_key_check finds broken. The daemons enforce
// foreign keys only on new writes, so rows written before they did stay as
// they are; this is how an operator learns of them. It opens the database
// read-only and changes nothing.
func ForeignKeyViolations(ctx context.Context, path string) ([]ForeignKeyViolation, error) {
	db, err := openReadOnly(path)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read database %q: %v", ErrUnreadable, path, err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		return nil, fmt.Errorf("check foreign keys of %q: %w", path, err)
	}
	defer rows.Close()
	counts := make(map[[2]string]int)
	for rows.Next() {
		// table, rowid, parent, foreign key index
		var table, parent string
		var rowID, fkIndex any
		if err := rows.Scan(&table, &rowID, &parent, &fkIndex); err != nil {
			return nil, fmt.Errorf("check foreign keys of %q: %w", path, err)
		}
		counts[[2]string{table, parent}]++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("check foreign keys of %q: %w", path, err)
	}
	violations := make([]ForeignKeyViolation, 0, len(counts))
	for key, n := range counts {
		violations = append(violations, ForeignKeyViolation{Table: key[0], Parent: key[1], Rows: n})
	}
	sort.Slice(violations, func(i, j int) bool {
		if violations[i].Table != violations[j].Table {
			return violations[i].Table < violations[j].Table
		}
		return violations[i].Parent < violations[j].Parent
	})
	return violations, nil
}
