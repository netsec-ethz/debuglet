package storagecheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
)

// hotJournal returns a copy of a current database of role taken while a
// write transaction was in progress, as a process killed mid-write leaves it:
// the database file already holds some uncommitted pages and the rollback
// journal next to it holds the committed ones. It also returns the digest of
// the database as last committed.
func hotJournal(t *testing.T, role Role) (path, committed string) {
	t.Helper()
	source := fixture(t, role, 0)
	committed = digest(t, source)
	db, err := sqlitedb.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	// A tiny page cache makes SQLite spill the transaction's pages into
	// the database file before it commits, which it does only after it
	// has synced their original content to the journal.
	if _, err := db.ExecContext(ctx, "PRAGMA cache_size = 2"); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for _, statement := range []string{
		"CREATE TABLE crash_probe (payload BLOB)",
		"WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 256) " +
			"INSERT INTO crash_probe SELECT randomblob(4000) FROM n",
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	if digest(t, source) == committed {
		t.Fatal("the transaction did not spill into the database file")
	}
	path = filepath.Join(t.TempDir(), filepath.Base(source))
	for _, suffix := range []string{"", "-journal"} {
		data, err := os.ReadFile(source + suffix)
		if err != nil {
			t.Fatalf("copy the database mid-write: %v", err)
		}
		if err := os.WriteFile(path+suffix, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return path, committed
}

func TestHotJournalIsRefusedReadOnly(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		path, _ := hotJournal(t, role)
		before, journal := digest(t, path), digest(t, path+"-journal")
		// This is what the startup check hit before it recovered journals.
		err := probe(context.Background(), path)
		var coded interface{ Code() int }
		if !errors.As(err, &coded) || coded.Code() != sqliteReadOnlyRollback {
			t.Fatalf("%s: a read-only open of a hot journal returned %v, not SQLITE_READONLY_ROLLBACK", role, err)
		}
		err = Check(context.Background(), role, path)
		if !errors.Is(err, ErrNeedsRecovery) || !errors.Is(err, ErrUnreadable) {
			t.Fatalf("%s: Check of a hot journal returned %v", role, err)
		}
		for _, want := range []string{path + "-journal", "-upgrade-database", "do not delete the journal"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("%s: refusal %q does not name %q", role, err, want)
			}
		}
		unchangedBytes(t, path, before)
		if digest(t, path+"-journal") != journal {
			t.Fatalf("%s: Check changed the journal", role)
		}
	}
}

func TestCheckAtStartRollsBackAHotJournal(t *testing.T) {
	for _, role := range []Role{Dispatcher, Executor} {
		path, committed := hotJournal(t, role)
		var recoveries []Recovery
		if err := CheckAtStart(context.Background(), role, path, func(r Recovery) { recoveries = append(recoveries, r) }); err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		if len(recoveries) != 1 || recoveries[0] != (Recovery{Path: path, Journal: path + "-journal"}) {
			t.Fatalf("%s: reported recoveries %+v", role, recoveries)
		}
		// Rolling back restores exactly the committed bytes and removes
		// the journal; nothing else is written.
		unchanged(t, path, committed)
		if err := Check(context.Background(), role, path); err != nil {
			t.Fatalf("%s: recovered database: %v", role, err)
		}
		if err := CheckAtStart(context.Background(), role, path, func(r Recovery) { t.Errorf("%s: recovered again: %+v", role, r) }); err != nil {
			t.Fatalf("%s: %v", role, err)
		}
		unchanged(t, path, committed)
	}
}

func TestCheckAtStartLeavesACommittedDatabaseUnchanged(t *testing.T) {
	path := fixture(t, Executor, 1)
	before := digest(t, path)
	err := CheckAtStart(context.Background(), Executor, path, func(r Recovery) { t.Errorf("recovered: %+v", r) })
	if !errors.Is(err, ErrOutdated) {
		t.Fatalf("outdated database: %v", err)
	}
	unchanged(t, path, before)
}

func TestUpgradeRollsBackAHotJournal(t *testing.T) {
	path, committed := hotJournal(t, Executor)
	var recoveries []Recovery
	version, err := Upgrade(context.Background(), Executor, path, ReportRecovery(func(r Recovery) { recoveries = append(recoveries, r) }))
	if err != nil {
		t.Fatal(err)
	}
	if len(recoveries) != 1 || recoveries[0].Journal != path+"-journal" {
		t.Fatalf("reported recoveries %+v", recoveries)
	}
	if schemaVersionOf(t, path) != version {
		t.Fatalf("upgrade reported version %d", version)
	}
	// The database was current, so the upgrade itself had nothing to do.
	unchanged(t, path, committed)
}

func TestFailedRecoveryNamesTheJournal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes a read-only file")
	}
	path, _ := hotJournal(t, Dispatcher)
	// SQLite opens a database it may not write read-only, so the writer
	// cannot roll the journal back either.
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	before, journal := digest(t, path), digest(t, path+"-journal")
	err := CheckAtStart(context.Background(), Dispatcher, path, func(r Recovery) { t.Errorf("recovered: %+v", r) })
	if !errors.Is(err, ErrNeedsRecovery) {
		t.Fatalf("failed recovery: %v", err)
	}
	for _, want := range []string{path + "-journal", "could not roll back", "restore the database from a backup"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not name %q", err, want)
		}
	}
	unchangedBytes(t, path, before)
	if digest(t, path+"-journal") != journal {
		t.Fatal("failed recovery changed the journal")
	}
}
