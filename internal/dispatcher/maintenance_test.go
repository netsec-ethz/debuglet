package dispatcher

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/demo/service"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// The operator tool writes the switch and this daemon reads it. The two live
// in different packages on purpose - the dispatcher must not depend on a
// command-line package - so this test holds them to one contract.
func TestMaintenanceSwitchIsTheContractTheOperatorToolWrites(t *testing.T) {
	if service.MaintenanceFileEnv != MaintenanceFileEnv {
		t.Fatalf("the operator tool points at %q, the dispatcher reads %q", service.MaintenanceFileEnv, MaintenanceFileEnv)
	}
	path := filepath.Join(t.TempDir(), "maintenance")
	if err := maintenanceStop(""); err != nil {
		t.Fatalf("a dispatcher without a switch must admit work: %v", err)
	}
	if err := maintenanceStop(path); err != nil {
		t.Fatalf("an absent switch must admit work: %v", err)
	}
	if err := service.WriteMaintenance(path, "planned\tmaintenance\nwindow", time.Now()); err != nil {
		t.Fatalf("write switch: %v", err)
	}
	err := maintenanceStop(path)
	if !errors.Is(err, ErrMaintenanceMode) {
		t.Fatalf("a published switch did not stop admission: %v", err)
	}
	if !strings.Contains(err.Error(), "planned maintenance window") {
		t.Fatalf("the operator note did not reach the refusal: %v", err)
	}
	if cleared, err := service.ClearMaintenance(path); err != nil || !cleared {
		t.Fatalf("clear switch: %v %v", cleared, err)
	}
	if err := maintenanceStop(path); err != nil {
		t.Fatalf("a cleared switch must admit work again: %v", err)
	}
}

func TestMaintenanceSwitchRefusesWhatItCannotUnderstand(t *testing.T) {
	dir := t.TempDir()
	for name, content := range map[string]string{
		"not json":       "stop everything",
		"other schema":   `{"schema_version":99,"paused":true}`,
		"trailing bytes": `{"schema_version":1,"paused":true} and more`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, "switch-"+strings.ReplaceAll(name, " ", "-"))
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			if err := maintenanceStop(path); !errors.Is(err, ErrMaintenanceMode) {
				t.Fatalf("an unreadable switch admitted work: %v", err)
			}
		})
	}
	t.Run("explicitly not paused", func(t *testing.T) {
		path := filepath.Join(dir, "resumed")
		if err := os.WriteFile(path, []byte(`{"schema_version":1,"paused":false}`), 0600); err != nil {
			t.Fatal(err)
		}
		if err := maintenanceStop(path); err != nil {
			t.Fatalf("a switch that is not set stopped admission: %v", err)
		}
	})
	t.Run("directory", func(t *testing.T) {
		path := filepath.Join(dir, "directory")
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := maintenanceStop(path); !errors.Is(err, ErrMaintenanceMode) {
			t.Fatalf("a switch that is not a regular file admitted work: %v", err)
		}
	})
}

// TestSubmissionAdmissionStopsForMaintenance checks the hook itself: a paused
// dispatcher refuses before it reserves capacity, opens a transaction or
// persists anything, and it serves again as soon as the switch is cleared.
func TestSubmissionAdmissionStopsForMaintenance(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	path := filepath.Join(t.TempDir(), "maintenance")
	if err := service.WriteMaintenance(path, "draining for an upgrade", time.Now()); err != nil {
		t.Fatal(err)
	}
	t.Setenv(MaintenanceFileEnv, path)

	spec := f.spec(t, 60)
	ids, err := f.d.SubmitDebuglets(f.ctx, []models.DebugletSpec{spec}, nil)
	if !errors.Is(err, ErrMaintenanceMode) || ids != nil {
		t.Fatalf("submission during maintenance = (%v, %v)", ids, err)
	}
	if got := batchRows(t, f); got != 0 {
		t.Fatalf("a refused submission persisted %d debuglets", got)
	}
	if got := len(peer.recordedUploads()); got != 0 {
		t.Fatalf("a refused submission uploaded %d workloads", got)
	}
	if got := batchReserved(f, f.start, f.start.Add(tgTimeout+10*time.Second)); got != 0 {
		t.Fatalf("a refused submission reserved %d", got)
	}

	if err := AdmissionPaused(); !errors.Is(err, ErrMaintenanceMode) {
		t.Fatalf("the switch this process was pointed at was not read: %v", err)
	}
	if _, err := service.ClearMaintenance(path); err != nil {
		t.Fatal(err)
	}
	if _, err := f.submit(t, 60); err != nil {
		t.Fatalf("submission after maintenance: %v", err)
	}
	if got := batchRows(t, f); got != 1 {
		t.Fatalf("persisted debuglets after maintenance = %d, want 1", got)
	}
}

// An operator note is bounded in bytes, because bytes are what a refusal body
// costs. The bound must not land inside a character: a note cut mid-rune would
// put invalid UTF-8 into a JSON response and into every log line that repeats
// it.
func TestAMaintenanceReasonIsBoundedOnARuneBoundary(t *testing.T) {
	for name, note := range map[string]string{
		"two-byte runes":      strings.Repeat("ä", 300),
		"three-byte runes":    strings.Repeat("€", 300),
		"four-byte runes":     strings.Repeat("🛠", 300),
		"a rune on the bound": strings.Repeat("a", maintenanceReasonLimit-1) + "ä",
	} {
		t.Run(name, func(t *testing.T) {
			bounded := maintenanceReason(note)
			if len(bounded) > maintenanceReasonLimit {
				t.Fatalf("a note of %d bytes was bounded to %d", len(note), len(bounded))
			}
			if !utf8.ValidString(bounded) {
				t.Fatalf("the bounded note is not valid UTF-8: %q", bounded)
			}
			if bounded == "" {
				t.Fatal("the whole note was dropped")
			}
		})
	}
}

// A refusal is repeated to whoever made the request, so it says what is wrong
// with the switch and never where the switch is. Where a host keeps its
// administration files is not part of answering a submission.
func TestAMaintenanceRefusalNeverNamesTheSwitchFile(t *testing.T) {
	directory := t.TempDir()
	// A regular file where a directory belongs makes every inspection of the
	// path below it fail, whatever account this test runs as.
	blocked := filepath.Join(directory, "services")
	if err := os.WriteFile(blocked, []byte("not a directory"), 0644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(blocked, "dispatcher-local.maintenance")
	err := maintenanceStop(path)
	if !errors.Is(err, ErrMaintenanceMode) {
		t.Fatalf("a switch that cannot be inspected must stop admission: %v", err)
	}
	for _, secret := range []string{path, blocked, directory} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("the refusal names %s: %q", secret, err)
		}
	}
}
