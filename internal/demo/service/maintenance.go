package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaintenanceFileEnv is the environment variable a generated dispatcher unit
// sets to point the daemon at its admission switch. The dispatcher defines the
// same name and reads the same record; internal/dispatcher's maintenance test
// checks the two against each other, so the writer here and the reader there
// cannot drift apart unnoticed.
const MaintenanceFileEnv = "DEBUGLET_MAINTENANCE_FILE"

// maintenanceSchema is the record version the dispatcher understands.
const maintenanceSchema = 1

// reasonLimit bounds the operator note the record carries, in bytes. The
// dispatcher applies the same bound to what it repeats to a client.
const reasonLimit = 200

// Maintenance is the dispatcher admission switch as an operator sees it.
type Maintenance struct {
	SchemaVersion int    `json:"schema_version"`
	Paused        bool   `json:"paused"`
	Reason        string `json:"reason,omitempty"`
	Since         string `json:"since,omitempty"`
}

// WriteMaintenance stops submission admission on a managed dispatcher. The
// record is published atomically, mode 0644, in the administration directory:
// the running daemon reads it without any change to its privileges and cannot
// write, replace or unlink it, so a dispatcher cannot take itself out of
// maintenance.
//
// Writing it stops one thing: the admission of new submissions. Accepted work
// keeps its persistence and its schedule, connected executors keep running,
// results keep being reported and every query keeps answering.
func WriteMaintenance(path string, reason string, at time.Time) error {
	record := Maintenance{SchemaVersion: maintenanceSchema, Paused: true,
		Reason: trimReason(reason), Since: at.UTC().Format(time.RFC3339)}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return writeFileAtomic(path, append(data, '\n'), 0644)
}

// ClearMaintenance resumes submission admission by removing the switch. A
// dispatcher reads the switch for every submission, so admission resumes
// without a restart.
func ClearMaintenance(path string) (bool, error) {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ReadMaintenance reports the switch an operator previously wrote. An absent
// switch is reported as not paused, with no error.
func ReadMaintenance(path string) (Maintenance, error) {
	var record Maintenance
	if path == "" {
		return record, nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return record, nil
	}
	if err != nil {
		return record, err
	}
	if !info.Mode().IsRegular() || info.Size() > maintenanceLimit {
		return record, fmt.Errorf("%s is not a maintenance record within %d bytes", path, maintenanceLimit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(data, &record); err != nil {
		return record, fmt.Errorf("invalid maintenance record %s: %w", path, err)
	}
	return record, nil
}

// trimReason keeps an operator note printable and short. It reaches clients
// and logs through the dispatcher's refusal, which applies the same bound. The
// bound is in bytes and is moved back onto a character boundary, so a note cut
// inside a multi-byte rune never becomes invalid UTF-8 in a record or a body.
func trimReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, reason)
	reason = strings.TrimSpace(reason)
	if len(reason) > reasonLimit {
		reason = strings.TrimSpace(strings.ToValidUTF8(reason[:reasonLimit], ""))
	}
	return reason
}
