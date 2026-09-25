package dispatcher

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// An operator stops submission admission for maintenance by creating one file,
// which the service manager names to this process and which this process may
// read and not write. The file is the whole mechanism:
//
//   - It adds no route, so it cannot be reached over the network and needs no
//     credential, no client and no API version to agree with.
//   - It survives a restart of the dispatcher, so maintenance is not undone by
//     the very restart it was declared for.
//   - It is read on each submission, so clearing it takes effect immediately
//     and a paused dispatcher never has to be restarted to serve again.
//   - It belongs to an administrator, so a dispatcher cannot replace, remove
//     or rewrite it and therefore cannot take itself out of maintenance.
//
// It stops exactly one thing: the admission of new submissions. Accepted work
// keeps its persistence, executors keep their control sessions, results keep
// being reported, and every query keeps answering.

// MaintenanceFileEnv names the environment variable that points the dispatcher
// at its maintenance switch. A dispatcher started without it has no switch and
// performs no file access per submission at all.
const MaintenanceFileEnv = "DEBUGLET_MAINTENANCE_FILE"

// maintenanceSwitchSchema is the only record version this build understands.
const maintenanceSwitchSchema = 1

// maintenanceLimit bounds a read of the switch file.
const maintenanceLimit = 4 << 10

// maintenanceReasonLimit bounds the operator note this build repeats to a
// client, in bytes.
const maintenanceReasonLimit = 200

// ErrMaintenanceMode reports a dispatcher whose operator has stopped
// submission admission. It is a refusal to accept new work, not a failure:
// nothing was reserved, persisted or charged.
var ErrMaintenanceMode = errors.New("dispatcher is in maintenance: submission admission is stopped")

// MaintenanceSwitch is the record the switch file carries.
type MaintenanceSwitch struct {
	SchemaVersion int    `json:"schema_version"`
	Paused        bool   `json:"paused"`
	Reason        string `json:"reason,omitempty"`
	Since         string `json:"since,omitempty"`
}

// AdmissionPaused reports whether this dispatcher may admit new submissions.
// A transport checks it before it looks up or charges anything, so a refusal
// costs a submitter nothing; the submission path checks it again, because that
// is where the decision has to hold.
func AdmissionPaused() error { return maintenanceStop(os.Getenv(MaintenanceFileEnv)) }

// maintenanceStop reads the switch at path. An absent file admits work. A file
// that exists but cannot be read or understood stops admission: the file is an
// administrator's, written outside anything this daemon can reach, so anything
// unexpected about it is a reason to stop rather than to guess, and an operator
// removes the file to serve again.
//
// What went wrong with the file is stated, but never the file: this message is
// repeated to whoever made the request, and where a host keeps its
// administration files is not part of answering one. The operator reads the
// same condition from the tool that wrote the switch.
func maintenanceStop(path string) error {
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("%w: its switch file cannot be inspected", ErrMaintenanceMode)
	}
	if !info.Mode().IsRegular() || info.Size() > maintenanceLimit {
		return fmt.Errorf("%w: its switch file is not a regular file within %d bytes", ErrMaintenanceMode, maintenanceLimit)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: its switch file cannot be read", ErrMaintenanceMode)
	}
	var state MaintenanceSwitch
	if err := json.Unmarshal(data, &state); err != nil || state.SchemaVersion != maintenanceSwitchSchema {
		return fmt.Errorf("%w: its switch file is not a maintenance record this build understands", ErrMaintenanceMode)
	}
	if !state.Paused {
		return nil
	}
	if reason := maintenanceReason(state.Reason); reason != "" {
		return fmt.Errorf("%w (%s)", ErrMaintenanceMode, reason)
	}
	return ErrMaintenanceMode
}

// maintenanceReason keeps an operator's note printable and short: it reaches
// clients and logs, so it carries no control characters and no unbounded text.
// The bound is in bytes, because that is what a response body costs, but it is
// moved back onto a character boundary: a note cut inside a multi-byte rune
// would put invalid UTF-8 into a JSON refusal.
func maintenanceReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, reason)
	reason = strings.TrimSpace(reason)
	if len(reason) > maintenanceReasonLimit {
		reason = strings.TrimSpace(strings.ToValidUTF8(reason[:maintenanceReasonLimit], ""))
	}
	return reason
}
