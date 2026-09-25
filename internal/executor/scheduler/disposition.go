package scheduler

import "fmt"

// Disposition is what an executor's retained storage holds once no session
// owns it any more: the evidence an operator needs before deciding whether a
// drained node may be upgraded, deleted or rebuilt.
//
// It is a count of stored rows, not a claim about remote state. A retained
// terminal event in particular says only that this executor selected a result
// and does not know whether the dispatcher recorded it; a delivered but
// unacknowledged result and an undelivered one are indistinguishable here, and
// both are reported as still retained.
type Disposition struct {
	// Retained is every stored execution row, whatever its binding.
	Retained int64 `json:"retained"`
	// Started counts retained rows that carry a start marker. This build
	// never re-runs one: a restarted executor refuses a row it already
	// started instead of executing it a second time.
	Started int64 `json:"started"`
	// Queued counts retained rows that were accepted and persisted but
	// never started. They stay in the database; nothing replays them.
	Queued int64 `json:"queued"`
	// Quarantined counts retained rows the next start will refuse to
	// restore. This build quarantines every stored binding, so a stopped
	// executor's whole retained queue is quarantined work.
	Quarantined int64 `json:"quarantined"`
	// Bindings counts the distinct control sessions the retained rows came
	// from, so an operator can see whether retained work accumulated over
	// several sessions.
	Bindings int `json:"bindings"`
	// RetainedTerminal counts terminal results this executor still holds
	// because it has not observed a durable acknowledgement for them.
	RetainedTerminal int64 `json:"retained_terminal"`
	// UnsentTerminal counts retained results no delivery attempt ever left
	// the executor for. The dispatcher cannot hold these.
	UnsentTerminal int64 `json:"unsent_terminal"`
	// RejectedTerminal counts retained results the dispatcher refused
	// permanently. They stay as evidence and are never retried.
	RejectedTerminal int64 `json:"rejected_terminal"`
	// Truncated reports that the retained rows come from more control
	// sessions than the inspection counts, so Bindings is a lower bound.
	// The counts of rows and results above are always exact.
	Truncated bool `json:"truncated"`
}

// Empty reports storage that holds no retained execution row and no retained
// terminal result: nothing local is left that an operator has to preserve.
func (d Disposition) Empty() bool {
	return d.Retained == 0 && d.RetainedTerminal == 0
}

// Summary describes the disposition in one line of operator-facing text.
func (d Disposition) Summary() string {
	sessions := fmt.Sprintf("%d control sessions", d.Bindings)
	if d.Truncated {
		sessions = fmt.Sprintf("at least %d control sessions", d.Bindings)
	}
	return fmt.Sprintf("%d queued and %d started rows retained from %s, %d quarantined on the next start, %d terminal results still unacknowledged (%d never sent, %d permanently refused)",
		d.Queued, d.Started, sessions, d.Quarantined, d.RetainedTerminal, d.UnsentTerminal, d.RejectedTerminal)
}
