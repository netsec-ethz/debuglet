package dispatcher

import (
	"errors"
	"strings"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

// TestCancellationResultThatIsNotRecordedIsReported cancels a run whose
// executor acknowledges the Abort while SQLite refuses the terminal write.
// The cancellation is reported as acknowledged but not recorded, and the run
// and its resources stay as they were. Once the write succeeds the
// cancellation is recorded, and repeating it on the terminal run keeps that
// result and releases nothing again. A refusal by the executor stays a
// refusal.
func TestCancellationResultThatIsNotRecordedIsReported(t *testing.T) {
	peer := &tgPeer{}
	f := newTGFixture(t, peer)
	a, err := f.submit(t, tgFloorA)
	if err != nil {
		t.Fatalf("submit A: %v", err)
	}
	b, err := f.submit(t, tgFloorB)
	if err != nil {
		t.Fatalf("submit B: %v", err)
	}
	tgAssertReserved(t, f, a, tgFloorA+tgFloorB)

	before := f.snapshot(t)
	aborts := len(peer.recordedAborts())
	drop := f.installTrigger(t)
	err = f.abort(t, a.id, "operator abort")
	if !errors.Is(err, ErrCancellationNotRecorded) || !strings.Contains(err.Error(), tgSentinel) {
		t.Fatalf("abort with a failing terminal write returned %v, want %v caused by %q", err, ErrCancellationNotRecorded, tgSentinel)
	}
	if recorded := peer.recordedAborts(); len(recorded) != aborts+1 || recorded[aborts].GetDebugletId() != a.id.String() {
		t.Fatalf("peer recorded aborts %+v, want the acknowledged one", recorded)
	}
	tgAssertSnapshot(t, f, before, "unrecorded cancellation")
	tgAssertRow(t, f.row(t, a.id), models.RunStateUploaded, tgNull)
	tgAssertReserved(t, f, a, tgFloorA+tgFloorB)

	drop()
	if err := f.abort(t, a.id, "operator abort"); err != nil {
		t.Fatalf("abort once the write succeeds: %v", err)
	}
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("operator abort"))
	tgAssertOrder(t, f, a, models.Outstanding)
	tgAssertReserved(t, f, a, tgFloorB)
	after := f.snapshot(t)

	if err := f.abort(t, a.id, "repeated abort"); err != nil {
		t.Fatalf("abort of the terminal run: %v", err)
	}
	tgAssertRow(t, f.row(t, a.id), models.RunStateExited, tgText("operator abort"))
	tgAssertSnapshot(t, f, after, "repeated cancellation")
	tgAssertReserved(t, f, a, tgFloorB)

	peer.scriptAbort(errors.New("executor refused the abort"))
	if err := f.abort(t, b.id, "refused"); err == nil || errors.Is(err, ErrCancellationNotRecorded) {
		t.Fatalf("refused abort returned %v, want a refusal", err)
	}
	tgAssertRow(t, f.row(t, b.id), models.RunStateUploaded, tgNull)
	tgAssertSnapshot(t, f, after, "refused cancellation")
	tgAssertReserved(t, f, b, tgFloorB)
}
