package dispatcher

import (
	"errors"
	"io"
	"testing"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	pb "github.com/netsec-ethz/debuglet/protocol"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// outputBrokenStream delivers its frames and then fails the way a broken
// transport does, while its context stays live: the failure is not a
// cancellation of the call.
type outputBrokenStream struct {
	effectStream
	err error
}

func (s *outputBrokenStream) Recv() (*pb.DebugletStreamRequest, error) {
	in, err := s.effectStream.Recv()
	if err == io.EOF {
		return nil, s.err
	}
	return in, err
}

func outputStoredFrames(t *testing.T, f *tgFixture) int {
	t.Helper()
	var frames int
	if err := f.db.QueryRow("SELECT count(*) FROM debuglet_logs").Scan(&frames); err != nil {
		t.Fatal(err)
	}
	return frames
}

// TestOutputStreamFailureIsNoTerminalResult breaks an identified output
// stream while the run is still live. A failed transport is no evidence of
// how the guest ended: the run keeps its state and the failed delivery is
// only logged, with the run ID. The executor's own report then wins with its
// exit code and error, and a second report changes nothing.
func TestOutputStreamFailureIsNoTerminalResult(t *testing.T) {
	f := newTGFixture(t, nil)
	core, logged := observer.New(zap.WarnLevel)
	f.d.logger = zap.New(core)
	run, other := f.seedDirect(t, tgFloorA), f.seedDirect(t, tgFloorB)
	if err := f.state(t, run.id, pb.RunState_RUN_STATE_STARTED); err != nil {
		t.Fatalf("Started: %v", err)
	}
	f.d.mu.RLock()
	owner := f.d.executors[tgExecutorID].owner
	f.d.mu.RUnlock()
	before := f.snapshot(t)

	broken := status.Error(codes.Unavailable, "output transport reset")
	stream := &outputBrokenStream{effectStream: effectStream{ctx: f.ctx, frames: []*pb.DebugletStreamRequest{effectIdent(run.id.String()), effectOutput()}}, err: broken}
	if err := f.d.OnDebugletStream(owner, stream); !errors.Is(err, broken) {
		t.Fatalf("broken stream returned %v, want its receive error", err)
	}
	if f.ctx.Err() != nil {
		t.Fatal("the stream context ended, so the failure was a cancellation")
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateStarted, tgNull)
	tgAssertSnapshot(t, f, before, "failed output stream")
	tgAssertReserved(t, f, run, tgFloorA+tgFloorB)
	if frames := outputStoredFrames(t, f); frames != 1 {
		t.Fatalf("stored output frames=%d, want the one received before the failure", frames)
	}
	if entries := logged.FilterField(zap.String("debugletID", run.id.String())).All(); len(entries) != 1 {
		t.Fatalf("failed delivery logged %d times with the run ID, want once: %+v", len(entries), logged.All())
	}

	// The executor's report is the outcome, with its own code and error.
	if err := f.exit(t, run.id, 3, tgStr("guest crashed")); err != nil {
		t.Fatalf("real exit after the failed stream: %v", err)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText("guest crashed"))
	tgAssertOrder(t, f, run, models.Outstanding)
	tgAssertReserved(t, f, run, tgFloorB)
	after := f.snapshot(t)
	if err := f.exit(t, run.id, 0, nil); err != nil {
		t.Fatalf("second report: %v", err)
	}
	tgAssertRow(t, f.row(t, run.id), models.RunStateExited, tgText("guest crashed"))
	tgAssertSnapshot(t, f, after, "second report")
	tgAssertReserved(t, f, run, tgFloorB)
	tgAssertEarnings(t, f, 0)
	tgAssertRow(t, f.row(t, other.id), models.RunStateUploaded, tgNull)
}

// TestOutputStreamFailureWithoutAuthorityHasNoEffect breaks streams that hold
// no authority over a run: one that fails before it is identified, and one
// whose session was retired before its transport failed. Neither changes the
// run.
func TestOutputStreamFailureWithoutAuthorityHasNoEffect(t *testing.T) {
	for _, name := range []string{"unidentified", "retired_session"} {
		t.Run(name, func(t *testing.T) {
			f := newTGFixture(t, nil)
			run := f.seedDirect(t, tgFloorA)
			f.d.mu.RLock()
			owner := f.d.executors[tgExecutorID].owner
			f.d.mu.RUnlock()
			stream := &outputBrokenStream{effectStream: effectStream{ctx: f.ctx}, err: status.Error(codes.Unavailable, "output transport reset")}
			if name == "retired_session" {
				stream.frames = []*pb.DebugletStreamRequest{effectIdent(run.id.String())}
				stream.beforeRecv = func(i int) {
					if i == 1 {
						owner.Retire()
					}
				}
			}
			before := f.snapshot(t)
			if err := f.d.OnDebugletStream(owner, stream); status.Code(err) != codes.Unavailable {
				t.Fatalf("broken stream returned %v, want its receive error", err)
			}
			tgAssertSnapshot(t, f, before, "broken "+name+" stream")
			tgAssertRow(t, f.row(t, run.id), models.RunStateUploaded, tgNull)
			tgAssertReserved(t, f, run, tgFloorA)
		})
	}
}
