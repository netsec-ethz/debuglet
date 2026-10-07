package rpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// inspectionState adds the optional inspection to a scripted executor state.
// A plain negotiationState deliberately lacks it, which is how an executor
// without retained-run inspection behaves on the wire.
type inspectionState struct {
	*negotiationState
	calls    atomic.Int32
	admitted atomic.Value
}

func (s *inspectionState) OnInspectRetainedRun(_ context.Context, binding controlsession.Binding, _ *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	s.calls.Add(1)
	s.admitted.Store(binding)
	return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
}

func inspectionRequest(binding *pb.ControlBinding) *pb.InspectRetainedRunRequest {
	return &pb.InspectRetainedRunRequest{DebugletId: "00000000-0000-4000-8000-00000000000a", ControlBinding: binding}
}

// Inspection is admitted exactly like every other reverse effect, and an
// executor without it answers UNIMPLEMENTED. Neither outcome can be confused
// with a successful answer that no such row exists.
func TestBidiOptionalInspectionAdmission(t *testing.T) {
	for _, supported := range []bool{false, true} {
		name := "unsupported"
		if supported {
			name = "supported"
		}
		t.Run(name, func(t *testing.T) {
			base := &negotiationState{}
			var state ExecutorState = base
			scripted := &inspectionState{negotiationState: base}
			if supported {
				state = scripted
			}
			offer := negotiationOffer()
			f := newNegotiationFixture(t, state, offer, time.Second, func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
				return &pb.BindSessionResponse{LeaseDurationMs: time.Minute.Milliseconds()}, nil
			})
			hello := f.helloResult()
			if hello.err != nil {
				t.Fatal(hello.err)
			}
			if err := f.client.WaitReadyContext(f.ctx); err != nil {
				t.Fatal(err)
			}
			own := &pb.ControlBinding{DispatcherIncarnation: offer.DispatcherIncarnation, SessionId: offer.SessionId}

			// Without control metadata the call never reaches the state.
			if _, err := hello.client.InspectRetainedRun(f.ctx, inspectionRequest(own)); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("unadmitted inspection status=%v", status.Code(err))
			}
			credentials := controlrpc.Credentials{Binding: controlsession.Binding{Incarnation: offer.DispatcherIncarnation, SessionID: offer.SessionId}}
			copy(credentials.Token[:], offer.SessionToken)
			ctx := credentials.Outgoing(f.ctx)

			if !supported {
				if _, err := hello.client.InspectRetainedRun(ctx, inspectionRequest(own)); status.Code(err) != codes.Unimplemented {
					t.Fatalf("executor without inspection answered %v", status.Code(err))
				}
				if scripted.calls.Load() != 0 {
					t.Fatal("unsupported peer reached a scripted handler")
				}
				return
			}

			other := &pb.ControlBinding{DispatcherIncarnation: offer.DispatcherIncarnation, SessionId: "00000000-0000-4000-8000-000000000009"}
			if _, err := hello.client.InspectRetainedRun(ctx, inspectionRequest(other)); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("inspection named another session: %v", status.Code(err))
			}
			if _, err := hello.client.InspectRetainedRun(ctx, inspectionRequest(&pb.ControlBinding{})); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("malformed inspection binding: %v", status.Code(err))
			}
			if scripted.calls.Load() != 0 {
				t.Fatal("rejected inspection reached the state")
			}
			resp, err := hello.client.InspectRetainedRun(ctx, inspectionRequest(own))
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetStatus() != pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT || scripted.calls.Load() != 1 {
				t.Fatalf("admitted inspection: %+v calls=%d", resp, scripted.calls.Load())
			}
			if got, _ := scripted.admitted.Load().(controlsession.Binding); got != credentials.Binding {
				t.Fatalf("state received %+v, want the admitted binding", got)
			}
		})
	}
}

// verificationState adds the optional tag verification to a scripted state.
type verificationState struct {
	*negotiationState
	calls    atomic.Int32
	admitted atomic.Value
}

func (s *verificationState) OnVerifyTags(_ context.Context, binding controlsession.Binding, _ *pb.VerifyTagsRequest) (*pb.VerifyTagsResponse, error) {
	s.calls.Add(1)
	s.admitted.Store(binding)
	return &pb.VerifyTagsResponse{Verdict: "unmatched"}, nil
}

func verificationRequest(binding *pb.ControlBinding) *pb.VerifyTagsRequest {
	return &pb.VerifyTagsRequest{ControlBinding: binding, Epoch: 1,
		CandidateRunIds: []string{"00000000-0000-4000-8000-00000000000a"}, Packets: [][]byte{make([]byte, 20)}}
}

// Tag verification is admitted exactly like retained-run inspection, and an
// executor without it answers UNIMPLEMENTED.
func TestBidiOptionalVerificationAdmission(t *testing.T) {
	for _, supported := range []bool{false, true} {
		name := "unsupported"
		if supported {
			name = "supported"
		}
		t.Run(name, func(t *testing.T) {
			base := &negotiationState{}
			var state ExecutorState = base
			scripted := &verificationState{negotiationState: base}
			if supported {
				state = scripted
			}
			offer := negotiationOffer()
			f := newNegotiationFixture(t, state, offer, time.Second, func(context.Context, *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
				return &pb.BindSessionResponse{LeaseDurationMs: time.Minute.Milliseconds()}, nil
			})
			hello := f.helloResult()
			if hello.err != nil {
				t.Fatal(hello.err)
			}
			if err := f.client.WaitReadyContext(f.ctx); err != nil {
				t.Fatal(err)
			}
			own := &pb.ControlBinding{DispatcherIncarnation: offer.DispatcherIncarnation, SessionId: offer.SessionId}

			// Without control metadata the call never reaches the state.
			if _, err := hello.client.VerifyTags(f.ctx, verificationRequest(own)); status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("unadmitted verification status=%v", status.Code(err))
			}
			credentials := controlrpc.Credentials{Binding: controlsession.Binding{Incarnation: offer.DispatcherIncarnation, SessionID: offer.SessionId}}
			copy(credentials.Token[:], offer.SessionToken)
			ctx := credentials.Outgoing(f.ctx)

			if !supported {
				if _, err := hello.client.VerifyTags(ctx, verificationRequest(own)); status.Code(err) != codes.Unimplemented {
					t.Fatalf("executor without verification answered %v", status.Code(err))
				}
				if scripted.calls.Load() != 0 {
					t.Fatal("unsupported peer reached a scripted handler")
				}
				return
			}

			other := &pb.ControlBinding{DispatcherIncarnation: offer.DispatcherIncarnation, SessionId: "00000000-0000-4000-8000-000000000009"}
			if _, err := hello.client.VerifyTags(ctx, verificationRequest(other)); status.Code(err) != codes.PermissionDenied {
				t.Fatalf("verification named another session: %v", status.Code(err))
			}
			if _, err := hello.client.VerifyTags(ctx, verificationRequest(&pb.ControlBinding{})); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("malformed verification binding: %v", status.Code(err))
			}
			if scripted.calls.Load() != 0 {
				t.Fatal("rejected verification reached the state")
			}
			resp, err := hello.client.VerifyTags(ctx, verificationRequest(own))
			if err != nil {
				t.Fatal(err)
			}
			if resp.GetVerdict() != "unmatched" || scripted.calls.Load() != 1 {
				t.Fatalf("admitted verification: %+v calls=%d", resp, scripted.calls.Load())
			}
			if got, _ := scripted.admitted.Load().(controlsession.Binding); got != credentials.Binding {
				t.Fatalf("state received %+v, want the admitted binding", got)
			}
		})
	}
}
