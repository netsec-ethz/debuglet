package executor

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// The executor converts the numbers the control protocol carries into a run
// budget and into rates. It checks them itself: the dispatcher has its own
// bounds, but a run that is scheduled against an unchecked budget or a rate
// that is charged against an unchecked limit is the executor's own failure.

// boundsUploadPolicy is the policy every case below starts from.
func boundsUploadPolicy() *pb.DebugletPolicy {
	return &pb.DebugletPolicy{FloorBw: 64_000, CeilBw: 1_000_000, TimeoutMs: 30_000, Addresses: []string{"127.0.0.1"}}
}

func boundsUploadRequest() *pb.UploadRequest {
	return &pb.UploadRequest{
		Id:             uuid.NewString(),
		ControlBinding: operationWireBinding(),
		Wasm:           []byte("\x00asm\x01\x00\x00\x00"),
		TransactionId:  "local-policy-bounds",
		Policy:         boundsUploadPolicy(),
	}
}

// TestUploadRejectsOutOfRangePolicyNumbers drives the Upload boundary with the
// values a compromised or buggy control peer can send. Every one of them used
// to become a scheduled run: a negative floor as a negative rate, a
// maximum-integer budget as a duration that wrapped.
func TestUploadRejectsOutOfRangePolicyNumbers(t *testing.T) {
	storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
	e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
	ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
	defer cancel()

	// The unedited request is admitted, so every rejection below is the edit.
	if _, err := e.OnUpload(ctx, operationBinding(), boundsUploadRequest()); err != nil {
		t.Fatalf("valid upload rejected: %v", err)
	}
	if len(storage.inserted) != 1 {
		t.Fatalf("valid upload reached persistence %d times, want 1", len(storage.inserted))
	}

	for _, tc := range []struct {
		name string
		edit func(*pb.UploadRequest)
	}{
		{"missing policy", func(r *pb.UploadRequest) { r.Policy = nil }},
		{"negative floor", func(r *pb.UploadRequest) { r.Policy.FloorBw = -1 }},
		{"maximum floor", func(r *pb.UploadRequest) { r.Policy.FloorBw, r.Policy.CeilBw = math.MaxInt64, math.MaxInt64 }},
		{"floor above the bound", func(r *pb.UploadRequest) {
			r.Policy.FloorBw, r.Policy.CeilBw = maxPolicyBitrate+1, maxPolicyBitrate+1
		}},
		{"negative ceiling", func(r *pb.UploadRequest) { r.Policy.FloorBw, r.Policy.CeilBw = 0, -1 }},
		{"ceiling above the bound", func(r *pb.UploadRequest) { r.Policy.CeilBw = maxPolicyBitrate + 1 }},
		{"ceiling below floor", func(r *pb.UploadRequest) { r.Policy.CeilBw = r.Policy.FloorBw - 1 }},
		{"zero timeout", func(r *pb.UploadRequest) { r.Policy.TimeoutMs = 0 }},
		{"negative timeout", func(r *pb.UploadRequest) { r.Policy.TimeoutMs = -1 }},
		{"maximum timeout", func(r *pb.UploadRequest) { r.Policy.TimeoutMs = math.MaxInt64 }},
		{"timeout above the bound", func(r *pb.UploadRequest) { r.Policy.TimeoutMs = maxPolicyTimeoutMS + 1 }},
		{"unrepresentable start time", func(r *pb.UploadRequest) {
			r.StartTime = &timestamppb.Timestamp{Seconds: math.MaxInt64}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(boundsUploadRequest()).(*pb.UploadRequest)
			tc.edit(req)
			_, err := e.OnUpload(ctx, operationBinding(), req)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Upload code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
			if len(storage.inserted) != 1 {
				t.Fatalf("rejected Upload reached persistence: %d inserts", len(storage.inserted))
			}
		})
	}
}

// TestUploadKeepsUnitsAtTheBoundaries pins the conversion the Upload performs:
// bits per second stay bits per second and milliseconds become exactly that
// many milliseconds.
func TestUploadKeepsUnitsAtTheBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		floor   int64
		ceiling int64
		timeout int64
	}{
		{"zero bandwidth", 0, 0, 1},
		{"typical", 64_000, 1_000_000, 30_000},
		{"largest bandwidth", maxPolicyBitrate, maxPolicyBitrate, 1},
		{"largest budget", 0, 1, maxPolicyTimeoutMS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := &uploadBindingScheduler{abortTestScheduler: &abortTestScheduler{}}
			e, _ := newExecutorRPCFixture(t, newOperationPeer(), storage)
			ctx, cancel := context.WithTimeout(context.Background(), operationTestBound)
			defer cancel()

			req := boundsUploadRequest()
			req.Policy.FloorBw, req.Policy.CeilBw, req.Policy.TimeoutMs = tc.floor, tc.ceiling, tc.timeout
			if _, err := e.OnUpload(ctx, operationBinding(), req); err != nil {
				t.Fatalf("boundary upload rejected: %v", err)
			}
			if len(storage.inserted) != 1 {
				t.Fatalf("boundary upload reached persistence %d times, want 1", len(storage.inserted))
			}
			policy := storage.inserted[0].Policy
			if policy.FloorBW != tc.floor || policy.CeilBW != tc.ceiling {
				t.Fatalf("bandwidth = (%d, %d), want (%d, %d) bits per second", policy.FloorBW, policy.CeilBW, tc.floor, tc.ceiling)
			}
			if policy.Timeout != time.Duration(tc.timeout)*time.Millisecond {
				t.Fatalf("timeout = %s, want %d ms", policy.Timeout, tc.timeout)
			}
			if got := policy.Timeout.Milliseconds(); got != tc.timeout {
				t.Fatalf("timeout round trip = %d ms, want %d ms", got, tc.timeout)
			}
		})
	}
}

// TestBandwidthRejectsOutOfRangeLimitsWithoutApplyingAny covers the limits an
// allocation answers with. The message is one decision, so a value the
// executor cannot account for must leave every capacity as it was, including
// the ones named before it in the same message.
func TestBandwidthRejectsOutOfRangeLimitsWithoutApplyingAny(t *testing.T) {
	const (
		good = "203.0.113.40"
		bad  = "203.0.113.41"
	)
	for _, tc := range []struct {
		name  string
		limit int64
	}{
		{"negative", -1},
		{"maximum", math.MaxInt64},
		{"above the bound", maxPolicyBitrate + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			counter := newRecordingPacketCount()
			e := newFixtureExecutor(t, fixtureConfig(), counter, newFixtureMemoryStorage(t))
			id := uuid.New()
			if err := e.limiter.InsertDebuglet(id, 0, 1000, []string{good, bad}); err != nil {
				t.Fatal(err)
			}
			e.running[id] = RunningDebuglet{id: id}

			req := &pb.BandwidthRequest{Limits: []*pb.DestinationLimit{
				{Address: good, BitsLimit: 800},
				{Address: bad, BitsLimit: tc.limit},
			}}
			if _, err := e.applyBandwidth(operationBinding(), req); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("Bandwidth code = %v (%v), want InvalidArgument", status.Code(err), err)
			}
			for _, addr := range []string{good, bad} {
				if applied := counter.appliedDestination(addr, id); applied != 0 {
					t.Fatalf("rejected message applied %d bits per second to %s, want none", applied, addr)
				}
			}

			// The same message without the rejected value is applied in full,
			// so the rejection is the value and not the message.
			req.Limits[1].BitsLimit = 400
			if _, err := e.applyBandwidth(operationBinding(), req); err != nil {
				t.Fatalf("valid Bandwidth rejected: %v", err)
			}
			if applied := counter.appliedDestination(good, id); applied != 800 {
				t.Fatalf("applied %d bits per second to %s, want 800", applied, good)
			}
			if applied := counter.appliedDestination(bad, id); applied != 400 {
				t.Fatalf("applied %d bits per second to %s, want 400", applied, bad)
			}
		})
	}
}
