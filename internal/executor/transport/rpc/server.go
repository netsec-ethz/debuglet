// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

type server struct {
	pb.UnsafeExecutorServiceServer
	state ExecutorState
	bidi  *BidiClient
}

func (s *server) Hello(ctx context.Context, in *pb.HelloRequest) (*pb.HelloResponse, error) {
	if in.GetControlVersion() != controlsession.ProtocolVersion {
		s.bidi.Stop(endCause(controlsession.IncompatibleProfile, unsupportedProfile()))
		return nil, unsupportedProfile()
	}
	timing, err := controlsession.LeaseTimingFromMillis(in.GetLeaseDurationMs())
	if err != nil {
		return nil, controlrpc.Malformed()
	}
	binding, err := controlsession.ParseBinding(in.GetDispatcherIncarnation(), in.GetSessionId())
	if err != nil || len(in.GetSessionToken()) != 32 {
		return nil, controlrpc.Malformed()
	}
	credentials := controlrpc.Credentials{Binding: binding}
	copy(credentials.Token[:], in.GetSessionToken())
	b := s.bidi
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, controlrpc.Unavailable()
	}
	if b.control != nil {
		same := b.control.Matches(credentials) && b.lease == timing
		b.mu.Unlock()
		if !same {
			return nil, controlrpc.Unavailable()
		}
		select {
		case <-b.helloDone:
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.helloErr != nil || b.closed {
			return nil, controlrpc.Unavailable()
		}
		return proto.Clone(b.hello).(*pb.HelloResponse), nil
	}
	b.control = &credentials
	b.lease = timing
	b.mu.Unlock()
	// The session token stays here; only the binding reaches the state below.
	profileReq := &pb.HelloRequest{ControlVersion: controlsession.ProtocolVersion, DispatcherIncarnation: binding.Incarnation, SessionId: binding.SessionID, LeaseDurationMs: timing.Duration.Milliseconds()}
	out, err := s.state.OnHello(ctx, profileReq)
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil || out == nil || out.GetExecutorId() == "" || b.closed || ctx.Err() != nil || !b.now().Before(b.startupDeadline) {
		b.helloErr = controlrpc.Unavailable()
		close(b.helloDone)
		return nil, b.helloErr
	}
	b.hello = proto.Clone(out).(*pb.HelloResponse)
	b.hello.ControlVersion = controlsession.ProtocolVersion
	b.hello.DispatcherIncarnation = binding.Incarnation
	b.hello.SessionId = binding.SessionID
	b.hello.LeaseDurationMs = timing.Duration.Milliseconds() // Offer only; Bind send arms authority.
	close(b.helloDone)
	close(b.offered)
	return proto.Clone(b.hello).(*pb.HelloResponse), nil
}

func (s *server) admission(ctx context.Context, pending bool) (controlsession.Binding, error) {
	credentials, err := controlrpc.Read(ctx)
	if err != nil {
		return controlsession.Binding{}, err
	}
	b := s.bidi
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.control == nil || !b.control.Matches(credentials) || b.leaseLocked(credentials.Binding, pending) != nil {
		return controlsession.Binding{}, controlrpc.Unavailable()
	}
	return b.control.Binding, nil
}
func (s *server) Upload(ctx context.Context, in *pb.UploadRequest) (*pb.UploadResponse, error) {
	binding, err := s.admission(ctx, true)
	if err != nil {
		return nil, err
	}
	if err := CheckPayloadBinding(in.GetControlBinding(), binding); err != nil {
		return nil, err
	}
	return s.state.OnUpload(ctx, binding, in)
}
func (s *server) Abort(ctx context.Context, in *pb.AbortRequest) (*pb.AbortResponse, error) {
	binding, err := s.admission(ctx, false)
	if err != nil {
		return nil, err
	}
	return s.state.OnAbort(ctx, binding, in)
}
func (s *server) Bandwidth(ctx context.Context, in *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	binding, err := s.admission(ctx, false)
	if err != nil {
		return nil, err
	}
	return s.state.OnBandwidth(ctx, binding, in)
}

// retainedRunInspector is the optional part of ExecutorState behind the
// optional inspection RPC. A state that does not implement it answers
// UNIMPLEMENTED, which a caller must never read as a missing row.
type retainedRunInspector interface {
	OnInspectRetainedRun(ctx context.Context, binding controlsession.Binding, req *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error)
}

// InspectRetainedRun admits the exact armed session like every other effect,
// then requires the caller to name that same session in the request, so a
// lookup can never be replayed against a different binding.
func (s *server) InspectRetainedRun(ctx context.Context, in *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	binding, err := s.admission(ctx, false)
	if err != nil {
		return nil, err
	}
	inspector, ok := s.state.(retainedRunInspector)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "retained run inspection is unavailable")
	}
	if err := CheckPayloadBinding(in.GetControlBinding(), binding); err != nil {
		return nil, err
	}
	return inspector.OnInspectRetainedRun(ctx, binding, in)
}

// ProbeSession touches no scheduler, telemetry, SQL or outbound RPC. It is a
// bounded reverse-path proof under the same confirmed lease as other effects.
func (s *server) ProbeSession(ctx context.Context, in *pb.ProbeSessionRequest) (*pb.ProbeSessionResponse, error) {
	if _, err := s.admission(ctx, false); err != nil {
		return nil, err
	}
	if in.GetSequence() == 0 {
		return nil, controlrpc.Malformed()
	}
	return &pb.ProbeSessionResponse{Sequence: in.Sequence}, nil
}
