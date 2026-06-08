package rpc

import (
	"context"
	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (s *Server) UploadDebuglet(ctx context.Context, debugletID string, d dispatcher.DebugletSpec) error {
	stream, ok := s.registry.Get(d.ExecutorID)
	if !ok {
		return fmt.Errorf("executor '%s' not found", d.ExecutorID)
	}

	// abort if request context has already been cancelled
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	var startTime *timestamppb.Timestamp
	if d.StartTime != nil {
		timestamppb.New(*d.StartTime)
	}

	return stream.Send(&pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Upload{
			Upload: &pb.DebugletSpec{
				Id:        debugletID,
				StartTime: startTime,
				Wasm:      d.Wasm,
				Policy: &pb.DebugletSpec_Policy{
					FloorBw:   d.Policy.FloorBW,
					CeilBw:    d.Policy.CeilBW,
					TimeoutMs: d.Policy.Timeout.Milliseconds(),
					Addresses: d.Policy.Addresses,
				},
			},
		},
	})
}
