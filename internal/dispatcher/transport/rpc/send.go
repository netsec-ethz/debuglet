package rpc

import (
	"context"
	"debuglet/internal/dispatcher"
	pb "debuglet/protocol"
	"fmt"
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

	return stream.Send(&pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Upload{
			Upload: &pb.Debuglet{
				SessionId: debugletID,
				Wasm:      d.Wasm,
				Policy: &pb.Debuglet_Policy{
					FloorBw:   d.Policy.FloorBW,
					CeilBw:    d.Policy.CeilBW,
					TimeoutMs: d.Policy.Timeout.Milliseconds(),
					Addresses: d.Policy.Addresses,
				},
			},
		},
	})
}
