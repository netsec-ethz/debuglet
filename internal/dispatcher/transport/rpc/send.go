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

	var startTime *timestamppb.Timestamp
	if d.StartTime != nil {
		timestamppb.New(*d.StartTime)
	}

	return stream.Send(ctx, &pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Upload{
			Upload: &pb.DebugletUploadSpec{
				Id:        debugletID,
				StartTime: startTime,
				Wasm:      d.Wasm,
				Policy: &pb.DebugletUploadSpec_Policy{
					FloorBw:   d.Policy.FloorBW,
					CeilBw:    d.Policy.CeilBW,
					TimeoutMs: d.Policy.Timeout.Milliseconds(),
					Addresses: d.Policy.Addresses,
				},
			},
		},
	})
}

func (s *Server) AbortDebuglet(ctx context.Context, executorID, debugletID, reason string) error {
	stream, ok := s.registry.Get(executorID)
	if !ok {
		return fmt.Errorf("executor '%s' not found", executorID)
	}

	return stream.Send(ctx, &pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Abort{
			Abort: &pb.AbortDebuglet{
				DebugletId: debugletID,
				Reason:     reason,
			},
		},
	})
}
