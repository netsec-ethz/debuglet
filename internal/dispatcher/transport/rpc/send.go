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
		startTime = timestamppb.New(*d.StartTime)
	}

	return stream.Send(ctx, &pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Upload{
			Upload: &pb.DebugletUploadSpec{
				Id:        debugletID,
				StartTime: startTime,
				Wasm:      d.Wasm,
				Args:      d.Args,
				Policy: &pb.DebugletPolicy{
					FloorBw:   int64(d.Policy.FloorBW),
					CeilBw:    int64(d.Policy.CeilBW),
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

func (s *Server) DestinationUpdates(ctx context.Context, executorID string, updates []dispatcher.LimitUpdate) error {
	stream, ok := s.registry.Get(executorID)
	if !ok {
		return fmt.Errorf("executor '%s' not found", executorID)
	}

	var limits []*pb.DestinationUpdates_DestinationLimit
	for _, up := range updates {
		limits = append(limits, &pb.DestinationUpdates_DestinationLimit{
			Address:   up.Address,
			BitsLimit: int64(up.Limit),
		})
	}

	return stream.Send(ctx, &pb.DispatcherControlMessage{
		Msg: &pb.DispatcherControlMessage_Updates{
			Updates: &pb.DestinationUpdates{
				Limits: limits,
			},
		},
	})
}
