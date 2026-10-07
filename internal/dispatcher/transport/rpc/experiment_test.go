// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"testing"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func (s *lifecycleState) OnExperimentReady(ctx context.Context, mutation *Mutation, req *pb.ExperimentReadyRequest) (*pb.ExperimentReadyResponse, error) {
	if !mutation.Live() || mutation.IsSetup() || mutation.Owner().ExecutorID() != req.ExecutorId {
		return nil, status.Error(codes.Internal, "invalid readiness mutation")
	}
	return &pb.ExperimentReadyResponse{ExperimentId: "authenticated"}, nil
}

func TestExperimentReadyUsesBoundAuthenticatedSession(t *testing.T) {
	f := newControlTLS(t, controlTLSOptions{requireClientIdentity: true})
	owned := f.connectedPeer(&lifecyclePeer{id: "executor", version: "A"}, f.ca.ClientConfig(f.client, ""))
	owner := f.registered("A")
	if err := owned.client.WaitReadyContext(f.ctx); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, executor string
		strip          bool
		want           codes.Code
	}{
		{"owner", "executor", false, codes.OK},
		{"foreign executor", "foreign", false, codes.PermissionDenied},
		{"empty executor", "", false, codes.PermissionDenied},
		{"missing credentials", "executor", true, codes.PermissionDenied},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := f.directCall(f.client, owner, func(ctx context.Context, client pb.DispatcherServiceClient) error {
				if tc.strip {
					ctx = metadata.NewOutgoingContext(ctx, metadata.MD{})
				}
				_, err := client.ExperimentReady(ctx, &pb.ExperimentReadyRequest{DebugletId: "run", ExecutorId: tc.executor})
				return err
			})
			if status.Code(err) != tc.want {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
	// Each poll has finished its mutation; retiring the session need not wait on
	// an application barrier or a guest's next poll.
	owner.Retire()
	awaitSessionSignal(t, owner.MutationsDrained())
}
