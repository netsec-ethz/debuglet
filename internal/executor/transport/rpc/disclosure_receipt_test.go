// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
)

type delayedReceiptClient struct {
	pb.DispatcherServiceClient
	finish func()
}

func (c *delayedReceiptClient) Heartbeat(context.Context, *pb.HeartbeatRequest, ...grpc.CallOption) (*pb.HeartbeatResponse, error) {
	c.finish()
	return &pb.HeartbeatResponse{DisclosureReceipts: []*pb.TeslaDisclosureReceipt{{StoredThroughEpoch: 1}}}, nil
}
func TestDisclosureReceiptCannotOutliveSessionLease(t *testing.T) {
	base := time.Now()
	var elapsed atomic.Int64
	b, binding := newLeaseUnitClient(t, func() time.Time { return base.Add(time.Duration(elapsed.Load())) })
	b.client = &delayedReceiptClient{finish: func() { elapsed.Store(int64(time.Second)) }}
	client, err := b.ClientFor(binding)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Heartbeat(t.Context(), &pb.HeartbeatRequest{})
	if err == nil || response != nil {
		t.Fatal("expired session exposed receipt", response, err)
	}
}
