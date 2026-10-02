// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package rpc

import (
	"context"
	"errors"
	"net"
	"net/netip"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ReflectAddress opens one additional direct channel to an operator-selected
// literal address of this dispatcher, under the existing TLS identity and
// control binding. No request, peer response or DNS result chooses its target.
func (b *BidiClient) ReflectAddress(ctx context.Context, binding controlsession.Binding, endpoint string, request *pb.ReflectAddressRequest) (*pb.ReflectAddressResponse, error) {
	address, err := netip.ParseAddrPort(endpoint)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Addr().Zone() != "" {
		return nil, errors.New("invalid configured reflector")
	}
	b.mu.Lock()
	if b.control == nil || b.leaseLocked(binding, false) != nil {
		b.mu.Unlock()
		return nil, errors.New("reflector control session unavailable")
	}
	control := *b.control
	creds := b.opts.TLSCreds
	b.mu.Unlock()
	if creds == nil {
		if !address.Addr().IsLoopback() {
			return nil, errors.New("plaintext reflection requires loopback")
		}
		creds = insecure.NewCredentials()
	} else {
		creds = creds.Clone()
	}
	family := "tcp6"
	if address.Addr().Is4() {
		family = "tcp4"
	}
	connection, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, family, endpoint)
	}))
	if err != nil {
		return nil, err
	}
	defer connection.Close()
	response, err := pb.NewDispatcherServiceClient(connection).ReflectAddress(control.Outgoing(ctx), request)
	if err == nil {
		err = b.CheckLease(binding)
	}
	return response, control.RedactError(err)
}

func (c *boundDispatcherClient) ReflectAddress(ctx context.Context, in *pb.ReflectAddressRequest, opts ...grpc.CallOption) (*pb.ReflectAddressResponse, error) {
	if err := c.owner.CheckLease(c.credentials.Binding); err != nil {
		return nil, err
	}
	out, err := c.client.ReflectAddress(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
