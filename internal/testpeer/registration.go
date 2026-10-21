// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package testpeer

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

// Dispatcher is the lifetime and control state needed by a registered peer.
// It avoids importing the dispatcher package into its own test fixtures.
type Dispatcher interface {
	drpc.DispatcherState
	OnReflectAddress(context.Context, *drpc.Mutation, *pb.ReflectAddressRequest, string) (*pb.ReflectAddressResponse, error)
	ControlIncarnation() string
	ControlLeaseDuration() time.Duration
	Close()
}

type registration struct {
	Dispatcher
	ready chan registered
	once  sync.Once
}

type registered struct {
	owner *drpc.SessionOwner
	err   error
}

func (r *registration) OnExecutorConnected(ctx context.Context, owner *drpc.SessionOwner, hello *pb.HelloResponse, sourceIP string) error {
	err := r.Dispatcher.OnExecutorConnected(ctx, owner, hello, sourceIP)
	// The transport marks availability after this callback returns.
	r.once.Do(func() { r.ready <- registered{owner, err} })
	return err
}

// RegisteredControl includes the negotiated identity and direct RPC client.
// Stop joins both the transport and the dispatcher, even after a caller timeout.
type RegisteredControl struct {
	Owner  *drpc.SessionOwner
	Client pb.DispatcherServiceClient
	stop   func(context.Context) error
}

func (p *RegisteredControl) Stop(ctx context.Context) error { return p.stop(ctx) }

// StartRegistered replaces an idle dispatcher transport, connects a scripted
// executor and acknowledges its capacity. The registration deadline does not
// shorten the lifetime of a successful connection. On failure, a non-nil result
// retains a shutdown whose join exceeded the cleanup deadline.
func StartRegistered(ctx context.Context, d Dispatcher, bidi **drpc.BidiServer, capacity bitrate.Bitrate, service pb.ExecutorServiceServer, timeout time.Duration) (*RegisteredControl, error) {
	if capacity <= 0 {
		return nil, errors.New("control peer: capacity must be positive")
	}
	if service == nil {
		return nil, errors.New("control peer: nil executor service")
	}
	registrationCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	(*bidi).Close()
	state := &registration{Dispatcher: d, ready: make(chan registered, 1)}
	replacement, err := drpc.NewBidiServer(zap.NewNop(), state, d.ControlIncarnation(), d.ControlLeaseDuration())
	if err != nil {
		return nil, err
	}
	*bidi = replacement
	transport, err := Start(ctx, replacement, service)
	if err != nil {
		d.Close()
		return nil, err
	}
	var once sync.Once
	joined := make(chan struct{})
	p := &RegisteredControl{}
	p.stop = func(cleanup context.Context) error {
		once.Do(func() {
			go func() {
				defer close(joined)
				_ = transport.Stop(context.Background())
				d.Close()
			}()
		})
		select {
		case <-joined:
			return nil
		case <-cleanup.Done():
			return cleanup.Err()
		}
	}
	fail := func(cause error) (*RegisteredControl, error) {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := p.Stop(cleanup); err != nil {
			return p, errors.Join(cause, err)
		}
		return nil, cause
	}
	if err := transport.Client.WaitReadyContext(registrationCtx); err != nil {
		if registrationCtx.Err() != nil {
			err = registrationCtx.Err()
		}
		return fail(fmt.Errorf("control peer: registration: %w", err))
	}
	var result registered
	select {
	case result = <-state.ready:
	case <-registrationCtx.Done():
		return fail(registrationCtx.Err())
	}
	if result.err != nil {
		return fail(result.err)
	}
	if result.owner == nil || !result.owner.Available() {
		return fail(errors.New("control peer: registration has no available owner"))
	}
	binding, ok := transport.Client.Binding()
	if !ok || binding != result.owner.Binding() {
		return fail(errors.New("control peer: negotiated identity mismatch"))
	}
	p.Owner = result.owner
	p.Client, err = transport.Client.ClientFor(binding)
	if err != nil {
		return fail(err)
	}
	if _, err := p.Client.Resources(registrationCtx, &pb.ResourcesRequest{ExecutorId: p.Owner.ExecutorID(), BandwidthCapacity: int64(capacity)}); err != nil {
		return fail(err)
	}
	if _, ok := replacement.GetClientFor(p.Owner); !ok {
		return fail(errors.New("control peer: exact reverse client is unavailable"))
	}
	return p, nil
}
