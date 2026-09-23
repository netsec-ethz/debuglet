// Package testpeer supplies real control transports around a scripted executor
// for integration tests. The scripts choose application responses; negotiation,
// metadata, admission and transport lifetime remain production implementations.
package testpeer

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/netsec-ethz/debuglet/internal/controlsession"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
)

type ExecutorState struct{ Service pb.ExecutorServiceServer }

func (s ExecutorState) OnHello(ctx context.Context, r *pb.HelloRequest) (*pb.HelloResponse, error) {
	return s.Service.Hello(ctx, r)
}
func (s ExecutorState) OnUpload(ctx context.Context, _ controlsession.Binding, r *pb.UploadRequest) (*pb.UploadResponse, error) {
	return s.Service.Upload(ctx, r)
}
func (s ExecutorState) OnAbort(ctx context.Context, _ controlsession.Binding, r *pb.AbortRequest) (*pb.AbortResponse, error) {
	return s.Service.Abort(ctx, r)
}
func (s ExecutorState) OnBandwidth(ctx context.Context, _ controlsession.Binding, r *pb.BandwidthRequest) (*pb.BandwidthResponse, error) {
	return s.Service.Bandwidth(ctx, r)
}

// Control owns separate loopback direct and reverse listeners and one actual
// executor client. Startup readiness is deliberately observed by the caller
// with its separate registration deadline.
type Control struct {
	Client          *erpc.BidiClient
	cancel          context.CancelFunc
	bidi            *drpc.BidiServer
	direct, reverse net.Listener
	serves          sync.WaitGroup
	stop            sync.Once
	joined          chan struct{}
}

func Start(ctx context.Context, bidi *drpc.BidiServer, service pb.ExecutorServiceServer) (*Control, error) {
	if service == nil {
		return nil, errors.New("control peer: nil executor service")
	}
	lifetime, cancel := context.WithCancel(ctx)
	p := &Control{cancel: cancel, bidi: bidi, joined: make(chan struct{})}
	var err error
	p.direct, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, err
	}
	p.reverse, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		p.direct.Close()
		return nil, err
	}
	p.Client, err = erpc.NewBidiClient(erpc.BidiOptions{Logger: zap.NewNop(), Address: p.direct.Addr().String(), YamuxAddress: p.reverse.Addr().String()}, ExecutorState{Service: service})
	if err != nil {
		cancel()
		p.direct.Close()
		p.reverse.Close()
		return nil, err
	}
	p.serves.Add(3)
	go func() { defer p.serves.Done(); _ = bidi.ServeGRPCListener(lifetime, p.direct) }()
	go func() { defer p.serves.Done(); _ = bidi.ServeYamux(lifetime, p.reverse) }()
	go func() { defer p.serves.Done(); _ = p.Client.ConnectAndServe(lifetime) }()
	return p, nil
}

// Stop retains the real join even when a caller's cleanup deadline expires.
// A later invocation joins that same shutdown; a timed-out wait is not cleanup.
func (p *Control) Stop(ctx context.Context) error {
	p.stop.Do(func() {
		go func() {
			defer close(p.joined)
			p.cancel()
			p.direct.Close()
			p.reverse.Close()
			p.Client.Close()
			p.bidi.Close()
			p.serves.Wait()
		}()
	})
	select {
	case <-p.joined:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
