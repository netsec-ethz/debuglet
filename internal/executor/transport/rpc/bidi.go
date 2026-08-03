package rpc

import (
	"context"
	"crypto/tls"
	pb "debuglet/protocol"
	"fmt"
	"net"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type BidiOptions struct {
	Logger       *zap.Logger
	Address      string
	YamuxAddress string
	TLSCreds     credentials.TransportCredentials
	TLSConfig    *tls.Config
}

// BidiClient connects to the dispatcher and sets up a bidirectional stream allowing
// for the dispatcher to call the executor's gRPC server's methods.
//
// [BidiClient.Client] can be used to directly send messages to the dispatcher (i.e. sending heartbeats).
type BidiClient struct {
	Client     pb.DispatcherServiceClient
	grpcServer *grpc.Server
	gconn      *grpc.ClientConn
	opts       BidiOptions
	state      ExecutorState
	ready      chan struct{}
}

func NewBidiClient(opts BidiOptions, state ExecutorState) (*BidiClient, error) {
	grpcServer := grpc.NewServer(
		grpc.MaxRecvMsgSize(32*1024*1024),
		grpc.MaxSendMsgSize(32*1024*1024),
	)
	pb.RegisterExecutorServiceServer(grpcServer, &server{state: state})
	reflection.Register(grpcServer)

	grpcCreds := insecure.NewCredentials()
	if opts.TLSCreds != nil {
		grpcCreds = opts.TLSCreds
	}
	gconn, err := grpc.NewClient(opts.Address, grpc.WithTransportCredentials(grpcCreds))
	if err != nil {
		return nil, err
	}

	if opts.YamuxAddress == "" {
		opts.YamuxAddress = opts.Address
	}

	return &BidiClient{
		Client:     pb.NewDispatcherServiceClient(gconn),
		grpcServer: grpcServer,
		gconn:      gconn,
		opts:       opts,
		state:      state,
		ready:      make(chan struct{}),
	}, nil
}

func (b *BidiClient) Close() {
	b.grpcServer.GracefulStop()
	b.gconn.Close()
}

func (b *BidiClient) WaitReady() {
	<-b.ready
}

// ConnectAndServe opens a yamux bidirectional session to the dispatcher and
// starts the executor gRPC server. If TLSConfig is set, the yamux connection
// will be wrapped in TLS (required when connecting through a TLS-terminating proxy).
func (b *BidiClient) ConnectAndServe(ctx context.Context) error {
	var conn net.Conn
	var err error

	if b.opts.TLSConfig != nil {
		d := tls.Dialer{Config: b.opts.TLSConfig}
		conn, err = d.DialContext(ctx, "tcp", b.opts.YamuxAddress)
	} else {
		d := net.Dialer{}
		conn, err = d.DialContext(ctx, "tcp", b.opts.YamuxAddress)
	}
	if err != nil {
		return fmt.Errorf("failed to connect to dispatcher yamux: %w", err)
	}
	defer conn.Close()
	b.opts.Logger.Info("Connected to dispatcher yamux", zap.String("address", b.opts.YamuxAddress))

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return fmt.Errorf("failed to create yamux session: %w", err)
	}
	dur, err := session.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping yamux session: %w", err)
	}
	b.opts.Logger.Info("Yamux session established", zap.String("address", b.opts.YamuxAddress), zap.Duration("ping_duration", dur))

	errCh := make(chan error, 1)
	go func() {
		close(b.ready)
		err := b.grpcServer.Serve(session)
		if err != nil {
			b.ready = make(chan struct{})
			session.Close()
		}
		errCh <- err
	}()

	<-session.CloseChan()
	if err := <-errCh; err != nil {
		return fmt.Errorf("grpc server exited with error: %w", err)
	}
	return nil
}
