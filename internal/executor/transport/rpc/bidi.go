package rpc

import (
	"context"
	pb "debuglet/protocol"
	"fmt"
	"log"
	"net"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type BidiOptions struct {
	Logger   *zap.Logger
	Address  string
	TLSCreds credentials.TransportCredentials
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
// starts the executor gRPC server.
func (b *BidiClient) ConnectAndServe(ctx context.Context) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", b.opts.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	b.opts.Logger.Info("Connected to dispatcher", zap.String("address", b.opts.Address))

	session, err := yamux.Client(conn, nil)
	if err != nil {
		return err
	}
	// Sending initial data is required to trigger cmux routing on the dispatcher side and correctly establish the yamux session.
	dur, err := session.Ping()
	if err != nil {
		return fmt.Errorf("failed to ping yamux session: %w", err)
	}
	b.opts.Logger.Info("Yamux session established", zap.String("address", b.opts.Address), zap.Duration("ping_duration", dur))

	var errRet error
	go func() {
		close(b.ready)
		errRet = b.grpcServer.Serve(session)
		if errRet != nil {
			b.ready = make(chan struct{})
			log.Printf("failed to serve gRPC: %v", errRet)
			session.Close()
		}
	}()

	<-session.CloseChan()
	return errRet
}
