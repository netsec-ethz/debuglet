package rpc

import (
	"context"
	pb "debuglet/protocol"
	"fmt"
	"net"
	"sync"

	"github.com/hashicorp/yamux"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"
)

type ExecutorConn struct {
	gconn   *grpc.ClientConn
	client  pb.ExecutorServiceClient
	session *yamux.Session
}

// BidiServer handles the bidirectional connection between the dispatcher and multiple executors.
// It serves a gRPC server for DispatcherService and a yamux listener for executor callbacks.
//
// [BidiServer.GetClient] can be used to get a specific connected executor client for sending messages (i.e. uploading a debuglet).
type BidiServer struct {
	grpcServer *grpc.Server
	logger     *zap.Logger
	state      DispatcherState

	clients  map[string]ExecutorConn
	mu       sync.RWMutex
	sessions sync.WaitGroup
}

func NewBidiServer(l *zap.Logger, state DispatcherState) *BidiServer {
	bidi := &BidiServer{
		grpcServer: grpc.NewServer(),
		logger:     l,
		state:      state,
		clients:    make(map[string]ExecutorConn),
	}
	pb.RegisterDispatcherServiceServer(bidi.grpcServer, &server{state: state})
	reflection.Register(bidi.grpcServer)
	return bidi
}

// Close shuts down the gRPC server and closes all client connections. It waits for all sessions to finish before returning.
func (b *BidiServer) Close() {
	b.grpcServer.GracefulStop()
	b.mu.Lock()
	for _, conn := range b.clients {
		conn.gconn.Close()
		conn.session.Close()
	}
	b.mu.Unlock()
	b.sessions.Wait()
}

// GetClient retrieves the gRPC client for a specific executor by its ID. It returns the client and a boolean indicating whether the client exists.
func (b *BidiServer) GetClient(executorID string) (pb.ExecutorServiceClient, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	conn, exists := b.clients[executorID]
	return conn.client, exists
}

func (b *BidiServer) RemoveClient(executorID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if conn, exists := b.clients[executorID]; exists {
		conn.gconn.Close()
		conn.session.Close()
		delete(b.clients, executorID)
	}
}

// ServeGRPC starts the gRPC server on the given address for DispatcherService RPCs.
func (b *BidiServer) ServeGRPC(ctx context.Context, addr string) error {
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	b.logger.Info("gRPC server listening", zap.String("address", addr))
	return b.grpcServer.Serve(lis)
}

// ServeYamux accepts yamux connections from executors on the given listener.
func (b *BidiServer) ServeYamux(ctx context.Context, lis net.Listener) error {
	b.logger.Info("Yamux listener started", zap.String("address", lis.Addr().String()))

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				b.logger.Error("failed to accept connection", zap.Error(err))
				continue
			}
		}
		b.sessions.Go(func() { b.handleSession(ctx, conn) })
	}
}

// handleSession manages the full lifecycle of a single executor connection, including establishing a yamux session, creating a gRPC client, registering the executor, and waiting for disconnection.
func (b *BidiServer) handleSession(ctx context.Context, conn net.Conn) {
	session, err := b.acceptYamux(conn)
	if err != nil {
		b.logger.Error("failed to listen for yamux", zap.Error(err))
		return
	}

	gconn, err := b.createExecutorClient(session)
	if err != nil {
		b.logger.Error("failed to create gRPC connection", zap.Error(err))
		session.Close()
		return
	}

	hello, err := b.registerExecutor(ctx, gconn, session)
	if err != nil {
		b.logger.Error("failed to register executor", zap.Error(err))
		gconn.Close()
		session.Close()
		return
	}
	defer b.RemoveClient(hello.GetExecutorId())

	b.state.OnExecutorConnected(hello)
	defer b.state.OnExecutorDisconnected(hello.GetExecutorId())

	b.waitForDisconnect(ctx, session, hello.GetExecutorId())
}

func (b *BidiServer) acceptYamux(conn net.Conn) (*yamux.Session, error) {
	b.logger.Debug("Accepted connection", zap.String("remote_addr", conn.RemoteAddr().String()))
	session, err := yamux.Server(conn, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create yamux session: %v", err)
	}
	b.logger.Info("Yamux session established", zap.String("remote_addr", session.RemoteAddr().String()))
	return session, nil
}

func (b *BidiServer) createExecutorClient(session *yamux.Session) (*grpc.ClientConn, error) {
	dial := func(context.Context, string) (net.Conn, error) { return session.Open() }
	gconn, err := grpc.NewClient("passthrough:///unused",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(dial),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client: %v", err)
	}
	return gconn, nil
}

func (b *BidiServer) registerExecutor(ctx context.Context, gconn *grpc.ClientConn, session *yamux.Session) (*pb.HelloResponse, error) {
	client := pb.NewExecutorServiceClient(gconn)
	out, err := client.Hello(ctx, &pb.HelloRequest{})
	if err != nil {
		return nil, fmt.Errorf("hello: %w", err)
	}

	b.mu.Lock()
	execID := out.GetExecutorId()
	b.logger.Info("registered executor", zap.String("executor_id", execID))
	if old, exists := b.clients[execID]; exists {
		b.logger.Warn("executor already registered, closing previous connection and overwriting", zap.String("executor_id", execID))
		old.gconn.Close()
		old.session.Close()
		b.state.OnExecutorDisconnected(execID)
	}
	b.clients[execID] = ExecutorConn{gconn: gconn, client: client, session: session}
	b.mu.Unlock()

	return out, nil
}

// waitForDisconnect waits for either the yamux session to close or the context to close.
func (b *BidiServer) waitForDisconnect(ctx context.Context, session *yamux.Session, execID string) {
	select {
	case <-session.CloseChan():
		b.logger.Info("yamux session closed", zap.String("executor_id", execID))
	case <-ctx.Done():
		b.logger.Info("context cancelled, closing session", zap.String("executor_id", execID))
		session.Close()
	}
}
