// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/enrollment"
	drpc "github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	erpc "github.com/netsec-ethz/debuglet/internal/executor/transport/rpc"
	"github.com/netsec-ethz/debuglet/internal/testpeer"
	"github.com/netsec-ethz/debuglet/internal/testtls"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

type outputPeer struct {
	pb.UnimplementedExecutorServiceServer
	token string
}

func (p *outputPeer) Hello(context.Context, *pb.HelloRequest) (*pb.HelloResponse, error) {
	return &pb.HelloResponse{ExecutorId: "output-executor", Version: "output-v1", Currency: "TEST", PricePerBwS: 1, EnrollmentToken: &p.token, OutputVersion: pb.OutputVersion}, nil
}

// This scripted peer retains no scheduler rows; a successful metadata lookup
// therefore attests absence for retirement fixtures using this transport.
func (p *outputPeer) InspectRetainedRun(context.Context, *pb.InspectRetainedRunRequest) (*pb.InspectRetainedRunResponse, error) {
	return &pb.InspectRetainedRunResponse{Status: pb.RetainedRunStatus_RETAINED_RUN_STATUS_ABSENT}, nil
}

// outputTLSFixture uses the real transport, enrollment database and stream
// handler. Reconnection changes the control binding without changing the node.
type outputTLSFixture struct {
	t               *testing.T
	d               *Dispatcher
	ctx             context.Context
	ca              *testtls.Authority
	identity        *testtls.Identity
	store           *enrollment.Store
	direct, reverse net.Listener
	clients         []*erpc.BidiClient
	workers         sync.WaitGroup
}

func newOutputTLS(t *testing.T) *outputTLSFixture {
	t.Helper()
	d := newTerminalPeerDispatcher(t)
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	f := &outputTLSFixture{t: t, d: d, ctx: ctx, store: enrollment.NewStore(d.db)}
	var err error
	f.ca, err = testtls.NewAuthority(t.TempDir(), "output")
	if err != nil {
		t.Fatal(err)
	}
	server, err := f.ca.Issue("dispatcher", testtls.Options{Hosts: []string{"127.0.0.1"}, Server: true})
	if err != nil {
		t.Fatal(err)
	}
	f.identity, err = f.ca.Issue("executor", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	f.direct, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.reverse, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		f.direct.Close()
		t.Fatal(err)
	}
	directTLS := f.ca.ServerConfig(server, true)
	directTLS.NextProtos = []string{"h2"}
	f.direct = tls.NewListener(f.direct, directTLS)
	f.reverse = drpc.VerifiedClientListener(tls.NewListener(f.reverse, f.ca.ServerConfig(server, true)), zap.NewNop())
	d.Bidi.EnforceEnrollment(f.store)
	f.workers.Add(2)
	go func() { defer f.workers.Done(); _ = d.Bidi.ServeGRPCListener(ctx, f.direct) }()
	go func() { defer f.workers.Done(); _ = d.Bidi.ServeYamux(ctx, f.reverse) }()
	t.Cleanup(func() {
		cancel()
		for _, client := range f.clients {
			client.Close()
		}
		f.direct.Close()
		f.reverse.Close()
		d.Close()
		f.workers.Wait()
	})
	return f
}

func (f *outputTLSFixture) connect(identity *testtls.Identity, enroll bool) (*erpc.BidiClient, *drpc.SessionOwner) {
	f.t.Helper()
	token := ""
	var err error
	if enroll {
		token, err = f.store.Issue(f.ctx, "output-executor", time.Hour)
		if err != nil {
			f.t.Fatal(err)
		}
	}
	tlsConfig := f.ca.ClientConfig(identity, "")
	client, err := erpc.NewBidiClient(erpc.BidiOptions{Logger: zap.NewNop(), Address: f.direct.Addr().String(), YamuxAddress: f.reverse.Addr().String(), TLSConfig: tlsConfig, TLSCreds: credentials.NewTLS(tlsConfig.Clone())}, testpeer.ExecutorState{Service: &outputPeer{token: token}})
	if err != nil {
		f.t.Fatal(err)
	}
	f.clients = append(f.clients, client)
	f.workers.Add(1)
	go func() { defer f.workers.Done(); _ = client.ConnectAndServe(f.ctx) }()
	if err := client.WaitReadyContext(f.ctx); err != nil {
		f.t.Fatal(err)
	}
	f.d.mu.RLock()
	owner := f.d.executors["output-executor"].owner
	f.d.mu.RUnlock()
	return client, owner
}

func outputClientStream(t *testing.T, ctx context.Context, client *erpc.BidiClient, id uuid.UUID, original controlsession.Binding) grpc.BidiStreamingClient[pb.DebugletStreamRequest, pb.DebugletStreamResponse] {
	t.Helper()
	binding, ok := client.Binding()
	if !ok {
		t.Fatal("client has no binding")
	}
	bound, err := client.ClientFor(binding)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := bound.DebugletStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: id.String(), ExecutorId: "output-executor", OriginalBinding: &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID}}}}); err != nil {
		t.Fatal(err)
	}
	return stream
}

func TestDurableOutputTLSReconnectAndCredentialFencing(t *testing.T) {
	f := newOutputTLS(t)
	client, owner := f.connect(f.identity, true)
	writer, err := outputWriterFor(owner, &pb.ControlBinding{DispatcherIncarnation: owner.Binding().Incarnation, SessionId: owner.Binding().SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if writer.fingerprint == "" || writer.version != pb.OutputVersion {
		t.Fatalf("missing authenticated admission identity: %+v", writer)
	}
	id := outputTestRun(t, f.d, writer, nil)
	stream := outputClientStream(t, f.ctx, client, id, writer.original)
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 0 {
		t.Fatalf("identify: %v %v", receipt, err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: outputFrame(1, "before reconnect")}}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 1 {
		t.Fatalf("first ACK: %v %v", receipt, err)
	}
	client.Close()
	client, replacement := f.connect(f.identity, false)
	if replacement.Binding() == writer.binding {
		t.Fatal("reconnect reused control binding")
	}
	stream = outputClientStream(t, f.ctx, client, id, writer.original)
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 1 {
		t.Fatalf("resumed ACK: %v %v", receipt, err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: outputFrame(1, "before reconnect")}}); err != nil {
		t.Fatal(err)
	}
	if receipt, err := stream.Recv(); err != nil || receipt.CommittedSequence != 1 {
		t.Fatalf("replayed ACK: %v %v", receipt, err)
	}
	// Output resumption grants no authority to report the original run's exit.
	bound, err := client.ClientFor(replacement.Binding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bound.DebugletExit(f.ctx, &pb.DebugletExitRequest{DebugletId: id.String()}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-binding exit: %v", err)
	}
	if _, err := f.store.Revoke(f.ctx, writer.executorID); err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: outputFrame(2, "revoked")}}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked output: %v", err)
	}
	client.Close()
	rotated, err := f.ca.Issue("rotated", testtls.Options{Client: true})
	if err != nil {
		t.Fatal(err)
	}
	client, _ = f.connect(rotated, true)
	stream = outputClientStream(t, f.ctx, client, id, writer.original)
	if _, err := stream.Recv(); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("rotated original-output claim: %v", err)
	}
}
