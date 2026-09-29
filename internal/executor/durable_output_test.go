// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/sqlitedb"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestDurableOutputRetainsAcceptedQueueAfterBrokenTransport(t *testing.T) {
	peer := newOperationPeer()
	var streams atomic.Int32
	var mu sync.Mutex
	committed := int64(0)
	var saved []*pb.DebugletOutput
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		attempt := streams.Add(1)
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.GetIdent().GetOriginalBinding().GetSessionId() != operationBinding().SessionID {
			return errors.New("wrong original binding")
		}
		mu.Lock()
		ack := committed
		mu.Unlock()
		if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: ack}); err != nil {
			return err
		}
		for {
			req, err = stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if out := req.GetOutput(); out != nil {
				mu.Lock()
				if out.Sequence != committed+1 {
					mu.Unlock()
					return errors.New("duplicate or gap")
				}
				committed = out.Sequence
				saved = append(saved, proto.Clone(out).(*pb.DebugletOutput))
				ack = committed
				mu.Unlock()
				// Commit happened, but no receipt reached the executor.
				if attempt == 1 {
					return status.Error(codes.Unavailable, "lost acknowledgement")
				}
				if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: ack}); err != nil {
					return err
				}
			} else if end := req.GetEnd(); end != nil {
				return stream.Send(&pb.DebugletStreamResponse{CommittedSequence: end.LastSequence, End: end})
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.outputVersion.Store(pb.OutputVersion)
	spec := operationSpec()
	spec.Policy.Timeout = time.Minute
	accepted := make(chan struct{})
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		for _, s := range []string{"one", "two", "three"} {
			out <- []byte(s)
		}
		close(accepted)
		<-ctx.Done()
		return context.Cause(ctx)
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, accepted, "accepted bounded output") || !operationAwait(t, call.done, "producer and spool join") {
		return
	}
	retained, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.End == nil || retained.End.LastSequence != 3 || retained.EndAcknowledged || retained.AcknowledgedSequence != 0 || retained.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("retained accepted prefix: %+v %v", retained, err)
	}
	if runtime.starts.Load() != 1 || runtime.closes.Load() != 1 {
		t.Fatal("producer ownership lost")
	}
	if err := e.deliverOutput(t.Context(), spec.Binding, retained); err != nil {
		t.Fatal(err)
	}
	after, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || !after.EndAcknowledged || after.QueuedFrames != 0 || after.QueuedBytes != 0 {
		t.Fatalf("durable receipt not released: %+v %v", after, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(saved) != 3 || string(saved[0].Output) != "one" || string(saved[1].Output) != "two" || string(saved[2].Output) != "three" {
		t.Fatal("output replay changed or duplicated bytes")
	}
	if runtime.starts.Load() != 1 {
		t.Fatal("delivery replayed workload")
	}
}

func TestDurableOutputQuotaReceiptWaitsForProducerJoin(t *testing.T) {
	peer := newOperationPeer()
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
			return err
		}
		for seq := int64(1); seq <= 2; seq++ {
			req, err := stream.Recv()
			if err != nil {
				return err
			}
			if req.GetOutput().GetSequence() != seq {
				return errors.New("frame sequence")
			}
			ack := &pb.DebugletStreamResponse{CommittedSequence: seq}
			if seq == 2 {
				ack.CommittedSequence = 1
				ack.End = &pb.DebugletOutputEnd{LastSequence: 1, Status: pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED, Reason: "storage_limit"}
			}
			if err := stream.Send(ack); err != nil {
				return err
			}
		}
		return nil
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.outputVersion.Store(pb.OutputVersion)
	spec := operationSpec()
	spec.Policy.Timeout = time.Minute
	canceled, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		out <- []byte("accepted")
		out <- []byte("spooled suffix")
		<-ctx.Done()
		close(canceled)
		<-release
		return context.Cause(ctx)
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	if !operationAwait(t, canceled, "quota cancels producer") {
		return
	}
	retained, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.End != nil || retained.Receipt != nil || retained.QueuedFrames != 1 {
		t.Fatalf("suffix dropped before producer joined: %+v %v", retained, err)
	}
	once.Do(func() { close(release) })
	if !operationAwait(t, call.done, "quota producer joins") {
		return
	}
	retained, err = e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.End == nil || retained.End.LastSequence != 2 || retained.Receipt == nil || retained.Receipt.LastSequence != 1 || retained.Receipt.Reason != "storage_limit" || retained.QueuedFrames != 0 {
		t.Fatalf("producer and server prefixes not distinct: %+v %v", retained, err)
	}
}

func TestDurableOutputFloodIsBoundedAndSiblingProgresses(t *testing.T) {
	peer := newOperationPeer()
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		if _, err := stream.Recv(); err != nil {
			return err
		}
		if err := stream.Send(&pb.DebugletStreamResponse{}); err != nil {
			return err
		}
		for {
			req, err := stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			receipt := &pb.DebugletStreamResponse{}
			if out := req.GetOutput(); out != nil {
				receipt.CommittedSequence = out.Sequence
			}
			if end := req.GetEnd(); end != nil {
				receipt.CommittedSequence = end.LastSequence
				receipt.End = end
			}
			if err := stream.Send(receipt); err != nil {
				return err
			}
		}
	}
	e, _ := newExecutorRPCFixture(t, peer, nil)
	e.outputVersion.Store(pb.OutputVersion)
	// The quota counts all emitted bytes, including those already acknowledged.
	e.cfg.Output.RunBytes = 2 * pb.MaxOutputFrameBytes
	var err error
	// The node's DB is private to this runtime, so use a second real store with
	// tighter limits to exercise normal SQLite admission and charge transitions.
	db := newFixtureDatabase(t)
	e.output, err = outputstore.New(db, e.cfg.Output.Limits())
	if err != nil {
		t.Fatal(err)
	}
	spec := operationSpec()
	spec.Policy.Timeout = time.Minute
	var attempted atomic.Int32
	runtime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error {
		for {
			if ctx.Err() != nil {
				return context.Cause(ctx)
			}
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case out <- bytes.Repeat([]byte("x"), pb.MaxOutputFrameBytes):
				attempted.Add(1)
			}
		}
	}}
	installOperationRuntime(e, spec, runtime)
	call := startOperationTest(t, e, spec)
	if !operationAwait(t, call.done, "flood quota cancellation and join") {
		return
	}
	retained, err := e.output.Get(t.Context(), spec.DebugletID)
	if err != nil || retained.EmittedBytes > 2*pb.MaxOutputFrameBytes || retained.End == nil || retained.End.Reason != "output_limit" || attempted.Load() > outputQueueFrames+4 {
		t.Fatalf("unbounded flood: %+v attempts=%d err=%v", retained, attempted.Load(), err)
	}
	if e.outputFailed.Load() {
		t.Fatal("one guest quota poisoned sibling admission")
	}
	sibling := operationSpec()
	siblingRuntime := &operationRuntime{run: func(ctx context.Context, out chan<- []byte) error { out <- []byte("sibling"); return nil }}
	installOperationRuntime(e, sibling, siblingRuntime)
	second := startOperationTest(t, e, sibling)
	if !operationAwait(t, second.done, "sibling output progress") {
		return
	}
	siblingOutput, err := e.output.Get(t.Context(), sibling.DebugletID)
	if err != nil || !siblingOutput.EndAcknowledged || siblingOutput.End.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE {
		t.Fatalf("sibling did not finish: %+v %v", siblingOutput, err)
	}
}

func TestDurableOutputRestartsOverTLSInBoundedPasses(t *testing.T) {
	material := newCredentialFixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peer := newOperationPeer()
	var calls atomic.Int32
	var received atomic.Int64
	original := operationBinding()
	peer.stream = func(stream grpc.BidiStreamingServer[pb.DebugletStreamRequest, pb.DebugletStreamResponse]) error {
		calls.Add(1)
		remote, ok := grpcpeer.FromContext(stream.Context())
		if !ok {
			return errors.New("missing TLS peer")
		}
		identity, ok := remote.AuthInfo.(credentials.TLSInfo)
		if !ok || len(identity.State.VerifiedChains) == 0 || !bytes.Equal(identity.State.PeerCertificates[0].Raw, material.client.Certificate.Certificate[0]) {
			return errors.New("unverified executor certificate")
		}
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		if req.GetIdent().GetOriginalBinding().GetSessionId() != original.SessionID {
			return errors.New("original binding was retargeted")
		}
		if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: received.Load()}); err != nil {
			return err
		}
		for {
			req, err = stream.Recv()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if out := req.GetOutput(); out != nil {
				if out.Sequence != received.Load()+1 {
					return errors.New("replayed acknowledged prefix or sequence gap")
				}
				received.Store(out.Sequence)
				if err := stream.Send(&pb.DebugletStreamResponse{CommittedSequence: out.Sequence}); err != nil {
					return err
				}
			} else if end := req.GetEnd(); end != nil {
				if end.Status != pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED || end.Reason != "executor_interrupted" {
					return errors.New("restart falsely completed output")
				}
				return stream.Send(&pb.DebugletStreamResponse{CommittedSequence: received.Load(), End: end})
			}
		}
	}
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(material.ca.ServerConfig(material.server, true))), grpc.WaitForHandlers(true))
	pb.RegisterDispatcherServiceServer(server, peer)
	served := make(chan struct{})
	go func() { defer close(served); _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); listener.Close(); <-served })
	_, creds, err := getClientCredentials(material.config(""))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(creds))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	e := newFixtureExecutor(t, fixtureConfig(), nil, newFixtureMemoryStorage(t))
	db := newFixtureDatabase(t)
	var number int
	var name, path string
	if err := db.QueryRow("PRAGMA database_list").Scan(&number, &name, &path); err != nil {
		t.Fatal(err)
	}
	store, err := outputstore.New(db, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	if err := store.Admit(t.Context(), id, original, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < outputPassFrames+2; i++ {
		if _, err := store.Append(t.Context(), id, time.Now().UTC(), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	// The first frame was acknowledged and locally deleted before this restart.
	if err := store.Acknowledge(t.Context(), id, 1, nil); err != nil {
		t.Fatal(err)
	}
	received.Store(1)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := sqlitedb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	e.output, err = outputstore.New(reopened, outputstore.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := e.output.InterruptOpen(t.Context()); err != nil {
		t.Fatal(err)
	}
	retained, err := e.output.Get(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	current := controlsession.Binding{Incarnation: uuid.NewString(), SessionID: uuid.NewString()}
	e.clientFor = func(_ context.Context, binding controlsession.Binding) (pb.DispatcherServiceClient, error) {
		if binding != current {
			return nil, errors.New("old authority used for current transport")
		}
		return pb.NewDispatcherServiceClient(conn), nil
	}
	e.cfg.TLS.Disable = false
	if err := e.deliverOutput(t.Context(), current, retained); err != nil {
		t.Fatal(err)
	}
	if received.Load() != 1+outputPassFrames {
		t.Fatal("delivery pass exceeded its frame bound")
	}
	retained, err = e.output.Get(t.Context(), id)
	if err != nil || retained.EndAcknowledged {
		t.Fatal("first bounded pass falsely finalized output")
	}
	if err := e.deliverOutput(t.Context(), current, retained); err != nil {
		t.Fatal(err)
	}
	retained, err = e.output.Get(t.Context(), id)
	if err != nil || !retained.EndAcknowledged || retained.QueuedFrames != 0 || received.Load() != outputPassFrames+2 {
		t.Fatalf("restart tail not acknowledged: %+v %v", retained, err)
	}

	// A plaintext profile has no credential that could resume another binding,
	// so it never contacts the dispatcher and releases its local copy instead.
	plain := uuid.New()
	if err := e.output.Admit(t.Context(), plain, original, pb.OutputVersion); err != nil {
		t.Fatal(err)
	}
	if _, err := e.output.Append(t.Context(), plain, time.Now().UTC(), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.output.Finish(t.Context(), plain, pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE, ""); err != nil {
		t.Fatal(err)
	}
	unsent, err := e.output.Get(t.Context(), plain)
	if err != nil {
		t.Fatal(err)
	}
	before := calls.Load()
	e.cfg.TLS.Disable = true
	if err := e.deliverOutput(t.Context(), current, unsent); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != before {
		t.Fatal("insecure profile resumed a different binding")
	}
	if released, err := e.output.Get(t.Context(), plain); err != nil || !released.EndAcknowledged || released.QueuedFrames != 0 {
		t.Fatalf("plaintext output kept its spool: %+v %v", released, err)
	}
}
