package dispatcher

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Forward the same two methods as the production RPC adapter over real local
// gRPC. The existing terminal peer records any recursive outgoing Abort.
type allocationDispatcherServer struct {
	pb.UnimplementedDispatcherServiceServer
	d     *Dispatcher
	owner *rpc.SessionOwner
}

func (s *allocationDispatcherServer) DebugletAllocate(ctx context.Context, req *pb.DebugletAllocateRequest) (*pb.DebugletAllocateResponse, error) {
	mutation, err := s.owner.AdmitMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer mutation.Finish()
	return s.d.OnDebugletAllocate(mutation.Context(), mutation, req)
}

func (s *allocationDispatcherServer) DebugletExit(ctx context.Context, req *pb.DebugletExitRequest) (*pb.DebugletExitResponse, error) {
	mutation, err := s.owner.AdmitMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer mutation.Finish()
	return s.d.OnDebugletExit(mutation.Context(), mutation, req)
}

func allocationClient(t *testing.T, d *Dispatcher) pb.DispatcherServiceClient {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer(grpc.WaitForHandlers(true))
	d.mu.RLock()
	owner := d.executors[tgExecutorID].owner
	d.mu.RUnlock()
	pb.RegisterDispatcherServiceServer(srv, &allocationDispatcherServer{d: d, owner: owner})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop() // WaitForHandlers joins database users before fixture DB cleanup.
		lis.Close()
		if err := <-done; err != nil && !errors.Is(err, grpc.ErrServerStopped) && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return pb.NewDispatcherServiceClient(conn)
}

func TestAllocationRejectionUnwindsThroughExit(t *testing.T) {
	for _, reason := range []string{"unpaid", "payment lookup", "capacity", "invalid limits", "changed policy", "rollback"} {
		t.Run(reason, func(t *testing.T) {
			peer := &tgPeer{}
			f := newTGFixture(t, peer)
			deb := f.seedDirect(t, tgFloorA)
			client := allocationClient(t, f.d)
			const destination, blocked = "127.0.0.1", "127.0.0.2"
			addresses := []string{destination}
			if reason == "rollback" {
				// The first destination is charged, the second one cannot be,
				// and the whole allocation is undone again.
				addresses = append(addresses, blocked)
			}
			if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET addresses = ? WHERE uuid = ?", models.CommaSeparatedList(addresses), deb.id); err != nil {
				t.Fatal(err)
			}
			req := &pb.DebugletAllocateRequest{DebugletId: deb.id.String(), ExecutorId: tgExecutorID, TransactionId: deb.txID,
				Policy: &pb.DebugletPolicy{Addresses: addresses, FloorBw: int64(deb.floor), CeilBw: int64(2 * deb.floor)}}
			want := ""
			switch reason {
			case "unpaid":
				if _, err := f.db.ExecContext(f.ctx, "UPDATE transactions SET status = ? WHERE id = ?", int64(models.Outstanding), deb.txID); err != nil {
					t.Fatal(err)
				}
				want = "debuglet has not been paid for"
			case "payment lookup":
				req.TransactionId = "missing-transaction"
				if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET transaction_id = ? WHERE uuid = ?", req.TransactionId, deb.id); err != nil {
					t.Fatal(err)
				}
				want = "check debuglet payment"
			case "capacity":
				f.d.SetDestinationLimit(destination, deb.floor-1)
				want = "allocate destinations"
			case "rollback":
				f.d.SetDestinationLimit(blocked, deb.floor-1)
				want = "allocate destinations"
			case "invalid limits":
				// An admitted policy whose ceiling is below its floor is
				// rejected before any destination is charged.
				if _, err := f.db.ExecContext(f.ctx, "UPDATE debuglets SET ceil_bw = ? WHERE uuid = ?", int64(deb.floor-1), deb.id); err != nil {
					t.Fatal(err)
				}
				req.Policy.CeilBw = int64(deb.floor - 1)
				want = "allocate destinations"
			case "changed policy":
				// The request no longer repeats the admitted policy of the run.
				req.Policy.CeilBw = int64(3 * deb.floor)
				want = "does not repeat the admitted policy"
			}
			before := f.snapshot(t)
			ctx, cancel := context.WithTimeout(f.ctx, 2*time.Second)
			defer cancel()
			if _, err := client.DebugletAllocate(ctx, req); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("allocation rejection = %v, want %q", err, want)
			}
			if got := len(peer.recordedAborts()); got != 0 {
				t.Fatalf("allocation made %d recursive Abort RPCs", got)
			}
			tgAssertSnapshot(t, f, before, "allocation rejection before executor unwind")
			tgAssertReserved(t, f, deb, deb.floor)
			if f.d.destinations.Len() != 0 {
				t.Fatal("rejected allocation retained a destination allocation")
			}
			// Observe the existing terminal/effect path after executor unwind.
			// TEST refund failure remains the current behavior.
			message := "allocation rejected: " + reason
			exit := &pb.DebugletExitRequest{DebugletId: deb.id.String(), ExitCode: 1, ErrorMessage: &message}
			if _, err := client.DebugletExit(ctx, exit); err != nil {
				t.Fatal(err)
			}
			tgAssertRow(t, f.row(t, deb.id), models.RunStateExited, tgText(message))
			tgAssertReserved(t, f, deb, 0)
			if f.d.destinations.Len() != 0 {
				t.Fatal("existing exit path retained partial destination allocation")
			}
			tgAssertOrder(t, f, deb, models.Outstanding)
			tgAssertEarnings(t, f, 0)
			after := f.snapshot(t)
			if _, err := client.DebugletExit(ctx, exit); err != nil {
				t.Fatal(err)
			}
			tgAssertSnapshot(t, f, after, "duplicate exit")
			tgAssertReserved(t, f, deb, 0)
		})
	}
}
