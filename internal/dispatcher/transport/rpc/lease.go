package rpc

import (
	"context"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func (b *BidiServer) renewLease(ctx context.Context, in *pb.RenewLeaseRequest) (*pb.RenewLeaseResponse, error) {
	ticket, err := b.admitted(ctx, "")
	if err != nil {
		return nil, err
	}
	defer ticket.Finish()
	if in.GetSequence() == 0 {
		return nil, controlrpc.Malformed()
	}
	owner := ticket.Owner()
	b.mu.RLock()
	conn, ok := b.clients[owner.ExecutorID()]
	if b.closed || !ok || conn.owner != owner || !owner.Available() {
		b.mu.RUnlock()
		return nil, controlrpc.Unavailable()
	}
	credentials := conn.offer.credentials
	fingerprint := conn.offer.fingerprint
	// This client is captured from the admitted owner's exact reverse connection;
	// no later lookup by executor ID can retarget this probe.
	client := pb.NewExecutorServiceClient(conn.gconn)
	b.mu.RUnlock()
	if err := b.stillEnrolled(ticket.Context(), owner.ExecutorID(), fingerprint); err != nil {
		return nil, err
	}
	probeCtx, cancel := context.WithTimeout(ticket.Context(), b.lease.RequestTimeout)
	defer cancel()
	ack, err := client.ProbeSession(credentials.Outgoing(probeCtx), &pb.ProbeSessionRequest{Sequence: in.Sequence})
	if err != nil {
		return nil, credentials.RedactError(err)
	}
	if ack.GetSequence() != in.Sequence {
		return nil, controlrpc.Unavailable()
	}
	b.mu.RLock()
	current := !b.closed && b.clients[owner.ExecutorID()].owner == owner && probeCtx.Err() == nil
	committed := current && owner.commitLease(probeCtx, in.Sequence)
	b.mu.RUnlock()
	if !committed {
		return nil, controlrpc.Unavailable()
	}
	return &pb.RenewLeaseResponse{Sequence: in.Sequence, LeaseDurationMs: b.lease.Duration.Milliseconds()}, nil
}
