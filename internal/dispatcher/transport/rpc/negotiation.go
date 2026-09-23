package rpc

import (
	"context"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type controlOffer struct {
	credentials controlrpc.Credentials
	// fingerprint is the node credential of the reverse connection that
	// created this offer. It is fixed at construction and read without a lock.
	fingerprint  string
	published    chan struct{}
	confirmed    chan struct{}
	activated    chan struct{}
	owner        *SessionOwner // all fields below are guarded by b.mu
	confirmation bool
}

type sessionLane struct {
	current      *SessionOwner
	predecessors map[*SessionOwner]struct{}
}

// retireLocked revokes the owner, which clears its authority and signals its
// retirement, and moves it out of the current clients into its lane's
// predecessors. Cleanup runs in the tracked session invocation, and the owner
// stays in the lane until it has drained.
func (b *BidiServer) retireLocked(owner *SessionOwner) {
	owner.Retire()
	if conn, ok := b.clients[owner.ExecutorID()]; ok && conn.owner == owner {
		delete(b.clients, owner.ExecutorID())
	}
	lane := b.lanes[owner.ExecutorID()]
	if lane == nil {
		lane = &sessionLane{predecessors: make(map[*SessionOwner]struct{})}
		b.lanes[owner.ExecutorID()] = lane
	}
	if lane.current == owner {
		lane.current = nil
	}
	lane.predecessors[owner] = struct{}{}
	b.sweepLaneLocked(owner.ExecutorID())
}

func (b *BidiServer) sweepLaneLocked(id string) {
	lane := b.lanes[id]
	if lane == nil {
		return
	}
	for owner := range lane.predecessors {
		select {
		case <-owner.MutationsDrained():
			delete(lane.predecessors, owner)
		default:
		}
	}
	if lane.current != nil || len(lane.predecessors) != 0 {
		return
	}
	// A published offer stays owned until its own session's teardown joins.
	for _, offer := range b.offers {
		if offer.owner != nil && offer.owner.ExecutorID() == id {
			return
		}
	}
	delete(b.lanes, id)
}

// waitPredecessors delays the registration of a replacement session until every
// earlier session of the same executor ID has drained its admitted work. The
// replacement's own setup work may already exist while it waits; what is
// serialized is registration and the ordinary work that follows it. It waits on
// the drain signals it collected, then looks again: a predecessor may have been
// added while it slept, and this owner may have been replaced.
func (b *BidiServer) waitPredecessors(ctx context.Context, owner *SessionOwner) error {
	for {
		b.mu.Lock()
		current, ok := b.clients[owner.ExecutorID()]
		if !ok || current.owner != owner || !owner.Active() {
			b.mu.Unlock()
			return controlrpc.Unavailable()
		}
		b.sweepLaneLocked(owner.ExecutorID())
		var waits []<-chan struct{}
		for predecessor := range b.lanes[owner.ExecutorID()].predecessors {
			waits = append(waits, predecessor.MutationsDrained())
		}
		b.mu.Unlock()
		if len(waits) == 0 {
			return nil
		}
		for _, wait := range waits {
			select {
			case <-wait:
			case <-ctx.Done():
				return ctx.Err()
			case <-owner.Done():
				return controlrpc.Unavailable()
			}
		}
		// Recheck this owner and its predecessors after waking.
	}
}

// confirm serves BindSession: the executor proves on the direct channel that it
// holds the offer published for its reverse session, and then waits until that
// session has been activated. It confirms an offer only for the owner that is
// still current, and the name in the request must be that owner's executor ID.
func (b *BidiServer) confirm(ctx context.Context, req *pb.BindSessionRequest) (*pb.BindSessionResponse, error) {
	credentials, err := controlrpc.Read(ctx)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	offer := b.offers[credentials.Binding.SessionID]
	valid := !b.closed && offer != nil && offer.credentials.Matches(credentials)
	b.mu.RUnlock()
	if !valid {
		return nil, controlrpc.Unavailable()
	}
	if !b.boundNode(ctx, offer.fingerprint) {
		return nil, controlrpc.Denied()
	}
	select {
	case <-offer.published:
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-b.stop:
		return nil, controlrpc.Unavailable()
	}
	b.mu.RLock()
	owner := offer.owner
	current := owner != nil && b.clients[owner.ExecutorID()].owner == owner
	b.mu.RUnlock()
	if !current {
		return nil, controlrpc.Unavailable()
	}
	if req.GetExecutorId() != owner.ExecutorID() {
		return nil, controlrpc.Denied()
	}
	ticket, err := owner.AdmitSetup(ctx)
	if err != nil {
		return nil, controlrpc.Unavailable()
	}
	defer ticket.Finish()
	b.mu.Lock()
	current = b.clients[owner.ExecutorID()].owner == owner && owner.Active()
	if current && !offer.confirmation {
		offer.confirmation = true
		close(offer.confirmed)
	}
	b.mu.Unlock()
	if !current {
		return nil, controlrpc.Unavailable()
	}
	select {
	case <-offer.activated:
		if !owner.Available() {
			return nil, controlrpc.Unavailable()
		}
		return &pb.BindSessionResponse{LeaseDurationMs: b.lease.Duration.Milliseconds()}, nil
	case <-ticket.Context().Done():
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return nil, controlrpc.Unavailable()
	}
}

// admitted is how every direct request enters: the credentials it carries name
// an offer, that offer's owner must still be the current one for its executor
// ID, the request must arrive over the node credential the session was enrolled
// with, and an ordinary mutation is admitted on that owner. A caller that passes
// an executor ID also has it compared, so a request cannot name another node.
// The returned mutation is the caller's to finish.
func (b *BidiServer) admitted(ctx context.Context, executorID string) (*Mutation, error) {
	credentials, err := controlrpc.Read(ctx)
	if err != nil {
		return nil, err
	}
	b.mu.RLock()
	offer := b.offers[credentials.Binding.SessionID]
	var owner *SessionOwner
	if !b.closed && offer != nil && offer.credentials.Matches(credentials) && offer.owner != nil && b.clients[offer.owner.ExecutorID()].owner == offer.owner {
		owner = offer.owner
	}
	b.mu.RUnlock()
	if owner == nil {
		return nil, controlrpc.Unavailable()
	}
	if !b.boundNode(ctx, offer.fingerprint) {
		return nil, controlrpc.Denied()
	}
	if executorID != "" && executorID != owner.ExecutorID() {
		return nil, controlrpc.Denied()
	}
	ticket, err := owner.AdmitMutation(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		return nil, controlrpc.Unavailable()
	}
	return ticket, nil
}

type boundExecutorClient struct {
	client      pb.ExecutorServiceClient
	credentials controlrpc.Credentials
}

func (c *boundExecutorClient) Upload(ctx context.Context, in *pb.UploadRequest, opts ...grpc.CallOption) (*pb.UploadResponse, error) {
	out, err := c.client.Upload(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundExecutorClient) Abort(ctx context.Context, in *pb.AbortRequest, opts ...grpc.CallOption) (*pb.AbortResponse, error) {
	out, err := c.client.Abort(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
func (c *boundExecutorClient) Bandwidth(ctx context.Context, in *pb.BandwidthRequest, opts ...grpc.CallOption) (*pb.BandwidthResponse, error) {
	out, err := c.client.Bandwidth(c.credentials.Outgoing(ctx), in, opts...)
	return out, c.credentials.RedactError(err)
}
