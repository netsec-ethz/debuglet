package rpc

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/netsec-ethz/debuglet/internal/controlrpc"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const preOfferTimeout = 5 * time.Second
const unsupportedReason = "CONTROL_VERSION_UNSUPPORTED"
const unsupportedDomain = "debuglet.control"

func endCause(kind controlsession.EndKind, cause error) error {
	return &controlsession.EndError{Kind: kind, Err: cause}
}

func unsupportedProfile() error {
	s := status.New(codes.FailedPrecondition, "unsupported control profile")
	with, err := s.WithDetails(&errdetails.ErrorInfo{Reason: unsupportedReason, Domain: unsupportedDomain})
	if err != nil {
		return s.Err()
	}
	return with.Err()
}

func observedUnsupported(err error) bool {
	for _, detail := range status.Convert(err).Details() {
		if info, ok := detail.(*errdetails.ErrorInfo); ok && info.Reason == unsupportedReason && info.Domain == unsupportedDomain {
			return true
		}
	}
	return false
}

// Lost closes before teardown can block. It signals no handler or resource
// completion; the caller must still join ConnectAndServe and Close.
func (b *BidiClient) Lost() <-chan struct{} { return b.stop }
func (b *BidiClient) Cause() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cause
}

// Stop revokes eligibility only. The invocation's owned watcher cancels I/O;
// the lifecycle owner separately signals scheduler shutdown before joining.
func (b *BidiClient) Stop(cause error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopLocked(cause)
}

func (b *BidiClient) stopLocked(cause error) {
	if b.closed {
		return
	}
	if cause == nil {
		cause = endCause(controlsession.ParentStopped, context.Canceled)
	}
	if b.control != nil {
		if ended, ok := cause.(*controlsession.EndError); ok {
			cause = endCause(ended.Kind, b.control.RedactError(ended.Err))
		} else {
			cause = b.control.RedactError(cause)
		}
	}
	b.cause = cause
	b.closed, b.armed, b.negotiated = true, false, false
	close(b.stop)
}

// leaseLocked is the armed-binding check every effect goes through: it enters no
// other owner and runs no cancellation hook, and its own clock reading revokes an
// expired lease immediately, even when the watchdog has not fired yet.
func (b *BidiClient) leaseLocked(binding controlsession.Binding, pending bool) error {
	if b.closed {
		return b.cause
	}
	if !binding.Valid() || b.control == nil || b.control.Binding != binding || !b.armed {
		return controlrpc.Unavailable()
	}
	now := b.now()
	if !now.Before(b.deadline) || !b.negotiated && !now.Before(b.bindDeadline) {
		kind := controlsession.LeaseExpired
		if !b.negotiated {
			kind = controlsession.TransportUnavailable
		}
		b.stopLocked(endCause(kind, context.DeadlineExceeded))
		return b.cause
	}
	if !pending && !b.negotiated {
		return controlrpc.Unavailable()
	}
	return nil
}

func (b *BidiClient) CheckLease(binding controlsession.Binding) error {
	return b.CommitLease(binding, nil)
}

// CommitLease serializes a bounded start/admission transition with revocation.
// Callers may hold scheduler core first; the callback must not enter SQL, I/O,
// cancellation, other transport guards or any join.
func (b *BidiClient) CommitLease(binding controlsession.Binding, commit func()) error {
	return b.commit(binding, false, commit)
}

// CommitUpload also permits a live pending Bind interval. It authorizes only
// reserving queued persistence; it cannot authorize queue promotion or Run.
func (b *BidiClient) CommitUpload(binding controlsession.Binding, commit func()) error {
	return b.commit(binding, true, commit)
}
func (b *BidiClient) commit(binding controlsession.Binding, pending bool, commit func()) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.leaseLocked(binding, pending); err != nil {
		return err
	}
	if commit != nil {
		commit()
	}
	return nil
}

func (b *BidiClient) watchLease(ctx context.Context, done chan struct{}) {
	defer close(done)
	interval := 50 * time.Millisecond // <= negotiated S for every valid L.
	ticks, stop := b.newLeaseTicker(interval)
	if ticks == nil || stop == nil {
		if stop != nil {
			stop()
		}
		b.Stop(endCause(controlsession.LocalFailure, errors.New("invalid control watchdog ticker")))
		return
	}
	defer func() { stop() }()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case _, ok := <-ticks:
			if !ok {
				b.Stop(endCause(controlsession.LocalFailure, errors.New("control watchdog ticker closed")))
				return
			}
			b.mu.Lock()
			if b.closed {
				b.mu.Unlock()
				return
			}
			next := interval
			if b.armed {
				_ = b.leaseLocked(b.control.Binding, true)
				next = b.lease.WatchdogInterval
			} else if !b.now().Before(b.startupDeadline) {
				b.stopLocked(endCause(controlsession.TransportUnavailable, context.DeadlineExceeded))
			}
			stopped := b.closed
			b.mu.Unlock()
			if stopped {
				return
			}
			if next != interval {
				stop()
				ticks, stop = b.newLeaseTicker(next)
				if ticks == nil || stop == nil {
					if stop == nil {
						stop = func() {}
					}
					b.Stop(endCause(controlsession.LocalFailure, errors.New("invalid control watchdog ticker")))
					return
				}
				interval = next
			}
		}
	}
}

func (b *BidiClient) renewLoop(ctx context.Context, done chan struct{}) {
	defer close(done)
	if err := b.WaitReadyContext(ctx); err != nil {
		return
	}
	b.mu.Lock()
	timing := b.lease
	b.mu.Unlock()
	timer := time.NewTicker(timing.RenewInterval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-b.stop:
			return
		case <-timer.C:
			if !b.renewOnce(ctx) {
				return
			}
		}
	}
}

func (b *BidiClient) renewOnce(ctx context.Context) bool {
	b.mu.Lock()
	if b.closed || b.control == nil {
		b.mu.Unlock()
		return false
	}
	credentials := *b.control
	if err := b.leaseLocked(credentials.Binding, false); err != nil {
		b.mu.Unlock()
		return false
	}
	if b.sequence == math.MaxUint64 {
		b.stopLocked(endCause(controlsession.LocalFailure, errors.New("control renewal sequence exhausted")))
		b.mu.Unlock()
		return false
	}
	b.sequence++
	sequence := b.sequence
	sent := b.now()
	timing := b.lease
	b.mu.Unlock()
	callCtx, cancel := context.WithTimeout(ctx, timing.RequestTimeout)
	ack, err := b.client.RenewLease(credentials.Outgoing(callCtx), &pb.RenewLeaseRequest{Sequence: sequence})
	defer cancel()
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return false
	}
	// Recheck the prior deadline even if the watchdog is deliberately delayed.
	if b.leaseLocked(credentials.Binding, false) != nil {
		return false
	}
	if err != nil || callCtx.Err() != nil {
		if observedUnsupported(err) {
			b.stopLocked(endCause(controlsession.IncompatibleProfile, credentials.RedactError(err)))
			return false
		}
		return true // A lost reply never renews; the next sequence may try until expiry.
	}
	if ctx.Err() != nil {
		return false
	}
	if ack.GetSequence() != sequence || ack.GetLeaseDurationMs() != timing.Duration.Milliseconds() {
		b.stopLocked(endCause(controlsession.LocalFailure, errors.New("invalid control lease acknowledgement")))
		return false
	}
	deadline := sent.Add(timing.Duration)
	if b.sequence != sequence || !b.now().Before(deadline) {
		b.stopLocked(endCause(controlsession.LeaseExpired, context.DeadlineExceeded))
		return false
	}
	b.deadline = deadline
	return true
}
