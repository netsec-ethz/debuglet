package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"github.com/tetratelabs/wazero/sys"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// maxExitReportAttempts bounds one terminal delivery. Every attempt shares
	// the cleanup budget, so reporting never widens the bound that execution
	// cancellation and resource joins already observe.
	maxExitReportAttempts = 3
	// exitReportRetryDelay separates attempts inside that same budget.
	exitReportRetryDelay = 100 * time.Millisecond
	// maxReconciledPerPass bounds how many results one pass may deliver, and
	// reconcilePassBudget bounds the pass itself. A pass that runs out of
	// budget stops; the next one resumes from the oldest result still held.
	maxReconciledPerPass = 32
	reconcilePassBudget  = 15 * time.Second
)

// terminalRetention returns the durable terminal store when the configured
// scheduler has one. An in-memory scheduler has none: it reports and forgets.
func (e *Executor) terminalRetention() scheduler.TerminalRetention {
	retention, _ := e.scheduler.(scheduler.TerminalRetention)
	return retention
}

// beginDelivery claims one run's delivery. Reporting and reconciliation can
// otherwise reach the same result at once, and the loser would release or
// count an attempt against a row the winner already settled.
func (e *Executor) beginDelivery(id uuid.UUID) bool {
	e.deliveringMu.Lock()
	defer e.deliveringMu.Unlock()
	if _, busy := e.delivering[id]; busy {
		return false
	}
	e.delivering[id] = struct{}{}
	return true
}

func (e *Executor) endDelivery(id uuid.UUID) {
	e.deliveringMu.Lock()
	defer e.deliveringMu.Unlock()
	delete(e.delivering, id)
}

// reportDebugletExit selects the terminal result once, attempts to retain it
// under the run's immutable identity, and then tries to deliver it. Successful
// retention preserves evidence after a lost response or connection. A failed
// retention write is logged but does not prevent execution storage deletion.
// A failure's whole outcome is logged here under the run ID; the result that
// is retained and delivered carries only its public classification.
func (e *Executor) reportDebugletExit(op *debugletOperation, spec scheduler.Spec) {
	request := &pb.DebugletExitRequest{DebugletId: spec.DebugletID.String()}
	if op.outcome != nil {
		e.logger.Error("Debuglet handler failed", zap.String("debugletID", spec.DebugletID.String()), zap.Error(op.outcome))
		message := publicOutcome(op.outcome)
		request.ExitCode, request.ErrorMessage = -1, &message
	}
	// Reporting is bounded and independent of execution cancellation. Its
	// failure changes neither resource cleanup nor the chosen result.
	reportCtx, end := context.WithTimeout(context.WithoutCancel(op.ctx), scheduler.CleanupTimeout)
	defer end()
	retention := e.terminalRetention()
	retained := false
	if retention != nil {
		event := scheduler.TerminalEvent{
			DebugletID:   spec.DebugletID,
			Binding:      spec.Binding,
			ExitCode:     request.GetExitCode(),
			ErrorMessage: request.ErrorMessage,
			RecordedAt:   time.Now(),
		}
		if err := retention.RecordTerminal(reportCtx, event); err != nil {
			e.logger.Error("Failed to retain debuglet exit", zap.String("debugletID", spec.DebugletID.String()), zap.Error(err))
		} else {
			retained = true
		}
	}
	e.settleDebugletExit(reportCtx, retention, retained, spec.DebugletID, spec.Binding, request)
}

const (
	// maxPublicOutcome bounds the text a failed run reports, before the "..."
	// that marks a cut.
	maxPublicOutcome = 256
	// failedOutcome is the result of a failure the executor does not attribute
	// to the run itself.
	failedOutcome = "debuglet failed; the executor log has the details"
)

// abortReason is the cause of a run the dispatcher aborted with a reason. The
// reason is the dispatcher's own text, and the run reports it as given.
type abortReason struct{ reason string }

func (a abortReason) Error() string { return a.reason }

// policyTimeout is the cause of a run that used up its policy's timeout.
type policyTimeout struct{ budget time.Duration }

func (p policyTimeout) Error() string { return fmt.Sprintf("timeout of %s exceeded", p.budget) }

// publicOutcome classifies a failed run's outcome into the result its owner
// reads: an abort reason, the policy timeout, the guest's exit code, a refused
// destination, a module that does not compile, or a cancellation. Any other
// failure is the executor's own, and its text can carry the executor's
// addresses, its configuration and the stack traces wazero attaches to a
// failing host call; it reports failedOutcome. A trap is among them, because
// wazero reports it through a type no other package can match.
func publicOutcome(outcome error) string {
	var (
		abort   abortReason
		timeout policyTimeout
		exit    *sys.ExitError
		compile *debuglet.CompileError
	)
	text := failedOutcome
	switch {
	case errors.As(outcome, &abort):
		text = abort.reason
	case errors.As(outcome, &timeout):
		text = timeout.Error()
	case errors.As(outcome, &exit) && exit.ExitCode() != sys.ExitCodeContextCanceled && exit.ExitCode() != sys.ExitCodeDeadlineExceeded:
		text = fmt.Sprintf("debuglet exited with code %d", exit.ExitCode())
	case errors.Is(outcome, netpolicy.ErrNotInPolicy):
		text = "destination refused: " + netpolicy.ErrNotInPolicy.Error()
	case errors.Is(outcome, netpolicy.ErrDenied):
		text = "destination refused: " + netpolicy.ErrDenied.Error()
	case errors.Is(outcome, netpolicy.ErrTransportUnavailable):
		text = "destination refused: " + netpolicy.ErrTransportUnavailable.Error()
	case errors.As(outcome, &compile):
		text = "module does not compile: " + compile.Err.Error()
	case errors.Is(outcome, context.Canceled):
		text = "debuglet cancelled"
	}
	return publicLine(text, maxPublicOutcome)
}

// publicLine returns text as one line of valid UTF-8: an invalid byte becomes
// the replacement character, a control character a space, and text longer
// than limit bytes is cut on a rune boundary and marked with "...".
func publicLine(text string, limit int) string {
	var line strings.Builder
	for _, r := range text { // An invalid byte ranges as utf8.RuneError.
		if unicode.IsControl(r) {
			r = ' '
		}
		if line.Len()+utf8.RuneLen(r) > limit {
			line.WriteString("...")
			break
		}
		line.WriteRune(r)
	}
	return line.String()
}

// settleDebugletExit delivers one already chosen result and records what the
// executor learned. An acknowledged result ends its retention; a transient
// failure stays retained with its attempt count for a later pass under the
// same binding; a refusal the dispatcher would repeat is kept as evidence and
// leaves the reconciliation set.
func (e *Executor) settleDebugletExit(ctx context.Context, retention scheduler.TerminalRetention, retained bool,
	id uuid.UUID, binding controlsession.Binding, request *pb.DebugletExitRequest) {
	if !e.beginDelivery(id) {
		return // Another pass already owns this delivery.
	}
	defer e.endDelivery(id)
	attempts, err := e.deliverDebugletExit(ctx, binding, request)
	// Delivery may have consumed its whole budget. Recording what was learned
	// gets its own bounded, detached context so the evidence still lands.
	writeCtx, endWrite := context.WithTimeout(context.WithoutCancel(ctx), scheduler.CleanupTimeout)
	defer endWrite()
	if err == nil {
		if retention != nil && retained {
			if release := retention.ReleaseTerminal(writeCtx, id, binding); release != nil {
				// The result is delivered; the local row is only evidence.
				e.logger.Error("Failed to release an acknowledged debuglet exit",
					zap.String("debugletID", id.String()), zap.Error(release))
			}
		}
		return
	}
	rejected := permanentRejection(err)
	if rejected {
		e.logger.Error("Dispatcher refused a debuglet exit", zap.String("debugletID", id.String()), zap.Error(err))
	} else {
		e.logger.Error("Failed to notify debuglet exit", zap.String("debugletID", id.String()), zap.Error(err))
	}
	if retention != nil && retained {
		attempt := scheduler.TerminalAttempt{Attempts: attempts, Rejected: rejected, Failure: err}
		if note := retention.NoteTerminalFailure(writeCtx, id, binding, attempt); note != nil {
			e.logger.Error("Failed to record a terminal delivery attempt",
				zap.String("debugletID", id.String()), zap.Error(note))
		}
	}
}

// permanentRejection reports a dispatcher verdict no retry can change: the run
// belongs to another session, it does not exist, or the request itself is
// invalid. Only a reply to an actual request counts; a local session failure
// is transient and keeps the result deliverable.
func permanentRejection(err error) bool {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.NotFound, codes.InvalidArgument:
		return true
	default:
		return false
	}
}

// deliverDebugletExit retries only while the run's own control session can
// still carry the report. A revoked, expired or replaced session ends delivery
// immediately: retrying there would ask for authority this binding no longer
// has, and so does a refusal the dispatcher would only repeat. Every attempt
// sends the identical request, which the dispatcher's duplicate handling
// absorbs without repeating any effect.
func (e *Executor) deliverDebugletExit(ctx context.Context, binding controlsession.Binding, request *pb.DebugletExitRequest) (int64, error) {
	var err error
	var attempts int64
	for attempt := 1; attempt <= maxExitReportAttempts; attempt++ {
		var client pb.DispatcherServiceClient
		client, err = e.dispatcherClient(ctx, binding)
		if err != nil {
			return attempts, err
		}
		attempts++
		if _, err = client.DebugletExit(ctx, request); err == nil {
			return attempts, nil
		}
		if ctx.Err() != nil || attempt == maxExitReportAttempts || permanentRejection(err) {
			return attempts, err
		}
		e.logger.Debug("Retrying debuglet exit report", zap.String("debugletID", request.GetDebugletId()),
			zap.Int("attempt", attempt), zap.Error(err))
		timer := time.NewTimer(exitReportRetryDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return attempts, err
		}
		timer.Stop()
	}
	return attempts, err
}

// reconcileLoop owns every reconciliation pass for one session. The heartbeat
// only kicks it, so a slow pass delays no heartbeat, and the session worker
// joins this loop before its transport and database are closed.
func (e *Executor) reconcileLoop(ctx context.Context, binding controlsession.Binding) {
	e.reconcileTerminals(ctx, binding)
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.reconcileKick:
			e.reconcileTerminals(ctx, binding)
		}
	}
}

// kickReconcile requests one pass without waiting for it. A pass already
// pending covers the request, so callers never queue work behind each other.
func (e *Executor) kickReconcile() {
	select {
	case e.reconcileKick <- struct{}{}:
	default:
	}
}

// reconcileTerminals redelivers the results this session can still deliver. It
// reads and sends only: no queue entry is promoted, no runtime is constructed
// and no guest is executed again. The whole pass is bounded, and results
// accepted under another binding are never listed, because delivering them
// here would need authority this session was never granted.
func (e *Executor) reconcileTerminals(ctx context.Context, binding controlsession.Binding) {
	retention := e.terminalRetention()
	if retention == nil || !binding.Valid() || ctx.Err() != nil {
		return
	}
	passCtx, endPass := context.WithTimeout(ctx, reconcilePassBudget)
	defer endPass()
	listCtx, end := context.WithTimeout(passCtx, scheduler.CleanupTimeout)
	events, err := retention.ListRetainedTerminals(listCtx, binding, maxReconciledPerPass)
	end()
	if err != nil {
		if !errors.Is(err, scheduler.ErrClosed) && passCtx.Err() == nil {
			e.logger.Error("Failed to read retained debuglet exits", zap.Error(err))
		}
		return
	}
	for _, event := range events {
		if passCtx.Err() != nil {
			return
		}
		if event.Binding != binding {
			continue
		}
		request := &pb.DebugletExitRequest{
			DebugletId:   event.DebugletID.String(),
			ExitCode:     event.ExitCode,
			ErrorMessage: event.ErrorMessage,
		}
		eventCtx, done := context.WithTimeout(passCtx, scheduler.CleanupTimeout)
		e.settleDebugletExit(eventCtx, retention, true, event.DebugletID, event.Binding, request)
		done()
	}
}
