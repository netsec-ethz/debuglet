// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet"
	"github.com/netsec-ethz/debuglet/internal/executor/outputstore"
	"github.com/netsec-ethz/debuglet/internal/executor/scheduler"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	outputQueueFrames = 16 // At most 256 KiB; the writer chunks before copying.
	outputCallTimeout = 5 * time.Second
	outputPassFrames  = 64
)

// beginOutputDelivery excludes a second output pump or retry for this run.
// Terminal reporting uses its own set under the same short-lived mutex.
func (e *Executor) beginOutputDelivery(id uuid.UUID) bool {
	e.deliveringMu.Lock()
	defer e.deliveringMu.Unlock()
	if _, busy := e.outputDelivering[id]; busy {
		return false
	}
	e.outputDelivering[id] = struct{}{}
	return true
}

func (e *Executor) endOutputDelivery(id uuid.UUID) {
	e.deliveringMu.Lock()
	defer e.deliveringMu.Unlock()
	delete(e.outputDelivering, id)
}

type outputStream struct {
	stream pb.DispatcherService_DebugletStreamClient
	cancel context.CancelFunc
}

func (s *outputStream) exchange(req *pb.DebugletStreamRequest) (*pb.DebugletStreamResponse, error) {
	timer := time.AfterFunc(outputCallTimeout, s.cancel)
	defer timer.Stop()
	if err := s.stream.Send(req); err != nil {
		return nil, err
	}
	return s.stream.Recv()
}

func (e *Executor) openOutput(ctx context.Context, current, original controlsession.Binding, id uuid.UUID) (*outputStream, *pb.DebugletStreamResponse, error) {
	client, err := e.dispatcherClient(ctx, current)
	if err != nil {
		return nil, nil, err
	}
	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := client.DebugletStream(streamCtx, grpc.MaxCallRecvMsgSize(4096))
	if err != nil {
		cancel()
		return nil, nil, err
	}
	s := &outputStream{stream: stream, cancel: cancel}
	receipt, err := s.exchange(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{
		DebugletId: id.String(), ExecutorId: e.cfg.Identity.ExecutorID,
		OriginalBinding: &pb.ControlBinding{DispatcherIncarnation: original.Incarnation, SessionId: original.SessionID},
	}}})
	if err != nil {
		cancel()
		return nil, nil, err
	}
	return s, receipt, nil
}

func quotaReceipt(receipt *pb.DebugletStreamResponse) bool {
	end := receipt.GetEnd()
	return end != nil && end.GetStatus() == pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED &&
		(end.GetReason() == "output_limit" || end.GetReason() == "storage_limit")
}

// validateQuotaReceipt checks a remote rejection before it can change the
// producer's durable loss reason. The store rechecks before deleting a suffix.
func (e *Executor) validateQuotaReceipt(ctx context.Context, id uuid.UUID, receipt *pb.DebugletStreamResponse) error {
	ctx, cancel := context.WithTimeout(ctx, outputCallTimeout)
	defer cancel()
	end := receipt.GetEnd()
	if !pb.ValidOutputEnd(end) || receipt.GetCommittedSequence() != end.GetLastSequence() {
		return outputstore.ErrAcknowledgement
	}
	retained, err := e.output.Get(ctx, id)
	if err != nil {
		return err
	}
	if end.GetLastSequence() < retained.AcknowledgedSequence || end.GetLastSequence() > retained.LastSequence {
		return outputstore.ErrAcknowledgement
	}
	return nil
}

// acknowledgeOutput is called with a joined producer before accepting a quota
// receipt that abandons a local suffix. Other receipts delete only their prefix.
func (e *Executor) acknowledgeOutput(ctx context.Context, id uuid.UUID, receipt *pb.DebugletStreamResponse) error {
	ctx, cancel := context.WithTimeout(ctx, outputCallTimeout)
	defer cancel()
	if receipt == nil {
		return outputstore.ErrAcknowledgement
	}
	if quotaReceipt(receipt) {
		if receipt.GetCommittedSequence() != receipt.GetEnd().GetLastSequence() {
			return outputstore.ErrAcknowledgement
		}
		return e.output.AcceptTruncation(ctx, id, receipt.GetEnd())
	}
	return e.output.Acknowledge(ctx, id, receipt.GetCommittedSequence(), receipt.GetEnd())
}

func (e *Executor) outputStorageFailed(err error) {
	if err != nil && !errors.Is(err, outputstore.ErrOutputLimit) && !errors.Is(err, outputstore.ErrSpoolLimit) && e.outputFailed != nil {
		e.outputFailed.Store(true)
	}
}

// newDurableOutput admits metadata before any guest producer or fallible setup.
// A failed setup therefore still has a separately finalized empty output prefix.
func (e *Executor) newDurableOutput(op *debugletOperation, spec scheduler.Spec) (*outputPump, error) {
	if e.output == nil || e.outputVersion.Load() != pb.OutputVersion {
		return nil, nil
	}
	if e.outputFailed != nil && e.outputFailed.Load() {
		return nil, errors.New("executor output storage is unhealthy")
	}
	if !e.beginOutputDelivery(spec.DebugletID) {
		return nil, errors.New("run output is already being delivered")
	}
	// Cancellation may win before the scheduler enters this callback. Retain
	// bounded bookkeeping so its empty producer can still finalize output.
	admissionCtx, admissionCancel := context.WithTimeout(context.WithoutCancel(op.ctx), outputCallTimeout)
	defer admissionCancel()
	if err := e.output.Admit(admissionCtx, spec.DebugletID, spec.Binding, pb.OutputVersion); err != nil {
		e.endOutputDelivery(spec.DebugletID)
		if op.ctx.Err() == nil {
			e.outputStorageFailed(err)
		}
		return nil, err
	}
	retained, err := e.output.Get(admissionCtx, spec.DebugletID)
	if err != nil || retained.End != nil {
		e.endOutputDelivery(spec.DebugletID)
		if err == nil {
			err = outputstore.ErrFinalized
		}
		return nil, err
	}
	input := make(chan []byte, outputQueueFrames)
	storageCtx, storageCancel := context.WithCancel(context.WithoutCancel(op.ctx))
	deliveryCtx, deliveryCancel := context.WithCancel(op.ctx)
	// Cleanup may stop a slow delivery after the producer has joined. Its
	// accepted queue and final marker still belong to this worker; canceling
	// their storage context would strand an open run that cannot be retried.
	p := &outputPump{Input: input, done: make(chan struct{}), producerDone: make(chan struct{}), cancel: deliveryCancel}
	go func() {
		defer close(p.done)
		defer storageCancel()
		defer deliveryCancel()
		defer e.endOutputDelivery(spec.DebugletID)
		defer func() {
			select {
			case e.outputKick <- struct{}{}:
			default:
			}
		}()
		fail := func(err error) {
			if p.err == nil {
				p.err = err
			}
			op.cancel(err)
		}
		stream, receipt, err := e.openOutput(deliveryCtx, spec.Binding, spec.Binding, spec.DebugletID)
		var rejected *pb.DebugletStreamResponse
		if err != nil {
			fail(fmt.Errorf("open durable output: %w", err))
		} else {
			defer stream.cancel()
			if quotaReceipt(receipt) {
				if err := e.validateQuotaReceipt(storageCtx, spec.DebugletID, receipt); err != nil {
					fail(err)
				} else {
					rejected = receipt
					fail(outputstore.ErrOutputLimit)
				}
			} else if err := e.acknowledgeOutput(storageCtx, spec.DebugletID, receipt); err != nil {
				fail(err)
			}
		}
		bytesPerSecond, burst := e.cfg.Output.Rate()
		limiter := rate.NewLimiter(rate.Limit(bytesPerSecond), burst)
		loss := ""
		process := func(data []byte) {
			if len(data) == 0 || loss != "" {
				return
			}
			if op.ctx.Err() == nil {
				// Cancellation removes backpressure, but the already accepted bounded
				// queue is still spooled before its producer is finalized.
				if err := limiter.WaitN(op.ctx, len(data)); err != nil {
					fail(err)
					deliveryCancel()
				}
			}
			callCtx, done := context.WithTimeout(storageCtx, outputCallTimeout)
			frame, err := e.output.Append(callCtx, spec.DebugletID, time.Now().UTC(), data)
			done()
			if err != nil {
				switch {
				case errors.Is(err, outputstore.ErrOutputLimit):
					loss = "output_limit"
				case errors.Is(err, outputstore.ErrSpoolLimit):
					loss = "spool_limit"
				default:
					loss = "producer_failed"
					e.outputStorageFailed(err)
				}
				fail(err)
				return
			}
			if stream == nil || deliveryCtx.Err() != nil || rejected != nil {
				return
			}
			receipt, err := stream.exchange(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{
				Sequence: frame.Sequence, Timestamp: timestamppb.New(frame.Timestamp), Output: frame.Output,
			}}})
			if err != nil {
				fail(fmt.Errorf("deliver durable output: %w", err))
				deliveryCancel()
				return
			}
			if quotaReceipt(receipt) {
				if err := e.validateQuotaReceipt(storageCtx, spec.DebugletID, receipt); err != nil {
					fail(err)
				} else {
					rejected = receipt
					fail(outputstore.ErrOutputLimit)
				}
				deliveryCancel()
				return
			}
				if err := e.acknowledgeOutput(storageCtx, spec.DebugletID, receipt); err != nil {
				fail(err)
				deliveryCancel()
			}
		}
		// Only Run owns closing input. Failed setup never starts Run, so the
		// producer-finished signal also ends this bounded drain.
	drain:
		for {
			select {
			case data, ok := <-input:
				if !ok {
					break drain
				}
				process(data)
			case <-p.producerDone:
				for {
					select {
					case data, ok := <-input:
						if !ok {
							break drain
						}
						process(data)
					default:
						break drain
					}
				}
			case <-storageCtx.Done():
				fail(context.Cause(storageCtx))
				return
			}
		}
		<-p.producerDone
		if rejected != nil && loss == "" {
			loss = rejected.GetEnd().GetReason()
		}
		if loss == "" && errors.Is(p.producerErr, debuglet.ErrOutputIncomplete) {
			loss = "producer_failed"
		}
		status := pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_COMPLETE
		if loss != "" {
			status = pb.DebugletOutputStatus_DEBUGLET_OUTPUT_STATUS_TRUNCATED
		}
		finishCtx, finishDone := context.WithTimeout(storageCtx, outputCallTimeout)
		end, err := e.output.Finish(finishCtx, spec.DebugletID, status, loss)
		finishDone()
		if err != nil {
			e.outputStorageFailed(err)
			fail(err)
			return
		}
		if rejected != nil {
			if err := e.acknowledgeOutput(storageCtx, spec.DebugletID, rejected); err != nil {
				fail(err)
			}
			return
		}
		if stream == nil || deliveryCtx.Err() != nil {
			return
		}
		receipt, err = stream.exchange(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_End{End: end}})
		if err != nil {
			fail(fmt.Errorf("finalize durable output: %w", err))
			return
		}
		if err := e.acknowledgeOutput(storageCtx, spec.DebugletID, receipt); err != nil {
			fail(err)
			return
		}
		_ = stream.stream.CloseSend()
	}()
	return p, nil
}

// deliverOutput retries bytes, never execution. The current transport proves
// enrollment; the immutable original binding still identifies the output.
func (e *Executor) deliverOutput(ctx context.Context, current controlsession.Binding, run outputstore.Run) error {
	if e.cfg.TLS.Disable && run.Binding != current {
		// Plaintext sessions carry no credential that could resume the output.
		return e.output.Abandon(ctx, run.ID)
	}
	stream, receipt, err := e.openOutput(ctx, current, run.Binding, run.ID)
	if run.Binding != current && status.Code(err) == codes.PermissionDenied {
		// Only an enrolled credential may resume output of an ended session.
		// The dispatcher has finalized this output as interrupted.
		e.logger.Info("Output cannot resume over this session; releasing local copy", zap.String("debugletID", run.ID.String()), zap.Error(err))
		return e.output.Abandon(ctx, run.ID)
	}
	if err != nil {
		return err
	}
	defer stream.cancel()
	if err := e.acknowledgeOutput(ctx, run.ID, receipt); err != nil {
		return err
	}
	if receipt.GetEnd() != nil {
		return nil
	}
	frames, err := e.output.Frames(ctx, run.ID, receipt.GetCommittedSequence(), outputPassFrames)
	if err != nil {
		return err
	}
	last := receipt.GetCommittedSequence()
	for _, frame := range frames {
		receipt, err = stream.exchange(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{
			Sequence: frame.Sequence, Timestamp: timestamppb.New(frame.Timestamp), Output: frame.Output,
		}}})
		if err != nil {
			return err
		}
		if err := e.acknowledgeOutput(ctx, run.ID, receipt); err != nil {
			return err
		}
		if receipt.GetEnd() != nil {
			return nil
		}
		last = receipt.GetCommittedSequence()
	}
	if run.End != nil && last == run.End.GetLastSequence() {
		receipt, err = stream.exchange(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_End{End: run.End}})
		if err != nil {
			return err
		}
		if err := e.acknowledgeOutput(ctx, run.ID, receipt); err != nil {
			return err
		}
	}
	return stream.stream.CloseSend()
}

func (e *Executor) reconcileOutputLoop(ctx context.Context, binding controlsession.Binding) {
	if e.output == nil || e.outputVersion.Load() != pb.OutputVersion {
		return
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	after := ""
	for {
		passCtx, done := context.WithTimeout(ctx, reconcilePassBudget)
		runs, err := e.output.Pending(passCtx, after, maxReconciledPerPass)
		if len(runs) == 0 {
			after = ""
		}
		for _, run := range runs {
			if passCtx.Err() != nil {
				break
			}
			after = run.ID.String()
			if run.End == nil || !e.beginOutputDelivery(run.ID) {
				continue
			}
			err = e.deliverOutput(passCtx, binding, run)
			e.endOutputDelivery(run.ID)
			if err != nil && passCtx.Err() == nil {
				e.logger.Debug("Output remains pending", zap.String("debugletID", run.ID.String()), zap.Error(err))
			}
		}
		done()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-e.outputKick:
		}
	}
}
