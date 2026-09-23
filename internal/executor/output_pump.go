package executor

import (
	"context"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/controlsession"
	"io"

	"github.com/google/uuid"
	pb "github.com/netsec-ethz/debuglet/protocol"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// One worker owns every Send (including identification), CloseSend and Recv.
// Run owns closing Input; before Run starts cancellation also releases the pump.
type outputPump struct {
	Input  chan<- []byte
	cancel context.CancelFunc
	done   chan struct{}
	err    error // published by done
}

func (p *outputPump) Cancel() { p.cancel() }

func (p *outputPump) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		return p.err
	default:
	}
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (e *Executor) propagateOutputToStream(op *debugletOperation, id uuid.UUID, binding controlsession.Binding) (*outputPump, error) {
	ctx, cancel := context.WithCancel(op.ctx)
	client, err := e.dispatcherClient(ctx, binding)
	if err != nil {
		cancel()
		return nil, err
	}
	stream, err := client.DebugletStream(ctx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("open debuglet output stream: %w", err)
	}
	input := make(chan []byte, 1024)
	p := &outputPump{Input: input, cancel: cancel, done: make(chan struct{})}
	identified := make(chan error, 1)
	go func() {
		defer close(p.done)
		defer cancel()
		fail := func(err error) {
			p.err = err
			op.cancel(err)
		}
		err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Ident{Ident: &pb.DebugletIdent{DebugletId: id.String(), ExecutorId: e.cfg.Identity.ExecutorID}}})
		identified <- err
		if err != nil {
			fail(fmt.Errorf("send debuglet output identity: %w", err))
			return
		}
		for {
			select {
			case <-ctx.Done():
				p.err = context.Cause(ctx)
				return
			case out, ok := <-input:
				if !ok {
					if err := stream.CloseSend(); err != nil {
						fail(fmt.Errorf("finish debuglet output send: %w", err))
						return
					}
					for {
						_, err := stream.Recv()
						if err == io.EOF {
							return
						}
						if err != nil {
							fail(fmt.Errorf("finish debuglet output stream: %w", err))
							return
						}
					}
				}
				if err := stream.Send(&pb.DebugletStreamRequest{Msg: &pb.DebugletStreamRequest_Output{Output: &pb.DebugletOutput{Output: out, Timestamp: timestamppb.Now()}}}); err != nil {
					fail(fmt.Errorf("send debuglet output: %w", err))
					return
				}
			}
		}
	}()
	select {
	case err := <-identified:
		if err == nil {
			return p, nil
		}
		p.Cancel()
		return p, fmt.Errorf("identify debuglet output: %w", err)
	case <-ctx.Done():
		p.Cancel()
		return p, context.Cause(ctx)
	}
}
