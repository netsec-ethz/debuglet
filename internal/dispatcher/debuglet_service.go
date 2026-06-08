package dispatcher

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"
)

func (d *Dispatcher) SubmitDebuglets(ctx context.Context, specs []DebugletSpec) ([]string, error) {
	g, subCtx := errgroup.WithContext(ctx)
	debugletIDS := make([]string, len(specs))

	d.mu.RLock()
	for _, spec := range specs {
		_, exists := d.executors[spec.ExecutorID]
		if !exists {
			d.mu.RUnlock()
			return nil, fmt.Errorf("executor '%s' not found", spec.ExecutorID)
		}
	}
	d.mu.RUnlock()

	for i, spec := range specs {
		debugletID := uuid.New().String()
		debugletIDS[i] = debugletID
		g.Go(d.uploadToExecutor(subCtx, i, debugletID, spec))
	}

	if err := g.Wait(); err != nil {
		for _, ID := range debugletIDS {
			AbortDebuglet(ID)
		}
		return nil, fmt.Errorf("failed to upload debuglets: %w", err)
	}

	return debugletIDS, nil
}

func (d *Dispatcher) uploadToExecutor(ctx context.Context, i int, debugletID string, spec DebugletSpec) func() error {
	return func() error {
		if err := d.sender.UploadDebuglet(ctx, debugletID, spec); err != nil {
			return fmt.Errorf("failed to upload debuglet i=%d", i)
		}
		return nil
	}
}

// (idempotent)
func AbortDebuglet(debugletID string) {

}
