package executor

import (
	"context"
	"debuglet/internal/executor/debuglet/wasm/hostconn"
	"debuglet/internal/executor/transport/rpc"
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"go.uber.org/zap"
)

func (e *Executor) HandleUpload(ctx context.Context, upload rpc.Spec) {
	// TODO: perform checks and throw error if can't submit

	e.logger.Debug("Handling upload", zap.String("debugletID", upload.DebugletID))
	if err := e.scheduler.Insert(upload); err != nil {
		e.logger.Error("Failed to schedule debuglet spec", zap.Error(err))
		err = fmt.Errorf("failed to schedule: %w", err)
		if err2 := e.control.SendError(ctx, &upload.DebugletID, err); err2 != nil {
			e.logger.Error("Failed to forward error to dispatcher", zap.Error(err2), zap.NamedError("original", err))
		}
	}
}

func (e *Executor) HandleAbort(ctx context.Context, debugletID, reason string) {
	e.logger.Debug("Handling abort", zap.String("debugletID", debugletID), zap.String("reason", reason))
	existed := e.scheduler.Remove(debugletID)
	if existed {
		e.logger.Info("Removed debuglet from storage before it was started", zap.String("debugletID", debugletID))
		return
	}

	e.mu.Lock()
	run, exists := e.running[debugletID]
	e.mu.Unlock()
	if !exists {
		e.logger.Error("Did not find debuglet when aborting. Probably due to a race condition between OnStart and Abort being called at the same time", zap.String("debugletID", debugletID))
		return
	}
	run.cancelCtx(errors.New(reason))
}

func (e *Executor) HandleUpdate(ctx context.Context, updates []rpc.Update) {
	e.logger.Debug("Handling update", zap.Objects("destination", updates))
	var ipUpdates []rpc.Update
	for _, up := range updates {
		ips, err := hostconn.DomainsToIP6(ctx, []string{up.Address})
		if err != nil {
			e.logger.Error("Failed to resolve address", zap.String("address", up.Address), zap.Error(err))
			continue
		}
		for _, ip := range ips {
			ipUpdates = append(ipUpdates, rpc.Update{
				Address: ip,
				Limit:   up.Limit,
			})
		}
	}
	e.logger.Debug("Resolved update addresses", zap.Objects("destination", ipUpdates))

	e.mu.Lock()
	defer e.mu.Unlock()
	for _, up := range ipUpdates {
		e.limiter.SetAddrCapacity(up.Address, up.Limit)
	}

	if e.packetCount == nil {
		return
	}
	for _, up := range ipUpdates {
		// TODO: have the dispatcher send the IP directly
		ip, err := netip.ParseAddr(up.Address)
		if err != nil {
			continue
		}
		for _, running := range e.running {
			if !slices.Contains(running.addresses, up.Address) {
				continue
			}
			limit, err := e.limiter.GetLimit(running.id.String(), up.Address)
			if err != nil {
				continue
			}
			e.packetCount.SetLimit(ip, running.id, min(limit.Executor, limit.Address))
			e.packetCount.SetExecLimit(running.id, limit.Executor)
		}
	}
}
