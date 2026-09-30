// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// State and its receipt observation commit together. These are dispatcher
// receipt times, not executor clocks or evidence of end-to-end reachability.
func (d *Dispatcher) recordStateObservation(ctx context.Context, owner *rpc.SessionOwner, id uuid.UUID, state models.DebugletRunState, listener *pb.ListenerEndpoint) (database.Debuglet, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return database.Debuglet{}, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	run, err := q.UpdateDebugletState(ctx, database.UpdateDebugletStateParams{
		State: state, StateRank: state.SemanticRank(), Uuid: id, ExitedState: models.RunStateExited,
		ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID,
	})
	if err != nil {
		return run, err
	}
	if state == models.RunStateStarted {
		address := listener.GetAddress()
		if address != "" {
			document, err := q.GetDebugletProvenance(ctx, id)
			if err != nil {
				return run, err
			}
			var provenance wire.ResultProvenance
			if err := json.Unmarshal([]byte(document), &provenance); err != nil {
				return run, err
			}
			if !validListenerEndpoint(address, provenance) {
				return run, errors.New("listener endpoint does not match admitted TCP listener")
			}
		}
		if err := q.RecordMeasurementStarted(ctx, database.RecordMeasurementStartedParams{DebugletID: run.ID, StartedObservedNs: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true}, TcpEndpoint: address}); err != nil {
			return run, err
		}
	}
	return run, tx.Commit()
}

func validListenerEndpoint(address string, p wire.ResultProvenance) bool {
	if len(address) > 512 || !p.AdmittedPolicy.ListenTCP || p.VantagePoint == nil || p.VantagePoint.PublicHost.Value == nil {
		return false
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return false
	}
	expected := *p.VantagePoint.PublicHost.Value
	if ip := net.ParseIP(host); ip != nil {
		return ip.Equal(net.ParseIP(expected))
	}
	return host != "" && strings.EqualFold(host, expected)
}

func (d *Dispatcher) recordTerminalObservation(ctx context.Context, owner *rpc.SessionOwner, id uuid.UUID, exitCode int32, message *string) (database.Debuglet, error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return database.Debuglet{}, err
	}
	defer tx.Rollback()
	q := database.New(tx)
	run, err := q.CompleteDebuglet(ctx, database.CompleteDebugletParams{ExitedState: models.RunStateExited, Error: terminalError(exitCode, message), Uuid: id, ExecutorID: owner.ExecutorID(), DispatcherIncarnation: owner.Binding().Incarnation, SessionID: owner.Binding().SessionID})
	if err != nil {
		return run, err
	}
	if err = q.RecordMeasurementTerminal(ctx, database.RecordMeasurementTerminalParams{DebugletID: run.ID, TerminalObservedNs: sql.NullInt64{Int64: d.now().UTC().UnixNano(), Valid: true}, ExitCode: sql.NullInt64{Int64: int64(exitCode), Valid: true}}); err != nil {
		return run, err
	}
	return run, tx.Commit()
}
