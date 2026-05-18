// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package executor

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	"debuglet/internal/executor/engine"
	"debuglet/internal/executor/resource"
	"debuglet/pkg/tesla"
	pb "debuglet/protocol"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Executor struct {
	id     string
	client pb.DebugletDispatcherClient
	conn   *grpc.ClientConn
	logger *zap.Logger

	version string

	mu        sync.RWMutex
	debuglets map[string]*engine.Debuglet

	stdoutWg sync.WaitGroup

	// manager keeps track of the maximum bandwidth a destination is allowed to use on a destination-level
	// and in total on the executor
	manager *resource.LimitManager
	// tracker keeps of how much bandwidth is actively being used by a debuglet

	teslaSchedule *tesla.KeySchedule
}

func getClientCredentials(cfg *Config) (credentials.TransportCredentials, error) {
	// Load client certificate
	cert, err := tls.LoadX509KeyPair(
		cfg.Credentials.ClientCert,
		cfg.Credentials.ClientKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // skip server cert verification - insecure! TODO: server authentication
		// RootCAs:      nil,
		// ClientCAs:  nil,
		// ClientAuth: tls.RequireAndVerifyClientCert,
		// MinVersion: tls.VersionTLS13,
	}

	creds := credentials.NewTLS(tlsConfig)
	return creds, nil
}

func NewExecutor(cfg *Config, logger *zap.Logger) (*Executor, error) {
	creds, err := getClientCredentials(cfg)
	if err != nil {
		return nil, err
	}
	conn, err := grpc.NewClient(cfg.DispatcherAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	logger.Info("Connected to dispatcher", zap.String("address", cfg.DispatcherAddr))
	client := pb.NewDebugletDispatcherClient(conn)
	schedule, err := tesla.NewKeySchedule(tesla.Config{
		Seed:  []byte(cfg.TeslaSeed),
		Delay: time.Duration(cfg.TeslaDelay) * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return &Executor{
		id:            cfg.ExecutorID,
		client:        client,
		conn:          conn,
		logger:        logger,
		version:       cfg.Version,
		debuglets:     make(map[string]*engine.Debuglet),
		manager:       resource.New(cfg.Capacity),
		teslaSchedule: schedule,
	}, nil
}

func (e *Executor) Start(ctx context.Context) error {
	controlStream, err := e.client.ControlStream(ctx)
	if err != nil {
		return err
	}
	e.logger.Info("Executor started", zap.String("executor_id", e.id))

	// Send hello
	controlStream.Send(&pb.ControlMessage{
		Msg: &pb.ControlMessage_Hello{Hello: &pb.ExecutorHello{
			ExecutorId:              e.id,
			Version:                 e.version,
			SourceIp:                "127.0.0.1", // TODO: detect public IP
			TeslaDelaySec:           int64(e.teslaSchedule.Config().Delay.Seconds()),
			TeslaAnchorTimestampNs: e.teslaSchedule.Config().Epoch.UnixNano(),
		}},
	})
	// Initialize executor to have a bandwidth capacity of 1gbit/s
	controlStream.Send(&pb.ControlMessage{
		Msg: &pb.ControlMessage_Resources{Resources: &pb.ExecutorResources{
			BandwidthCapacity: 1_000_000_000,
		}},
	})

	sendHeartbeat := func() {
		now := time.Now()
		epoch, key, _ := e.teslaSchedule.DisclosedKey(now)
		controlStream.Send(&pb.ControlMessage{
			Msg: &pb.ControlMessage_Heartbeat{Heartbeat: &pb.ExecutorHeartbeat{
				Timestamp:     now.UnixNano(),
				TeslaKeyEpoch: epoch,
				TeslaKey:      key,
			}},
		})
	}

	// Send initial heartbeat
	sendHeartbeat()

	// Heartbeat loop
	go func() {
		interval := 30 * time.Second
		if disclosureInterval := e.teslaSchedule.Config().Delay / 2; disclosureInterval < interval {
			interval = disclosureInterval
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sendHeartbeat()
			}
		}
	}()

	// Listen for assignments
	for {
		msg, err := controlStream.Recv()
		if err == io.EOF {
			e.logger.Info("Control stream closed", zap.Error(err))
			return nil
		}
		if err != nil {
			e.logger.Error("Error receiving", zap.Error(err))
			return err
		}

		if assign := msg.GetAssignment(); assign != nil {
			e.logger.Info("Received assignment", zap.String("session_id", assign.SessionId))
			// TODO: check error
			go e.handleAssignment(ctx, assign)
		} else if update := msg.GetUpdates(); update != nil {
			e.logger.Debug("Received destination update", zap.Int("len", len(update.Updates)))
			for _, up := range update.GetUpdates() {
				e.logger.Debug("Updating destination limit", zap.String("destination", up.GetDestination()), zap.String("assignment_id", up.GetAssignmentId()), zap.Int64("new_ceil", up.GetNewCeilBw()))
				e.manager.SetDestinationLimit(up.GetAssignmentId(), up.GetDestination(), up.GetNewCeilBw())
			}
		}
	}
}

func (e *Executor) handleAssignment(ctx context.Context, assign *pb.DebugletAssignment) {
	session, err := e.client.SessionStream(ctx)

	if err != nil {
		e.logger.Error("Failed to open session", zap.Error(err))
		return
	}

	e.logger.Debug("Locking")
	e.mu.Lock()
	db := engine.NewDebuglet(e.logger, e.manager, assign.SessionId, e.teslaSchedule, []byte(assign.MeasurementId))
	err = db.Init(assign.Code, assign.Addresses)
	if err != nil {
		e.mu.Unlock()
		e.logger.Error("Failed to init debuglet", zap.String("session_id", assign.SessionId), zap.Error(err))
		return
	}
	e.debuglets[assign.SessionId] = db
	e.mu.Unlock()
	e.logger.Info("Debuglet created", zap.String("session_id", assign.SessionId))

	session.Send(&pb.SessionMessage{
		Msg: &pb.SessionMessage_Ready{
			Ready: &pb.DebugletReady{
				SessionId:     assign.SessionId,
				ExecutorId:    e.id,
				MeasurementId: assign.MeasurementId,
				ScionAddr:     db.GetSCIONAddr(),
			},
		},
	})

	// Listen for dispatcher commands
	go func() {
		for {
			in, err := session.Recv()
			if err == io.EOF {
				e.logger.Error("Session stream closed", zap.Error(err))
				return
			}
			if err != nil {
				e.logger.Error("Session recv error", zap.Error(err))
				return
			}
			if cmd := in.GetDispatcherCmd(); cmd == nil || cmd.Type != pb.DispatcherCommandType_START_EXECUTION {
				continue
			}
			e.mu.Lock()
			err = e.manager.RegisterAssignment(assign.SessionId, assign.Policy.FloorBw, assign.Policy.CeilBw)
			e.mu.Unlock()
			if err != nil {
				e.logger.Error("Failed to register assignment", zap.Error(err))
				return
			}

			e.runDebuglet(assign, session)

			e.mu.Lock()
			e.manager.RemoveAssignment(assign.SessionId)
			e.mu.Unlock()
		}
	}()
}

func (e *Executor) flushDebugletOutput(assign *pb.DebugletAssignment, db *engine.Debuglet, session pb.DebugletDispatcher_SessionStreamClient, sessionId string) {
	defer e.stdoutWg.Done()
	for stdout := range db.StdoutChan() {
		session.Send(&pb.SessionMessage{
			Msg: &pb.SessionMessage_Stdout{
				Stdout: &pb.DebugletStdout{
					SessionId: assign.SessionId,
					Stdout:    stdout,
				},
			},
		})
	}
}

func (e *Executor) runDebuglet(assign *pb.DebugletAssignment, session pb.DebugletDispatcher_SessionStreamClient) {
	e.mu.Lock()
	db, exists := e.debuglets[assign.SessionId]
	e.mu.Unlock()
	if !exists {
		e.logger.Error("Debuglet not found", zap.String("session_id", assign.SessionId))
		session.Send(&pb.SessionMessage{
			Msg: &pb.SessionMessage_Exit{
				Exit: &pb.DebugletExit{SessionId: assign.SessionId, ExitCode: -1},
			},
		})
		return
	}

	e.stdoutWg.Add(1)
	go e.flushDebugletOutput(assign, db, session, assign.SessionId)

	result, err := db.Run()
	e.stdoutWg.Wait()
	if err != nil {
		session.Send(&pb.SessionMessage{
			Msg: &pb.SessionMessage_Exit{
				Exit: &pb.DebugletExit{SessionId: assign.SessionId, ExitCode: 1},
			},
		})
		return
	}
	session.Send(&pb.SessionMessage{
		Msg: &pb.SessionMessage_Exit{
			Exit: &pb.DebugletExit{SessionId: assign.SessionId, ExitCode: 0, Result: result},
		},
	})
	e.mu.Lock()
	delete(e.debuglets, assign.SessionId)
	e.mu.Unlock()
	db.Close()
}
