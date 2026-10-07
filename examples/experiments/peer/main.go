// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// peer exchanges one UDP datagram with every other experiment participant.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

type endpoint struct { Address string `json:"endpoint"` }
type packet struct {
	ExperimentID string `json:"experiment_id"`
	RunID string `json:"run_id"`
	SentAtNS int64 `json:"sent_at_ns"`
}

func main() {
	if err := run(); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
}

func run() error {
	address, err := debuglet.ListenUDPAddr()
	if err != nil { return err }
	metadata, err := json.Marshal(endpoint{Address: address})
	if err != nil { return err }
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	readyAt := time.Now().UnixNano()
	experiment, err := debuglet.Ready(ctx, metadata)
	if err != nil { return err }
	if len(experiment.Participants) != 5 { return errors.New("peer example requires five participants") }
	seen := map[string]bool{}
	peers := map[string]string{}
	self := ""
	for _, member := range experiment.Participants {
		if seen[member.ExecutorID] { return errors.New("peer example requires five distinct executors") }
		seen[member.ExecutorID] = true
		var listener endpoint
		if err := json.Unmarshal(member.Metadata, &listener); err != nil { return err }
		if listener.Address == "" { return errors.New("participant has no endpoint") }
		if listener.Address == address { self = member.ID } else { peers[member.ID] = listener.Address }
	}
	if self == "" || len(peers) != 4 { return errors.New("listener endpoints must be distinct") }
	if err := debuglet.WaitStart(ctx, experiment); err != nil { return err }
	startedAt := time.Now().UnixNano()
	packets := []map[string]any{}
	for id, destination := range peers {
		conn, err := debuglet.ConnectUDP(destination)
		if err != nil { return err }
		sentAt := time.Now().UnixNano()
		data, err := json.Marshal(packet{ExperimentID:experiment.ID, RunID:self, SentAtNS:sentAt})
		if err != nil { conn.Close(); return err }
		err = conn.Write(data)
		conn.Close()
		if err != nil { return err }
		packets = append(packets, map[string]any{"direction":"sent", "peer_run_id":id, "endpoint":destination, "sent_at_ns":sentAt})
	}
	buffer := make([]byte, 1024)
	received := map[string]bool{}
	for len(received) < len(peers) {
		n, from, err := debuglet.ReadFromUDP(buffer)
		if err != nil { return err }
		receivedAt := time.Now().UnixNano()
		var message packet
		if err := json.Unmarshal(buffer[:n], &message); err != nil { return err }
		if message.ExperimentID != experiment.ID || peers[message.RunID] == "" || received[message.RunID] { return errors.New("unexpected peer datagram") }
		received[message.RunID] = true
		packets = append(packets, map[string]any{"direction":"received", "peer_run_id":message.RunID, "endpoint":from, "sent_at_ns":message.SentAtNS, "received_at_ns":receivedAt})
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"experiment_id":experiment.ID, "run_id":self, "endpoint":address, "ready_at_ns":readyAt, "start_time_ns":experiment.StartTimeNS, "actual_start_ns":startedAt, "lateness_ns":startedAt-experiment.StartTimeNS, "sent":len(peers), "received":len(received), "finished_at_ns":time.Now().UnixNano(), "packets":packets})
}
