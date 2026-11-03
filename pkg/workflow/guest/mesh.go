// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/netsec-ethz/debuglet/pkg/debuglet"
	"sort"
	"time"
)

func (e *Experiment) ParticipantID() string { return e.participant }
func (e *Experiment) ParticipantIDs() []string {
	ids := make([]string, 0, len(e.peers))
	for id := range e.peers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (e *Experiment) StartTime() time.Time { return e.startTime }
func (e *Experiment) Peers(map[string]any) (map[string]any, error) {
	ids := e.ParticipantIDs()
	rows := []map[string]any{}
	index := 0
	for i, id := range ids {
		if id == e.participant {
			index = i
			continue
		}
		p := e.peers[id]
		rows = append(rows, map[string]any{"participant": id, "tcp_address": p.address, "udp_address": p.udpAddress})
	}
	return Normalize(map[string]any{"self": e.participant, "participants": ids, "peers": rows, "index": index})
}
func (e *Experiment) meshConfig(kind string, in map[string]any) (debuglet.MeshConfig, error) {
	duration, err := networkInteger(in, "duration_ms", 86400000, 1000, 86400000)
	if err != nil {
		return debuglet.MeshConfig{}, err
	}
	if e.id == "" || e.startTime.IsZero() || len(e.peers) < 2 || len(e.peers) > 16 {
		return debuglet.MeshConfig{}, fmt.Errorf("mesh service requires 2–16 admitted participants")
	}
	c := debuglet.MeshConfig{Kind: kind, Self: e.participant, Group: e.id, Fingerprint: e.fingerprint, StartMS: e.startTime.UnixMilli(), DurationMS: int64(duration)}
	for _, id := range e.ParticipantIDs() {
		p := e.peers[id]
		c.Peers = append(c.Peers, debuglet.MeshPeer{Participant: id, RunID: p.runID, ExecutorID: p.executorID, TCPAddress: p.address, UDPAddress: p.udpAddress})
	}
	return c, nil
}
func (e *Experiment) UDPProbeStart(in map[string]any) (map[string]any, error) {
	c, err := e.meshConfig("udp", in)
	if err != nil {
		return nil, err
	}
	interval, err := networkInteger(in, "interval_ms", 1000, 1000, 60000)
	if err != nil {
		return nil, err
	}
	window, err := networkInteger(in, "window_ms", 300000, interval, 300000)
	if err != nil || window%interval != 0 {
		return nil, fmt.Errorf("window_ms must be an interval multiple up to 300000")
	}
	c.IntervalMS, c.WindowMS = int64(interval), int64(window)
	return e.startService(c)
}
func (e *Experiment) TCPResponderStart(in map[string]any) (map[string]any, error) {
	c, err := e.meshConfig("tcp", in)
	if err != nil {
		return nil, err
	}
	bytes, err := networkInteger(in, "max_bytes", 32<<20, 1, 32<<20)
	if err != nil {
		return nil, err
	}
	ms, err := networkInteger(in, "max_transfer_ms", 10000, 1, 10000)
	if err != nil {
		return nil, err
	}
	c.MaxBytes, c.MaxTransferMS = int64(bytes), int64(ms)
	return e.startService(c)
}
func (e *Experiment) startService(c debuglet.MeshConfig) (map[string]any, error) {
	name := "mesh:" + c.Kind
	if e.meshServices[name] != nil {
		return nil, fmt.Errorf("%s service already started", c.Kind)
	}
	service, err := debuglet.StartMesh(c)
	if err != nil {
		return nil, err
	}
	if e.meshServices == nil {
		e.meshServices = map[string]*debuglet.MeshService{}
	}
	e.meshServices[name] = service
	return map[string]any{"service": name}, nil
}
func (e *Experiment) meshService(in map[string]any, kind string) (*debuglet.MeshService, error) {
	name, err := networkString(in, "service", "")
	if err != nil {
		return nil, err
	}
	if name != "mesh:"+kind || e.meshServices[name] == nil {
		return nil, fmt.Errorf("service is not an active %s measurement", kind)
	}
	return e.meshServices[name], nil
}
func (e *Experiment) UDPProbeSnapshot(in map[string]any) (map[string]any, error) {
	service, err := e.meshService(in, "udp")
	if err != nil {
		return nil, err
	}
	result, err := service.Snapshot()
	if err != nil {
		return nil, err
	}
	return meshValue(result)
}
func (e *Experiment) stopService(in map[string]any, kind string) (map[string]any, error) {
	service, err := e.meshService(in, kind)
	if err != nil {
		return nil, err
	}
	if err := service.Close(); err != nil {
		return nil, err
	}
	delete(e.meshServices, "mesh:"+kind)
	return map[string]any{"ok": true}, nil
}
func (e *Experiment) UDPProbeStop(in map[string]any) (map[string]any, error) {
	return e.stopService(in, "udp")
}
func (e *Experiment) TCPResponderStop(in map[string]any) (map[string]any, error) {
	return e.stopService(in, "tcp")
}
func (e *Experiment) TCPTransfer(in map[string]any, deadline time.Time) (map[string]any, error) {
	peer, err := networkString(in, "peer", "")
	if err != nil {
		return nil, err
	}
	if _, ok := e.peers[peer]; !ok || peer == e.participant {
		return nil, fmt.Errorf("peer must be another admitted participant")
	}
	bytes, err := networkInteger(in, "bytes", 32<<20, 1, 32<<20)
	if err != nil {
		return nil, err
	}
	ms, err := networkInteger(in, "timeout_ms", 10000, 1, 10000)
	if err != nil {
		return nil, err
	}
	result := debuglet.MeshTransfer{Peer: peer}
	service := e.meshServices["mesh:tcp"]
	if service == nil {
		return nil, fmt.Errorf("start the TCP receiver before a transfer")
	}
	timeout := time.Duration(ms) * time.Millisecond
	// Reserve the protocol's bounded tail/receipt grace inside the scheduled slot.
	if !deadline.IsZero() {
		timeout = min(timeout, time.Until(deadline)-2*time.Second)
	}
	if timeout < time.Millisecond {
		result.Error = "transfer slot has expired"
		return meshValue(result)
	}
	result, err = service.Transfer(peer, int64(bytes), timeout)
	if err != nil {
		result = debuglet.MeshTransfer{Peer: peer, Error: err.Error()}
	}
	return meshValue(result)
}
func meshValue(value any) (map[string]any, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(data, &out)
	return out, err
}

// Close joins all host measurement services before the program exits.
func (e *Experiment) Close() error {
	var errs []error
	for name, service := range e.meshServices {
		errs = append(errs, service.Close())
		delete(e.meshServices, name)
	}
	return errors.Join(errs...)
}
