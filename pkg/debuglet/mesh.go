// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"encoding/json"
	"fmt"
	"github.com/netsec-ethz/debuglet/internal/guestio"
	"time"
)

// Mesh services are bounded host-owned measurements over an admitted experiment.
// They continue while the sequential guest reports results or performs other I/O.
// A service exclusively owns its run's UDP or TCP listener until closed. It does
// not encrypt probes or authenticate peer traffic against on-path attackers.
type MeshConfig = guestio.MeshConfig
type MeshPeer = guestio.MeshPeer
type MeshSnapshot = guestio.MeshSnapshot
type MeshTransfer = guestio.MeshTransfer
type MeshService struct{ id uint32 }

func StartMesh(config MeshConfig) (*MeshService, error) {
	var out struct {
		Service uint32 `json:"service"`
	}
	if err := meshCall(invokeMeshStart, guestio.MeshRequest{Config: &config}, &out); err != nil {
		return nil, err
	}
	if out.Service < 1 || out.Service > 2 {
		return nil, fmt.Errorf("invalid mesh service handle")
	}
	return &MeshService{id: out.Service}, nil
}
func (s *MeshService) Snapshot() (MeshSnapshot, error) {
	var out MeshSnapshot
	err := meshCall(invokeMeshSnapshot, guestio.MeshRequest{Service: s.id}, &out)
	return out, err
}
func (s *MeshService) Transfer(peer string, bytes int64, timeout time.Duration) (MeshTransfer, error) {
	var out MeshTransfer
	err := meshCall(invokeMeshTransfer, guestio.MeshRequest{Service: s.id, Peer: peer, Bytes: bytes, TimeoutMS: timeout.Milliseconds()}, &out)
	return out, err
}
func (s *MeshService) Close() error {
	var out struct {
		OK bool `json:"ok"`
	}
	return meshCall(invokeMeshStop, guestio.MeshRequest{Service: s.id}, &out)
}
func meshCall(invoke func([]byte) ([]byte, error), request guestio.MeshRequest, out any) error {
	data, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if len(data) > 16384 {
		return fmt.Errorf("mesh request exceeds bound")
	}
	response, err := invoke(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(response, out)
}
