// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

// Host services never access guest memory after a host call returns.
func hostMesh(env *WasmEnv, operation string) func(context.Context, Memory, uint32, uint32, uint32, uint32) uint64 {
	return func(ctx context.Context, mem Memory, ptr, size, out, capacity uint32) uint64 {
		if size > 16384 || capacity < 32768 {
			return ioResult(0, fmt.Errorf("mesh buffer bounds"))
		}
		if uint64(out)+32768 > 1<<32 {
			panic("invalid mesh output buffer")
		}
		if _, ok := mem.Read(out, 1); !ok {
			panic("invalid mesh output buffer")
		}
		if _, ok := mem.Read(out+32767, 1); !ok {
			panic("invalid mesh output buffer")
		}
		if uint64(ptr)+uint64(size) > 1<<32 {
			panic("invalid mesh input buffer")
		}
		raw := make([]byte, 0, size)
		for offset := uint32(0); offset < size; {
			n := min(size-offset, uint32(MAX_SLICE_LENGTH))
			part, ok := mem.Read(ptr+offset, n)
			if !ok {
				panic("invalid mesh input buffer")
			}
			raw = append(raw, part...)
			offset += n
		}
		var err error
		var req guestio.MeshRequest
		if err := meshDecode(raw, &req); err != nil {
			return ioResult(0, err)
		}
		var value any
		switch operation {
		case "start":
			value, err = env.startMesh(ctx, req.Config)
		case "snapshot":
			env.meshMu.Lock()
			service := env.meshUDP
			env.meshMu.Unlock()
			if req.Service != 1 || service == nil {
				err = net.ErrClosed
			} else {
				value = service.Snapshot()
			}
		case "stop":
			err = env.stopMesh(req.Service)
			value = map[string]bool{"ok": err == nil}
		case "transfer":
			env.meshMu.Lock()
			service := env.meshTCP
			env.meshMu.Unlock()
			if req.Service != 2 || service == nil {
				err = net.ErrClosed
			} else {
				value, err = service.Transfer(ctx, req.Peer, req.Bytes, time.Duration(req.TimeoutMS)*time.Millisecond)
			}
		default:
			err = fmt.Errorf("unknown mesh operation")
		}
		if err != nil {
			return ioResult(0, err)
		}
		data, err := json.Marshal(value)
		if err != nil {
			return ioResult(0, err)
		}
		if len(data) > 32768 {
			return ioResult(0, fmt.Errorf("mesh response exceeds bound"))
		}
		for offset := 0; offset < len(data); {
			end := min(offset+MAX_SLICE_LENGTH, len(data))
			if !mem.Write(out+uint32(offset), data[offset:end]) {
				panic("invalid mesh output buffer")
			}
			offset = end
		}
		return ioResult(len(data), nil)
	}
}

func (e *WasmEnv) validateMesh(c *guestio.MeshConfig) error {
	if c == nil || (c.Kind != "udp" && c.Kind != "tcp") || c.DurationMS < 1000 || c.DurationMS > 86400000 || len(c.Peers) < 2 || len(c.Peers) > 16 {
		return fmt.Errorf("invalid mesh service bounds")
	}
	e.mu.Lock()
	admitted := e.meshGroup
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if admitted == nil || c.Group != admitted.ID || len(c.Peers) != len(admitted.Participants) || c.StartMS != admitted.StartTimeNS/int64(time.Millisecond) {
		return netpolicy.ErrDenied
	}
	if time.UnixMilli(c.StartMS).Add(time.Duration(c.DurationMS) * time.Millisecond).Before(time.Now()) {
		return fmt.Errorf("mesh deadline passed")
	}
	seen := map[string]bool{}
	self := false
	for _, p := range c.Peers {
		if p.Participant == "" || len(p.Participant) > 128 || seen[p.Participant] {
			return netpolicy.ErrDenied
		}
		seen[p.Participant] = true
		found := false
		for _, member := range admitted.Participants {
			if member.ID != p.RunID || member.ExecutorID != p.ExecutorID {
				continue
			}
			var metadata struct {
				Participant string `json:"participant"`
				Fingerprint string `json:"fingerprint"`
				Address     string `json:"address"`
				UDPAddress  string `json:"udp_address,omitempty"`
			}
			if json.Unmarshal(member.Metadata, &metadata) != nil || metadata.Participant != p.Participant || metadata.Fingerprint != c.Fingerprint || metadata.Address != p.TCPAddress || metadata.UDPAddress != p.UDPAddress {
				return netpolicy.ErrDenied
			}
			found = true
			if p.Participant == c.Self {
				if p.RunID != e.DebugletID.String() || p.TCPAddress != e.TcpServerAddr || (c.Kind == "udp" && p.UDPAddress != e.UdpServerAddr) {
					return netpolicy.ErrDenied
				}
				self = true
			}
			break
		}
		if !found {
			return netpolicy.ErrDenied
		}
		if c.Kind == "udp" && p.UDPAddress == "" {
			return fmt.Errorf("every mesh participant needs an admitted UDP listener")
		}
	}
	if !self {
		return netpolicy.ErrDenied
	}
	return nil
}

func (e *WasmEnv) startMesh(ctx context.Context, c *guestio.MeshConfig) (map[string]uint32, error) {
	e.meshMu.Lock()
	defer e.meshMu.Unlock()
	if err := e.validateMesh(c); err != nil {
		return nil, err
	}
	e.mu.Lock()
	if c.Kind == "udp" {
		if e.meshUDPUsed {
			e.mu.Unlock()
			return nil, fmt.Errorf("UDP service may start once per run")
		}
		e.meshUDPUsed, e.meshUDPClaim = true, true
	} else {
		if e.meshTCPUsed {
			e.mu.Unlock()
			return nil, fmt.Errorf("TCP service may start once per run")
		}
		e.meshTCPUsed, e.meshTCPClaim = true, true
	}
	e.mu.Unlock()
	var err error
	id := uint32(1)
	if c.Kind == "udp" {
		e.meshUDP, err = startMeshUDP(ctx, e, *c)
	} else {
		id = 2
		e.meshTCP, err = startMeshTCP(ctx, e, *c)
	}
	if err != nil {
		e.mu.Lock()
		if c.Kind == "udp" {
			e.meshUDPClaim = false
		} else {
			e.meshTCPClaim = false
		}
		e.mu.Unlock()
		return nil, err
	}
	return map[string]uint32{"service": id}, nil
}

func (e *WasmEnv) stopMesh(id uint32) error {
	e.meshMu.Lock()
	defer e.meshMu.Unlock()
	var err error
	switch id {
	case 1:
		if e.meshUDP != nil {
			err = e.meshUDP.Close()
			e.meshUDP = nil
		}
	case 2:
		if e.meshTCP != nil {
			err = e.meshTCP.Close()
			e.meshTCP = nil
		}
	default:
		return fmt.Errorf("invalid mesh service")
	}
	e.mu.Lock()
	if id == 1 {
		e.meshUDPClaim = false
	} else {
		e.meshTCPClaim = false
	}
	e.mu.Unlock()
	return err
}
func (e *WasmEnv) closeMesh() error { return errors.Join(e.stopMesh(1), e.stopMesh(2)) }
func (e *WasmEnv) meshOwnsListener(tcp bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if tcp {
		return e.meshTCPClaim
	}
	return e.meshUDPClaim
}

func meshDecode(raw []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return fmt.Errorf("unexpected trailing mesh request")
	}
	return nil
}
