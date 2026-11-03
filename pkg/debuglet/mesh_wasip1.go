// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

import "fmt"

//go:wasmimport debuglet_io_v1 mesh_start
func meshStart(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 mesh_snapshot
func meshSnapshot(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 mesh_stop
func meshStop(ptr, size, out, capacity uint32) uint64

//go:wasmimport debuglet_io_v1 mesh_transfer
func meshTransfer(ptr, size, out, capacity uint32) uint64

func invokeMeshStart(data []byte) ([]byte, error)    { return meshResponse(data, meshStart) }
func invokeMeshSnapshot(data []byte) ([]byte, error) { return meshResponse(data, meshSnapshot) }
func invokeMeshStop(data []byte) ([]byte, error)     { return meshResponse(data, meshStop) }
func invokeMeshTransfer(data []byte) ([]byte, error) { return meshResponse(data, meshTransfer) }
func meshResponse(data []byte, invoke func(uint32, uint32, uint32, uint32) uint64) ([]byte, error) {
	out := make([]byte, 32768)
	n, err := ioOutcome(invoke(bytePtr(data), uint32(len(data)), bytePtr(out), uint32(len(out))))
	if err != nil {
		return nil, err
	}
	if n < 0 || n > len(out) {
		return nil, fmt.Errorf("invalid mesh response length")
	}
	return out[:n], nil
}
