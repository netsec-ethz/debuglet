// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build wasip1

package debuglet

//go:wasmimport debuglet_experiment_v1 ready
func experimentReadyHost(metadataPtr, metadataLen, resultPtr, resultLen uint32, deadlineNS int64) int32

func experimentReady(metadata, result []byte, deadlineNS int64) int32 {
 var ptr uint32
 if len(metadata) > 0 { ptr = bytePtr(metadata) }
 return experimentReadyHost(ptr, uint32(len(metadata)), bytePtr(result), uint32(len(result)), deadlineNS)
}
