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

package wasm

import (
	"encoding/binary"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

const (
	MAX_SLICE_LENGTH = 8192
)

// GetResult extracts the first len bytes from the result buffer and returns them.
func GetResult(mod api.Module, len int32) ([]byte, error) {
	if len > MAX_SLICE_LENGTH {
		len = MAX_SLICE_LENGTH
	}
	contents, err := ExtractSlice(mod, "result", 0, len)
	if err != nil {
		return nil, fmt.Errorf("failed to extract result buffer: %w", err)
	}

	return contents, nil
}

// ExtractSlice extracts the contents of the buffer with the given name from WASM memory,
// starting at `start` and ending at `end` (excluded).
func ExtractSlice(mod api.Module, name string, start, end int32) ([]byte, error) {
	global := mod.ExportedGlobal(name)
	if global == nil {
		return nil, fmt.Errorf("failed to retrieve exported global (memory buffer is not correctly exported)")
	}

	numbersAddress := int32(global.Get())

	mem := mod.Memory()
	if mem == nil {
		return nil, fmt.Errorf("failed to retrieve exported memory (global memory is not correctly exported)")
	}

	ptrBuf, ok := mem.Read(uint32(numbersAddress), 4)
	if !ok {
		return nil, fmt.Errorf("failed to read pointer from memory at %d", numbersAddress)
	}

	newAddress := int32(binary.LittleEndian.Uint32(ptrBuf))
	dataLen := end - start
	toWrite, ok := mem.Read(uint32(newAddress+start), uint32(dataLen))
	if !ok {
		return nil, fmt.Errorf("failed to read data from memory at %d", newAddress+start)
	}
	return toWrite, nil
}

// ExtractResIdx extracts the result length from "result_idx".
// This is intended to be used if the debuglet hasn't returned a result length (because of a failure),
// but we'd still like to recover results of work performed so far.
func ExtractResIdx(mod api.Module) ([]byte, error) {
	global := mod.ExportedGlobal("result_idx")
	if global == nil {
		return nil, fmt.Errorf("failed to retrieve exported global (memory buffer is not correctly exported)")
	}

	numbersAddress := int32(global.Get())

	mem := mod.Memory()
	if mem == nil {
		return nil, fmt.Errorf("failed to retrieve exported memory (global memory is not correctly exported)")
	}

	ptrBuf, ok := mem.Read(uint32(numbersAddress), 4)
	if !ok {
		return nil, fmt.Errorf("failed to read pointer from memory at %d", numbersAddress)
	}

	newAddress := int32(binary.LittleEndian.Uint32(ptrBuf))

	toWrite, ok := mem.Read(uint32(newAddress), 4)
	if !ok {
		return nil, fmt.Errorf("failed to read result_idx data from memory at %d", newAddress)
	}
	return toWrite, nil
}
