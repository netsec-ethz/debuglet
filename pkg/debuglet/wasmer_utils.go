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

package debuglet

import (
	"encoding/binary"
	"fmt"

	"github.com/wasmerio/wasmer-go/wasmer"
)

const (
	MAX_SLICE_LENGTH = 8192
)

// Extracts first len bytes from the result buffer and returns them.
// Takes as input a wasm instance object and the number of bytes to read.
func getResult(instance *wasmer.Instance, len int32) ([]byte, error) {
	if len > MAX_SLICE_LENGTH {
		len = MAX_SLICE_LENGTH
	}
	contents, err := extractSlice(instance, "result", 0, len)
	if err != nil {
		return nil, fmt.Errorf("failed to extract result buffer: %w", err)
	}

	return contents, nil
}

// Extracts the contents of the buffer with the given name from the wasm runtime,
// starting at `start` and ending at `end` (excluded), and return them
func extractSlice(instanceTarget *wasmer.Instance, name string, start, end int32) ([]byte, error) {
	numbersAddressBox, err := instanceTarget.Exports.GetGlobal(name)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve exported global (memory buffer is not correctly exported): %w", err)
	}

	numbersAddress, err := numbersAddressBox.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve global's value (memory buffer is not correctly exported): %w", err)
	}

	memory, err := instanceTarget.Exports.GetMemory("memory")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve exported memory (global memory is not correctly exported): %w", err)
	}

	newAddress := int32(binary.LittleEndian.Uint32(memory.Data()[numbersAddress.(int32) : numbersAddress.(int32)+4]))

	toWrite := memory.Data()[newAddress+start : newAddress+end]
	return toWrite, nil
}

// Extracts the result length from "result_idx".
// This is intended to be used if the debuglet hasn't returned a result length (because of a failure),
// but we'd still like to recover results of work performed so far.
func extractResIdx(instanceTarget *wasmer.Instance) ([]byte, error) {
	numbersAddressBox, err := instanceTarget.Exports.GetGlobal("result_idx")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve exported global (memory buffer is not correctly exported): %w", err)
	}

	numbersAddress, err := numbersAddressBox.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve global's value (memory buffer is not correctly exported): %w", err)
	}

	memory, err := instanceTarget.Exports.GetMemory("memory")
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve exported memory (global memory is not correctly exported): %w", err)
	}

	newAddress := int32(binary.LittleEndian.Uint32(memory.Data()[numbersAddress.(int32) : numbersAddress.(int32)+4]))

	toWrite := memory.Data()[newAddress : newAddress+4]
	return toWrite, nil
}
