// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"fmt"
	"unsafe"

	"github.com/tetratelabs/wazero/api"
)

const (
	MAX_SLICE_LENGTH = 8192
)

type PrimitiveType interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 |
		~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 |
		~float32 | ~float64
}

func ExtractStr(mod api.Module, source, num uint32) (string, error) {
	num = min(num, MAX_SLICE_LENGTH)
	mem := mod.Memory()
	buf, valid := mem.Read(source, num)
	if !valid {
		return "", fmt.Errorf("out of memory bounds: pointer %d, length %d", source, num)
	}
	return string(buf), nil
}

func ExtractMem[T PrimitiveType](mod api.Module, source, num uint32) ([]T, error) {
	num = min(num, MAX_SLICE_LENGTH)
	mem := mod.Memory()
	var dummy T

	// 'num' is the amount of elements (size depending on int type)
	elementSize := uint32(unsafe.Sizeof(dummy))
	byteCount := num * elementSize
	buf, valid := mem.Read(source, byteCount)
	if !valid {
		return nil, fmt.Errorf("out of memory bounds: pointer %d, bytes needed %d", source, byteCount)
	}
	if len(buf) == 0 {
		return []T{}, nil
	}
	typed := unsafe.Slice((*T)(unsafe.Pointer(&buf[0])), num)
	return typed, nil

}
