// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"context"
	"encoding/binary"
	"errors"
	"io"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/wasm"
	"github.com/tetratelabs/wazero/api"
)

const (
	workerArgument    = "--debuglet-private-worker-v1"
	bridgeFrame       = 16 << 10
	workerModuleBytes = 24 << 20
	workerArgsBytes   = 1 << 20
)
const (
	frameInit byte = iota + 1
	frameData
	frameCompiled
	frameRun
	frameOutput
	frameCall
	frameRead
	frameWrite
	frameMemory
	frameReturn
	frameTrap
	frameResult
)

// bridge has one synchronous owner. A guest waits while its parent executes a
// host call; the parent requests only the memory ranges the host function uses.
// Neither peer buffers an unbounded queue or trusts a received frame length.
type bridge struct{ io.ReadWriter }

func (b bridge) send(kind byte, data []byte) error {
	if len(data) > bridgeFrame {
		return errors.New("worker bridge frame exceeds bound")
	}
	var header [5]byte
	header[0] = kind
	binary.LittleEndian.PutUint32(header[1:], uint32(len(data)))
	if err := writeAll(b.ReadWriter, header[:]); err != nil {
		return err
	}
	return writeAll(b.ReadWriter, data)
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
func (b bridge) read() (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(b.ReadWriter, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.LittleEndian.Uint32(header[1:])
	if size > bridgeFrame {
		return 0, nil, errors.New("worker bridge frame exceeds bound")
	}
	data := make([]byte, int(size))
	_, err := io.ReadFull(b.ReadWriter, data)
	return header[0], data, err
}
func (b bridge) blob(data []byte) error {
	for len(data) > 0 {
		n := min(len(data), bridgeFrame)
		if err := b.send(frameData, data[:n]); err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
func (b bridge) receiveBlob(size uint32, limit uint32) ([]byte, error) {
	if size > limit {
		return nil, errors.New("worker payload exceeds bound")
	}
	data := make([]byte, int(size))
	offset := 0
	for offset < len(data) {
		kind, part, err := b.read()
		if err != nil {
			return nil, err
		}
		if kind != frameData || len(part) == 0 || len(part) > len(data)-offset {
			return nil, errors.New("invalid worker payload")
		}
		copy(data[offset:], part)
		offset += len(part)
	}
	return data, nil
}
func u32(data []byte) uint32                    { return binary.LittleEndian.Uint32(data) }
func append32(data []byte, value uint32) []byte { return binary.LittleEndian.AppendUint32(data, value) }

// remoteMemory returns copies, never an alias to the child. The actual guest
// access runs inside the child while its guest thread is paused at a host call.
type remoteMemory struct{ bridge }

func (m remoteMemory) Read(ptr, size uint32) ([]byte, bool) {
	if size > wasm.MAX_SLICE_LENGTH {
		return nil, false
	}
	request := append32(append32(nil, ptr), size)
	if m.send(frameRead, request) != nil {
		return nil, false
	}
	kind, data, err := m.read()
	if err != nil || kind != frameMemory || len(data) != int(size)+1 || data[0] != 1 {
		return nil, false
	}
	return data[1:], true
}
func (m remoteMemory) Write(ptr uint32, data []byte) bool {
	if len(data) > wasm.MAX_SLICE_LENGTH {
		return false
	}
	request := append32(nil, ptr)
	request = append(request, data...)
	if m.send(frameWrite, request) != nil {
		return false
	}
	kind, result, err := m.read()
	return err == nil && kind == frameMemory && len(result) == 1 && result[0] == 1
}
func (m remoteMemory) WriteUint32Le(ptr, value uint32) bool {
	return m.Write(ptr, append32(nil, value))
}

func (b bridge) proxy(_ context.Context, mod api.Module, id int, stack []uint64) {
	request := append32(nil, uint32(id))
	for _, v := range stack {
		request = binary.LittleEndian.AppendUint64(request, v)
	}
	if err := b.send(frameCall, request); err != nil {
		panic("worker bridge closed")
	}
	for {
		kind, data, err := b.read()
		if err != nil {
			panic("worker bridge closed")
		}
		switch kind {
		case frameRead:
			if len(data) != 8 || u32(data[4:]) > wasm.MAX_SLICE_LENGTH {
				panic("invalid memory request")
			}
			bytes, ok := mod.Memory().Read(u32(data), u32(data[4:]))
			result := []byte{0}
			if ok {
				result[0] = 1
				result = append(result, bytes...)
			}
			if err := b.send(frameMemory, result); err != nil {
				panic("worker bridge closed")
			}
		case frameWrite:
			if len(data) < 4 || len(data)-4 > wasm.MAX_SLICE_LENGTH {
				panic("invalid memory request")
			}
			result := byte(0)
			if mod.Memory().Write(u32(data), data[4:]) {
				result = 1
			}
			if err := b.send(frameMemory, []byte{result}); err != nil {
				panic("worker bridge closed")
			}
		case frameReturn:
			if len(data) != len(stack)*8 {
				panic("invalid host result")
			}
			for i := range stack {
				stack[i] = binary.LittleEndian.Uint64(data[i*8:])
			}
			return
		case frameTrap:
			panic("host call refused")
		default:
			panic("invalid worker bridge message")
		}
	}
}

func invokeHost(ctx context.Context, f wasm.Function, mem wasm.Memory, stack []uint64) (err error) {
	defer func() {
		if p := recover(); p != nil {
			if e, ok := p.(error); ok {
				err = e
			} else {
				err = errors.New("host call refused")
			}
		}
	}()
	f.Call(ctx, mem, stack)
	return nil
}
