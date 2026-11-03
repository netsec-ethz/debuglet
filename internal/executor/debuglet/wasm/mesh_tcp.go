// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

const (
	meshTCPMaxBytes    = 32 << 20
	meshTCPRunBytes    = int64(8 << 30)
	meshTCPHeaderBytes = 2048
	meshTCPMaxTime     = 10 * time.Second
	meshTCPTailTime    = 2 * time.Second
)

// meshTCP receives independently of the guest's sequential host calls. Its
// listener belongs to this service until Close; sockets still pass ordinary
// network admission, attribution, accounting and descriptor limits.
type meshTCP struct {
	env                        *WasmEnv
	cfg                        guestio.MeshConfig
	peers                      map[string]guestio.MeshPeer
	ctx                        context.Context
	cancel                     context.CancelFunc
	mu                         sync.Mutex
	closed, sending            bool
	sentBudget, receivedBudget int64
	handles                    map[int32]struct{}
	wg                         sync.WaitGroup
	interruptOnce, closeOnce   sync.Once
	closeErr                   error
}

type meshTCPRequest struct {
	Group       string `json:"group"`
	Fingerprint string `json:"fingerprint"`
	From        string `json:"from"`
	To          string `json:"to"`
	FromRun     string `json:"from_run"`
	ToRun       string `json:"to_run"`
	Nonce       string `json:"nonce"`
	Bytes       int64  `json:"bytes"`
	TimeoutMS   int64  `json:"timeout_ms"`
}

type meshTCPReceipt struct {
	Nonce string `json:"nonce"`
	Bytes int64  `json:"bytes"`
}

func startMeshTCP(ctx context.Context, env *WasmEnv, cfg guestio.MeshConfig) (*meshTCP, error) {
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = meshTCPMaxBytes
	}
	if cfg.MaxTransferMS == 0 {
		cfg.MaxTransferMS = meshTCPMaxTime.Milliseconds()
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > meshTCPMaxBytes || cfg.MaxTransferMS < 1 || cfg.MaxTransferMS > meshTCPMaxTime.Milliseconds() {
		return nil, errors.New("TCP mesh transfer limits must not exceed 32 MiB and 10 seconds")
	}
	if env.TcpServer == nil || env.Registry == nil || cfg.DurationMS <= 0 || cfg.DurationMS > int64(24*time.Hour/time.Millisecond) {
		return nil, errors.New("TCP mesh requires an admitted listener and a duration up to 24 hours")
	}
	peers := make(map[string]guestio.MeshPeer, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		if peer.Participant == "" || peer.RunID == "" || peers[peer.Participant].Participant != "" {
			return nil, errors.New("invalid TCP mesh membership")
		}
		if _, err := netip.ParseAddrPort(peer.TCPAddress); err != nil {
			return nil, errors.New("TCP mesh peers require literal public IP:port endpoints")
		}
		peers[peer.Participant] = peer
	}
	if peers[cfg.Self].RunID != env.DebugletID.String() || len(peers) < 2 || len(peers) > 16 || cfg.Group == "" || cfg.Fingerprint == "" {
		return nil, errors.New("invalid TCP mesh identity")
	}
	end := time.UnixMilli(cfg.StartMS).Add(time.Duration(cfg.DurationMS) * time.Millisecond)
	if !end.After(time.Now()) || time.Until(end) > 24*time.Hour {
		return nil, errors.New("TCP mesh end must be within the next 24 hours")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := env.TcpServer.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	serviceCtx, cancel := context.WithDeadline(ctx, end)
	m := &meshTCP{env: env, cfg: cfg, peers: peers, ctx: serviceCtx, cancel: cancel, handles: map[int32]struct{}{}}
	context.AfterFunc(serviceCtx, m.interrupt)
	m.wg.Add(1)
	go m.accept()
	return m, nil
}

func (m *meshTCP) interrupt() {
	m.interruptOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		handles := make([]int32, 0, len(m.handles))
		for handle := range m.handles {
			handles = append(handles, handle)
		}
		m.mu.Unlock()
		// Wake the blocked accept without destroying the run's listener.
		m.closeErr = m.env.TcpServer.SetDeadline(time.Now())
		for _, handle := range handles {
			m.closeErr = errors.Join(m.closeErr, m.env.Registry.Close(handle))
		}
	})
}

func (m *meshTCP) Close() error {
	m.closeOnce.Do(func() {
		m.cancel()
		m.interrupt()
		m.wg.Wait()
		m.closeErr = errors.Join(m.closeErr, m.env.TcpServer.SetDeadline(time.Time{}))
	})
	return m.closeErr
}

func (m *meshTCP) track(handle int32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		_ = m.env.Registry.Close(handle)
		return false
	}
	m.handles[handle] = struct{}{}
	return true
}

func (m *meshTCP) release(handle int32) {
	_ = m.env.Registry.Close(handle)
	m.mu.Lock()
	delete(m.handles, handle)
	m.mu.Unlock()
}

func (m *meshTCP) accept() {
	defer m.wg.Done()
	defer m.cancel()
	slots := make(chan struct{}, 2)
	for {
		select {
		case slots <- struct{}{}:
		case <-m.ctx.Done():
			return
		}
		handle, err := acceptTCPSocket(m.ctx, m.ctx, m.env)
		if err != nil {
			<-slots
			return
		}
		if !m.track(handle) {
			<-slots
			return
		}
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer func() { <-slots }()
			defer m.release(handle)
			m.receive(handle)
		}()
	}
}

func (m *meshTCP) receive(handle int32) {
	conn, err := m.env.Registry.Get(handle)
	if err != nil {
		return
	}
	if meshTCPDeadline(conn, time.Now().Add(2*time.Second)) != nil {
		return
	}
	var request meshTCPRequest
	if meshTCPReadJSON(conn, &request) != nil || !m.validRequest(conn.RemoteAddr(), request) {
		return
	}
	m.mu.Lock()
	admitted := !m.closed && request.Bytes <= meshTCPRunBytes-m.receivedBudget
	if admitted {
		m.receivedBudget += request.Bytes
	}
	m.mu.Unlock()
	if !admitted {
		return
	}
	if meshTCPDeadline(conn, time.Now().Add(time.Duration(request.TimeoutMS)*time.Millisecond+meshTCPTailTime)) != nil {
		return
	}
	if meshTCPWriteJSON(conn, meshTCPReceipt{Nonce: request.Nonce}) != nil {
		return
	}
	buf := make([]byte, 32<<10)
	var received int64
	for {
		n, err := meshTCPReadChunk(conn, buf[:min(int64(len(buf)), request.Bytes-received)])
		received += int64(n)
		if err != nil || received > request.Bytes {
			return
		}
		if n == 0 {
			break
		}
	}
	_ = meshTCPWriteJSON(conn, meshTCPReceipt{Nonce: request.Nonce, Bytes: received})
}

func (m *meshTCP) validRequest(remote string, request meshTCPRequest) bool {
	peer, exists := m.peers[request.From]
	if !exists || request.From == m.cfg.Self || request.Group != m.cfg.Group || request.Fingerprint != m.cfg.Fingerprint ||
		request.To != m.cfg.Self || request.FromRun != peer.RunID || request.ToRun != m.env.DebugletID.String() ||
		request.Bytes < 1 || request.Bytes > m.cfg.MaxBytes || request.TimeoutMS < 1 || request.TimeoutMS > m.cfg.MaxTransferMS {
		return false
	}
	nonce, err := hex.DecodeString(request.Nonce)
	if err != nil || len(nonce) != 16 {
		return false
	}
	actual, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	expected, err := netip.ParseAddrPort(peer.TCPAddress)
	return err == nil && actual.Addr().Unmap() == expected.Addr().Unmap()
}

// Transfer reports goodput only after the receiver confirms every payload byte.
// Bytes and timeout cap payload generation, with at most two further seconds
// for the final bounded chunk and receipt. Duration includes connection setup
// and the receipt, not just socket writes. Failed byte reservations are retained.
func (m *meshTCP) Transfer(ctx context.Context, peer string, size int64, timeout time.Duration) (result guestio.MeshTransfer, err error) {
	result.Peer = peer
	target, exists := m.peers[peer]
	if !exists || peer == m.cfg.Self || size < 1 || size > m.cfg.MaxBytes || timeout < time.Millisecond || timeout > time.Duration(m.cfg.MaxTransferMS)*time.Millisecond {
		return result, errors.New("TCP transfer requires another peer and must fit the configured byte and time limits")
	}
	m.mu.Lock()
	if m.closed || m.sending || size > meshTCPRunBytes-m.sentBudget {
		m.mu.Unlock()
		return result, errors.New("TCP measurement is closed, busy or its 8 GiB transfer budget is exhausted")
	}
	m.sending = true
	m.sentBudget += size
	m.wg.Add(1)
	m.mu.Unlock()
	defer func() { m.mu.Lock(); m.sending = false; m.mu.Unlock(); m.wg.Done() }()
	started := time.Now()
	defer func() {
		result.DurationMS = float64(time.Since(started)) / float64(time.Millisecond)
		if err != nil {
			result.Error = err.Error()
			err = nil
		}
		if result.Complete {
			result.GoodputMbps = float64(result.ReceivedBytes) * 8 / (result.DurationMS * 1000)
		}
	}()
	opCtx, cancel := context.WithTimeout(ctx, timeout+meshTCPTailTime)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return result, err
	}
	handle, err := connectSocket(opCtx, opCtx, m.env, socket.SocketTypeTCP, target.TCPAddress)
	if err != nil {
		return result, err
	}
	if !m.track(handle) {
		return result, net.ErrClosed
	}
	defer m.release(handle)
	stopSocket := context.AfterFunc(opCtx, func() { _ = m.env.Registry.Close(handle) })
	defer stopSocket()
	conn, err := m.env.Registry.Get(handle)
	if err != nil {
		return result, err
	}
	deadline, _ := opCtx.Deadline()
	if err = meshTCPDeadline(conn, deadline); err != nil {
		return result, err
	}
	request := meshTCPRequest{Group: m.cfg.Group, Fingerprint: m.cfg.Fingerprint, From: m.cfg.Self, To: peer,
		FromRun: m.env.DebugletID.String(), ToRun: target.RunID, Nonce: hex.EncodeToString(nonce[:]), Bytes: size, TimeoutMS: timeout.Milliseconds()}
	if err = meshTCPWriteJSON(conn, request); err != nil {
		return result, err
	}
	var receipt meshTCPReceipt
	if err = meshTCPReadJSON(conn, &receipt); err != nil {
		return result, err
	}
	if receipt.Nonce != request.Nonce || receipt.Bytes != 0 {
		return result, errors.New("invalid TCP readiness receipt")
	}
	buf := make([]byte, 32<<10)
	dataEnd := started.Add(timeout)
	for result.SentBytes < size && time.Now().Before(dataEnd) {
		var n int
		n, err = meshTCPWriteChunk(conn, buf[:min(int64(len(buf)), size-result.SentBytes)])
		result.SentBytes += int64(n)
		if err != nil {
			return result, err
		}
	}
	if result.SentBytes == 0 {
		return result, errors.New("TCP transfer window ended before payload was sent")
	}
	if _, err = meshTCPWriteChunk(conn, nil); err != nil {
		return result, err
	}
	if err = meshTCPReadJSON(conn, &receipt); err != nil {
		return result, fmt.Errorf("receiver confirmation: %w", err)
	}
	if receipt.Nonce != request.Nonce || receipt.Bytes != result.SentBytes {
		return result, errors.New("receiver byte count does not match this transfer")
	}
	result.ReceivedBytes, result.Complete = receipt.Bytes, true
	return result, nil
}

func meshTCPWriteChunk(writer io.Writer, data []byte) (int, error) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err := meshTCPWrite(writer, header[:]); err != nil {
		return 0, err
	}
	return meshTCPWrite(writer, data)
}

func meshTCPReadChunk(reader io.Reader, buffer []byte) (int, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > uint32(len(buffer)) {
		return 0, errors.New("TCP measurement chunk exceeds 32 KiB")
	}
	return io.ReadFull(reader, buffer[:n])
}

func meshTCPDeadline(conn socket.Socket, deadline time.Time) error {
	s, ok := conn.(interface {
		SetReadDeadline(time.Time) error
		SetWriteDeadline(time.Time) error
	})
	if !ok {
		return errors.New("TCP socket does not support deadlines")
	}
	return errors.Join(s.SetReadDeadline(deadline), s.SetWriteDeadline(deadline))
}

func meshTCPWrite(writer io.Writer, data []byte) (written int, err error) {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if n < 0 || n > len(data) {
			return written, errors.New("invalid TCP write count")
		}
		written += n
		data = data[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrNoProgress
		}
	}
	return written, nil
}

func meshTCPWriteJSON(writer io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(data) > meshTCPHeaderBytes {
		return errors.New("TCP measurement header exceeds 2 KiB")
	}
	packet := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(packet, uint32(len(data)))
	copy(packet[4:], data)
	_, err = meshTCPWrite(writer, packet)
	return err
}

func meshTCPReadJSON(reader io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > meshTCPHeaderBytes {
		return errors.New("invalid TCP measurement header size")
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing TCP measurement header data")
	}
	return nil
}
