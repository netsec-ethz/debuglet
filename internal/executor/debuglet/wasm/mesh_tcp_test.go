// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wasm

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/bitrate"
	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/netpolicy"
	"github.com/netsec-ethz/debuglet/internal/guestio"
)

func meshTCPFixture(t *testing.T) (*WasmEnv, *WasmEnv, guestio.MeshConfig, guestio.MeshConfig) {
	t.Helper()
	makeEnv := func() *WasmEnv {
		env := policyEnv(t, localSpec(), netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		env.TcpServer, env.TcpServerAddr = listener, listener.Addr().String()
		return env
	}
	a, b := makeEnv(), makeEnv()
	peers := []guestio.MeshPeer{
		{Participant: "a", RunID: a.DebugletID.String(), ExecutorID: "exec-a", TCPAddress: a.TcpServerAddr},
		{Participant: "b", RunID: b.DebugletID.String(), ExecutorID: "exec-b", TCPAddress: b.TcpServerAddr},
	}
	config := guestio.MeshConfig{Kind: "tcp", Self: "a", Group: "fixture", Fingerprint: strings.Repeat("f", 64), Peers: peers, StartMS: time.Now().UnixMilli(), DurationMS: 60_000}
	other := config
	other.Self = "b"
	return a, b, config, other
}

func meshTCPStart(t *testing.T, env *WasmEnv, cfg guestio.MeshConfig) *meshTCP {
	t.Helper()
	m, err := startMeshTCP(t.Context(), env, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func TestMeshTCPReceiverConfirmedTransfer(t *testing.T) {
	a, b, ca, cb := meshTCPFixture(t)
	ma, mb := meshTCPStart(t, a, ca), meshTCPStart(t, b, cb)
	for _, test := range []struct {
		service *meshTCP
		peer    string
	}{{ma, "b"}, {mb, "a"}} {
		result, err := test.service.Transfer(t.Context(), test.peer, 256<<10, 3*time.Second)
		if err != nil || !result.Complete || result.Error != "" || result.SentBytes != 256<<10 || result.ReceivedBytes != result.SentBytes || result.DurationMS <= 0 || result.GoodputMbps <= 0 {
			t.Fatalf("transfer: %+v, %v", result, err)
		}
	}
}

func TestMeshTCPRejectsWrongIdentityAndOversizeBeforePayload(t *testing.T) {
	a, b, ca, cb := meshTCPFixture(t)
	_ = a
	m := meshTCPStart(t, b, cb)
	valid := meshTCPRequest{Group: ca.Group, Fingerprint: ca.Fingerprint, From: "a", To: "b", FromRun: ca.Peers[0].RunID, ToRun: cb.Peers[1].RunID, Nonce: strings.Repeat("a", 32), Bytes: 1024, TimeoutMS: 1000}
	for _, test := range []struct {
		name   string
		change func(*meshTCPRequest)
	}{
		{"group", func(r *meshTCPRequest) { r.Group = "different" }},
		{"run", func(r *meshTCPRequest) { r.FromRun = cb.Peers[1].RunID }},
		{"peer", func(r *meshTCPRequest) { r.From = "outsider" }},
		{"bytes", func(r *meshTCPRequest) { r.Bytes = meshTCPMaxBytes + 1 }},
		{"timeout", func(r *meshTCPRequest) { r.TimeoutMS = 10001 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.change(&request)
			conn, err := net.DialTimeout("tcp4", b.TcpServerAddr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			if err := meshTCPWriteJSON(conn, request); err != nil {
				t.Fatal(err)
			}
			var receipt meshTCPReceipt
			if err := meshTCPReadJSON(conn, &receipt); err == nil {
				t.Fatalf("unauthorized request accepted: %+v", receipt)
			}
		})
	}
	m.mu.Lock()
	reserved := m.receivedBudget
	m.mu.Unlock()
	if reserved != 0 {
		t.Fatalf("rejected requests consumed %d payload bytes", reserved)
	}
}

func TestMeshTCPCancellationUnblocksAcceptAndRetainsListener(t *testing.T) {
	a, _, ca, _ := meshTCPFixture(t)
	m := meshTCPStart(t, a, ca)
	done := make(chan error, 1)
	go func() { done <- m.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close left accept blocked")
	}
	// The service releases ownership, not the listener itself.
	conn, err := net.DialTimeout("tcp4", a.TcpServerAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = a.TcpServer.SetDeadline(time.Now().Add(time.Second))
	accepted, err := a.TcpServer.AcceptTCP()
	if err != nil {
		t.Fatalf("listener not reusable: %v", err)
	}
	_ = accepted.Close()
}

func TestMeshTCPDoesNotTrustSocketWriteWithoutReceipt(t *testing.T) {
	a, b, ca, _ := meshTCPFixture(t)
	m := meshTCPStart(t, a, ca)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := b.TcpServer.AcceptTCP()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var request meshTCPRequest
		if err = meshTCPReadJSON(conn, &request); err != nil {
			serverDone <- err
			return
		}
		if err = meshTCPWriteJSON(conn, meshTCPReceipt{Nonce: request.Nonce}); err != nil {
			serverDone <- err
			return
		}
		for {
			var n int
			n, err = meshTCPReadChunk(conn, make([]byte, 32<<10))
			if err != nil || n == 0 {
				break
			}
		}
		if err == nil {
			err = meshTCPWriteJSON(conn, meshTCPReceipt{Nonce: request.Nonce, Bytes: request.Bytes - 1})
		}
		serverDone <- err
	}()
	result, err := m.Transfer(t.Context(), "b", 4096, time.Second)
	if err != nil || result.Complete || result.Error == "" || result.GoodputMbps != 0 || result.ReceivedBytes != 0 {
		t.Fatalf("unconfirmed delivery accepted: %+v %v", result, err)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestMeshTCPTimeCapConfirmsPartialDelivery(t *testing.T) {
	a, b, ca, cb := meshTCPFixture(t)
	a.Limiter.SetExecutorCapacity(8 * bitrate.Megabit)
	a.Limiter.SetAddrCapacity("127.0.0.1", 8*bitrate.Megabit)
	ma := meshTCPStart(t, a, ca)
	meshTCPStart(t, b, cb)
	result, err := ma.Transfer(t.Context(), "b", meshTCPMaxBytes, 200*time.Millisecond)
	if err != nil || !result.Complete || result.Error != "" || result.ReceivedBytes <= 0 || result.ReceivedBytes >= meshTCPMaxBytes || result.ReceivedBytes != result.SentBytes || result.GoodputMbps <= 0 {
		t.Fatalf("time-capped delivery: %+v %v", result, err)
	}
	if result.DurationMS > 2200 {
		t.Fatalf("transfer exceeded data and receipt bounds: %+v", result)
	}
}

func TestMeshTCPBoundedFramingAndCanceledTransfer(t *testing.T) {
	var oversized [4]byte
	binary.BigEndian.PutUint32(oversized[:], meshTCPHeaderBytes+1)
	if err := meshTCPReadJSON(strings.NewReader(string(oversized[:])), new(meshTCPRequest)); err == nil {
		t.Fatal("oversized frame accepted")
	}
	a, b, ca, _ := meshTCPFixture(t)
	m := meshTCPStart(t, a, ca)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		conn, err := b.TcpServer.AcceptTCP()
		if err == nil {
			accepted <- conn
		}
	}()
	done := make(chan guestio.MeshTransfer, 1)
	go func() { result, _ := m.Transfer(ctx, "b", 4096, 10*time.Second); done <- result }()
	var conn *net.TCPConn
	select {
	case conn = <-accepted:
	case <-time.After(time.Second):
		t.Fatal("transfer did not connect")
	}
	defer conn.Close()
	cancel()
	select {
	case result := <-done:
		if result.Complete || result.Error == "" {
			t.Fatalf("cancellation hidden: %+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not interrupt receipt wait")
	}
}

func TestMeshTCPPolicyAndRunBudgetRemainEnforced(t *testing.T) {
	a, _, ca, _ := meshTCPFixture(t)
	operator := localSpec()
	operator.TCP = false
	parsed, err := netpolicy.Parse(operator)
	if err != nil {
		t.Fatal(err)
	}
	a.Net = netpolicy.New(parsed, netpolicy.Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true})
	m := meshTCPStart(t, a, ca)
	result, err := m.Transfer(t.Context(), "b", 1024, time.Second)
	if result.Complete || err == nil && result.Error == "" {
		t.Fatalf("TCP policy ignored: %+v %v", result, err)
	}
	healthy, _, config, _ := meshTCPFixture(t)
	quota := meshTCPStart(t, healthy, config)
	quota.mu.Lock()
	quota.sentBudget = meshTCPRunBytes
	quota.mu.Unlock()
	if _, err := quota.Transfer(t.Context(), "b", 1, time.Second); err == nil {
		t.Fatal("run byte cap ignored")
	}
}

func TestMeshTCPConfiguredTransferLimits(t *testing.T) {
	a, b, ca, cb := meshTCPFixture(t)
	ca.MaxBytes, ca.MaxTransferMS = 1024, 1000
	cb.MaxBytes, cb.MaxTransferMS = 256, 1000
	ma := meshTCPStart(t, a, ca)
	meshTCPStart(t, b, cb)
	if _, err := ma.Transfer(t.Context(), "b", 1025, time.Second); err == nil {
		t.Fatal("sender byte limit ignored")
	}
	if _, err := ma.Transfer(t.Context(), "b", 128, 1001*time.Millisecond); err == nil {
		t.Fatal("sender time limit ignored")
	}
	refused, err := ma.Transfer(t.Context(), "b", 512, time.Second)
	if err != nil || refused.Complete || refused.Error == "" {
		t.Fatalf("receiver byte limit ignored: %+v %v", refused, err)
	}
	accepted, err := ma.Transfer(t.Context(), "b", 128, time.Second)
	if err != nil || !accepted.Complete || accepted.ReceivedBytes != 128 {
		t.Fatalf("smaller transfer failed: %+v %v", accepted, err)
	}
}

func TestMeshTCPConfiguredEndStopsListener(t *testing.T) {
	a, _, ca, _ := meshTCPFixture(t)
	ca.DurationMS = 50
	m := meshTCPStart(t, a, ca)
	select {
	case <-m.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("configured end was ignored")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Transfer(t.Context(), "b", 1, time.Second); err == nil {
		t.Fatal("expired service accepted a transfer")
	}
}
