// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/connectivity"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/transport/rpc"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func (a *siAdapter) OnReflectAddress(ctx context.Context, mutation *rpc.Mutation, req *pb.ReflectAddressRequest, address string) (*pb.ReflectAddressResponse, error) {
	return a.DispatcherState.(*Dispatcher).OnReflectAddress(ctx, mutation, req, address)
}

func TestConnectivityOwnedDualStackReflectionAndListenerProof(t *testing.T) {
	plan := siNewPlan()
	f := siNewHarness(t, map[string]*siPlan{"connectivity": plan})
	peer := f.connect("network", "connectivity")
	owner := siEntered(t, plan)
	siAvailable(t, plan, owner)
	client := f.boundClient("connectivity")
	binding, _ := peer.client.Binding()
	v6, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatal(err)
	}
	f.serves.Add(1)
	go func() { defer f.serves.Done(); _ = f.d.Bidi.ServeGRPCListener(f.ctx, v6) }()
	egress := []*pb.EgressTest{}
	for i, endpoint := range []string{f.directAddress, v6.Addr().String()} {
		nonce := bytes.Repeat([]byte{byte(i + 1)}, 32)
		response, err := peer.client.ReflectAddress(f.ctx, binding, endpoint, &pb.ReflectAddressRequest{ExecutorId: "network", Nonce: nonce})
		if err != nil {
			t.Fatal(err)
		}
		want := "127.0.0.1"
		if i == 1 {
			want = "::1"
		}
		if response.Address != want {
			t.Fatalf("actual reflector peer = %q, want %q", response.Address, want)
		}
		egress = append(egress, &pb.EgressTest{State: "reachable", Nonce: nonce})
	}
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		tcp.Close()
		t.Fatal(err)
	}
	token := bytes.Repeat([]byte{3}, 32)
	stopTCP, stopUDP := connectivity.ServeTCP(tcp, token), connectivity.ServeUDP(udp, token)
	defer stopTCP()
	defer stopUDP()
	tcpPort, udpPort := tcp.Addr().(*net.TCPAddr).Port, udp.LocalAddr().(*net.UDPAddr).Port
	f.d.mu.Lock()
	entry := f.d.executors["network"]
	host := "127.0.0.1"
	entry.publicHost = &host
	entry.display = config.ExecutorDisplay{ConnectivityHost: host, ConnectivityPorts: strconv.Itoa(tcpPort) + "," + strconv.Itoa(udpPort)}
	f.d.mu.Unlock()
	report := &pb.ConnectivityReport{Ipv4: egress[0], Ipv6: egress[1], ListenersEnabled: true, Listeners: []*pb.ListenerChallenge{{Transport: "tcp", Port: uint32(tcpPort), Token: token}, {Transport: "udp", Port: uint32(udpPort), Token: token}}}
	if _, err := client.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: "network", VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, Listeners: []string{"tcp", "udp"}, Connectivity: report}}); err != nil {
		t.Fatal(err)
	}
	snapshot, ok := f.d.GetExecutor("network")
	if !ok {
		t.Fatal("executor disappeared")
	}
	private := snapshot.Connectivity(true)
	for _, observation := range []wire.Reachability{private.IPv4, private.IPv6, private.TCPListener, private.UDPListener} {
		if !observation.FreshReachable(time.Now()) || observation.Source != wire.SourceDispatcherObserved {
			t.Fatalf("missing direct observation: %+v", observation)
		}
	}
	public, _ := json.Marshal(snapshot.Connectivity(false))
	if bytes.Contains(public, []byte("127.0.0.1")) || bytes.Contains(public, []byte("::1")) || bytes.Contains(public, token) {
		t.Fatalf("private observation leaked: %s", public)
	}
	admitted := admissionVantagePoint(entry, time.Now())
	before, _ := json.Marshal(admitted)
	// A later failed challenge has authority over future admission only.
	stopTCP()
	f.d.mu.Lock()
	entry.connectivityNext = time.Time{}
	f.d.mu.Unlock()
	if _, err := client.Heartbeat(f.ctx, &pb.HeartbeatRequest{ExecutorId: "network", VantagePoint: &pb.VantagePointReport{SchemaVersion: 1, Listeners: []string{"tcp", "udp"}, Connectivity: report}}); err != nil {
		t.Fatal(err)
	}
	f.d.mu.RLock()
	current := f.d.executors["network"]
	err = validateExecutorCapabilities(&models.DebugletSpec{OrderID: 42, Policy: models.DebugletPolicy{ListenTCP: true}}, current, time.Now())
	stale := snapshotLocked(current, time.Now().Add(capabilityLifetime))
	f.d.mu.RUnlock()
	var field *CapabilityError
	if !errors.As(err, &field) || !errors.Is(err, ErrInvalidPolicy) || field.Field != "policy.listen_tcp" || field.OrderID != 42 || field.Code != "reachability_failed" {
		t.Fatalf("structured refusal: %v", err)
	}
	if !stale.Connectivity(true).IPv4.Stale {
		t.Fatal("expiry renewed without a new observation")
	}
	after, _ := json.Marshal(admitted)
	if !bytes.Equal(before, after) {
		t.Fatal("later observation rewrote admission snapshot")
	}
	// The same executor name under a new owner cannot reuse reflection proof.
	replacement := registryOwner(t, "network")
	defer replacement.Retire()
	if err := registryRegisterWithSetup(t.Context(), f.d, replacement, registryHello("network"), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	if result := f.d.observeConnectivity(t.Context(), replacement, report, time.Now()); result.IPv4.State != "untested" || result.IPv4.Reason != "unconfirmed" {
		t.Fatal("reflection proof crossed a control binding")
	}
	after, _ = json.Marshal(admitted)
	if !bytes.Equal(before, after) {
		t.Fatal("re-registration rewrote admission snapshot")
	}
}

func TestCapabilityAdmissionKeepsUnmeasuredLegacyAndRejectsExpiredMeasured(t *testing.T) {
	host := "127.0.0.1"
	entry := &executorEntry{RegisteredExecutor: &RegisteredExecutor{publicHost: &host, ICMPEnabled: true}}
	spec := &models.DebugletSpec{Policy: models.DebugletPolicy{ListenTCP: true, Addresses: []string{"127.0.0.1", "::1"}}}
	now := time.Now()
	if err := validateExecutorCapabilities(spec, entry, now); err != nil {
		t.Fatalf("legacy declaration refused: %v", err)
	}
	entry.connectivity = emptyConnectivity()
	if err := validateExecutorCapabilities(spec, entry, now); err != nil {
		t.Fatal(err)
	}
	entry.connectivity.IPv6 = observedReachability("reachable", "", wire.SourceDispatcherObserved, now.Add(-capabilityLifetime))
	err := validateExecutorCapabilities(spec, entry, now)
	var field *CapabilityError
	if !errors.As(err, &field) || field.Field != "policy.addresses" || field.Code != "stale_observation" {
		t.Fatalf("stale family admitted: %v", err)
	}
}
