// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

//go:build linux

package ebpf

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
)

func TestBPFCounterAssociationAndMissingRate(t *testing.T) {
	for _, associated := range []bool{false, true} {
		name := "unassociated"
		if associated {
			name = "associated_missing_rate"
		}
		t.Run(name, func(t *testing.T) {
			counter := loopbackCounter(t)
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			id := uuid.New()
			if associated {
				if _, err := counter.Attach(client, id, "127.0.0.1"); err != nil {
					t.Fatal(err)
				}
			}
			received := receiveAll(listener)
			for range countedDatagrams {
				if _, err := client.Write(make([]byte, countedPayloadSize)); err != nil {
					t.Fatal(err)
				}
			}
			got, want := <-received, countedDatagrams
			if associated {
				want = 0
			}
			if got != want {
				t.Fatalf("observed %d/%d, expected %d", got, countedDatagrams, want)
			}
			var state countTbState
			err = counter.objs.PacketSizeMap.Lookup(&countDebugletKey{Uuid: [16]byte(id), Ipv6: netip.MustParseAddr("127.0.0.1").As16()}, &state)
			if !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("unexpected allowance bucket: %v", err)
			}
			t.Logf("%s: %d/%d received; unassociated traffic is outside this counter's guarantee", name, got, countedDatagrams)
		})
	}
}

func TestBPFCounterConcurrentRunsKeepIndependentBuckets(t *testing.T) {
	counter := loopbackCounter(t)
	var joined sync.WaitGroup
	start := make(chan struct{})
	for range 2 {
		listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialUDP("udp4", nil, listener.LocalAddr().(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		id := uuid.New()
		conn, err := counter.Attach(client, id, "127.0.0.1")
		if err != nil {
			_ = client.Close()
			t.Fatal(err)
		}
		defer conn.Close()
		if err := counter.SetLimit("127.0.0.1", id, 0); err != nil {
			t.Fatal(err)
		}
		if err := counter.SetExecLimit(id, 0); err != nil {
			t.Fatal(err)
		}
		received := receiveAll(listener)
		joined.Add(1)
		go func() {
			defer joined.Done()
			<-start
			for range countedDatagrams {
				if _, err := conn.Write(make([]byte, countedPayloadSize)); err != nil {
					t.Error(err)
					return
				}
			}
			if got := <-received; got != initialBurst/countedPacketSize {
				t.Errorf("run %s received %d; independent burst permits %d", id, got, initialBurst/countedPacketSize)
			}
		}()
	}
	close(start)
	joined.Wait()
}
