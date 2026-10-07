// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
)

func TestAggregateEgressDNSDoesNotHoldRegistryLock(t *testing.T) {
	f := egressFixture(t)
	previous := net.DefaultResolver
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		once.Do(func() { close(entered) })
		select {
		case <-release:
		case <-ctx.Done():
		}
		return nil, errors.New("owned resolver unavailable")
	}}
	defer func() { net.DefaultResolver = previous }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	spec := egressSpec(t, f, "owned-fixture.invalid")
	done := make(chan error, 1)
	go func() { _, err := f.d.SubmitDebuglets(ctx, []models.DebugletSpec{spec}, nil); done <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("DNS was not reached")
	}
	locked := make(chan struct{})
	go func() { f.d.mu.Lock(); f.d.mu.Unlock(); close(locked) }()
	select {
	case <-locked:
	case <-ctx.Done():
		close(release)
		<-done
		t.Fatal("DNS retained registry lock")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrEgressBudget) {
		t.Fatalf("DNS error: %v", err)
	}
}

func TestAggregateEgressConfiguredNameUsesOneDNSAnswer(t *testing.T) {
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var addressQueries atomic.Int64
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		buf := make([]byte, 4096)
		for {
			n, peer, err := listener.ReadFrom(buf)
			if err != nil {
				return
			}
			var request dnsmessage.Message
			if err := request.Unpack(buf[:n]); err != nil {
				t.Errorf("owned DNS parse: %v", err)
				return
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: request.ID, Response: true, RecursionAvailable: true}, Questions: request.Questions}
			for _, question := range request.Questions {
				if question.Type == dnsmessage.TypeA {
					ip := [4]byte{127, 0, 0, 1}
					if addressQueries.Add(1) > 1 {
						ip[3] = 2
					}
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: ip}})
				}
			}
			wire, err := response.Pack()
			if err != nil {
				t.Errorf("owned DNS encode: %v", err)
				return
			}
			if _, err := listener.WriteTo(wire, peer); err != nil {
				return
			}
		}
	}()
	defer func() { _ = listener.Close(); <-stopped }()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp4", listener.LocalAddr().String())
	}}
	defer func() { net.DefaultResolver = previous }()
	cfg := egressConfig()
	cfg.Groups[0].Prefixes = nil
	cfg.Groups[0].Names = []string{"OWNED.EXAMPLE."}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	reservation, err := prepareEgress(ctx, cfg, models.DebugletSpec{ExecutorID: "owned", Policy: models.DebugletPolicy{Addresses: []string{"owned.example:80"}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reservation.buckets["group:owned-targets"]; !ok {
		t.Fatal("rotating DNS bypassed configured-name group")
	}
	if addressQueries.Load() != 1 || len(reservation.grant.Addresses) != 1 || reservation.grant.Addresses[0] != "127.0.0.1" {
		t.Fatalf("answers=%d grant=%v", addressQueries.Load(), reservation.grant.Addresses)
	}
}
