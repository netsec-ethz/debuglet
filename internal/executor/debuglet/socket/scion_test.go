// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package socket

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/netsec-ethz/scion-apps/pkg/pan"
)

func TestSCIONExactPathSelection(t *testing.T) {
	a, b := makeTestPath("a"), makeTestPath("b")
	a.Expiry = time.Now().Add(time.Hour)
	b.Expiry = a.Expiry
	sel := NewPathSelector()
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, []*pan.Path{a, b})
	id := SCIONPathID(b)
	selected, err := sel.SelectPathID(id)
	if err != nil || selected != b {
		t.Fatalf("select = %v, %v", selected, err)
	}
	refreshed := makeTestPath("b")
	refreshed.Expiry = a.Expiry
	sel.Refresh([]*pan.Path{refreshed, a})
	if got := sel.Path(); got != refreshed || SCIONPathID(got) != id {
		t.Fatalf("reorder changed pin: %v", got)
	}
	// Selecting a path absent from the current snapshot must block subsequent
	// automatic writes rather than retaining the previous path as a fallback.
	missing := makeTestPath("not-present")
	missing.Expiry = a.Expiry
	if _, err := sel.SelectPathID(SCIONPathID(missing)); err == nil || sel.Path() != nil {
		t.Fatal("missing exact pin did not fail closed")
	}
	sel.Refresh([]*pan.Path{a, refreshed, missing})
	if got := sel.Path(); got != missing {
		t.Fatalf("refresh did not restore exact missing pin: %v", got)
	}
}

func TestSCIONExpiredPinCannotFallback(t *testing.T) {
	expired := makeTestPath("expired")
	expired.Expiry = time.Now().Add(-time.Minute)
	live := makeTestPath("live")
	live.Expiry = time.Now().Add(time.Hour)
	sel := NewPathSelector()
	sel.Initialize(pan.UDPAddr{}, pan.UDPAddr{}, []*pan.Path{expired, live, nil})
	if paths := sel.Paths(); len(paths) != 1 || paths[0] != live {
		t.Fatalf("expired paths visible: %v", paths)
	}
	if _, err := sel.SelectPathID(SCIONPathID(expired)); err == nil || sel.Path() != nil {
		t.Fatal("expired pin fell back to live path")
	}
	if _, err := sel.SelectPathID(SCIONPathID(live)); err != nil {
		t.Fatal(err)
	}
	// No daemon refresh is necessary to stop using an expired selected path.
	live.Expiry = time.Now().Add(-time.Minute)
	if sel.Path() != nil || len(sel.Paths()) != 0 {
		t.Fatal("expired selected path remained usable")
	}
	for _, id := range []string{"", "not-hex", "0"} {
		if _, err := sel.SelectPathID(id); err == nil {
			t.Fatalf("accepted malformed path ID %q", id)
		}
	}
}

func TestDescribeSCIONPath(t *testing.T) {
	path := &pan.Path{
		Fingerprint: "a b", Source: pan.IA(1), Destination: pan.IA(2),
		Expiry: time.UnixMilli(1700000000123),
		Metadata: &pan.PathMetadata{MTU: 1472, Interfaces: []pan.PathInterface{
			{IA: pan.IA(1), IfID: 3}, {IA: pan.IA(2), IfID: 4},
		}},
	}
	description := DescribeSCIONPath(path)
	if description.ID != SCIONPathID(path) || description.ExpiresMS != 1700000000123 || description.MTU != 1472 || description.HopCount != 1 {
		t.Fatalf("wrong metadata: %+v", description)
	}
	if len(description.Interfaces) != 2 || description.Interfaces[1].IA != path.Destination.String() || description.Interfaces[1].ID != 4 {
		t.Fatalf("wrong interfaces: %+v", description.Interfaces)
	}
	copy := description.Interfaces[0]
	path.Metadata.Interfaces[0].IfID++
	if !reflect.DeepEqual(description.Interfaces[0], copy) {
		t.Fatal("descriptor aliases mutable path metadata")
	}
}

func TestSCIONOperationLockCancellation(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	var conn pan.Conn = &localSCIONConn{Conn: left}
	scion := &SCIONConn{Conn: &conn, Selector: NewPathSelector()}
	entered, release, completed := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		completed <- scion.WithLock(context.Background(), func(pan.Conn, *PathSelector) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := scion.WithLock(ctx, func(pan.Conn, *PathSelector) error {
		t.Error("cancelled operation acquired occupied socket")
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled wait = %v", err)
	}
	close(release)
	if err := <-completed; err != nil {
		t.Fatal(err)
	}
	if err := scion.WithLock(context.Background(), func(pan.Conn, *PathSelector) error { return nil }); err != nil {
		t.Fatalf("released lock unusable: %v", err)
	}
}
