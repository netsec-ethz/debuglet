// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"context"
	"reflect"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/netsec-ethz/debuglet/internal/dispatcher/database"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

// A registration, the maintenance flush, a disconnect and the passage of time
// move an executor through connected, disconnected and abandoned, with its
// uptime, host tags, system tags and last addresses.
func TestProbeStatusLifecycleAndTags(t *testing.T) {
	d, db, _ := newRegistryFixture(t)
	start := time.Unix(1_790_000_000, 0)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	d.now = func() time.Time { return time.Unix(0, clock.Load()) }
	advance := func(by time.Duration) time.Time {
		return time.Unix(0, clock.Add(int64(by)))
	}
	owner := registryOwner(t, "probe-a")
	defer owner.Retire()
	hello := registryHello("probe-a")
	hello.VantagePoint = &pb.VantagePointReport{SchemaVersion: 1, HostTags: []string{"fibre", "home"}}
	setup, err := owner.AdmitSetup(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.OnExecutorConnected(setup.Context(), owner, hello, "9.9.9.9"); err != nil {
		t.Fatal(err)
	}
	setup.Finish()
	owner.MarkRegistered()

	live := func() wire.ProbeStatus {
		t.Helper()
		book, err := d.ProbeBook(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		e, ok := d.GetExecutor("probe-a")
		if !ok {
			t.Fatal("executor not listed")
		}
		return book.Live(e)
	}
	got := live()
	if got.Status == nil || got.Status.Name != wire.ProbeConnected || *got.Status.Since != start.Unix() || *got.FirstConnected != start.Unix() || *got.TotalUptime != 0 {
		t.Fatalf("first registration: %+v", got)
	}
	if want := []string{"home", "fibre", wire.TagIPv4Works, wire.TagIPv4Capable}; !reflect.DeepEqual(got.Tags, want) {
		t.Fatalf("tags = %v, want %v", got.Tags, want)
	}

	// Two days of heartbeats, a reflection over IPv6 and a self-check.
	now := advance(48 * time.Hour)
	d.mu.Lock()
	entry := d.executors["probe-a"]
	entry.LastSeen = now
	entry.probe.reflected[1] = addressSighting{address: "2620:fe::fe", via: wire.AddressViaReflection, at: now.Add(-time.Hour)}
	private := true
	entry.vantage = &vantageReport{listeners: []string{}, addressCheck: &addressCheck{ipv4LocalPrivate: &private, resolvesA: true}}
	entry.vantageObserved = now
	d.mu.Unlock()
	d.flushProbeStatusDue()
	got = live()
	if *got.TotalUptime != int64((48*time.Hour).Seconds()) || *got.Status.Since != start.Unix() {
		t.Fatalf("uptime after two days: %+v", got)
	}
	// IPv6 was seen an hour ago, which is capable but no longer working; the
	// IPv4 address has been the same for two days.
	want := []string{"home", "fibre", wire.TagIPv4Works, wire.TagIPv4Capable, wire.TagIPv4Stable1d, wire.TagIPv6Capable, wire.TagIPv4RFC1918, wire.TagResolvesA}
	if !reflect.DeepEqual(got.Tags, want) {
		t.Fatalf("tags = %v, want %v", got.Tags, want)
	}

	// The executor goes away; the next flush closes its record at its last
	// heartbeat.
	d.OnExecutorDisconnected(owner)
	advance(time.Hour)
	d.flushProbeStatusDue()
	book, err := d.ProbeBook(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	offline := book.Offline(map[string]bool{}, []string{wire.ProbeDisconnected}, d.ConfiguredDisplay, false)
	if len(offline) != 1 {
		t.Fatalf("offline = %+v", offline)
	}
	gone := offline[0]
	if gone.Status.Name != wire.ProbeDisconnected || *gone.Status.Since != now.Unix() || *gone.LastConnected != now.Unix() || gone.Version != "registry-v1" ||
		!reflect.DeepEqual(gone.Tags, []string{"home", "fibre"}) || gone.Admission != wire.AdmissionOffline || gone.Ready {
		t.Fatalf("disconnected entry: %+v", gone)
	}
	if gone.AddressV4 == nil || *gone.AddressV4 != "9.9.9.9" || gone.AddressV6 == nil || *gone.AddressV6 != "2620:fe::fe" || gone.AddressObservations.V6.Via != wire.AddressViaReflection {
		t.Fatalf("last addresses: %+v", gone.ProbeAddressing)
	}
	if len(book.Offline(map[string]bool{}, []string{wire.ProbeAbandoned}, d.ConfiguredDisplay, false)) != 0 {
		t.Fatal("recent executor is abandoned")
	}

	advance(wire.AbandonedAfter)
	book, err = d.ProbeBook(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	abandoned := book.Offline(map[string]bool{}, wire.ProbeStatuses, d.ConfiguredDisplay, false)
	if len(abandoned) != 1 || abandoned[0].Status.Name != wire.ProbeAbandoned || *abandoned[0].Status.Since != now.Add(wire.AbandonedAfter).Unix() {
		t.Fatalf("abandoned: %+v", abandoned)
	}

	// An enrolled executor that never registered.
	if _, err := db.ExecContext(context.Background(), `INSERT INTO users (id, uuid, name) VALUES (9, ?, 'owner')`, uuid.New()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(context.Background(), `INSERT INTO owned_executors (executor_id, user_id, name, created_at) VALUES ('probe-new', 9, 'new', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	book, err = d.ProbeBook(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	all := book.Offline(map[string]bool{}, wire.ProbeStatuses, d.ConfiguredDisplay, false)
	names := []string{}
	for _, e := range all {
		names = append(names, e.ID+":"+e.Status.Name)
	}
	if !slices.Equal(names, []string{"probe-a:abandoned", "probe-new:never_connected"}) {
		t.Fatalf("listing = %v", names)
	}
	if never := all[1]; never.FirstConnected != nil || never.Status.Since != nil || never.AddressV4 != nil || len(never.Tags) != 0 {
		t.Fatalf("never connected: %+v", never)
	}
}

func TestProbeStatusPrivateAndMalformedTags(t *testing.T) {
	got := probeFromHello(&pb.VantagePointReport{AddressOptOut: true, HostTags: []string{"home", "moon"}}, time.Unix(1, 0))
	if !got.optOut || len(got.hostTags) != 0 {
		t.Fatalf("malformed tags kept: %+v", got)
	}
	got = probeFromHello(&pb.VantagePointReport{HostTags: []string{"nat", "home"}}, time.Unix(1, 0))
	if got.optOut || !slices.Equal(got.hostTags, []string{"home", "nat"}) {
		t.Fatalf("tags not canonical: %+v", got)
	}
	// A private disconnected executor keeps its network facts but not its
	// addresses, unless the caller may see them.
	run := &database.ProbeAddress{ExecutorID: "hidden", Family: 4, Address: "192.0.2.4", Via: wire.AddressViaControl, FirstObserved: 5, LastObserved: 9}
	book := &ProbeBook{now: time.Unix(10_000, 0),
		status:    map[string]database.ProbeStatus{"hidden": {ExecutorID: "hidden", FirstConnected: 1, LastConnected: 9, StatusSince: 9, IsPublic: 0, HostTags: "home,unknown"}},
		addresses: map[string][2]*database.ProbeAddress{"hidden": {run, nil}}}
	display := func(string) wire.ExecutorDisplay { return wire.ExecutorDisplay{} }
	public := book.Offline(map[string]bool{}, []string{wire.ProbeDisconnected}, display, false)
	if len(public) != 1 || public[0].IsPublic == nil || *public[0].IsPublic || public[0].AddressV4 != nil || public[0].AddressObservations.V4 == nil || public[0].AddressObservations.V4.ObservedAt != 9 {
		t.Fatalf("private offline entry: %+v", public)
	}
	if len(public[0].Tags) != 0 {
		t.Fatalf("a stored tag outside the vocabulary was published: %v", public[0].Tags)
	}
	if operator := book.Offline(map[string]bool{}, []string{wire.ProbeDisconnected}, display, true); operator[0].AddressV4 == nil || *operator[0].AddressV4 != "192.0.2.4" {
		t.Fatalf("operator offline entry: %+v", operator[0].ProbeAddressing)
	}
	if listed := book.Offline(map[string]bool{"hidden": true}, wire.ProbeStatuses, display, true); len(listed) != 0 {
		t.Fatal("a registered executor was listed twice")
	}
}
