// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/config"
	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
	pb "github.com/netsec-ethz/debuglet/protocol"
)

func TestIPMetadataRegistrationOverrideAndImmutableSnapshot(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	databases, err := ipmetadata.Open("../ipmetadata/testdata/different.mmdb", "../ipmetadata/testdata/different.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer databases.Close()
	if err = d.ConfigureIPMetadata(databases); err != nil {
		t.Fatal(err)
	}
	if err = d.ConfigureExecutorDisplay(map[string]config.ExecutorDisplay{"lab": {Country: "DE"}}); err != nil {
		t.Fatal(err)
	}
	hello := registryHello("lab")
	host := "200.1.1.1"
	hello.PublicHost = &host
	owner := registryOwner(t, "lab")
	defer owner.Retire()
	if err := registryRegisterWithSetup(t.Context(), d, owner, hello, "8.8.8.8"); err != nil {
		t.Fatal(err)
	}
	owner.MarkRegistered()
	e, ok := d.GetExecutor("lab")
	if !ok {
		t.Fatal("missing executor")
	}
	if e.Display().City.Value != nil || *e.Display().Country.Value != "DE" || *e.Display().Country.Source != wire.SourceOperator {
		t.Fatalf("operator location must override as a group: %+v", e.Display())
	}
	m := e.IPMetadata()
	if m.Observed.ASN.Value == nil || m.Observed.ASN.Value.Number != 64500 || m.Advertised.ASN.Value == nil || m.Advertised.ASN.Value.Number != 64501 || m.Advertised.Location.Value == nil || !slices.Contains(m.Disagreements, "operator_location") || !slices.Contains(m.Disagreements, "observed_advertised_asn") || !slices.Contains(m.Disagreements, "observed_advertised_location") {
		t.Fatalf("metadata: %+v", m)
	}
	m.Observed.ASN.Value.Number = 1
	m.Disagreements[0] = "changed"
	if again := e.IPMetadata(); again.Observed.ASN.Value.Number != 64500 || again.Disagreements[0] == "changed" {
		t.Fatal("caller mutated registry metadata")
	}
	snapshot := admissionVantagePoint(d.executors["lab"], time.Now())
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ConfigureIPMetadata(nil); err == nil {
		t.Fatal("databases changed after registration")
	}
	replacement := registryOwner(t, "lab")
	defer replacement.Retire()
	hello.VantagePoint = &pb.VantagePointReport{SchemaVersion: 1, LocationOptOut: true}
	if err := registryRegisterWithSetup(t.Context(), d, replacement, hello, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	replacement.MarkRegistered()
	current, _ := d.GetExecutor("lab")
	if v := current.IPMetadata(); v.Observed.ASN.Reason != "non_global" || v.Observed.Location.Value != nil || v.Advertised.Location.Value != nil || v.Advertised.Location.Reason != "opted_out" {
		t.Fatalf("replacement: %+v", v)
	}
	after, _ := json.Marshal(snapshot)
	if string(encoded) != string(after) || snapshot.IPMetadata.Observed.Location.Value == nil {
		t.Fatal("re-registration rewrote admitted metadata")
	}
}

func TestIPMetadataPreservesOperatorDisplayAndExplicitUnknown(t *testing.T) {
	databases, err := ipmetadata.Open("../ipmetadata/testdata/asn.mmdb", "../ipmetadata/testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer databases.Close()
	host := "8.8.8.8"
	e := &RegisteredExecutor{sourceIp: "127.0.0.1", sourceIPObserved: true, publicHost: &host, LastSeen: time.Unix(1700000123, 0)}
	e.collectIPMetadata(databases, false)
	if d := e.Display(); d.City.Value != nil || d.Country.Value != nil {
		t.Fatalf("automatic lookup changed legacy operator fields: %+v", d)
	}
	if snapshot := admissionVantagePoint(&executorEntry{RegisteredExecutor: e}, e.LastSeen); snapshot.Display.City.Value != nil || snapshot.Display.Country.Value != nil {
		t.Fatal("automatic location changed old result display contract")
	}
	city, country := (wire.Executor{Display: e.Display(), IPMetadata: e.IPMetadata()}).Location()
	if city.Value == nil || *city.Value != "Fixture city" || country.Value == nil || *country.Value != "CH" || *city.Source != "database:Debuglet-Test-City@1700000000" {
		t.Fatalf("client fallback: %+v %+v", city, country)
	}
	if m := e.IPMetadata(); m.Observed.ASN.Reason != "non_global" || m.Advertised.AddressSource != wire.SourceExecutorReported {
		t.Fatalf("source distinction: %+v", m)
	}
	e.collectIPMetadata(databases, true)
	if e.Display().City.Value != nil || e.Display().Country.Value != nil {
		t.Fatal("opt-out exposed automatic location")
	}
	e.collectIPMetadata(nil, false)
	if e.Display().City.Value != nil || e.IPMetadata().Advertised.ASN.Reason != "no_database" {
		t.Fatal("missing database invented value")
	}
	if !locationsDiffer(&wire.GeoLocation{Country: "CH"}, &wire.GeoLocation{Country: "DE"}) || locationsDiffer(&wire.GeoLocation{Country: "CH"}, &wire.GeoLocation{Country: "CH", City: "Fixture city"}) {
		t.Fatal("location disagreement mixed unknown values")
	}
}

// A database replaced while the dispatcher runs applies to registrations
// after the switch; the registered executor and admitted snapshots keep the
// values and source they were looked up with.
func TestIPMetadataReloadAppliesToLaterRegistrations(t *testing.T) {
	d, _, _ := newRegistryFixture(t)
	path := filepath.Join(t.TempDir(), "asn.mmdb")
	replace := func(fixture string) {
		t.Helper()
		data, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".staging", data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".staging", path); err != nil {
			t.Fatal(err)
		}
	}
	replace("../ipmetadata/testdata/asn.mmdb")
	databases, err := ipmetadata.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer databases.Close()
	if err = d.ConfigureIPMetadata(databases); err != nil {
		t.Fatal(err)
	}
	hello := registryHello("lab")
	host := "200.1.1.1"
	hello.PublicHost = &host
	register := func() *executorEntry {
		t.Helper()
		owner := registryOwner(t, "lab")
		t.Cleanup(func() { owner.Retire() })
		if err := registryRegisterWithSetup(t.Context(), d, owner, hello, "8.8.8.8"); err != nil {
			t.Fatal(err)
		}
		owner.MarkRegistered()
		return d.executors["lab"]
	}
	first := register()
	snapshot := admissionVantagePoint(first, time.Now())
	if v := first.IPMetadata().Advertised.ASN; v.Value == nil || v.Value.Number != 64500 || *v.Source != "database:Debuglet-Test-ASN@1700000000" {
		t.Fatalf("first registration: %+v", v)
	}

	replace("../ipmetadata/testdata/different.mmdb")
	if r := databases.Reload(); len(r) != 1 || r[0].Err != nil {
		t.Fatalf("reload: %+v", r)
	}
	if v := first.IPMetadata().Advertised.ASN; v.Value.Number != 64500 || *v.Source != "database:Debuglet-Test-ASN@1700000000" {
		t.Fatalf("the registered executor was looked up again: %+v", v)
	}
	if v := snapshot.IPMetadata.Advertised.ASN; v.Value.Number != 64500 || *v.Source != "database:Debuglet-Test-ASN@1700000000" {
		t.Fatalf("an admitted snapshot changed: %+v", v)
	}
	second := register()
	if v := second.IPMetadata().Advertised.ASN; v.Value == nil || v.Value.Number != 64501 || *v.Source != "database:Debuglet-Test-Different@1700000000" {
		t.Fatalf("re-registration after the reload: %+v", v)
	}
}
