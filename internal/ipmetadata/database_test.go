// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ipmetadata

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestOfflineMetadataProvenanceAndPrivacy(t *testing.T) {
	d, err := Open("testdata/asn.mmdb", "testdata/city.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	// Only synthetic fixture lookup; no network contact occurs.
	got := d.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false)
	if got.ASN.Value == nil || got.ASN.Value.Number != 64500 || got.ASN.Value.Name != "Synthetic network" || *got.ASN.Source != "database:Debuglet-Test-ASN@1700000000" || got.ASN.ObservedAt != 1700000123 {
		t.Fatalf("ASN: %+v", got.ASN)
	}
	if got.Location.Value == nil || got.Location.Value.Country != "CH" || got.Location.Value.City != "Fixture city" || got.Location.Value.Precision != "city" || *got.Location.Source != "database:Debuglet-Test-City@1700000000" {
		t.Fatalf("location: %+v", got.Location)
	}
	mapped := d.Lookup("::ffff:8.8.8.8", wire.SourceExecutorReported, 1700000123, false)
	if mapped.ASN.Value == nil || mapped.ASN.Value.Number != 64500 {
		t.Fatalf("mapped IPv4: %+v", mapped)
	}
	opted := d.Lookup("8.8.8.8", wire.SourceExecutorReported, 1700000123, true)
	if opted.Location.Value != nil || opted.Location.Source != nil || opted.Location.Reason != "opted_out" || opted.ASN.Value == nil {
		t.Fatalf("optout: %+v", opted)
	}
	for _, address := range []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1", "::1", "fc00::1", "fe80::1", "192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1", "2001:db8::1", "0.1.2.3", "240.0.0.1", "2002:808:808::1", "3fff::1"} {
		v := d.Lookup(address, wire.SourceDispatcherObserved, 1700000123, false)
		if v.ASN.Value != nil || v.Location.Value != nil || v.ASN.Reason != "non_global" || v.Location.Reason != "non_global" || v.ASN.Source != nil {
			t.Errorf("non-global %s: %+v", address, v)
		}
	}
	for _, address := range []string{"", "example.test"} {
		v := d.Lookup(address, wire.SourceExecutorReported, 1700000123, false)
		if v.ASN.Value != nil || v.Location.Value != nil || v.ASN.Source != nil {
			t.Errorf("unknown address %q: %+v", address, v)
		}
	}
	var absent *Databases
	if v := absent.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false); v.ASN.Reason != "no_database" || v.Location.Reason != "no_database" {
		t.Fatalf("no database: %+v", v)
	}
}

func TestDatabaseValidationAndCountryPrecision(t *testing.T) {
	empty, err := Open("testdata/empty.mmdb", "testdata/empty.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	missing := empty.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false)
	if missing.ASN.Reason != "not_found" || missing.Location.Reason != "not_found" || missing.ASN.Value != nil || missing.ASN.Source == nil {
		t.Fatalf("missing data: %+v", missing)
	}

	d, err := Open("", "testdata/country.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	v := d.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false)
	if v.Location.Value == nil || v.Location.Value.Precision != "country" || v.Location.Value.City != "" {
		t.Fatalf("country precision: %+v", v.Location)
	}
	bad, err := Open("testdata/invalid.mmdb", "testdata/invalid.mmdb")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	invalid := bad.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1700000123, false)
	if invalid.ASN.Reason != "invalid_record" || invalid.Location.Reason != "invalid_record" {
		t.Fatalf("invalid values: %+v", invalid)
	}
	path := filepath.Join(t.TempDir(), "bad.mmdb")
	if err := os.WriteFile(path, []byte("bad"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, ""); err == nil {
		t.Fatal("malformed database accepted")
	}
	if _, err := Open("testdata/asn.mmdb", path); err == nil {
		t.Fatal("second malformed database accepted")
	}
	if _, err := Open("missing.mmdb", ""); err == nil {
		t.Fatal("missing database accepted")
	}
	for _, address := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		if !Global(netip.MustParseAddr(address)) {
			t.Fatalf("global address rejected: %s", address)
		}
	}
}
