// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ipmetadata

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

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

// install copies a fixture next to path and renames it over path, as the
// refresh timer does.
func install(t *testing.T, fixture, path string) {
	t.Helper()
	if err := replace(fixture, path); err != nil {
		t.Fatal(err)
	}
}

func replace(fixture, path string) error {
	data, err := os.ReadFile(fixture)
	if err != nil {
		return err
	}
	staging := path + ".staging"
	if err := os.WriteFile(staging, data, 0600); err != nil {
		return err
	}
	return os.Rename(staging, path)
}

func TestReloadReplacesRenamedDatabaseAndKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	asn, city := filepath.Join(dir, "asn.mmdb"), filepath.Join(dir, "city.mmdb")
	install(t, "testdata/asn.mmdb", asn)
	install(t, "testdata/city.mmdb", city)
	d, err := Open(asn, city)
	if err != nil {
		t.Fatal(err)
	}
	lookup := func() wire.AddressMetadata {
		return d.Lookup("200.1.1.1", wire.SourceDispatcherObserved, 1700000123, false)
	}
	before := lookup()
	if r := d.Reload(); len(r) != 0 {
		t.Fatalf("unchanged files reloaded: %+v", r)
	}

	install(t, "testdata/different.mmdb", asn)
	r := d.Reload()
	if len(r) != 1 || r[0].Kind != "asn" || r[0].Err != nil || r[0].Source != "database:Debuglet-Test-Different@1700000000" {
		t.Fatalf("reload: %+v", r)
	}
	after := lookup()
	if after.ASN.Value == nil || after.ASN.Value.Number != 64501 || *after.ASN.Source != "database:Debuglet-Test-Different@1700000000" {
		t.Fatalf("after reload: %+v", after.ASN)
	}
	// A value looked up earlier keeps its own source, and the city database
	// was not touched.
	if before.ASN.Value.Number != 64500 || *before.ASN.Source != "database:Debuglet-Test-ASN@1700000000" || after.Location.Value.City != "Fixture city" {
		t.Fatalf("earlier lookup or city changed: %+v %+v", before.ASN, after.Location)
	}

	// A malformed replacement is refused once and the previous database
	// stays in use.
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	install(t, bad, asn)
	r = d.Reload()
	if len(r) != 1 || r[0].Err == nil || r[0].Source != "database:Debuglet-Test-Different@1700000000" {
		t.Fatalf("malformed replacement: %+v", r)
	}
	if v := lookup(); v.ASN.Value == nil || v.ASN.Value.Number != 64501 {
		t.Fatalf("previous database dropped: %+v", v.ASN)
	}
	if r := d.Reload(); len(r) != 0 {
		t.Fatalf("the same refused file was reported again: %+v", r)
	}
	// So is a removed file, once.
	if err := os.Remove(asn); err != nil {
		t.Fatal(err)
	}
	if r := d.Reload(); len(r) != 1 || r[0].Err == nil {
		t.Fatalf("missing file: %+v", r)
	}
	if r := d.Reload(); len(r) != 0 {
		t.Fatalf("missing file reported again: %+v", r)
	}
	install(t, "testdata/asn.mmdb", asn)
	if r := d.Reload(); len(r) != 1 || r[0].Err != nil || r[0].Source != "database:Debuglet-Test-ASN@1700000000" {
		t.Fatalf("recovery: %+v", r)
	}

	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	install(t, "testdata/different.mmdb", asn)
	if r := d.Reload(); len(r) != 0 {
		t.Fatalf("reload after close: %+v", r)
	}
	if v := lookup(); v.ASN.Reason != "no_database" || v.ASN.Value != nil {
		t.Fatalf("lookup after close: %+v", v.ASN)
	}
}

// Lookups racing replacements always see one complete database: run with
// -race to check the swap.
func TestReloadDuringLookups(t *testing.T) {
	dir := t.TempDir()
	asn := filepath.Join(dir, "asn.mmdb")
	install(t, "testdata/asn.mmdb", asn)
	d, err := Open(asn, "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(t.Context())
	reports := make(chan Reloaded, 100)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		d.Watch(ctx, time.Millisecond, func(r Reloaded) {
			select {
			case reports <- r:
			default:
			}
		})
	}()
	done := make(chan error, 1)
	go func() {
		var err error
		for i := 0; i < 200 && err == nil; i++ {
			err = replace([]string{"testdata/different.mmdb", "testdata/asn.mmdb"}[i%2], asn)
			time.Sleep(100 * time.Microsecond)
		}
		done <- err
	}()
	for running := true; running; {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			running = false
		default:
		}
		v := d.Lookup("8.8.8.8", wire.SourceDispatcherObserved, 1, false).ASN
		if v.Value == nil || v.Value.Number != 64500 {
			t.Fatalf("lookup during reload: %+v", v)
		}
	}
	cancel()
	<-watched
	for len(reports) > 0 {
		if r := <-reports; r.Err != nil {
			t.Fatalf("atomic replacement refused: %+v", r)
		}
	}
}

func TestGlobalPrefix(t *testing.T) {
	for prefix, want := range map[string]bool{
		"11.0.0.0/8": true, "193.0.0.0/21": true, "8.8.8.8/32": true, "2a00:1::/32": true, "2001:200::/23": true,
		"10.0.0.0/8": false, "10.1.0.0/16": false, "8.0.0.0/4": false, "0.0.0.0/0": false, "192.0.0.0/8": false,
		"100.64.0.0/16": false, "224.0.0.0/8": false, "240.0.0.0/8": false, "198.51.100.0/25": false,
		"::/0": false, "2000::/3": false, "2001::/16": false, "2002::/16": false, "2001:db8:1::/48": false,
		"fc00::/7": false, "::ffff:11.0.0.0/104": false, "3fff::/20": false,
	} {
		if got := GlobalPrefix(netip.MustParsePrefix(prefix)); got != want {
			t.Errorf("GlobalPrefix(%s) = %t", prefix, got)
		}
	}
}
