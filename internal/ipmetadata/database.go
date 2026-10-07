// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package ipmetadata performs offline ASN and approximate location lookups.
// It does not resolve names or contact any network service.
package ipmetadata

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Databases holds the configured readers. Reload replaces a reader whose file
// was atomically renamed over; a lookup in progress keeps the reader it
// started with, which is closed only after that lookup returns. Never rewrite
// or truncate a mapped file in place.
type Databases struct {
	reloading sync.Mutex // serialises Reload
	mu        sync.RWMutex
	asn, city database
	closed    bool
}

// database is one configured file. identity describes the file the reader
// was opened from, failed the last replacement that was refused and missing
// whether the path was last found absent, so that the same broken or missing
// file is reported once rather than on every check.
type database struct {
	kind, path       string
	reader           *maxminddb.Reader
	identity, failed os.FileInfo
	missing          bool
}

func Open(asnPath, cityPath string) (*Databases, error) {
	out := &Databases{asn: database{kind: "asn", path: asnPath}, city: database{kind: "city", path: cityPath}}
	for _, item := range []*database{&out.asn, &out.city} {
		if item.path == "" {
			continue
		}
		reader, identity, err := openDatabase(item.path)
		if err != nil {
			_ = out.Close()
			return nil, err
		}
		item.reader, item.identity = reader, identity
	}
	return out, nil
}

// openDatabase opens and verifies one file. The file is examined before and
// after it is mapped, so a rename racing the open is refused rather than
// recorded under the wrong identity.
func openDatabase(path string) (*maxminddb.Reader, os.FileInfo, error) {
	before, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open metadata database %q: %w", path, err)
	}
	reader, err := maxminddb.Open(path)
	if err == nil {
		err = reader.Verify()
	}
	if err == nil && !wire.DatabaseSource(source(reader)) {
		err = errors.New("database must have a printable database_type and positive build_epoch")
	}
	if err == nil {
		after, statErr := os.Stat(path)
		if statErr != nil {
			err = statErr
		} else if !sameFile(before, after) {
			err = errReplaced
		}
	}
	if err != nil {
		if reader != nil {
			_ = reader.Close()
		}
		return nil, nil, fmt.Errorf("open metadata database %q: %w", path, err)
	}
	return reader, before, nil
}

// errReplaced is transient: the next check opens the file now in place.
var errReplaced = errors.New("file was replaced while it was being opened")

func sameFile(a, b os.FileInfo) bool {
	return a != nil && b != nil && os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// Reloaded reports one replacement attempt: Source names the database now in
// use, and Err why a replacement was refused, in which case the previous
// database stays in use.
type Reloaded struct {
	Kind, Path, Source string
	Err                error
}

// Reload reopens each configured database whose file is no longer the one it
// was opened from, typically because a new file was renamed into place. A
// replacement is validated as at startup before it is swapped in; when it is
// refused, the previous database stays in use. Lookups made afterwards use the
// new database; values already looked up keep their own source.
func (d *Databases) Reload() []Reloaded {
	if d == nil {
		return nil
	}
	d.reloading.Lock()
	defer d.reloading.Unlock()
	var out []Reloaded
	for _, item := range []*database{&d.asn, &d.city} {
		if r, ok := d.reload(item); ok {
			out = append(out, r)
		}
	}
	return out
}

func (d *Databases) reload(item *database) (Reloaded, bool) {
	d.mu.RLock()
	path, current, failed, missing, closed := item.path, item.identity, item.failed, item.missing, d.closed
	d.mu.RUnlock()
	if path == "" || closed {
		return Reloaded{}, false
	}
	report := Reloaded{Kind: item.kind, Path: path}
	now, err := os.Stat(path)
	if err == nil && (sameFile(now, current) || sameFile(now, failed)) || err != nil && missing {
		return Reloaded{}, false
	}
	var reader *maxminddb.Reader
	var opened os.FileInfo
	if err == nil {
		reader, opened, err = openDatabase(path)
	} else {
		err = fmt.Errorf("open metadata database %q: %w", path, err)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		if reader != nil {
			_ = reader.Close()
		}
		return Reloaded{}, false
	}
	if errors.Is(err, errReplaced) {
		return Reloaded{}, false
	}
	if err != nil {
		item.failed, item.missing = now, now == nil
		if item.reader != nil {
			report.Source = source(item.reader)
		}
		report.Err = err
		return report, true
	}
	previous := item.reader
	item.reader, item.identity, item.failed, item.missing = reader, opened, nil, false
	report.Source = source(reader)
	if previous != nil {
		_ = previous.Close()
	}
	return report, true
}

// Watch calls Reload every interval until ctx ends and passes each result to
// report. Executors are looked up again when they (re)register, so a
// replacement applies to registrations after it.
func (d *Databases) Watch(ctx context.Context, interval time.Duration, report func(Reloaded)) {
	if d == nil || interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, r := range d.Reload() {
				report(r)
			}
		}
	}
}

func (d *Databases) Close() error {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	var errs []error
	for _, item := range []*database{&d.asn, &d.city} {
		if item.reader != nil {
			errs = append(errs, item.reader.Close())
			item.reader = nil
		}
	}
	return errors.Join(errs...)
}

func source(r *maxminddb.Reader) string {
	return "database:" + r.Metadata.DatabaseType + "@" + strconv.FormatUint(uint64(r.Metadata.BuildEpoch), 10)
}

// Lookup accepts literal global addresses only. A hostname is unknown without
// a DNS lookup. IPv4-mapped IPv6 is treated as IPv4.
func (d *Databases) Lookup(address, addressSource string, observedAt int64, optOut bool) wire.AddressMetadata {
	out := wire.AddressMetadata{AddressSource: addressSource,
		ASN:      wire.IPLookup[wire.ASInfo]{ObservedAt: observedAt, Reason: "no_database"},
		Location: wire.IPLookup[wire.GeoLocation]{ObservedAt: observedAt, Reason: "no_database"}}
	ip, err := netip.ParseAddr(address)
	switch {
	case address == "":
		out.ASN.Reason, out.Location.Reason = "no_address", "no_address"
	case err != nil || ip.Zone() != "":
		out.ASN.Reason, out.Location.Reason = "not_ip", "not_ip"
	case !Global(ip):
		out.ASN.Reason, out.Location.Reason = "non_global", "non_global"
	case d != nil:
		ip = ip.Unmap()
		d.mu.RLock()
		if d.asn.reader != nil {
			out.ASN = lookupASN(d.asn.reader, ip, observedAt)
		}
		if !optOut && d.city.reader != nil {
			out.Location = lookupCity(d.city.reader, ip, observedAt)
		}
		d.mu.RUnlock()
	}
	if optOut {
		out.Location = wire.IPLookup[wire.GeoLocation]{ObservedAt: observedAt, Reason: "opted_out"}
	}
	return out
}

func lookupASN(db *maxminddb.Reader, ip netip.Addr, at int64) wire.IPLookup[wire.ASInfo] {
	src := source(db)
	out := wire.IPLookup[wire.ASInfo]{Source: &src, ObservedAt: at, Reason: "not_found"}
	var record struct {
		Number uint32 `maxminddb:"autonomous_system_number"`
		Name   string `maxminddb:"autonomous_system_organization"`
		// Optional: the length of the announced prefix the record was
		// built from. The tree node is narrower where more-specific
		// prefixes are carved out of it, and wider where adjacent
		// prefixes with equal records are merged.
		Announced uint16 `maxminddb:"announced_prefix_length"`
	}
	result := db.Lookup(ip)
	if err := result.Decode(&record); err != nil {
		out.Reason = "lookup_error"
		return out
	}
	if !result.Found() {
		return out
	}
	// An unnamed AS is a known number with an unknown name.
	prefix := result.Prefix()
	if record.Announced != 0 {
		prefix = netip.PrefixFrom(ip, int(record.Announced)).Masked()
	}
	if record.Number == 0 || record.Name != "" && !text(record.Name, 128) || !prefix.IsValid() {
		out.Reason = "invalid_record"
		return out
	}
	out.Value = &wire.ASInfo{Number: record.Number, Name: record.Name, Prefix: prefix.String()}
	out.Reason = ""
	return out
}

func lookupCity(db *maxminddb.Reader, ip netip.Addr, at int64) wire.IPLookup[wire.GeoLocation] {
	src := source(db)
	out := wire.IPLookup[wire.GeoLocation]{Source: &src, ObservedAt: at, Reason: "not_found"}
	var record struct {
		Country struct {
			Code string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		City struct {
			Names struct {
				English string `maxminddb:"en"`
			} `maxminddb:"names"`
		} `maxminddb:"city"`
	}
	result := db.Lookup(ip)
	if err := result.Decode(&record); err != nil {
		out.Reason = "lookup_error"
		return out
	}
	if !result.Found() {
		return out
	}
	country, city := record.Country.Code, record.City.Names.English
	if len(country) != 2 || country[0] < 'A' || country[0] > 'Z' || country[1] < 'A' || country[1] > 'Z' || !text(city, 64) {
		out.Reason = "invalid_record"
		return out
	}
	precision := "country"
	if city != "" {
		precision = "city"
	}
	out.Value = &wire.GeoLocation{Country: country, City: city, Precision: precision}
	out.Reason = ""
	return out
}

func text(s string, limit int) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > limit || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Non-global special-purpose ranges that IsGlobalUnicast deliberately includes.
// Restrict IPv6 to currently allocated global unicast (2000::/3); exclude
// documentation, benchmarking and transition space rather than guessing.
var nonGlobal = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}
var globalV6 = netip.MustParsePrefix("2000::/3")

func Global(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.Zone() != "" || ip.Is6() && !globalV6.Contains(ip) {
		return false
	}
	for _, prefix := range nonGlobal {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

// excluded adds to nonGlobal the ranges Global excludes through the netip
// predicates.
var excluded = append([]netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
}, nonGlobal...)

// GlobalPrefix reports whether every address in p is global as Global
// defines it, so that a database never holds a record Lookup cannot reach.
func GlobalPrefix(p netip.Prefix) bool {
	if !p.IsValid() || p.Addr().Is4In6() || p.Addr().Zone() != "" {
		return false
	}
	p = p.Masked()
	last := p.Addr().AsSlice()
	for i := range last {
		if host := p.Bits() - 8*i; host <= 0 {
			last[i] = 0xff
		} else if host < 8 {
			last[i] |= 0xff >> host
		}
	}
	end, _ := netip.AddrFromSlice(last)
	if !Global(p.Addr()) || !Global(end) {
		return false
	}
	for _, q := range excluded {
		if p.Overlaps(q) {
			return false
		}
	}
	return true
}
