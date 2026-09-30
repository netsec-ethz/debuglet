// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package ipmetadata performs offline ASN and approximate location lookups.
// It does not resolve names or contact any network service.
package ipmetadata

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/pkg/wire"
	"github.com/oschwald/maxminddb-golang/v2"
)

// Databases remain immutable until Close, after dispatcher shutdown. The caller
// must atomically replace database files, never rewrite a mapped file in place.
type Databases struct{ asn, city *maxminddb.Reader }

func Open(asnPath, cityPath string) (*Databases, error) {
	out := &Databases{}
	for _, item := range []struct {
		path string
		dst  **maxminddb.Reader
	}{{asnPath, &out.asn}, {cityPath, &out.city}} {
		if item.path == "" {
			continue
		}
		reader, err := maxminddb.Open(item.path)
		if err == nil {
			err = reader.Verify()
		}
		if err == nil && !wire.DatabaseSource(source(reader)) {
			err = errors.New("database must have a printable database_type and positive build_epoch")
		}
		if err != nil {
			if reader != nil {
				_ = reader.Close()
			}
			_ = out.Close()
			return nil, fmt.Errorf("open metadata database %q: %w", item.path, err)
		}
		*item.dst = reader
	}
	return out, nil
}

func (d *Databases) Close() error {
	if d == nil {
		return nil
	}
	var errs []error
	for _, r := range []*maxminddb.Reader{d.asn, d.city} {
		if r != nil {
			errs = append(errs, r.Close())
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
	default:
		ip = ip.Unmap()
		if d != nil && d.asn != nil {
			out.ASN = lookupASN(d.asn, ip, observedAt)
		}
		if !optOut && d != nil && d.city != nil {
			out.Location = lookupCity(d.city, ip, observedAt)
		}
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
	}
	result := db.Lookup(ip)
	if err := result.Decode(&record); err != nil {
		out.Reason = "lookup_error"
		return out
	}
	if !result.Found() {
		return out
	}
	if record.Number == 0 || record.Name == "" || !text(record.Name, 128) {
		out.Reason = "invalid_record"
		return out
	}
	out.Value = &wire.ASInfo{Number: record.Number, Name: record.Name, Prefix: result.Prefix().String()}
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
