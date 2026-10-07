// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// Package ris builds the dispatcher's ASN database from RIPE RIS routing data,
// the method RIPE Atlas uses for a probe's prefix and ASN: an address belongs
// to the longest prefix announced in BGP, and to that prefix's origin AS.
//
// The inputs are RIPE RIS's daily whois dumps, which list every (origin,
// prefix) pair in the combined RIS routing tables with the number of RIS peers
// that see it, and RIPE's list of AS names. A pair counts when at least
// MinPeers RIS peers see it; a prefix announced by several origins (MOAS) is
// attributed to the origin the most peers see, the lowest AS number on a tie.
package ris

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
)

const (
	// DefaultMinPeers is the visibility threshold: the number of RIS peers
	// that must see an (origin, prefix) pair. RIS has several hundred
	// full-table peers, so ten is a small fraction that still drops
	// prefixes only a handful of peers see: leaks, transient more-specifics
	// and peers' internal or default routes.
	DefaultMinPeers = 10

	// Minimum sizes of a usable build. Today's tables are roughly twice as
	// large; a smaller result means truncated or garbled input, or a
	// threshold that discards most of the table, and is refused.
	MinIPv4Prefixes = 500_000
	MinIPv6Prefixes = 100_000
	MinASNames      = 50_000

	// Shortest prefixes accepted. Nothing shorter is a real announcement;
	// default and other aggregate routes some peers export are.
	minIPv4Bits = 8
	minIPv6Bits = 16
)

// Row is one line of a RIS whois dump. Origin is 0 for an AS set with more
// than one member, whose origin is ambiguous.
type Row struct {
	Origin uint32
	Prefix netip.Prefix
	Peers  int
}

// Dump is one parsed RIS whois dump.
type Dump struct {
	Generated time.Time
	Rows      []Row
}

const (
	generatedPrefix = "% This file was generated at "
	endOfDump       = "% End of dump"
)

// ParseDump reads a decompressed riswhoisdump file of one address family. It
// refuses a file without its generation time or end marker, and any line it
// cannot read, rather than build from part of a table.
func ParseDump(r io.Reader, ipv6 bool) (Dump, error) {
	var out Dump
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	line, ended := 0, false
	for scanner.Scan() {
		line++
		text := scanner.Text()
		switch {
		case strings.TrimSpace(text) == "":
			continue
		case ended:
			return Dump{}, fmt.Errorf("line %d: content after %q", line, endOfDump)
		case strings.HasPrefix(text, generatedPrefix):
			stamp := strings.TrimSuffix(strings.TrimPrefix(text, generatedPrefix), ".")
			at, err := time.Parse("Mon Jan _2 15:04:05 MST 2006", stamp)
			if err != nil || !out.Generated.IsZero() {
				return Dump{}, fmt.Errorf("line %d: unreadable or repeated generation time %q", line, stamp)
			}
			out.Generated = at.UTC()
			continue
		case strings.TrimSpace(text) == endOfDump:
			ended = true
			continue
		case strings.HasPrefix(text, "%"):
			continue
		}
		row, err := parseRow(text, ipv6)
		if err != nil {
			return Dump{}, fmt.Errorf("line %d: %w", line, err)
		}
		out.Rows = append(out.Rows, row)
	}
	if err := scanner.Err(); err != nil {
		return Dump{}, fmt.Errorf("line %d: %w", line+1, err)
	}
	if out.Generated.IsZero() {
		return Dump{}, errors.New("dump has no generation time")
	}
	if !ended {
		return Dump{}, fmt.Errorf("dump is truncated: no %q line", endOfDump)
	}
	return out, nil
}

func parseRow(text string, ipv6 bool) (Row, error) {
	fields := strings.Split(text, "\t")
	if len(fields) != 3 {
		return Row{}, fmt.Errorf("expected origin, prefix and peer count, got %q", text)
	}
	origin, err := parseOrigin(fields[0])
	if err != nil {
		return Row{}, err
	}
	prefix, err := netip.ParsePrefix(fields[1])
	if err != nil || prefix.Addr().Is6() != ipv6 || prefix != prefix.Masked() {
		return Row{}, fmt.Errorf("invalid prefix %q for this address family", fields[1])
	}
	peers, err := strconv.Atoi(fields[2])
	if err != nil || peers < 1 || strconv.Itoa(peers) != fields[2] {
		return Row{}, fmt.Errorf("invalid peer count %q", fields[2])
	}
	return Row{Origin: origin, Prefix: prefix, Peers: peers}, nil
}

// parseOrigin accepts an AS number or an AS set in braces. A set with one
// distinct member names that origin; a larger set is ambiguous (0).
func parseOrigin(s string) (uint32, error) {
	members, set := strings.CutPrefix(s, "{")
	if set {
		var ok bool
		if members, ok = strings.CutSuffix(members, "}"); !ok {
			return 0, fmt.Errorf("invalid origin %q", s)
		}
	}
	var origin uint32
	for _, member := range strings.Split(members, ",") {
		n, err := strconv.ParseUint(member, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != member || !set && strings.Contains(s, ",") {
			return 0, fmt.Errorf("invalid origin %q", s)
		}
		if origin != 0 && origin != uint32(n) {
			return 0, nil
		}
		origin = uint32(n)
	}
	return origin, nil
}

// ParseASNames reads RIPE's asn.txt: one "<number> <name>" per line. A name
// that is not printable text is dropped, leaving the AS unnamed; a name longer
// than the 128 characters the dispatcher accepts is shortened.
func ParseASNames(r io.Reader) (map[uint32]string, error) {
	names := map[uint32]string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 4096), 4096)
	line := 0
	for scanner.Scan() {
		line++
		text := scanner.Text()
		if strings.TrimSpace(text) == "" {
			continue
		}
		number, name, _ := strings.Cut(text, " ")
		n, err := strconv.ParseUint(number, 10, 32)
		if err != nil || strconv.FormatUint(n, 10) != number {
			return nil, fmt.Errorf("line %d: invalid AS number %q", line, number)
		}
		if _, ok := names[uint32(n)]; ok {
			return nil, fmt.Errorf("line %d: AS%d is listed twice", line, n)
		}
		names[uint32(n)] = cleanName(name)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return names, nil
}

func cleanName(name string) string {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || strings.IndexFunc(name, func(r rune) bool { return !unicode.IsPrint(r) }) >= 0 {
		return ""
	}
	if runes := []rune(name); len(runes) > 128 {
		name = strings.TrimSpace(string(runes[:128]))
	}
	return name
}

// Route is a selected prefix and the origin it is attributed to.
type Route struct {
	Prefix netip.Prefix
	Origin uint32
}

// Stats counts what Select kept and why it discarded rows.
type Stats struct {
	Rows, BelowThreshold, ASSets, ReservedOrigin, Unroutable int
	IPv4, IPv6, MOAS                                         int
}

// Select keeps the (origin, prefix) pairs at least minPeers RIS peers see,
// whose origin is a public AS and whose prefix is global unicast, and
// attributes each prefix to one origin: the one the most peers see, the
// lowest AS number on a tie. The result is sorted by prefix length, then
// address.
func Select(rows []Row, minPeers int) ([]Route, Stats) {
	type choice struct {
		origin uint32
		peers  int
		moas   bool
	}
	best := map[netip.Prefix]*choice{}
	var stats Stats
	for _, row := range rows {
		stats.Rows++
		switch {
		case row.Origin == 0:
			stats.ASSets++
		case !PublicASN(row.Origin):
			stats.ReservedOrigin++
		case row.Peers < minPeers:
			stats.BelowThreshold++
		case !routable(row.Prefix):
			stats.Unroutable++
		default:
			c := best[row.Prefix]
			if c == nil {
				best[row.Prefix] = &choice{origin: row.Origin, peers: row.Peers}
				continue
			}
			c.moas = c.moas || c.origin != row.Origin
			if row.Peers > c.peers || row.Peers == c.peers && row.Origin < c.origin {
				c.origin, c.peers = row.Origin, row.Peers
			}
		}
	}
	routes := make([]Route, 0, len(best))
	for prefix, c := range best {
		routes = append(routes, Route{Prefix: prefix, Origin: c.origin})
		if prefix.Addr().Is4() {
			stats.IPv4++
		} else {
			stats.IPv6++
		}
		if c.moas {
			stats.MOAS++
		}
	}
	slices.SortFunc(routes, func(a, b Route) int {
		if a.Prefix.Bits() != b.Prefix.Bits() {
			return a.Prefix.Bits() - b.Prefix.Bits()
		}
		return a.Prefix.Addr().Compare(b.Prefix.Addr())
	})
	return routes, stats
}

func routable(p netip.Prefix) bool {
	if p.Addr().Is4() && p.Bits() < minIPv4Bits || p.Addr().Is6() && p.Bits() < minIPv6Bits {
		return false
	}
	return ipmetadata.GlobalPrefix(p)
}

// PublicASN reports whether n is outside the AS numbers IANA reserves for
// private use, documentation, AS_TRANS and future use.
func PublicASN(n uint32) bool {
	switch {
	case n == 0, n == 23456, n >= 64496 && n <= 131071, n >= 4200000000:
		return false
	}
	return true
}

// requireFinalNewline refuses a text file whose last line is cut short.
func requireFinalNewline(data []byte) error {
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		return errors.New("file is truncated: the last line has no newline")
	}
	return nil
}
