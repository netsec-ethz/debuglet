// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ris

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// DatabaseType names the database in its metadata, and so in the
// database:<type>@<build_epoch> source of every value looked up in it.
const DatabaseType = "Debuglet-RIS-ASN"

// Write encodes routes as an MMDB in the GeoIP2-ASN-compatible layout the
// dispatcher reads: autonomous_system_number and, when RIPE lists a name,
// autonomous_system_organization. announced_prefix_length records the length
// of the announced prefix, which a more-specific prefix carved out of it would
// otherwise hide. routes must be sorted by prefix length, as Select returns
// them, so that a more-specific prefix replaces its covering one.
func Write(w io.Writer, routes []Route, names map[uint32]string, buildEpoch int64, minPeers int) error {
	tree, err := mmdbwriter.New(mmdbwriter.Options{
		DatabaseType: DatabaseType,
		Description: map[string]string{"en": "Origin AS of the longest matching prefix announced in BGP and seen by at least " +
			strconv.Itoa(minPeers) + " RIPE RIS peers; built from RIPE RIS riswhoisdump and RIPE asnames"},
		Languages:  []string{"en"},
		BuildEpoch: buildEpoch,
		IPVersion:  6,
		RecordSize: 28,
		// Lookup refuses non-global addresses itself and unmaps IPv4-mapped
		// addresses, and Select keeps only global prefixes.
		DisableIPv4Aliasing:     true,
		IncludeReservedNetworks: true,
		KeyGenerator:            recordKey{},
	})
	if err != nil {
		return err
	}
	values := map[[2]uint32]mmdbtype.Map{}
	var previous [2]int // per family: IPv4 lives at ::/96, apart from IPv6
	for _, route := range routes {
		family := 0
		if route.Prefix.Addr().Is6() {
			family = 1
		}
		if route.Prefix.Bits() < previous[family] {
			return errors.New("routes are not sorted by prefix length")
		}
		previous[family] = route.Prefix.Bits()
		key := [2]uint32{route.Origin, uint32(route.Prefix.Bits())}
		value, ok := values[key]
		if !ok {
			value = mmdbtype.Map{
				"autonomous_system_number": mmdbtype.Uint32(route.Origin),
				"announced_prefix_length":  mmdbtype.Uint16(route.Prefix.Bits()),
			}
			if name := names[route.Origin]; name != "" {
				value["autonomous_system_organization"] = mmdbtype.String(name)
			}
			values[key] = value
		}
		network := &net.IPNet{IP: route.Prefix.Addr().AsSlice(), Mask: net.CIDRMask(route.Prefix.Bits(), route.Prefix.Addr().BitLen())}
		if err := tree.Insert(network, value); err != nil {
			return fmt.Errorf("insert %s: %w", route.Prefix, err)
		}
	}
	_, err = tree.WriteTo(w)
	return err
}

// recordKey identifies a record by its AS number and announced prefix length,
// which determine it, instead of hashing its serialisation on every insert.
type recordKey struct{}

func (recordKey) Key(value mmdbtype.DataType) ([]byte, error) {
	m, ok := value.(mmdbtype.Map)
	if !ok {
		return nil, fmt.Errorf("unexpected record type %T", value)
	}
	asn, ok1 := m["autonomous_system_number"].(mmdbtype.Uint32)
	bits, ok2 := m["announced_prefix_length"].(mmdbtype.Uint16)
	if !ok1 || !ok2 {
		return nil, errors.New("record lacks its AS number or prefix length")
	}
	return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint32(nil, uint32(asn)), uint16(bits)), nil
}

// Verify opens path with the dispatcher's own loader and looks up the first
// address of every route. Each must resolve to a selected route at least as
// specific as the one looked up, with that route's origin and name, under
// this build's source. It is the check a file passes before it replaces the
// database in use.
func Verify(path string, routes []Route, names map[uint32]string, buildEpoch int64) error {
	db, err := ipmetadata.Open(path, "")
	if err != nil {
		return err
	}
	defer db.Close()
	selected := make(map[netip.Prefix]uint32, len(routes))
	for _, route := range routes {
		selected[route.Prefix] = route.Origin
	}
	want := "database:" + DatabaseType + "@" + strconv.FormatInt(buildEpoch, 10)
	for _, route := range routes {
		got := db.Lookup(route.Prefix.Addr().String(), wire.SourceDispatcherObserved, 0, true).ASN
		if got.Value == nil || got.Source == nil || *got.Source != want {
			return fmt.Errorf("%s does not resolve in the written database (%s)", route.Prefix, got.Reason)
		}
		prefix, err := netip.ParsePrefix(got.Value.Prefix)
		origin, ok := selected[prefix]
		if err != nil || !ok || prefix.Bits() < route.Prefix.Bits() || !prefix.Contains(route.Prefix.Addr()) {
			return fmt.Errorf("%s resolves to %s, which was not selected for it", route.Prefix, got.Value.Prefix)
		}
		if got.Value.Number != origin || got.Value.Name != names[origin] {
			return fmt.Errorf("%s resolves to AS%d %q, want AS%d %q", prefix, got.Value.Number, got.Value.Name, origin, names[origin])
		}
	}
	return nil
}
