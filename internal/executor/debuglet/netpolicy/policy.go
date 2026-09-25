// Copyright 2025 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netpolicy holds the one network policy the executor applies to guest
// traffic: which transports a guest may use, which destinations it may reach,
// and on which ports. It has two halves that are always checked together. The
// operator half comes from the executor configuration and denies destinations
// and transports regardless of what a job asks for; the job half is the
// destination list the submitter declared for one run.
//
// The package deliberately takes plain strings and addresses rather than
// configuration or scheduler types, so the same rules can be applied before a
// connect, before a handshake, on an accepted connection, and on a received
// datagram, without those call sites sharing anything but this package.
package netpolicy

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Transport identifies one guest transport. Every enforcement point names the
// transport it is about, so a capability switch and an error message can be
// specific about which path was refused.
type Transport uint8

const (
	TCP Transport = iota
	TLS
	UDP
	ICMP
	SCION
	// Inbound covers accepted TCP connections and datagrams received on the
	// job's UDP listener: traffic a peer starts, not the guest.
	Inbound
	numTransports
)

var transportNames = [numTransports]string{"tcp", "tls", "udp", "icmp", "scion", "inbound"}

func (t Transport) String() string {
	if int(t) >= len(transportNames) {
		return "unknown"
	}
	return transportNames[t]
}

// Refusals. Every enforcement point wraps one of these, so a caller can tell a
// policy refusal from a network failure without matching on message text.
var (
	// ErrTransportUnavailable is a transport the operator disabled, one the
	// job did not request, or one whose host privileges are missing.
	ErrTransportUnavailable = errors.New("transport unavailable")
	// ErrDenied is an operator denial: a reserved or internal range, an
	// opted-out destination, or a port outside the permitted ranges.
	ErrDenied = errors.New("denied by the operator network policy")
	// ErrNotInPolicy is an address the job did not declare.
	ErrNotInPolicy = errors.New("outside the job's destination policy")
)

// Spec is the operator policy as the configuration file writes it. It is
// plain data: the configuration package resolves omitted keys to their
// documented defaults and hands the result here.
//
// The zero Spec disables every transport, which is what an unconfigured
// executor should do rather than fall open.
type Spec struct {
	// Per-transport capability switches.
	TCP, TLS, UDP, ICMP, SCION, Inbound bool
	// LocalTargets re-allows loopback destinations, which the reserved-range
	// rule denies. It is the local profile's switch and nothing else: link
	// local, private and unique-local ranges stay denied.
	LocalTargets bool
	// DeniedDestinations are additional operator denials as a comma-separated
	// list of CIDR blocks, IP addresses and DNS names.
	DeniedDestinations string
	// PermittedPorts are the destination ports a guest may reach, written as
	// the same comma-separated ranges as the listener pool. Empty permits
	// every port.
	PermittedPorts string
}

// Defaults is the policy an executor applies where its configuration says
// nothing: the transports this build supports are on, SCION is off because it
// cannot be held to the same contract, and every reserved or internal range is
// denied on every port.
//
// Loopback is denied with them. An executor that measures against services on
// its own host — the local, wallet-free profile — has to say so with
// local_targets, so that a deployment which never writes the section cannot be
// asked by a submitter to reach the services behind its own loopback
// interface.
func Defaults() Spec {
	return Spec{
		TCP:     true,
		TLS:     true,
		UDP:     true,
		ICMP:    true,
		SCION:   false,
		Inbound: true,
	}
}

// Operator is a compiled operator policy. It is immutable once parsed and
// safe for concurrent use.
type Operator struct {
	enabled      [numTransports]bool
	localTargets bool
	denied       []netip.Prefix
	deniedHosts  []string
	ports        []portRange
}

type portRange struct{ lo, hi int }

// reserved are the ranges no guest reaches in any profile: this host, private
// and carrier-grade address space, link-local addresses including the cloud
// metadata address, protocol assignments, benchmarking space, the ranges
// reserved for documentation and examples, the 6to4 relay anycast prefix,
// multicast and the reserved remainder. Loopback is in this list and is
// re-allowed only by the local profile's switch.
var reserved = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"2001:db8::/32",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

var loopback = mustPrefixes("127.0.0.0/8", "::1/128")

// nat64, sixToFour and compatible carry an IPv4 address inside an IPv6 one. An
// address in any of them is checked as both, so the IPv4 rules cannot be
// stepped around by writing the destination in its IPv6 form.
var (
	nat64      = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour  = netip.MustParsePrefix("2002::/16")
	compatible = netip.MustParsePrefix("::/96")
)

func mustPrefixes(texts ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(texts))
	for _, text := range texts {
		prefixes = append(prefixes, netip.MustParsePrefix(text))
	}
	return prefixes
}

// Parse compiles a Spec. It reports the first unusable value, naming the
// configuration key, so an operator can correct the file.
func Parse(spec Spec) (Operator, error) {
	op := Operator{localTargets: spec.LocalTargets}
	op.enabled[TCP] = spec.TCP
	op.enabled[TLS] = spec.TLS
	op.enabled[UDP] = spec.UDP
	op.enabled[ICMP] = spec.ICMP
	op.enabled[SCION] = spec.SCION
	op.enabled[Inbound] = spec.Inbound

	for _, entry := range splitList(spec.DeniedDestinations) {
		switch {
		case strings.Contains(entry, "/"):
			prefix, err := netip.ParsePrefix(entry)
			if err != nil {
				return Operator{}, fmt.Errorf("denied_destinations: %q is not a CIDR block: %w", entry, err)
			}
			op.denied = append(op.denied, prefix.Masked())
		default:
			if addr, err := netip.ParseAddr(entry); err == nil {
				op.denied = append(op.denied, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
				continue
			}
			host := strings.ToLower(strings.TrimSuffix(entry, "."))
			if host == "" || strings.ContainsAny(host, " /:,") {
				return Operator{}, fmt.Errorf("denied_destinations: %q is not a CIDR block, an IP address or a DNS name", entry)
			}
			op.deniedHosts = append(op.deniedHosts, host)
		}
	}

	ports, err := parsePortRanges(spec.PermittedPorts)
	if err != nil {
		return Operator{}, fmt.Errorf("permitted_ports: %w", err)
	}
	op.ports = ports
	return op, nil
}

func splitList(list string) []string {
	var entries []string
	for _, entry := range strings.Split(list, ",") {
		if entry = strings.TrimSpace(entry); entry != "" {
			entries = append(entries, entry)
		}
	}
	return entries
}

// parsePortRanges reads "80,443,8000-8100". An empty specification permits
// every port and is stored as no ranges at all.
func parsePortRanges(spec string) ([]portRange, error) {
	var ranges []portRange
	for _, part := range splitList(spec) {
		lo, hi, found := strings.Cut(part, "-")
		low, err := parsePort(lo)
		if err != nil {
			return nil, err
		}
		high := low
		if found {
			if high, err = parsePort(hi); err != nil {
				return nil, err
			}
		}
		if low > high {
			return nil, fmt.Errorf("invalid port range %q: start %d is greater than end %d", part, low, high)
		}
		ranges = append(ranges, portRange{lo: low, hi: high})
	}
	return ranges, nil
}

func parsePort(text string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil {
		return 0, fmt.Errorf("invalid port %q", strings.TrimSpace(text))
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port %d: must be between 1 and 65535", port)
	}
	return port, nil
}

// Enabled reports whether the operator left transport t switched on.
func (o Operator) Enabled(t Transport) bool {
	return int(t) < len(o.enabled) && o.enabled[t]
}

// CheckAddr applies the operator's destination rules to one address. It is the
// rule that holds whatever a job declared: a destination the operator denies
// is never reached, on any transport.
func (o Operator) CheckAddr(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrDenied)
	}
	for _, alias := range aliases(addr) {
		if err := o.checkOne(alias, addr); err != nil {
			return err
		}
	}
	return nil
}

// checkOne checks one spelling of the destination. reported is the address the
// caller asked about, so an error names what the guest wrote rather than the
// derived form that matched.
func (o Operator) checkOne(addr, reported netip.Addr) error {
	for _, prefix := range o.denied {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: %s is in the denied range %s", ErrDenied, reported, prefix)
		}
	}
	if o.localTargets && contains(loopback, addr) {
		return nil
	}
	for _, prefix := range reserved {
		if prefix.Contains(addr) {
			return fmt.Errorf("%w: %s is in the reserved range %s", ErrDenied, reported, prefix)
		}
	}
	return nil
}

// CheckHost denies a destination by name, which is how an opted-out target is
// kept unreachable even while its addresses change.
func (o Operator) CheckHost(name string) error {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, denied := range o.deniedHosts {
		if name == denied {
			return fmt.Errorf("%w: %s is an opted-out destination", ErrDenied, name)
		}
	}
	return nil
}

// DeniedHosts are the names the operator denied, which admission resolves so
// that their current addresses are denied too.
func (o Operator) DeniedHosts() []string { return o.deniedHosts }

// CheckPort applies the permitted port ranges. Transports without a port, such
// as ICMP, pass a port of zero and are not checked.
func (o Operator) CheckPort(port int) error {
	if port == 0 || len(o.ports) == 0 {
		return nil
	}
	for _, r := range o.ports {
		if port >= r.lo && port <= r.hi {
			return nil
		}
	}
	return fmt.Errorf("%w: port %d is not a permitted destination port", ErrDenied, port)
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// Normalize is the one spelling of an address the policy works with: no IPv4
// mapping, no zone. Two guests writing the same destination differently reach
// the same decision, and the same accounting key.
func Normalize(addr netip.Addr) netip.Addr {
	return addr.Unmap().WithZone("")
}

// aliases returns every address a packet to addr can also be described as: the
// normalized address itself, and the IPv4 address embedded in a NAT64 or 6to4
// address. Checking all of them keeps an IPv4 denial from being stepped around
// through its IPv6 spelling.
func aliases(addr netip.Addr) []netip.Addr {
	normalized := Normalize(addr)
	list := []netip.Addr{normalized}
	if embedded, ok := embeddedV4(normalized); ok {
		list = append(list, embedded)
	}
	return list
}

func embeddedV4(addr netip.Addr) (netip.Addr, bool) {
	if !addr.Is6() {
		return netip.Addr{}, false
	}
	bytes := addr.As16()
	switch {
	case nat64.Contains(addr):
		return netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]}), true
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte{bytes[2], bytes[3], bytes[4], bytes[5]}), true
	case compatible.Contains(addr):
		// The unspecified address and the IPv6 loopback live in this prefix
		// too. They are decided as themselves, by the reserved ranges and by
		// the local profile's loopback rule, not as 0.0.0.0 and 0.0.0.1.
		embedded := netip.AddrFrom4([4]byte{bytes[12], bytes[13], bytes[14], bytes[15]})
		if embedded == netip.AddrFrom4([4]byte{0, 0, 0, 0}) || embedded == netip.AddrFrom4([4]byte{0, 0, 0, 1}) {
			return netip.Addr{}, false
		}
		return embedded, true
	default:
		return netip.Addr{}, false
	}
}
