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

package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// resolveTTL bounds how long one name's addresses are reused. Inbound traffic
// admits a peer on every accepted connection and every received datagram, and
// a remote peer must not be able to turn that into one resolver query per
// packet. The window is short enough that a destination which moves stops
// being reachable within a couple of seconds.
const resolveTTL = 2 * time.Second

// Resolver is the name resolution admission uses. The default is the host
// resolver; tests install their own so that alias and DNS-change behaviour can
// be observed without a name server.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Run is the job's half of the policy: the destinations the submitter declared
// and the capabilities the submission requested.
type Run struct {
	Addresses   []string
	RequireICMP bool
	ListenTCP   bool
	ListenUDP   bool
	ListenSCION bool
}

// Policy is the operator policy and one job's policy together. It is the only
// object the host functions consult, so a destination cannot be admitted by
// one half alone.
type Policy struct {
	op       Operator
	run      Run
	resolver Resolver
	icmp     func() error

	// Resolutions are reused for ttl, so admission cost stays bounded when the
	// peers, not the guest, decide how often it runs.
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	cache map[string]resolution
}

// resolution is one name's answer and the moment it was obtained. A failure is
// remembered too: a name that does not resolve must not become a way to ask
// the resolver again on every packet.
type resolution struct {
	addrs []netip.Addr
	err   error
	at    time.Time
}

// Option adjusts a Policy at construction. Options exist for the seams tests
// need: name resolution and the host privilege probe.
type Option func(*Policy)

// WithResolver replaces the name resolver.
func WithResolver(resolver Resolver) Option {
	return func(p *Policy) {
		if resolver != nil {
			p.resolver = resolver
		}
	}
}

// WithICMPProbe replaces the raw-socket privilege probe.
func WithICMPProbe(probe func() error) Option {
	return func(p *Policy) {
		if probe != nil {
			p.icmp = probe
		}
	}
}

// New combines an operator policy with one run's declared policy.
func New(op Operator, run Run, options ...Option) *Policy {
	p := &Policy{
		op:       op,
		run:      run,
		resolver: net.DefaultResolver,
		icmp:     ICMPPermitted,
		ttl:      resolveTTL,
		now:      time.Now,
		cache:    make(map[string]resolution),
	}
	for _, option := range options {
		option(p)
	}
	return p
}

// Available reports whether transport t may be used at all: the operator's
// switch, the capability the submission requested, and, for ICMP, whether this
// process actually holds the privilege the transport needs.
func (p *Policy) Available(t Transport) error {
	if p == nil {
		return fmt.Errorf("%w: no network policy is installed", ErrTransportUnavailable)
	}
	if !p.op.Enabled(t) {
		return fmt.Errorf("%w: %s is disabled by the operator network policy", ErrTransportUnavailable, t)
	}
	if t == ICMP {
		if !p.run.RequireICMP {
			return fmt.Errorf("%w: the job did not request icmp", ErrTransportUnavailable)
		}
		if err := p.icmp(); err != nil {
			return fmt.Errorf("%w: icmp: %w", ErrTransportUnavailable, err)
		}
	}
	return nil
}

// AvailableListener reports whether the job may run the listener for t.
// Inbound traffic needs both the operator's inbound switch and the listener
// the submission asked for.
func (p *Policy) AvailableListener(t Transport) error {
	if err := p.Available(Inbound); err != nil {
		return err
	}
	requested := false
	switch t {
	case TCP, TLS:
		requested = p.run.ListenTCP
	case UDP:
		requested = p.run.ListenUDP
	case SCION:
		if err := p.Available(SCION); err != nil {
			return err
		}
		requested = p.run.ListenSCION
	}
	if !requested {
		return fmt.Errorf("%w: the job did not request a %s listener", ErrTransportUnavailable, t)
	}
	return nil
}

// Destination is one admitted outbound target. It carries the addresses that
// were checked, so the connection is made to one of exactly those rather than
// to a name that may resolve differently a moment later.
type Destination struct {
	// Addrs are the admitted peers in the order the resolver returned them.
	// A name with several addresses keeps all of them, so a host that tries
	// them in turn reaches the destination the way dialling the name would
	// have, without any of them escaping the policy. The port is zero for
	// portless transports.
	Addrs []netip.AddrPort
	// Key is the address the submitter declared, which is what per-destination
	// bandwidth is accounted against.
	Key string
	// ServerName is the name the guest asked for, for TLS verification. It is
	// empty when the guest gave an address literal.
	ServerName string

	op Operator
}

// DialAddresses are the literals the host dials, in the order it should try
// them: the checked addresses, never the name the guest wrote.
func (d Destination) DialAddresses() []string {
	addresses := make([]string, 0, len(d.Addrs))
	for _, addr := range d.Addrs {
		if addr.Port() == 0 {
			addresses = append(addresses, addr.Addr().String())
			continue
		}
		addresses = append(addresses, addr.String())
	}
	return addresses
}

// CheckSocket is the last gate before a socket is connected. The dialer calls
// it with the address the operating system is about to use, after any name
// resolution of its own, so a destination that changed underneath admission
// never reaches connect. Only an address this destination was admitted for
// passes, whichever of them the host is trying.
func (d Destination) CheckSocket(network, address string) error {
	host, port, err := splitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDenied, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %s is not a resolved address", ErrDenied, host)
	}
	addr = Normalize(addr)
	admitted := false
	for _, candidate := range d.Addrs {
		if candidate.Addr() != addr {
			continue
		}
		if port != 0 && candidate.Port() != 0 && port != int(candidate.Port()) {
			continue
		}
		admitted = true
		break
	}
	if !admitted {
		return fmt.Errorf("%w: %s was not an admitted destination of this connection", ErrDenied, address)
	}
	if err := d.op.CheckPort(port); err != nil {
		return err
	}
	return d.op.CheckAddr(addr)
}

// Match is an admitted address that the host did not resolve itself: an
// accepted peer, a datagram sender, or a SCION destination. Key is the declared
// address its traffic is accounted against.
type Match struct {
	Key string
}

// AdmitDestination admits one outbound target written as the guest wrote it.
// It resolves the target and the job's declared destinations with the same
// resolver, applies the operator's rules to the result, and returns the
// address the caller must connect to. Nothing is sent to the target here: a
// refusal happens before any socket is connected.
func (p *Policy) AdmitDestination(ctx context.Context, t Transport, target string) (Destination, error) {
	if err := p.Available(t); err != nil {
		return Destination{}, err
	}
	host, port, err := splitTarget(t, target)
	if err != nil {
		return Destination{}, err
	}
	if err := p.op.CheckPort(port); err != nil {
		return Destination{}, err
	}
	if err := p.op.CheckHost(host); err != nil {
		return Destination{}, err
	}
	candidates, err := p.resolve(ctx, host)
	if err != nil {
		return Destination{}, err
	}
	allowed, err := p.allowlist(ctx)
	if err != nil {
		return Destination{}, err
	}
	denied, err := p.deniedAddrs(ctx)
	if err != nil {
		return Destination{}, err
	}

	// Every address of the destination that the policy admits is kept, in the
	// order the resolver gave them. Admitting only the first would make a
	// destination whose first address is unreachable unreachable altogether,
	// which dialling the name never was.
	destination := Destination{Key: "", op: p.op}
	if !isAddrLiteral(host) {
		destination.ServerName = host
	}
	var refusal error
	for _, candidate := range candidates {
		if t == ICMP && !candidate.Is4() {
			refusal = errors.Join(refusal, fmt.Errorf("%w: icmp: %s is not an IPv4 address", ErrDenied, candidate))
			continue
		}
		if _, ok := denied[candidate]; ok {
			refusal = errors.Join(refusal, fmt.Errorf("%w: %s resolves an opted-out destination", ErrDenied, candidate))
			continue
		}
		if err := p.op.CheckAddr(candidate); err != nil {
			refusal = errors.Join(refusal, err)
			continue
		}
		key, ok := allowed[candidate]
		if !ok {
			refusal = errors.Join(refusal, fmt.Errorf("%w: %s", ErrNotInPolicy, candidate))
			continue
		}
		if destination.Key == "" {
			// The declared destination that admitted the first address is what
			// the whole connection is accounted against, so one destination
			// keeps one bandwidth account whichever address answers.
			destination.Key = key
		}
		destination.Addrs = append(destination.Addrs, netip.AddrPortFrom(candidate, uint16(port)))
	}
	if len(destination.Addrs) > 0 {
		return destination, nil
	}
	if refusal == nil {
		refusal = fmt.Errorf("%w: %s has no address", ErrNotInPolicy, host)
	}
	return Destination{}, refusal
}

// AdmitAddr admits an address the host already holds: a peer that connected,
// the sender of a datagram, or a SCION destination this executor parsed. The
// source port of an inbound peer is whatever it happened to pick, so the
// permitted destination ports are not applied to it.
func (p *Policy) AdmitAddr(ctx context.Context, t Transport, addr netip.AddrPort) (Match, error) {
	if err := p.Available(t); err != nil {
		return Match{}, err
	}
	peer := Normalize(addr.Addr())
	if t != Inbound {
		if err := p.op.CheckPort(int(addr.Port())); err != nil {
			return Match{}, err
		}
	}
	denied, err := p.deniedAddrs(ctx)
	if err != nil {
		return Match{}, err
	}
	if _, ok := denied[peer]; ok {
		return Match{}, fmt.Errorf("%w: %s is an opted-out destination", ErrDenied, peer)
	}
	if err := p.op.CheckAddr(peer); err != nil {
		return Match{}, err
	}
	allowed, err := p.allowlist(ctx)
	if err != nil {
		return Match{}, err
	}
	key, ok := allowed[peer]
	if !ok {
		return Match{}, fmt.Errorf("%w: %s", ErrNotInPolicy, peer)
	}
	return Match{Key: key}, nil
}

// resolve turns one target into the addresses it currently has, normalized.
// An answer is reused for the resolution window: admission runs on traffic the
// executor did not ask for, and a peer that sends packets must not be able to
// spend one resolver query per packet. An address literal never resolves.
func (p *Policy) resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{Normalize(addr)}, nil
	}
	if entry, ok := p.cached(host); ok {
		return slices.Clone(entry.addrs), entry.err
	}
	entry := resolution{at: p.now()}
	addrs, err := p.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		entry.err = fmt.Errorf("failed to resolve %q: %w", host, err)
	} else {
		entry.addrs = normalizeAll(addrs)
	}
	p.remember(host, entry)
	return slices.Clone(entry.addrs), entry.err
}

// cached returns the answer for host while it is still within the resolution
// window.
func (p *Policy) cached(host string) (resolution, bool) {
	if p.ttl <= 0 {
		return resolution{}, false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	entry, ok := p.cache[host]
	if !ok || p.now().Sub(entry.at) >= p.ttl {
		return resolution{}, false
	}
	return entry, true
}

func (p *Policy) remember(host string, entry resolution) {
	if p.ttl <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cache == nil {
		p.cache = make(map[string]resolution)
	}
	p.cache[host] = entry
}

// allowlist resolves the job's declared destinations on every admission, so a
// destination that stops resolving to a declared address stops being reachable
// with it. Entries that do not resolve are skipped rather than failing the
// whole list: one unusable entry must not decide the others.
func (p *Policy) allowlist(ctx context.Context) (map[netip.Addr]string, error) {
	allowed := make(map[netip.Addr]string)
	var refusal error
	for _, declared := range p.run.Addresses {
		host := declaredHost(declared)
		if host == "" {
			continue
		}
		addrs, err := p.resolve(ctx, host)
		if err != nil {
			refusal = errors.Join(refusal, err)
			continue
		}
		for _, addr := range addrs {
			if _, ok := allowed[addr]; !ok {
				allowed[addr] = declared
			}
		}
	}
	if len(allowed) == 0 {
		if refusal != nil {
			return nil, fmt.Errorf("%w: no declared destination resolves: %w", ErrNotInPolicy, refusal)
		}
		return nil, fmt.Errorf("%w: the job declared no destination", ErrNotInPolicy)
	}
	return allowed, nil
}

// deniedAddrs resolves the operator's opted-out names. It is only a lookup
// when the operator configured one.
func (p *Policy) deniedAddrs(ctx context.Context) (map[netip.Addr]struct{}, error) {
	hosts := p.op.DeniedHosts()
	if len(hosts) == 0 {
		return nil, nil
	}
	denied := make(map[netip.Addr]struct{})
	for _, host := range hosts {
		addrs, err := p.resolve(ctx, host)
		if err != nil {
			// An opted-out name that cannot be resolved denies nothing extra;
			// the name itself is still denied by CheckHost.
			continue
		}
		for _, addr := range addrs {
			denied[addr] = struct{}{}
		}
	}
	return denied, nil
}

func normalizeAll(addrs []netip.Addr) []netip.Addr {
	normalized := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		normalized = append(normalized, Normalize(addr))
	}
	return normalized
}

// declaredHost reads the host out of one declared destination. A declared
// destination is normally a name or an address; a SCION address carries its
// host after the last comma, and a port is not part of a declaration.
func declaredHost(declared string) string {
	declared = strings.TrimSpace(declared)
	if index := strings.LastIndex(declared, ","); index >= 0 {
		declared = declared[index+1:]
	}
	if declared == "" {
		return ""
	}
	if _, err := netip.ParseAddr(declared); err == nil {
		return declared
	}
	if host, _, err := splitHostPort(declared); err == nil && host != "" {
		return host
	}
	return declared
}

// splitTarget reads the host and port a guest wrote. ICMP has no port: its
// destination is the address on its own.
func splitTarget(t Transport, target string) (string, int, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", 0, fmt.Errorf("%w: empty destination", ErrNotInPolicy)
	}
	if t == ICMP {
		if host, _, err := splitHostPort(target); err == nil && host != "" {
			return host, 0, nil
		}
		return target, 0, nil
	}
	host, port, err := splitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("%w: %w", ErrNotInPolicy, err)
	}
	if host == "" {
		return "", 0, fmt.Errorf("%w: %q has no host", ErrNotInPolicy, target)
	}
	return host, port, nil
}

// splitHostPort accepts both "host:port" and a bare host. A bracketed IPv6
// literal keeps its brackets off the returned host.
func splitHostPort(address string) (string, int, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		var addrErr *net.AddrError
		if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" {
			return strings.Trim(address, "[]"), 0, nil
		}
		return "", 0, fmt.Errorf("invalid address %q", address)
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 0 || number > 65535 {
		return "", 0, fmt.Errorf("invalid port %q in address %q", port, address)
	}
	return host, number, nil
}

func isAddrLiteral(host string) bool {
	_, err := netip.ParseAddr(strings.Trim(host, "[]"))
	return err == nil
}
