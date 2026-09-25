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
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeResolver answers from a table the test owns, so alias and DNS-change
// behaviour can be observed without a name server. Answers may be changed
// between lookups, which is what a destination that moves does.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups int
}

func newResolver(answers map[string][]string) *fakeResolver {
	return &fakeResolver{answers: answers}
}

func (r *fakeResolver) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lookups
}

func (r *fakeResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
}

func (r *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	texts, ok := r.answers[host]
	if !ok {
		return nil, fmt.Errorf("no such host %q", host)
	}
	addrs := make([]netip.Addr, 0, len(texts))
	for _, text := range texts {
		addr, err := netip.ParseAddr(text)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// localProfile is the policy of an executor that measures against services on
// its own host and says so. The shipped default does not, which is what
// TestDefaultsDenyLoopback covers.
func localProfile() Spec {
	spec := Defaults()
	spec.LocalTargets = true
	return spec
}

func mustParse(t *testing.T, spec Spec) Operator {
	t.Helper()
	operator, err := Parse(spec)
	if err != nil {
		t.Fatalf("Parse(%+v): %v", spec, err)
	}
	return operator
}

// permitted is the probe of a host that may open raw ICMP sockets.
func permitted() error { return nil }

// refused is the probe of a host that may not, which is every host that runs
// the executor without the raw-socket privilege.
func refused() error { return errors.New("operation not permitted") }

func TestParseRejectsMalformedPolicy(t *testing.T) {
	for name, spec := range map[string]Spec{
		"denied range":  {DeniedDestinations: "10.0.0.0/33"},
		"denied entry":  {DeniedDestinations: "not a destination"},
		"port zero":     {PermittedPorts: "0"},
		"port too high": {PermittedPorts: "70000"},
		"port range":    {PermittedPorts: "500-100"},
		"port text":     {PermittedPorts: "http"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(spec); err == nil {
				t.Fatalf("Parse(%+v) accepted an unusable policy", spec)
			}
		})
	}
}

func TestParseAcceptsTheDocumentedDefaults(t *testing.T) {
	operator := mustParse(t, Defaults())
	for _, transport := range []Transport{TCP, TLS, UDP, ICMP, Inbound} {
		if !operator.Enabled(transport) {
			t.Errorf("%s is disabled by default", transport)
		}
	}
	if operator.Enabled(SCION) {
		t.Error("scion is enabled by default; it cannot meet the policy contract in this profile")
	}
}

// TestDefaultsDenyLoopback is the fail-closed rule: an executor whose
// configuration says nothing about local targets reaches no service behind its
// own loopback interface, however the submitter writes the destination.
func TestDefaultsDenyLoopback(t *testing.T) {
	operator := mustParse(t, Defaults())
	for _, address := range []string{"127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1", "2002:7f00:0001::1"} {
		if err := operator.CheckAddr(netip.MustParseAddr(address)); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckAddr(%s) = %v under the default policy, want a denial", address, err)
		}
	}
	policy := New(operator, Run{Addresses: []string{"127.0.0.1"}}, WithResolver(newResolver(nil)))
	if _, err := policy.AdmitDestination(context.Background(), TCP, "127.0.0.1:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("a job declaring loopback reached it under the default policy: %v", err)
	}
}

// TestReservedRangesAreDenied covers the addresses a guest must not reach in
// any profile, including the spellings that describe the same IPv4 address in
// IPv6 form.
func TestReservedRangesAreDenied(t *testing.T) {
	operator := mustParse(t, Spec{})
	for name, address := range map[string]string{
		"private":              "10.1.2.3",
		"documentation":        "192.0.2.10",
		"documentation 2":      "198.51.100.10",
		"documentation 3":      "203.0.113.10",
		"documentation v6":     "2001:db8::1",
		"six to four relay":    "192.88.99.1",
		"compatible private":   "::10.1.2.3",
		"private 192":          "192.168.4.5",
		"carrier grade":        "100.64.0.1",
		"link local":           "169.254.169.254",
		"loopback":             "127.0.0.1",
		"unspecified":          "0.0.0.0",
		"broadcast":            "255.255.255.255",
		"multicast":            "224.0.0.1",
		"unique local":         "fd00::1",
		"link local v6":        "fe80::1",
		"loopback v6":          "::1",
		"mapped private":       "::ffff:10.1.2.3",
		"mapped link local":    "::ffff:169.254.169.254",
		"nat64 link local":     "64:ff9b::169.254.169.254",
		"six to four private":  "2002:0a01:0203::1",
		"six to four loopback": "2002:7f00:0001::1",
	} {
		t.Run(name, func(t *testing.T) {
			addr := netip.MustParseAddr(address)
			if err := operator.CheckAddr(addr); err == nil {
				t.Fatalf("CheckAddr(%s) admitted a reserved address", addr)
			} else if !errors.Is(err, ErrDenied) {
				t.Fatalf("CheckAddr(%s) = %v, want a denial", addr, err)
			}
		})
	}
}

func TestLocalTargetsReAllowsOnlyLoopback(t *testing.T) {
	operator := mustParse(t, Spec{LocalTargets: true})
	for _, address := range []string{"127.0.0.1", "127.0.0.53", "::1", "::ffff:127.0.0.1"} {
		if err := operator.CheckAddr(netip.MustParseAddr(address)); err != nil {
			t.Errorf("the local profile refused loopback %s: %v", address, err)
		}
	}
	for _, address := range []string{"10.1.2.3", "169.254.169.254", "fd00::1"} {
		if err := operator.CheckAddr(netip.MustParseAddr(address)); err == nil {
			t.Errorf("the local profile admitted %s, which is not loopback", address)
		}
	}
}

func TestConfiguredDenialsOutrankTheLocalProfile(t *testing.T) {
	// 93.184.216.0/24 is ordinary public space: the denial has to come from
	// the operator's list, not from a range that is reserved anyway.
	operator := mustParse(t, Spec{LocalTargets: true, DeniedDestinations: "127.0.0.9, 93.184.216.0/24"})
	for _, address := range []string{"127.0.0.9", "93.184.216.7"} {
		err := operator.CheckAddr(netip.MustParseAddr(address))
		if !errors.Is(err, ErrDenied) {
			t.Errorf("CheckAddr(%s) = %v, want an operator denial", address, err)
		}
	}
	if err := operator.CheckAddr(netip.MustParseAddr("127.0.0.1")); err != nil {
		t.Errorf("an unrelated loopback address was denied: %v", err)
	}
}

func TestPermittedPortsDenyEverythingElse(t *testing.T) {
	operator := mustParse(t, Spec{PermittedPorts: "80,443,8000-8002"})
	for _, port := range []int{80, 443, 8000, 8001, 8002} {
		if err := operator.CheckPort(port); err != nil {
			t.Errorf("port %d was denied: %v", port, err)
		}
	}
	for _, port := range []int{79, 444, 7999, 8003} {
		if err := operator.CheckPort(port); !errors.Is(err, ErrDenied) {
			t.Errorf("CheckPort(%d) = %v, want a denial", port, err)
		}
	}
	// A transport without ports, such as ICMP, is not decided by this rule.
	if err := operator.CheckPort(0); err != nil {
		t.Errorf("a portless transport was denied: %v", err)
	}
	// An empty specification permits every port.
	if err := mustParse(t, Spec{}).CheckPort(65535); err != nil {
		t.Errorf("the empty port policy denied port 65535: %v", err)
	}
}

// TestTransportMatrix is the supported matrix: which transports a job can use,
// and what each one needs beyond the operator's switch.
func TestTransportMatrix(t *testing.T) {
	spec := localProfile()
	run := Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true, ListenUDP: true}

	enabled := New(mustParse(t, spec), run, WithICMPProbe(permitted))
	for _, transport := range []Transport{TCP, TLS, UDP, Inbound} {
		if err := enabled.Available(transport); err != nil {
			t.Errorf("%s is not available under the default policy: %v", transport, err)
		}
	}
	if err := enabled.Available(SCION); !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("Available(scion) = %v, want the transport to be off by default", err)
	}
	// ICMP needs the job to have asked for it.
	if err := enabled.Available(ICMP); !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("Available(icmp) = %v, want a refusal for a job that did not request it", err)
	}
	icmpRun := Run{Addresses: []string{"127.0.0.1"}, RequireICMP: true}
	if err := New(mustParse(t, spec), icmpRun, WithICMPProbe(permitted)).Available(ICMP); err != nil {
		t.Errorf("Available(icmp) = %v for a job that requested it on a permitted host", err)
	}
	// ICMP also needs the privilege the host actually holds.
	err := New(mustParse(t, spec), icmpRun, WithICMPProbe(refused)).Available(ICMP)
	if !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("Available(icmp) = %v on a host without the raw-socket privilege", err)
	}

	// A transport the operator switched off is unavailable whatever the job
	// asked for.
	off := spec
	off.TCP, off.UDP, off.Inbound = false, false, false
	disabled := New(mustParse(t, off), run, WithICMPProbe(permitted))
	for _, transport := range []Transport{TCP, UDP, Inbound} {
		if err := disabled.Available(transport); !errors.Is(err, ErrTransportUnavailable) {
			t.Errorf("Available(%s) = %v, want the operator's refusal", transport, err)
		}
	}

	// A listener needs the operator's inbound switch and the job's request.
	listeners := New(mustParse(t, spec), Run{Addresses: []string{"127.0.0.1"}})
	if err := listeners.AvailableListener(TCP); !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("AvailableListener(tcp) = %v for a job that requested no listener", err)
	}
	if err := enabled.AvailableListener(TCP); err != nil {
		t.Errorf("AvailableListener(tcp) = %v for a job that requested one", err)
	}
	if err := enabled.AvailableListener(SCION); !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("AvailableListener(scion) = %v, want the disabled transport's refusal", err)
	}
}

func TestNoPolicyAdmitsNothing(t *testing.T) {
	var missing *Policy
	if err := missing.Available(TCP); !errors.Is(err, ErrTransportUnavailable) {
		t.Errorf("Available on a nil policy = %v, want a refusal", err)
	}
	if _, err := missing.AdmitDestination(context.Background(), TCP, "127.0.0.1:80"); err == nil {
		t.Error("a nil policy admitted a destination")
	}
}

func TestAdmitDestinationNormalizesLiterals(t *testing.T) {
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"127.0.0.1"}}, WithResolver(newResolver(nil)))
	for _, target := range []string{"127.0.0.1:8080", "[::ffff:127.0.0.1]:8080"} {
		destination, err := policy.AdmitDestination(context.Background(), TCP, target)
		if err != nil {
			t.Fatalf("AdmitDestination(%s): %v", target, err)
		}
		if got := destination.DialAddresses(); len(got) != 1 || got[0] != "127.0.0.1:8080" {
			t.Errorf("AdmitDestination(%s) dials %q, want the normalized literal", target, got)
		}
		if destination.Key != "127.0.0.1" {
			t.Errorf("AdmitDestination(%s) accounts to %q, want the declared destination", target, destination.Key)
		}
		if destination.ServerName != "" {
			t.Errorf("AdmitDestination(%s) invented the server name %q", target, destination.ServerName)
		}
	}
}

// TestAdmitDestinationResolvesAliases covers a job that declares one name and
// a guest that reaches it by another: the decision is made on the addresses,
// and the traffic is accounted against the declared destination.
func TestAdmitDestinationResolvesAliases(t *testing.T) {
	resolver := newResolver(map[string][]string{
		"target.example":  {"127.0.0.1"},
		"alias.example":   {"127.0.0.1"},
		"unknown.example": {"127.0.0.2"},
	})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"target.example"}}, WithResolver(resolver))

	destination, err := policy.AdmitDestination(context.Background(), TCP, "alias.example:80")
	if err != nil {
		t.Fatalf("an alias of the declared destination was refused: %v", err)
	}
	if destination.Key != "target.example" {
		t.Errorf("the alias is accounted to %q, want the declared destination", destination.Key)
	}
	if destination.ServerName != "alias.example" {
		t.Errorf("ServerName = %q, want the name the guest asked for", destination.ServerName)
	}
	if got := destination.DialAddresses(); len(got) != 1 || got[0] != "127.0.0.1:80" {
		t.Errorf("the alias dials %q, want the address that was checked", got)
	}

	if _, err := policy.AdmitDestination(context.Background(), TCP, "unknown.example:80"); !errors.Is(err, ErrNotInPolicy) {
		t.Errorf("AdmitDestination(unknown.example) = %v, want the job's refusal", err)
	}
}

// TestAdmitDestinationFollowsDNSChanges covers a destination that moves: the
// job's declared destinations are resolved again on every admission, so a name
// that stops resolving into them stops being reachable.
func TestAdmitDestinationFollowsDNSChanges(t *testing.T) {
	resolver := newResolver(map[string][]string{
		"target.example": {"127.0.0.1"},
		"moving.example": {"127.0.0.1"},
	})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"target.example"}}, WithResolver(resolver))
	policy.ttl = 0 // a destination that moves is observed without the resolution window
	if _, err := policy.AdmitDestination(context.Background(), TCP, "moving.example:80"); err != nil {
		t.Fatalf("the first admission was refused: %v", err)
	}

	resolver.set("moving.example", "127.0.0.2")
	if _, err := policy.AdmitDestination(context.Background(), TCP, "moving.example:80"); !errors.Is(err, ErrNotInPolicy) {
		t.Fatalf("a destination that moved out of the job's policy was still admitted: %v", err)
	}

	// The declared destination moving with it keeps the name reachable.
	resolver.set("target.example", "127.0.0.2")
	if _, err := policy.AdmitDestination(context.Background(), TCP, "moving.example:80"); err != nil {
		t.Fatalf("a declared destination that moved was refused: %v", err)
	}
}

func TestAdmitDestinationDeniesOptedOutTargets(t *testing.T) {
	resolver := newResolver(map[string][]string{
		"opted-out.example": {"127.0.0.1"},
		"alias.example":     {"127.0.0.1"},
	})
	spec := localProfile()
	spec.DeniedDestinations = "opted-out.example"
	policy := New(mustParse(t, spec), Run{Addresses: []string{"127.0.0.1"}}, WithResolver(resolver))

	// The name itself is denied.
	if _, err := policy.AdmitDestination(context.Background(), TCP, "opted-out.example:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("the opted-out name was admitted: %v", err)
	}
	// So is every address it currently has, whatever the guest calls it.
	if _, err := policy.AdmitDestination(context.Background(), TCP, "alias.example:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("an alias of the opted-out destination was admitted: %v", err)
	}
	if _, err := policy.AdmitDestination(context.Background(), TCP, "127.0.0.1:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("the opted-out address was admitted as a literal: %v", err)
	}
}

func TestAdmitDestinationAppliesPortsAfterResolution(t *testing.T) {
	resolver := newResolver(map[string][]string{"target.example": {"127.0.0.1"}})
	spec := localProfile()
	spec.PermittedPorts = "80"
	policy := New(mustParse(t, spec), Run{Addresses: []string{"target.example"}}, WithResolver(resolver))

	if _, err := policy.AdmitDestination(context.Background(), TCP, "target.example:80"); err != nil {
		t.Fatalf("the permitted port was refused: %v", err)
	}
	if _, err := policy.AdmitDestination(context.Background(), TCP, "target.example:81"); !errors.Is(err, ErrDenied) {
		t.Errorf("a port outside the permitted ranges was admitted")
	}
}

func TestAdmitDestinationRefusesJobsWithoutDestinations(t *testing.T) {
	policy := New(mustParse(t, localProfile()), Run{}, WithResolver(newResolver(nil)))
	if _, err := policy.AdmitDestination(context.Background(), TCP, "127.0.0.1:80"); !errors.Is(err, ErrNotInPolicy) {
		t.Errorf("a job that declared no destination reached one: %v", err)
	}
}

func TestAdmitICMPRequiresAnIPv4Destination(t *testing.T) {
	resolver := newResolver(map[string][]string{"target.example": {"::1"}})
	policy := New(mustParse(t, Spec{ICMP: true, LocalTargets: true}),
		Run{Addresses: []string{"target.example"}, RequireICMP: true},
		WithResolver(resolver), WithICMPProbe(permitted))
	policy.ttl = 0 // the case changes the answer, so it must not be reused
	if _, err := policy.AdmitDestination(context.Background(), ICMP, "target.example"); !errors.Is(err, ErrDenied) {
		t.Errorf("an IPv6 destination was admitted for ICMPv4: %v", err)
	}

	resolver.set("target.example", "127.0.0.1")
	destination, err := policy.AdmitDestination(context.Background(), ICMP, "target.example")
	if err != nil {
		t.Fatalf("an IPv4 ICMP destination was refused: %v", err)
	}
	if got := destination.DialAddresses(); len(got) != 1 || got[0] != "127.0.0.1" {
		t.Errorf("the ICMP destination dials %q, want an address without a port", got)
	}
}

// TestAdmitAddrInbound covers peers the host already holds: an accepted
// connection or the sender of a datagram.
func TestAdmitAddrInbound(t *testing.T) {
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true},
		WithResolver(newResolver(nil)))

	// An inbound peer's source port is whatever it picked; the permitted
	// destination ports do not decide it.
	match, err := policy.AdmitAddr(context.Background(), Inbound, netip.MustParseAddrPort("127.0.0.1:54321"))
	if err != nil {
		t.Fatalf("a declared peer was refused: %v", err)
	}
	if match.Key != "127.0.0.1" {
		t.Errorf("the peer is accounted to %q, want the declared destination", match.Key)
	}

	if _, err := policy.AdmitAddr(context.Background(), Inbound, netip.MustParseAddrPort("127.0.0.2:54321")); !errors.Is(err, ErrNotInPolicy) {
		t.Errorf("a peer outside the job's destinations was admitted: %v", err)
	}

	// A peer in a range the operator denies is refused even when the job
	// declared it.
	denied := New(mustParse(t, Spec{Inbound: true, LocalTargets: true, DeniedDestinations: "127.0.0.1"}),
		Run{Addresses: []string{"127.0.0.1"}, ListenTCP: true}, WithResolver(newResolver(nil)))
	if _, err := denied.AdmitAddr(context.Background(), Inbound, netip.MustParseAddrPort("127.0.0.1:54321")); !errors.Is(err, ErrDenied) {
		t.Errorf("an operator-denied peer was admitted: %v", err)
	}
}

// TestCheckSocketIsTheLastGate covers the hook the dialer calls between
// creating a socket and connecting it.
func TestCheckSocketIsTheLastGate(t *testing.T) {
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"127.0.0.1"}}, WithResolver(newResolver(nil)))
	destination, err := policy.AdmitDestination(context.Background(), TCP, "127.0.0.1:8080")
	if err != nil {
		t.Fatalf("AdmitDestination: %v", err)
	}
	if err := destination.CheckSocket("tcp", "127.0.0.1:8080"); err != nil {
		t.Errorf("the admitted socket was refused: %v", err)
	}
	for name, address := range map[string]string{
		"another address": "127.0.0.2:8080",
		"another port":    "127.0.0.1:9090",
		"unresolved":      "target.example:8080",
	} {
		t.Run(name, func(t *testing.T) {
			if err := destination.CheckSocket("tcp", address); !errors.Is(err, ErrDenied) {
				t.Errorf("CheckSocket(%s) = %v, want a denial", address, err)
			}
		})
	}
}

func TestDeclaredHostReadsSCIONAndPortedEntries(t *testing.T) {
	for declared, want := range map[string]string{
		"127.0.0.1":                       "127.0.0.1",
		"target.example":                  "target.example",
		"target.example:443":              "target.example",
		"1-ff00:0:110,127.0.0.1":          "127.0.0.1",
		"1-ff00:0:110,[::1]:443":          "::1",
		" 1-ff00:0:110,target.example:80": "target.example",
	} {
		if got := declaredHost(declared); got != want {
			t.Errorf("declaredHost(%q) = %q, want %q", declared, got, want)
		}
	}
}

func TestRefusalsNameTheDestination(t *testing.T) {
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"127.0.0.1"}}, WithResolver(newResolver(nil)))
	_, err := policy.AdmitDestination(context.Background(), TCP, "10.1.2.3:80")
	if err == nil || !strings.Contains(err.Error(), "10.1.2.3") {
		t.Fatalf("the refusal %v does not name the destination", err)
	}
}

// TestAdmitDestinationKeepsEveryAdmittedAddress covers a name with several
// addresses: all of the admitted ones are kept, in the resolver's order, so a
// host that tries them in turn reaches the destination the way dialling the
// name would have. The addresses the policy refuses are not among them.
func TestAdmitDestinationKeepsEveryAdmittedAddress(t *testing.T) {
	resolver := newResolver(map[string][]string{
		"target.example": {"127.0.0.2", "10.1.2.3", "127.0.0.1"},
	})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"target.example"}}, WithResolver(resolver))
	destination, err := policy.AdmitDestination(context.Background(), TCP, "target.example:80")
	if err != nil {
		t.Fatalf("AdmitDestination: %v", err)
	}
	want := []string{"127.0.0.2:80", "127.0.0.1:80"}
	got := destination.DialAddresses()
	if len(got) != len(want) {
		t.Fatalf("admitted addresses = %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("admitted addresses = %q, want %q in the resolver's order", got, want)
		}
	}
	for _, address := range want {
		if err := destination.CheckSocket("tcp", address); err != nil {
			t.Errorf("CheckSocket(%s) refused an admitted address: %v", address, err)
		}
	}
	if err := destination.CheckSocket("tcp", "10.1.2.3:80"); !errors.Is(err, ErrDenied) {
		t.Errorf("CheckSocket on the refused address = %v, want a denial", err)
	}
}

// TestResolutionIsReusedWithinTheWindow covers the cost of admitting traffic
// the executor did not ask for: a peer that keeps sending must not spend one
// resolver query per packet, and the answer must still be given up once the
// window passes.
func TestResolutionIsReusedWithinTheWindow(t *testing.T) {
	resolver := newResolver(map[string][]string{"target.example": {"127.0.0.1"}})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"target.example"}, ListenTCP: true},
		WithResolver(resolver))
	clock := time.Now()
	policy.now = func() time.Time { return clock }

	peer := netip.MustParseAddrPort("127.0.0.1:54321")
	for i := 0; i < 50; i++ {
		if _, err := policy.AdmitAddr(context.Background(), Inbound, peer); err != nil {
			t.Fatalf("AdmitAddr: %v", err)
		}
	}
	if got := resolver.calls(); got != 1 {
		t.Errorf("50 admitted peers spent %d resolver queries, want one", got)
	}

	clock = clock.Add(resolveTTL)
	resolver.set("target.example", "127.0.0.2")
	if _, err := policy.AdmitAddr(context.Background(), Inbound, peer); !errors.Is(err, ErrNotInPolicy) {
		t.Errorf("after the window the moved destination was still admitted: %v", err)
	}
	if got := resolver.calls(); got != 2 {
		t.Errorf("the window expired after %d resolver queries, want two", got)
	}
}

// TestResolutionFailuresAreAlsoBounded covers a declared destination that does
// not resolve: it must not become one resolver query per received packet.
func TestResolutionFailuresAreAlsoBounded(t *testing.T) {
	resolver := newResolver(map[string][]string{})
	policy := New(mustParse(t, localProfile()), Run{Addresses: []string{"missing.example"}, ListenTCP: true},
		WithResolver(resolver))
	peer := netip.MustParseAddrPort("127.0.0.1:54321")
	for i := 0; i < 10; i++ {
		if _, err := policy.AdmitAddr(context.Background(), Inbound, peer); !errors.Is(err, ErrNotInPolicy) {
			t.Fatalf("AdmitAddr = %v, want the job's refusal", err)
		}
	}
	if got := resolver.calls(); got != 1 {
		t.Errorf("10 refused peers spent %d resolver queries, want one", got)
	}
}
