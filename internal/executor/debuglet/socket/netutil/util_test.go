package netutil

import (
	"net/netip"
	"testing"
)

func TestSplitOptionalPort(t *testing.T) {
	for _, tc := range []struct {
		address, host, port string
		hasPort, fails      bool
	}{
		{address: "192.0.2.1:80", host: "192.0.2.1", port: "80", hasPort: true},
		{address: "[2001:db8::1]:443", host: "2001:db8::1", port: "443", hasPort: true},
		{address: "example.org:http", host: "example.org", port: "http", hasPort: true},
		{address: "example.org:", host: "example.org", port: "", hasPort: true},
		{address: "example.org", host: "example.org"},
		{address: "192.0.2.1", host: "192.0.2.1"},
		{address: "[2001:db8::1]", host: "[2001:db8::1]"},
		{address: "2001:db8::1", fails: true},
		{address: "a:b:c", fails: true},
	} {
		host, port, hasPort, err := SplitOptionalPort(tc.address)
		if (err != nil) != tc.fails || host != tc.host || port != tc.port || hasPort != tc.hasPort {
			t.Errorf("SplitOptionalPort(%q) = %q, %q, %v, %v", tc.address, host, port, hasPort, err)
		}
	}
	if _, err := HostFromAddr("a:b:c"); err == nil {
		t.Error("HostFromAddr accepted a malformed address")
	}
}

func TestToIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"192.0.2.1":    "::ffff:192.0.2.1",
		"2001:db8::1":  "2001:db8::1",
		"fe80::1%eth0": "fe80::1%eth0",
	} {
		if got := ToIPv6(netip.MustParseAddr(in)).String(); got != want {
			t.Errorf("ToIPv6(%s) = %s, want %s", in, got, want)
		}
	}
}
