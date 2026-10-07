package destinations

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/netsec-ethz/debuglet/internal/executor/debuglet/socket/netutil"
)

func ip(s string) netutil.IPv6 { return netutil.ToIPv6(netip.MustParseAddr(s)) }

func targets(r *Resolved, addr string, id uuid.UUID) []string {
	var out []string
	for target := range r.Targets(addr, id) {
		out = append(out, target.String())
	}
	slices.Sort(out)
	return out
}

func TestResolvedCountsAttachmentsPerNameAndDebuglet(t *testing.T) {
	var r Resolved
	a, b := uuid.New(), uuid.New()
	one, two := ip("192.0.2.1"), ip("192.0.2.2")
	r.Add("example.org", a, one)
	r.Add("example.org", a, one)
	r.Add("example.org", a, two)
	r.Add("example.org", b, two)

	if got := targets(&r, "example.org", a); !slices.Equal(got, []string{"::ffff:192.0.2.1", "::ffff:192.0.2.2"}) {
		t.Fatalf("targets of a: %v", got)
	}
	if got := targets(&r, "example.org", b); !slices.Equal(got, []string{"::ffff:192.0.2.2"}) {
		t.Fatalf("targets of b: %v", got)
	}
	if got := targets(&r, "other.example", a); len(got) != 0 {
		t.Fatalf("targets of an unknown name: %v", got)
	}
	if got := targets(&r, "2001:db8::1", a); !slices.Equal(got, []string{"2001:db8::1"}) {
		t.Fatalf("a literal targets itself: %v", got)
	}
	if got := targets(&r, "192.0.2.9", a); !slices.Equal(got, []string{"::ffff:192.0.2.9"}) {
		t.Fatalf("an IPv4 literal targets its mapped form: %v", got)
	}

	if remaining, ok := r.Remove("example.org", a, one); !ok || remaining != 1 {
		t.Fatalf("first remove: %d %v", remaining, ok)
	}
	if remaining, ok := r.Remove("example.org", a, one); !ok || remaining != 0 {
		t.Fatalf("last remove: %d %v", remaining, ok)
	}
	if _, ok := r.Remove("example.org", a, one); ok {
		t.Fatal("removed an attachment that was not recorded")
	}
	if _, ok := r.Remove("other.example", a, two); ok {
		t.Fatal("removed from an unknown name")
	}
	if remaining, ok := r.Remove("example.org", a, two); !ok || remaining != 0 {
		t.Fatalf("remove two: %d %v", remaining, ok)
	}
	if len(r.byAddr) != 1 {
		t.Fatalf("an emptied name was kept: %v", r.byAddr)
	}
	if got := targets(&r, "example.org", b); !slices.Equal(got, []string{"::ffff:192.0.2.2"}) {
		t.Fatalf("another debuglet's attachments changed: %v", got)
	}
}

func TestResolvedMatchesThePolicyDestinationKey(t *testing.T) {
	var r Resolved
	id := uuid.New()
	address := ip("192.0.2.7")
	r.Add("TARGET.Example.:443", id, address)
	if got := targets(&r, "target.example", id); !slices.Equal(got, []string{"::ffff:192.0.2.7"}) {
		t.Fatalf("normalized target: %v", got)
	}
	if left, ok := r.Remove("target.example.", id, address); !ok || left != 0 || len(r.byAddr) != 0 {
		t.Fatalf("normalized detach: %d %v %+v", left, ok, r.byAddr)
	}
}
