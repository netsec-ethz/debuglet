// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package ris

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/ipmetadata"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

// All data below is synthetic: documentation-range AS numbers would be
// discarded as reserved, so the tests use small public-looking numbers that
// describe no real announcement. Nothing contacts RIPE.

var generated = time.Date(2026, 10, 6, 2, 3, 14, 0, time.UTC)

func dump(rows ...string) string {
	return "%\n% This file was generated at Tue Oct  6 02:03:14 UTC 2026\n" +
		"% Format:  <origin> <tab> <prefix> <tab> <seen by #rispeers>\n%\n" +
		strings.Join(rows, "\n") + "\n\n% End of dump\n\n"
}

func TestParseDump(t *testing.T) {
	d, err := ParseDump(strings.NewReader(dump("100\t11.0.0.0/8\t40", "{200}\t11.1.0.0/16\t12", "{300,301}\t11.2.0.0/16\t50")), false)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Generated.Equal(generated) || len(d.Rows) != 3 || d.Rows[1].Origin != 200 || d.Rows[2].Origin != 0 || d.Rows[0].Peers != 40 {
		t.Fatalf("parsed %+v", d)
	}
	if _, err := ParseDump(strings.NewReader(dump("100\t2001:db8::/32\t40", "1\t::ffff:11.0.0.0/104\t3")), true); err != nil {
		t.Fatalf("IPv6 dump: %v", err)
	}
	full := dump("100\t11.0.0.0/8\t40")
	for name, input := range map[string]string{
		"no end marker":      strings.TrimSuffix(full, "% End of dump\n\n"),
		"cut mid-line":       strings.SplitAfter(full, "11.0.0")[0],
		"no generation time": strings.Replace(full, "This file was generated", "Generated", 1),
		"after end":          full + "100\t12.0.0.0/8\t40\n",
		"two fields":         dump("100\t11.0.0.0/8"),
		"bad origin":         dump("AS100\t11.0.0.0/8\t40"),
		"open set":           dump("{100\t11.0.0.0/8\t40"),
		"bare list":          dump("100,200\t11.0.0.0/8\t40"),
		"bad peers":          dump("100\t11.0.0.0/8\t0"),
		"padded peers":       dump("100\t11.0.0.0/8\t040"),
		"host bits":          dump("100\t11.0.0.1/8\t40"),
		"wrong family":       dump("100\t2001:db8::/32\t40"),
		"garbage":            dump("\x00\x01\x02"),
		"long line":          dump(strings.Repeat("1", 5000)),
	} {
		if _, err := ParseDump(strings.NewReader(input), false); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseASNames(t *testing.T) {
	long := strings.Repeat("x", 130)
	names, err := ParseASNames(strings.NewReader("100 EXAMPLE-A - Example A, CH\n200 \n300 C\x07D\n400 " + long + "\n\n500 Côte, CI\n"))
	if err != nil {
		t.Fatal(err)
	}
	if names[100] != "EXAMPLE-A - Example A, CH" || names[200] != "" || names[300] != "" || len([]rune(names[400])) != 128 || names[500] != "Côte, CI" {
		t.Fatalf("names %v", names)
	}
	for _, input := range []string{"100 A\n100 B\n", "AS100 A\n", "-1 A\n", "4294967296 A\n"} {
		if _, err := ParseASNames(strings.NewReader(input)); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestSelectThresholdMOASAndExclusions(t *testing.T) {
	p := netip.MustParsePrefix
	rows := []Row{
		{100, p("11.0.0.0/8"), 40},
		{100, p("11.1.0.0/16"), 9}, // below the threshold
		// MOAS: the origin more peers see wins.
		{200, p("11.2.0.0/16"), 30}, {201, p("11.2.0.0/16"), 31},
		// A tie goes to the lower AS number, whatever the order.
		{301, p("11.3.0.0/16"), 20}, {300, p("11.3.0.0/16"), 20},
		// The same origin seen as a number and a singleton set is one origin.
		{400, p("11.4.0.0/16"), 15}, {400, p("11.4.0.0/16"), 25},
		{0, p("11.5.0.0/16"), 99},     // AS set
		{64512, p("11.6.0.0/16"), 99}, // private AS
		{23456, p("11.7.0.0/16"), 99}, // AS_TRANS
		{500, p("10.0.0.0/8"), 99},    // private address space
		{500, p("0.0.0.0/0"), 99},     // default route
		{500, p("8.0.0.0/4"), 99},     // shorter than /8 and covering 10/8
		{500, p("2001:db8::/32"), 99}, // documentation
		{500, p("2a00::/12"), 99},     // shorter than /16
		{500, p("2a00:1::/32"), 99},
		{500, p("::ffff:11.0.0.0/104"), 99},
	}
	routes, stats := Select(rows, 10)
	got := map[string]uint32{}
	for _, r := range routes {
		got[r.Prefix.String()] = r.Origin
	}
	want := map[string]uint32{"11.0.0.0/8": 100, "11.2.0.0/16": 201, "11.3.0.0/16": 300, "11.4.0.0/16": 400, "2a00:1::/32": 500}
	if len(got) != len(want) {
		t.Fatalf("selected %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("selected %v, want %v", got, want)
		}
	}
	if stats.BelowThreshold != 1 || stats.ASSets != 1 || stats.ReservedOrigin != 2 || stats.Unroutable != 6 || stats.MOAS != 2 || stats.IPv4 != 4 || stats.IPv6 != 1 {
		t.Fatalf("stats %+v", stats)
	}
	if routes[0].Prefix.Bits() != 8 || routes[len(routes)-1].Prefix.Bits() != 32 {
		t.Fatalf("not sorted by length: %v", routes)
	}
	if again, _ := Select([]Row{rows[5], rows[4], rows[3], rows[2]}, 10); again[0].Origin != 201 || again[1].Origin != 300 {
		t.Fatalf("order-dependent MOAS choice: %v", again)
	}
}

func writeDatabase(t *testing.T, routes []Route, names map[uint32]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ris.mmdb")
	var b bytes.Buffer
	if err := Write(&b, routes, names, generated.Unix(), 10); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWriteLongestMatchAndAnnouncedPrefix(t *testing.T) {
	p := netip.MustParsePrefix
	routes, _ := Select([]Row{
		{100, p("11.0.0.0/8"), 40}, {200, p("11.1.0.0/16"), 40},
		// Adjacent halves with equal records merge into one tree node.
		{300, p("12.0.0.0/9"), 40}, {300, p("12.128.0.0/9"), 40},
		{400, p("2a00:1::/32"), 40}, {500, p("2a00:1:2::/48"), 40},
	}, 10)
	names := map[uint32]string{100: "EXAMPLE-A", 200: "EXAMPLE-B", 400: "EXAMPLE-D"}
	path := writeDatabase(t, routes, names)
	if err := Verify(path, routes, names, generated.Unix()); err != nil {
		t.Fatal(err)
	}
	db, err := ipmetadata.Open(path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := "database:Debuglet-RIS-ASN@" + strconv.FormatInt(generated.Unix(), 10)
	for address, want := range map[string]wire.ASInfo{
		"11.2.3.4":         {Number: 100, Name: "EXAMPLE-A", Prefix: "11.0.0.0/8"},
		"11.1.3.4":         {Number: 200, Name: "EXAMPLE-B", Prefix: "11.1.0.0/16"},
		"::ffff:11.1.3.4":  {Number: 200, Name: "EXAMPLE-B", Prefix: "11.1.0.0/16"},
		"12.200.0.1":       {Number: 300, Prefix: "12.128.0.0/9"}, // unnamed AS
		"12.1.0.1":         {Number: 300, Prefix: "12.0.0.0/9"},
		"2a00:1:3::1":      {Number: 400, Name: "EXAMPLE-D", Prefix: "2a00:1::/32"},
		"2a00:1:2:ffff::1": {Number: 500, Prefix: "2a00:1:2::/48"},
	} {
		got := db.Lookup(address, wire.SourceDispatcherObserved, 1, false).ASN
		if got.Value == nil || *got.Value != want || *got.Source != source {
			t.Errorf("%s: %+v %v", address, got.Value, got.Reason)
		}
	}
	if got := db.Lookup("13.0.0.1", wire.SourceDispatcherObserved, 1, false).ASN; got.Value != nil || got.Reason != "not_found" {
		t.Fatalf("unannounced address: %+v", got)
	}
	// A database that disagrees with the selection fails verification.
	if err := Verify(path, append(routes, Route{p("13.0.0.0/8"), 600}), names, generated.Unix()); err == nil {
		t.Fatal("missing route verified")
	}
	if err := Verify(path, routes, map[uint32]string{100: "OTHER"}, generated.Unix()); err == nil {
		t.Fatal("wrong name verified")
	}
	if err := Verify(path, routes, names, generated.Unix()+1); err == nil {
		t.Fatal("wrong build epoch verified")
	}
	if err := Write(&bytes.Buffer{}, []Route{routes[1], routes[0]}, names, 1, 10); err == nil {
		t.Fatal("unsorted routes written")
	}
}

type fixture struct {
	files map[string][]byte
	short map[string]bool // announce more bytes than are sent
}

func (f *fixture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, ok := f.files[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.short[r.URL.Path] {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)+100))
	} else {
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	_, _ = w.Write(data)
}

func gz(t *testing.T, s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestBuildInstallsVerifiedDatabaseAndFailsClosed(t *testing.T) {
	f := &fixture{files: map[string][]byte{
		"/v4.gz":   gz(t, dump("100\t11.0.0.0/8\t40", "200\t11.1.0.0/16\t40", "300\t11.2.0.0/16\t3")),
		"/v6.gz":   gz(t, strings.Replace(dump("400\t2a00:1::/32\t40"), "02:03:14", "02:06:14", 1)),
		"/asn.txt": []byte("100 EXAMPLE-A\n200 EXAMPLE-B\n400 EXAMPLE-D\n"),
	}, short: map[string]bool{}}
	server := httptest.NewServer(f)
	defer server.Close()
	output := filepath.Join(t.TempDir(), "ris-asn.mmdb")
	opts := Options{
		Output: output, MinIPv4: 2, MinIPv6: 1, MinNames: 3,
		IPv4URL: server.URL + "/v4.gz", IPv6URL: server.URL + "/v6.gz", ASNamesURL: server.URL + "/asn.txt",
		Client: server.Client(), Now: func() time.Time { return generated.Add(time.Hour) },
	}
	summary, err := Build(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	// The older dump dates the build.
	if !summary.Replaced || summary.Source != "database:Debuglet-RIS-ASN@"+strconv.FormatInt(generated.Unix(), 10) || summary.Stats.IPv4 != 2 || summary.Stats.BelowThreshold != 1 {
		t.Fatalf("summary %+v", summary)
	}
	db, err := ipmetadata.Open(output, "")
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup("11.1.0.1", wire.SourceDispatcherObserved, 1, false).ASN; got.Value == nil || got.Value.Number != 200 {
		t.Fatalf("lookup %+v", got)
	}
	_ = db.Close()
	installed, _ := os.ReadFile(output)

	// The same dumps again leave the file alone.
	if summary, err := Build(t.Context(), opts); err != nil || summary.Replaced {
		t.Fatalf("rebuild: %+v %v", summary, err)
	}

	refuse := func(name string, change func(*fixture, *Options)) {
		t.Helper()
		saved := map[string][]byte{}
		for k, v := range f.files {
			saved[k] = v
		}
		o := opts
		o.Now = func() time.Time { return generated.Add(2 * time.Hour) }
		// Newer dumps, so that only the failure can keep the old file.
		f.files["/v4.gz"] = gz(t, strings.Replace(dump("100\t11.0.0.0/8\t40", "200\t11.1.0.0/16\t40"), "02:03:14", "03:03:14", 1))
		f.files["/v6.gz"] = gz(t, strings.Replace(dump("400\t2a00:1::/32\t40"), "02:03:14", "03:03:14", 1))
		change(f, &o)
		if _, err := Build(t.Context(), o); err == nil {
			t.Errorf("%s: build accepted", name)
		} else {
			t.Logf("%s: %v", name, err)
		}
		if now, _ := os.ReadFile(output); !bytes.Equal(now, installed) {
			t.Errorf("%s: output changed", name)
		}
		entries, _ := os.ReadDir(filepath.Dir(output))
		if len(entries) != 1 {
			t.Errorf("%s: staging files left: %v", name, entries)
		}
		f.files, f.short = saved, map[string]bool{}
	}
	refuse("short download", func(f *fixture, _ *Options) { f.short["/v4.gz"] = true })
	refuse("corrupt gzip", func(f *fixture, _ *Options) {
		b := bytes.Clone(f.files["/v6.gz"])
		b[len(b)-6] ^= 0xff // CRC-32 in the trailer
		f.files["/v6.gz"] = b
	})
	refuse("truncated dump", func(f *fixture, _ *Options) {
		f.files["/v4.gz"] = gz(t, strings.TrimSuffix(dump("100\t11.0.0.0/8\t40"), "% End of dump\n\n"))
	})
	refuse("truncated names", func(f *fixture, _ *Options) { f.files["/asn.txt"] = []byte("100 EXAMPLE-A\n200 EXAMPLE-B\n400 EXAM") })
	refuse("missing file", func(f *fixture, _ *Options) { delete(f.files, "/asn.txt") })
	refuse("near-empty table", func(f *fixture, o *Options) { o.MinIPv4 = 3 })
	refuse("too few names", func(f *fixture, o *Options) { o.MinNames = 4 })
	refuse("stale dump", func(f *fixture, o *Options) {
		o.Now = func() time.Time { return generated.Add(DefaultMaxAge + 2*time.Hour) }
	})
	refuse("future dump", func(f *fixture, o *Options) { o.Now = func() time.Time { return generated.Add(-2 * time.Hour) } })
	refuse("threshold removes everything", func(f *fixture, o *Options) { o.MinPeers = 41 })
	refuse("invalid threshold", func(f *fixture, o *Options) { o.MinPeers = -1 })
}
