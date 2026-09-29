// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/client"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

const verifyRun = "6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57aaaa"

// verifyFixture is a dispatcher with one run on one chain, whose epoch 0
// began an hour ago: 10-second epochs, disclosure after 2 epochs.
type verifyFixture struct {
	keys [][]byte
	t0   time.Time
	*fixture
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	const length = 1000
	v := &verifyFixture{keys: make([][]byte, length+1), t0: time.Now().Add(-time.Hour).Truncate(time.Second)}
	tail := sha256.Sum256([]byte("verify fixture"))
	v.keys[length] = tail[:]
	for i := length - 1; i >= 0; i-- {
		sum := sha256.Sum256(v.keys[i+1])
		v.keys[i] = sum[:]
	}
	disclosed := v.epoch(time.Now()) - 2
	schedule := client.AttributionSchedule{ChainID: "c0ffee", K0: v.keys[0], T0UnixNs: v.t0.UnixNano(), EpochSeconds: 10,
		DisclosureDelayEpochs: 2, ChainLength: length, TagSpec: client.TagSpecVersionV1}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /attribution/candidates", func(w http.ResponseWriter, r *http.Request) {
		at, _ := time.Parse(time.RFC3339Nano, r.URL.Query().Get("at"))
		doc := client.AttributionCandidates{IP: r.URL.Query().Get("ip"), At: at, RetainedFrom: v.t0, Candidates: []client.AttributionCandidate{}}
		if doc.IP == "192.0.2.7" {
			doc.Candidates = append(doc.Candidates, client.AttributionCandidate{
				ExecutorID: "exec-zrh-1", RunID: verifyRun, ActiveFrom: v.t0, ActiveTo: time.Now().Add(time.Hour), IPSource: "observed",
				Schedule: schedule, DisclosedThrough: disclosed, DisclosedThroughAtNs: time.Now().UnixNano(),
				NextDisclosureAtNs: v.t0.Add(time.Duration(disclosed+3) * 10 * time.Second).UnixNano(),
			})
		}
		writeJSONResponse(w, http.StatusOK, doc)
	})
	mux.HandleFunc("GET /attribution/keys", func(w http.ResponseWriter, r *http.Request) {
		from, _ := strconv.ParseInt(r.URL.Query().Get("from_epoch"), 10, 64)
		to, _ := strconv.ParseInt(r.URL.Query().Get("to_epoch"), 10, 64)
		doc := client.AttributionKeys{ExecutorID: r.URL.Query().Get("executor_id"), ChainID: r.URL.Query().Get("chain_id"), Keys: []client.AttributionKey{}}
		for e := from; e <= min(to, disclosed, from+1023); e++ {
			doc.Keys = append(doc.Keys, client.AttributionKey{Epoch: e, Key: v.keys[e]})
		}
		writeJSONResponse(w, http.StatusOK, doc)
	})
	v.fixture = newFixture(t, mux)
	return v
}

func (v *verifyFixture) epoch(at time.Time) int64 { return int64(at.Sub(v.t0) / (10 * time.Second)) }
func (v *verifyFixture) at(e int64) time.Time {
	return v.t0.Add(time.Duration(e)*10*time.Second + time.Second)
}

// probe is a UDP probe from src, tagged by the fixture run in epoch e unless
// e is negative.
func (v *verifyFixture) probe(src [4]byte, e int64, fill byte) []byte {
	pkt := make([]byte, 80)
	pkt[0], pkt[8], pkt[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(pkt[2:], uint16(len(pkt)))
	copy(pkt[12:], src[:])
	copy(pkt[16:], []byte{198, 51, 100, 1})
	for i := 20; i < len(pkt); i++ {
		pkt[i] = fill + byte(i)
	}
	if e >= 0 {
		ak, _ := tagspec.DeriveAK(v.keys[e], []byte(verifyRun))
		tag, _ := tagspec.PacketTag(ak, pkt)
		binary.BigEndian.PutUint16(pkt[4:], tag)
	}
	return pkt
}

type verifyPacket struct {
	at  time.Time
	pkt []byte
}

// writeCapture writes a nanosecond raw-IP pcap.
func writeCapture(t *testing.T, pkts ...verifyPacket) string {
	out := binary.LittleEndian.AppendUint32(nil, 0xa1b23c4d)
	out = binary.LittleEndian.AppendUint16(out, 2)
	out = binary.LittleEndian.AppendUint16(out, 4)
	out = append(out, make([]byte, 8)...)
	out = binary.LittleEndian.AppendUint32(out, 65535)
	out = binary.LittleEndian.AppendUint32(out, 101)
	for _, p := range pkts {
		out = binary.LittleEndian.AppendUint32(out, uint32(p.at.Unix()))
		out = binary.LittleEndian.AppendUint32(out, uint32(p.at.Nanosecond()))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p.pkt)))
		out = binary.LittleEndian.AppendUint32(out, uint32(len(p.pkt)))
		out = append(out, p.pkt...)
	}
	path := filepath.Join(t.TempDir(), "capture.pcap")
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

var (
	probeSrc = [4]byte{192, 0, 2, 7}
	otherSrc = [4]byte{192, 0, 2, 99}
)

func TestVerifyCommandVerifiedAndEvidence(t *testing.T) {
	v := newVerifyFixture(t)
	capture := writeCapture(t, verifyPacket{v.at(100), v.probe(probeSrc, 100, 1)}, verifyPacket{v.at(100), v.probe(probeSrc, 100, 2)})
	evidence := filepath.Join(t.TempDir(), "evidence.json")
	// Flags may follow the capture, as the synopsis writes them.
	code, out, errout := runCLI(context.Background(), "--endpoint", v.endpoint(), "verify", capture, "--offline", "--evidence", evidence)
	assertCode(t, code, verifyExitVerified, out, errout)
	for _, want := range []string{"verified     run 6f1c2b1d…  executor exec-zrh-1  192.0.2.7", "2 packets  via offline",
		"1 group: 1 verified (2 packets", verifyRun, "captured before their keys were disclosed", "Evidence written to"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for _, r := range v.requests {
		if r.Method != http.MethodGet || len(r.Body) != 0 {
			t.Fatalf("request %s %s uploaded data", r.Method, r.Path)
		}
	}

	// The bundle checks out again without the dispatcher.
	v.server.Close()
	code, out, errout = runCLI(context.Background(), "--endpoint", v.endpoint(), "verify", evidence)
	assertCode(t, code, verifyExitVerified, out, errout)
	if !strings.Contains(out, "Evidence bundle created") || !strings.Contains(out, "via offline") {
		t.Fatalf("evidence output:\n%s", out)
	}
	raw, err := os.ReadFile(evidence)
	if err != nil {
		t.Fatal(err)
	}
	var ev client.Evidence
	if err := json.Unmarshal(raw, &ev); err != nil || ev.Tool.Name != "dbl" || ev.FormatVersion != 1 {
		t.Fatalf("bundle %+v, %v", ev.Tool, err)
	}
	ev.Groups[0].RunID = "6f1c2b1d-4c8e-4a6f-9d3b-2e1c4a57bbbb"
	tampered := filepath.Join(t.TempDir(), "tampered.json")
	raw, _ = json.Marshal(ev)
	if err := os.WriteFile(tampered, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errout = runCLI(context.Background(), "verify", tampered)
	assertCode(t, code, verifyExitError, out, errout)
	if !strings.Contains(errout, "does not check out") {
		t.Fatalf("tampered bundle: %s", errout)
	}
}

func TestVerifyCommandVerdictsAndExitCodes(t *testing.T) {
	v := newVerifyFixture(t)
	now := v.epoch(time.Now())
	for _, tc := range []struct {
		name  string
		pkts  []verifyPacket
		code  int
		wants []string
	}{
		{"invalid", []verifyPacket{{v.at(100), v.probe(probeSrc, 100, 1)}, {v.at(100), v.probe(otherSrc, -1, 1)}}, verifyExitInvalid,
			[]string{"invalid      192.0.2.99", "no_run", "Filter the capture"}},
		{"tag mismatch", []verifyPacket{{v.at(100), v.probe(probeSrc, -1, 1)}}, verifyExitInvalid,
			[]string{"tag_mismatch", "not sent by Debuglet"}},
		{"pending", []verifyPacket{{v.at(now), v.probe(probeSrc, now, 1)}}, verifyExitInconclusive,
			[]string{"pending      192.0.2.7", "until ", "Retry after "}},
		{"unsupported", []verifyPacket{{v.at(100), append([]byte{0x60}, make([]byte, 47)...)}}, verifyExitInconclusive,
			[]string{"unsupported", "IPv6 is not tagged"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errout := runCLI(context.Background(), "--endpoint", v.endpoint(), "verify", writeCapture(t, tc.pkts...))
			assertCode(t, code, tc.code, out, errout)
			for _, want := range tc.wants {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
	t.Run("json", func(t *testing.T) {
		code, out, errout := runCLI(context.Background(), "--endpoint", v.endpoint(), "verify", "--output", "json",
			writeCapture(t, verifyPacket{v.at(100), v.probe(probeSrc, 100, 1)}))
		assertCode(t, code, verifyExitVerified, out, errout)
		var rep client.VerifyReport
		if err := json.Unmarshal([]byte(out), &rep); err != nil || len(rep.Groups) != 1 || rep.Groups[0].Verdict != client.VerdictVerified ||
			rep.Groups[0].RunID != verifyRun {
			t.Fatalf("report %s: %v", out, err)
		}
	})
	for name, args := range map[string][]string{
		"no capture":    {"verify"},
		"two captures":  {"verify", "a", "b"},
		"bad time":      {"verify", "--at", "yesterday", "x.pcap"},
		"bad output":    {"verify", "--output", "yaml", "x.pcap"},
		"missing file":  {"verify", filepath.Join(t.TempDir(), "absent.pcap")},
		"not a capture": {"verify", writeFile(t, "hello")},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errout := runCLI(context.Background(), append([]string{"--endpoint", v.endpoint()}, args...)...)
			assertCode(t, code, verifyExitError, out, errout)
		})
	}
}

func writeFile(t *testing.T, content string) string {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
