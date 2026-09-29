// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tagvectors"
	"github.com/netsec-ethz/debuglet/pkg/tagspec"
)

// vectorCapture is the shared tag-spec-v1 vectors as one capture: every
// supported vector as tagged by the vector chain in epoch 1, every
// unsupported one as given, and the untagged (altered) form of udp_base in
// epoch 2.
type vectorCapture struct {
	file   *tagvectors.File
	chain  *testChain
	frames []testFrame
	// want is the expected outcome per frame: "match", "mismatch" or an
	// unsupported reason.
	want []string
}

func loadVectorCapture(t *testing.T) vectorCapture {
	f := tagvectors.Load(t)
	if f.Spec != tagspec.ID {
		t.Fatalf("vector file is %q, this build implements %q", f.Spec, tagspec.ID)
	}
	keys := make([][]byte, len(f.Chain.KeysHex))
	for i, k := range f.Chain.KeysHex {
		keys[i] = tagvectors.Hex(t, k)
	}
	chain := &testChain{executor: "exec-vectors", keys: keys, sched: EvidenceSchedule{
		ChainID: "vectors", K0: keys[0], T0UnixNs: testT0.UnixNano(), EpochSeconds: 10,
		DisclosureDelayEpochs: 2, ChainLength: f.Chain.ChainLength, TagSpec: tagspec.Version,
	}}
	vc := vectorCapture{file: f, chain: chain}
	at := chain.at(f.Chain.SigningEpoch, 2*time.Second)
	var untagged []byte
	for i, v := range f.Vectors {
		frame := testFrame{at: at.Add(time.Duration(i) * time.Millisecond), ip: tagvectors.Hex(t, v.PacketHex)}
		want := v.UnsupportedReason
		if v.Supported {
			frame.ip, want = tagvectors.Hex(t, v.TaggedPacketHex), "match"
		}
		vc.frames, vc.want = append(vc.frames, frame), append(vc.want, want)
		if v.Name == "udp_base" {
			untagged = tagvectors.Hex(t, v.PacketHex)
		}
	}
	vc.frames = append(vc.frames, testFrame{at: chain.at(2, 2*time.Second), ip: untagged})
	vc.want = append(vc.want, "mismatch")
	return vc
}

func (vc vectorCapture) source() *fakeSource {
	src := &fakeSource{now: testNow, retainedFrom: testT0}
	seen := map[netip.Addr]bool{}
	for _, f := range vc.frames {
		if addr, reason := classify(f.ip); reason == "" && !seen[addr] {
			seen[addr] = true
			src.runs = append(src.runs, fakeRun{ip: addr, run: vc.file.MeasurementID, chain: vc.chain, from: testT0, to: testNow})
		}
	}
	return src
}

// outcomes maps a report back to the per-frame outcome.
func outcomes(rep VerifyReport, n int) []string {
	out := make([]string, n)
	for _, g := range rep.Groups {
		for _, i := range g.Packets {
			switch {
			case g.Verdict == VerdictVerified:
				out[i] = "match"
			case g.Reason == ReasonTagMismatch:
				out[i] = "mismatch"
			default:
				out[i] = g.Reason
			}
		}
	}
	return out
}

// TestVerifyVectorsThroughCaptures runs the shared vectors end to end: written
// as every supported capture format and link type, read back by ReadCapture
// and verified offline, with the same outcome everywhere.
func TestVerifyVectorsThroughCaptures(t *testing.T) {
	vc := loadVectorCapture(t)
	var baseline []byte
	for name, link := range captureLinks {
		for fname, data := range map[string][]byte{
			"pcap":        writePcap(link, false, false, vc.frames),
			"pcap-ns":     writePcap(link, true, true, vc.frames),
			"pcapng":      writePcapng(link, 0, false, vc.frames),
			"pcapng-ns":   writePcapng(link, 9, true, vc.frames),
			"pcapng-pow2": writePcapng(link, 0x80|20, false, vc.frames),
		} {
			t.Run(name+"/"+fname, func(t *testing.T) {
				pkts, err := ReadCapture(bytes.NewReader(data))
				if err != nil {
					t.Fatal(err)
				}
				rep := runOffline(t, vc.source(), pkts, VerifyOptions{})
				got := outcomes(rep, len(vc.frames))
				for i := range got {
					if got[i] != vc.want[i] {
						t.Errorf("frame %d (%s): %s, want %s", i, vectorName(vc, i), got[i], vc.want[i])
					}
				}
				verdicts, _ := json.Marshal(outcomes(rep, len(vc.frames)))
				if baseline == nil {
					baseline = verdicts
				} else if !bytes.Equal(verdicts, baseline) {
					t.Errorf("outcomes differ between formats")
				}
			})
		}
	}
	t.Run("expired history", func(t *testing.T) {
		src := &fakeSource{now: testNow, retainedFrom: testNow.Add(-time.Minute)}
		rep := runOffline(t, src, []CapturedPacket{{Data: vc.frames[0].ip, CapturedAt: vc.frames[0].at}}, VerifyOptions{})
		if g := onlyGroup(t, rep); g.Verdict != VerdictMissing || g.Reason != ReasonNotRetained {
			t.Fatalf("group %s %s, want missing not_retained", g.Verdict, g.Reason)
		}
	})
}

func vectorName(vc vectorCapture, i int) string {
	if i < len(vc.file.Vectors) {
		return vc.file.Vectors[i].Name
	}
	return "udp_base untagged"
}

// TestVerifyMatchesVerifyPcap cross-checks the per-packet outcome of the
// shared-vector capture against tools/verify_pcap.py, the reference verifier,
// when a Python 3 interpreter is available.
func TestVerifyMatchesVerifyPcap(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	vc := loadVectorCapture(t)
	root := filepath.Dir(filepath.Dir(tagvectors.Path(t)))
	dir := t.TempDir()
	capture := filepath.Join(dir, "vectors.pcap")
	if err := os.WriteFile(capture, writePcap(linkTypeEthernet, true, false, vc.frames), 0o600); err != nil {
		t.Fatal(err)
	}
	disclosed := int64(len(vc.chain.keys) - 2)
	tesla, _ := json.Marshal(map[string]any{
		"anchor_key": base64.StdEncoding.EncodeToString(vc.chain.keys[0]), "anchor_timestamp_ns": testT0.UnixNano(),
		"epoch_seconds": 10, "disclosure_delay_epochs": 2, "disclosed_epoch": disclosed,
		"disclosed_key": base64.StdEncoding.EncodeToString(vc.chain.keys[disclosed]),
	})
	script := fmt.Sprintf(`
import json, sys
sys.path.insert(0, %q)
import verify_pcap as vp
tesla = json.loads(%q)
out = []
for p in vp.read_capture(%q):
    _, code = vp.tag_input(p.ip)
    if code:
        out.append(code)
        continue
    matched, _ = vp.verify_packet(p, tesla, [%q])
    out.append("match" if matched else "mismatch")
print(json.dumps(out))
`, filepath.Join(root, "tools"), string(tesla), capture, vc.file.MeasurementID)
	cmd := exec.Command(python, "-c", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("verify_pcap.py: %v\n%s", err, stderr.String())
	}
	var want []string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatalf("verify_pcap.py output %q: %v", raw, err)
	}
	pkts, err := ReadCapture(bytes.NewReader(writePcap(linkTypeEthernet, true, false, vc.frames)))
	if err != nil {
		t.Fatal(err)
	}
	got := outcomes(runOffline(t, vc.source(), pkts, VerifyOptions{}), len(pkts))
	if len(got) != len(want) {
		t.Fatalf("Go reads %d packets, verify_pcap.py %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("frame %d (%s): Go %s, verify_pcap.py %s", i, vectorName(vc, i), got[i], want[i])
		}
	}
}

// TestVerifyKeyPublicMatchesVerifyPcap cross-checks the key-public rule with
// tools/verify_pcap.py at its boundary: a packet tagged in epoch s and
// captured in epoch s+1 is checked under k_s only while the capture time plus
// the clock tolerance (1 s) is before k_s's disclosure less the dispatcher's
// 5 s skew allowance, t0 + (s+d)·I − 5 s.
func TestVerifyKeyPublicMatchesVerifyPcap(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}
	vc := loadVectorCapture(t)
	root := filepath.Dir(filepath.Dir(tagvectors.Path(t)))
	var tagged []byte
	for i, v := range vc.file.Vectors {
		if v.Name == "udp_base" {
			tagged = vc.frames[i].ip
		}
	}
	if tagged == nil {
		t.Fatal("no udp_base vector")
	}
	s := vc.file.Chain.SigningEpoch
	// Epochs are 10 s and d = 2: k_s may be public from t0 + (s+2)·10 s − 5 s,
	// 5 s into epoch s+1, so the last capture time it covers is before 4 s.
	offsets := []time.Duration{3500 * time.Millisecond, 4*time.Second - time.Microsecond, 4 * time.Second, 6 * time.Second}
	want := []string{"match", "match", ReasonKeyPublic, ReasonKeyPublic}
	dir := t.TempDir()
	var paths []string
	var captures [][]byte
	for i, off := range offsets {
		data := writePcap(linkTypeEthernet, true, false, []testFrame{{at: vc.chain.at(s+1, off), ip: tagged}})
		path := filepath.Join(dir, fmt.Sprintf("boundary-%d.pcap", i))
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		paths, captures = append(paths, path), append(captures, data)
	}
	disclosed := int64(len(vc.chain.keys) - 2)
	tesla, _ := json.Marshal(map[string]any{
		"anchor_key": base64.StdEncoding.EncodeToString(vc.chain.keys[0]), "anchor_timestamp_ns": testT0.UnixNano(),
		"epoch_seconds": 10, "disclosure_delay_epochs": 2, "disclosed_epoch": disclosed,
		"disclosed_key": base64.StdEncoding.EncodeToString(vc.chain.keys[disclosed]),
	})
	pathsJSON, _ := json.Marshal(paths)
	script := fmt.Sprintf(`
import json, sys
sys.path.insert(0, %q)
import verify_pcap as vp
tesla = json.loads(%q)
out = []
for path in json.loads(%q):
    (p,) = vp.read_capture(path)
    matched, why = vp.verify_packet(p, tesla, [%q])
    if matched:
        out.append("match")
    elif why.startswith("no candidate key was still secret"):
        out.append("key_public")
    else:
        out.append("mismatch: " + why)
print(json.dumps(out))
`, filepath.Join(root, "tools"), string(tesla), string(pathsJSON), vc.file.MeasurementID)
	cmd := exec.Command(python, "-c", script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("verify_pcap.py: %v\n%s", err, stderr.String())
	}
	var py []string
	if err := json.Unmarshal(raw, &py); err != nil || len(py) != len(offsets) {
		t.Fatalf("verify_pcap.py output %q: %v", raw, err)
	}
	for i, data := range captures {
		pkts, err := ReadCapture(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		got := outcomes(runOffline(t, vc.source(), pkts, VerifyOptions{}), 1)[0]
		if got != want[i] || py[i] != want[i] {
			t.Errorf("captured %s into epoch %d: Go %s, verify_pcap.py %s, want %s", offsets[i], s+1, got, py[i], want[i])
		}
	}
}
