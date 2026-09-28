// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

// evaluation reads saved local experiment artifacts without a dispatcher.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"

	"github.com/netsec-ethz/debuglet/pkg/client"
)

type condition struct {
	Name        string `json:"name"`
	DelayMS     int    `json:"delay_per_direction_ms"`
	LossPercent int    `json:"loss_percent_per_direction"`
	RateBPS     int    `json:"shared_rate_bits_per_second"`
	Mode        string `json:"mode"`
	Expected    string `json:"expected_sla"`
}

var conditions = []condition{
	{"baseline", 0, 0, 0, "both", "pass"},
	{"delay20", 20, 0, 0, "latency", "pass"},
	{"delay60", 60, 0, 0, "latency", "fail"},
	{"loss25", 0, 25, 0, "latency", "observe"},
	{"rate128k", 0, 0, 128000, "both", "fail"},
	{"loss100", 0, 100, 0, "latency", "fail"},
}

type trial struct {
	Condition string `json:"condition"`
	Repeat    int    `json:"repeat"`
	Kind      string `json:"kind"`
	Nonce     string `json:"nonce"`
	File      string `json:"file"`
	WallNS    int64  `json:"wall_ns"`
}
type experiment struct {
	Version        int         `json:"version"`
	SourceSHA      string      `json:"source_sha"`
	Target         string      `json:"target"`
	WorkloadSHA256 string      `json:"workload_sha256"`
	Conditions     []condition `json:"conditions"`
	Trials         []trial     `json:"trials"`
}
type reply struct {
	Sequence int   `json:"sequence"`
	Sent     int64 `json:"sent_unix_ns"`
	Received int64 `json:"received_unix_ns"`
	RTT      int64 `json:"rtt_ns"`
}
type measurement struct {
	Sent        int     `json:"sent"`
	Replies     []reply `json:"replies"`
	Elapsed     int64   `json:"elapsed_ns"`
	SendElapsed int64   `json:"send_elapsed_ns"`
	Late        int     `json:"late"`
}
type probeReport struct {
	Version      int          `json:"version"`
	Nonce        string       `json:"nonce"`
	PayloadBytes int          `json:"payload_bytes"`
	Latency      measurement  `json:"latency"`
	Burst        *measurement `json:"burst,omitempty"`
	Error        string       `json:"error,omitempty"`
}
type targetEvent struct {
	Nonce      string `json:"nonce"`
	Burst      bool   `json:"burst"`
	Sequence   uint32 `json:"sequence"`
	Received   int64  `json:"received_unix_ns"`
	Sent       int64  `json:"sent_unix_ns"`
	Turnaround int64  `json:"turnaround_ns"`
}
type observation struct {
	Trial                trial    `json:"trial"`
	Sent                 int      `json:"sent"`
	Received             int      `json:"received"`
	MedianNS             *int64   `json:"median_rtt_ns"`
	P95NS                *int64   `json:"p95_rtt_ns"`
	SLA                  bool     `json:"sla_pass"`
	Reason               string   `json:"reason"`
	RTT                  []int64  `json:"rtt_ns"`
	TimingExcessNS       []int64  `json:"rtt_minus_target_processing_and_nominal_delay_ns"`
	QdiscSent            uint64   `json:"qdisc_sent_packets"`
	QdiscDropped         uint64   `json:"qdisc_dropped_packets"`
	RealizedDropFraction float64  `json:"qdisc_realized_drop_fraction"`
	BurstGoodputBPS      *float64 `json:"burst_goodput_bits_per_second"`
	BurstOfferedBPS      *float64 `json:"burst_offered_bits_per_second"`
	ProbeElapsedNS       int64    `json:"probe_elapsed_ns"`
	ExecutionOverheadNS  int64    `json:"execution_overhead_ns"`
}
type comparison struct {
	Condition          string `json:"condition"`
	Repeat             int    `json:"repeat"`
	MedianDifferenceNS *int64 `json:"wasm_minus_native_median_ns"`
	WallDifferenceNS   int64  `json:"wasm_minus_native_wall_ns"`
}
type summary struct {
	Version      int           `json:"version"`
	SourceSHA    string        `json:"source_sha"`
	Hypothesis   string        `json:"hypothesis"`
	Observations []observation `json:"observations"`
	Comparisons  []comparison  `json:"comparisons"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: evaluation ARTIFACT_DIRECTORY")
		os.Exit(2)
	}
	report, err := analyze(os.Args[1])
	if err == nil {
		err = json.NewEncoder(os.Stdout).Encode(report)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func readJSON(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return errors.New("experiment JSON exceeds one MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("expected one JSON document")
	}
	return nil
}

func analyze(dir string) (summary, error) {
	var inputs experiment
	if err := readJSON(filepath.Join(dir, "experiment.json"), &inputs); err != nil {
		return summary{}, err
	}
	if inputs.Version != 1 || len(inputs.SourceSHA) != 40 || len(inputs.WorkloadSHA256) != 64 || len(inputs.Trials) != 36 {
		return summary{}, errors.New("incomplete experiment identity or trial count")
	}
	if len(inputs.Conditions) != len(conditions) {
		return summary{}, errors.New("unexpected condition set")
	}
	for i := range conditions {
		if inputs.Conditions[i] != conditions[i] {
			return summary{}, errors.New("experiment differs from the declared conditions")
		}
	}
	var targetEvents []targetEvent
	if err := readJSON(filepath.Join(dir, "target-events.json"), &targetEvents); err != nil {
		return summary{}, err
	}
	peers := make(map[string]targetEvent, len(targetEvents))
	for _, event := range targetEvents {
		key := fmt.Sprintf("%s/%t/%d", event.Nonce, event.Burst, event.Sequence)
		if _, duplicate := peers[key]; duplicate || event.Turnaround < 0 || event.Sent < event.Received {
			return summary{}, errors.New("invalid target timing identity")
		}
		peers[key] = event
	}
	result := summary{Version: 1, SourceSHA: inputs.SourceSHA, Hypothesis: "empirical p95 UDP echo RTT <= 80 ms and reply fraction >= 90%; no observations is failure"}
	seen := map[string]observation{}
	for _, item := range inputs.Trials {
		key := fmt.Sprintf("%s/%d/%s", item.Condition, item.Repeat, item.Kind)
		if _, duplicate := seen[key]; duplicate || item.Repeat < 0 || item.Repeat >= 3 || (item.Kind != "native" && item.Kind != "wasm") || !filepath.IsLocal(item.File) {
			return summary{}, errors.New("invalid or duplicate trial identity")
		}
		var setup *condition
		for i := range inputs.Conditions {
			if inputs.Conditions[i].Name == item.Condition {
				setup = &inputs.Conditions[i]
			}
		}
		if setup == nil {
			return summary{}, errors.New("trial condition missing")
		}
		var measured probeReport
		if item.Kind == "native" {
			if err := readJSON(filepath.Join(dir, item.File), &measured); err != nil {
				return summary{}, err
			}
		} else {
			f, err := os.Open(filepath.Join(dir, item.File))
			if err != nil {
				return summary{}, err
			}
			exported, err := client.ReadResult(f)
			closeErr := f.Close()
			if err = errors.Join(err, closeErr); err != nil {
				return summary{}, err
			}
			if exported.Outcome.State != client.StateExited || exported.Outcome.Error != "" || exported.Output.Status.State != "complete" || exported.Provenance == nil || exported.Provenance.WorkloadSHA256 != inputs.WorkloadSHA256 {
				return summary{}, errors.New("measurement export is incomplete, uncertain, failed or has a different workload")
			}
			if len(exported.Provenance.Arguments) != 3 || exported.Provenance.Arguments[0] != inputs.Target || exported.Provenance.Arguments[1] != item.Nonce || exported.Provenance.Arguments[2] != setup.Mode {
				return summary{}, errors.New("measurement export arguments disagree with trial")
			}
			var output []byte
			for _, entry := range exported.Output.Entries {
				output = append(output, entry.Output...)
			}
			if len(output) > 1<<20 {
				return summary{}, errors.New("measurement output exceeds one MiB")
			}
			if err := json.Unmarshal(output, &measured); err != nil {
				return summary{}, err
			}
		}
		if measured.Version != 1 || measured.Nonce != item.Nonce || measured.PayloadBytes != 1024 || measured.Error != "" || measured.Latency.Sent != 12 || measured.Latency.Elapsed <= 0 || item.WallNS <= 0 {
			return summary{}, errors.New("invalid probe result")
		}
		row := observation{Trial: item, Sent: 12, Received: len(measured.Latency.Replies), Reason: "latency or reply fraction exceeded", RTT: []int64{}, ProbeElapsedNS: measured.Latency.Elapsed}
		prefix := fmt.Sprintf("%s-%d-%s", item.Condition, item.Repeat, item.Kind)
		before, err := readNetem(filepath.Join(dir, prefix+"-qdisc-before.json"))
		if err != nil {
			return summary{}, err
		}
		after, err := readNetem(filepath.Join(dir, prefix+"-qdisc-after.json"))
		if err != nil {
			return summary{}, err
		}
		if after.Packets < before.Packets || after.Drops < before.Drops {
			return summary{}, errors.New("qdisc counters moved backwards")
		}
		row.QdiscSent, row.QdiscDropped = after.Packets-before.Packets, after.Drops-before.Drops
		if row.QdiscSent+row.QdiscDropped == 0 {
			return summary{}, errors.New("target traffic bypassed the controlled qdisc")
		}
		row.RealizedDropFraction = float64(row.QdiscDropped) / float64(row.QdiscSent+row.QdiscDropped)
		seqs := map[int]bool{}
		for _, response := range measured.Latency.Replies {
			if response.Sequence < 0 || response.Sequence >= 12 || seqs[response.Sequence] || response.RTT < 0 || response.Received < response.Sent {
				return summary{}, errors.New("invalid probe response identity or timing")
			}
			seqs[response.Sequence] = true
			row.RTT = append(row.RTT, response.RTT)
			peer, ok := peers[fmt.Sprintf("%s/false/%d", item.Nonce, response.Sequence)]
			if !ok {
				return summary{}, errors.New("probe reply has no independent target observation")
			}
			row.TimingExcessNS = append(row.TimingExcessNS, response.RTT-peer.Turnaround-int64(setup.DelayMS)*2_000_000)
		}
		if len(row.RTT) > 0 {
			sorted := append([]int64(nil), row.RTT...)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
			median, p95 := sorted[(len(sorted)-1)/2], sorted[int(math.Ceil(.95*float64(len(sorted))))-1]
			row.MedianNS, row.P95NS = &median, &p95
			row.SLA = len(sorted) >= 11 && p95 <= 80_000_000
			if row.SLA {
				row.Reason = "within the declared sample bounds"
			}
		} else {
			row.Reason = "no RTT observations; loss is not zero latency"
		}
		if burst := measured.Burst; burst != nil {
			if setup.Mode != "both" {
				return summary{}, errors.New("unexpected burst in latency-only trial")
			}
			if burst.Sent != 32 || len(burst.Replies) != 32 || burst.Elapsed <= 0 || burst.SendElapsed <= 0 {
				return summary{}, errors.New("incomplete fixed-byte burst")
			}
			seenBurst := map[int]bool{}
			for _, response := range burst.Replies {
				if response.Sequence < 0 || response.Sequence >= 32 || seenBurst[response.Sequence] || response.RTT < 0 || response.Received < response.Sent {
					return summary{}, errors.New("invalid burst response identity or timing")
				}
				seenBurst[response.Sequence] = true
				if _, ok := peers[fmt.Sprintf("%s/true/%d", item.Nonce, response.Sequence)]; !ok {
					return summary{}, errors.New("burst reply has no independent target observation")
				}
			}
			goodput := float64(32*1024*8) * 1e9 / float64(burst.Elapsed)
			offered := float64(32*1024*8) * 1e9 / float64(burst.SendElapsed)
			row.BurstGoodputBPS, row.BurstOfferedBPS = &goodput, &offered
			row.ProbeElapsedNS += burst.Elapsed
			if setup.RateBPS > 0 && (offered < float64(setup.RateBPS)*4 || goodput > float64(setup.RateBPS)) {
				return summary{}, errors.New("rate trial did not saturate its declared shared link or bypassed shaping")
			}
		} else if setup.Mode == "both" {
			return summary{}, errors.New("missing fixed-byte burst")
		}
		row.ExecutionOverheadNS = item.WallNS - row.ProbeElapsedNS
		if (setup.Expected == "pass" && !row.SLA) || (setup.Expected == "fail" && row.SLA) {
			return summary{}, fmt.Errorf("%s contradicts its predeclared SLA case", key)
		}
		if setup.LossPercent == 100 && row.Received != 0 {
			return summary{}, errors.New("total-loss condition delivered a reply")
		}
		seen[key] = row
		result.Observations = append(result.Observations, row)
	}
	for _, setup := range inputs.Conditions {
		for repeat := 0; repeat < 3; repeat++ {
			prefix := fmt.Sprintf("%s/%d/", setup.Name, repeat)
			native, nativeOK := seen[prefix+"native"]
			wasm, wasmOK := seen[prefix+"wasm"]
			if !nativeOK || !wasmOK {
				return summary{}, errors.New("missing paired native/WASM trial")
			}
			pair := comparison{Condition: setup.Name, Repeat: repeat, WallDifferenceNS: wasm.Trial.WallNS - native.Trial.WallNS}
			if native.MedianNS != nil && wasm.MedianNS != nil {
				difference := *wasm.MedianNS - *native.MedianNS
				pair.MedianDifferenceNS = &difference
			}
			result.Comparisons = append(result.Comparisons, pair)
		}
	}
	return result, nil
}

type qdiscStats struct {
	Kind    string `json:"kind"`
	Parent  string `json:"parent"`
	Packets uint64 `json:"packets"`
	Drops   uint64 `json:"drops"`
}

func readNetem(path string) (qdiscStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return qdiscStats{}, err
	}
	if len(data) > 64<<10 {
		return qdiscStats{}, errors.New("qdisc evidence exceeds bound")
	}
	var entries []qdiscStats
	if err := json.Unmarshal(data, &entries); err != nil {
		return qdiscStats{}, err
	}
	for _, entry := range entries {
		if entry.Kind == "netem" && entry.Parent == "1:2" {
			return entry, nil
		}
	}
	return qdiscStats{}, errors.New("owned netem qdisc missing")
}
