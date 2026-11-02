// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

func sampleInputs() map[string]any {
	return map[string]any{"name": "RTT", "series": "peer A", "unit": "ms", "value": 12.5}
}

func TestPlotSampleUsesGuestTimeAndWorkflowWriter(t *testing.T) {
	r := New(strings.Repeat("a", 64))
	var output bytes.Buffer
	r.writer = &output
	start := time.Now().UnixMilli()
	values, err := r.PlotSample(sampleInputs())
	if err != nil || len(values) != 0 {
		t.Fatalf("plot: %v %v", values, err)
	}
	var sample debuglet.Sample
	if err := json.Unmarshal(output.Bytes(), &sample); err != nil {
		t.Fatal(err)
	}
	if sample.Name != "RTT" || sample.Series != "peer A" || sample.Unit != "ms" || sample.Value != 12.5 || sample.TimestampMS < start || sample.TimestampMS > time.Now().UnixMilli() {
		t.Fatalf("sample lost its value or guest timestamp: %+v", sample)
	}
	if r.events != 1 || r.bytes != output.Len() {
		t.Fatal("sample did not consume the ordinary trace budget")
	}
}

func TestPlotSampleRejectsInvalidDynamicInputs(t *testing.T) {
	for _, test := range []struct {
		field string
		value any
	}{
		{"name", ""}, {"name", strings.Repeat("é", 81)}, {"series", strings.Repeat("s", 161)},
		{"unit", strings.Repeat("u", 41)}, {"value", "12"}, {"value", math.NaN()},
	} {
		r := New("")
		var output bytes.Buffer
		r.writer = &output
		in := sampleInputs()
		in[test.field] = test.value
		if _, err := r.PlotSample(in); err == nil || output.Len() != 0 {
			t.Fatalf("invalid %s wrote output: %v", test.field, err)
		}
	}
}

func TestPlotSampleSharesTraceLimitsAndReturnsWriteErrors(t *testing.T) {
	for _, budget := range []string{"events", "bytes"} {
		r := New("")
		var output bytes.Buffer
		r.writer = &output
		if budget == "events" {
			r.events = 4096
		} else {
			r.bytes = 4*1024*1024 - 1
		}
		if _, err := r.PlotSample(sampleInputs()); err == nil || output.Len() != 0 {
			t.Fatalf("sample bypassed %s limit: %v", budget, err)
		}
	}
	r := New("")
	want := errors.New("output unavailable")
	r.writer = sampleErrorWriter{want}
	if _, err := r.PlotSample(sampleInputs()); !errors.Is(err, want) {
		t.Fatalf("output error lost: %v", err)
	}
}

type sampleErrorWriter struct{ err error }

func (w sampleErrorWriter) Write([]byte) (int, error) { return 0, w.err }
