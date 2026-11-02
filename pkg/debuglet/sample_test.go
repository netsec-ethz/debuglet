// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
)

func TestWriteSamplePreservesObservationAndEscapesOneLine(t *testing.T) {
	sample := Sample{Name: "RTT\n<peer>", Series: "Zürich → Tokyo", Unit: "ms", TimestampMS: 1793612345678, Value: 12.5}
	var output bytes.Buffer
	if err := WriteSample(&output, sample); err != nil {
		t.Fatal(err)
	}
	if bytes.Count(output.Bytes(), []byte{'\n'}) != 1 || !bytes.HasSuffix(output.Bytes(), []byte{'\n'}) || output.Len() > 4096 {
		t.Fatalf("sample is not one bounded JSON line: %q", output.String())
	}
	var record struct {
		Schema string `json:"schema"`
		Sample
	}
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatal(err)
	}
	if record.Schema != "debuglet.timeseries.v1" || record.Sample != sample {
		t.Fatalf("observation changed: %+v", record)
	}
	output.Reset()
	if err := WriteSample(&output, Sample{Name: "count", Value: 0}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), `"series"`) || !strings.Contains(output.String(), `"unit":""`) || !strings.Contains(output.String(), `"timestamp_ms":0`) {
		t.Fatalf("empty series or required empty values encoded incorrectly: %s", &output)
	}
}

func TestWriteSampleRejectsInvalidObservationsBeforeWriting(t *testing.T) {
	for name, change := range map[string]func(*Sample){
		"empty name":         func(s *Sample) { s.Name = "" },
		"long name":          func(s *Sample) { s.Name = strings.Repeat("é", 81) },
		"long series":        func(s *Sample) { s.Series = strings.Repeat("x", 161) },
		"long unit":          func(s *Sample) { s.Unit = strings.Repeat("x", 41) },
		"invalid UTF-8":      func(s *Sample) { s.Name = string([]byte{0xff}) },
		"negative timestamp": func(s *Sample) { s.TimestampMS = -1 },
		"unsafe timestamp":   func(s *Sample) { s.TimestampMS = 9007199254740992 },
		"NaN":                func(s *Sample) { s.Value = math.NaN() },
		"infinite":           func(s *Sample) { s.Value = math.Inf(1) },
	} {
		t.Run(name, func(t *testing.T) {
			sample := Sample{Name: "Latency", Value: 1}
			change(&sample)
			var output bytes.Buffer
			if err := WriteSample(&output, sample); err == nil || output.Len() != 0 {
				t.Fatalf("invalid sample wrote %d bytes with error %v", output.Len(), err)
			}
		})
	}
	var output bytes.Buffer
	if err := WriteSample(&output, Sample{Name: strings.Repeat("é", 80), Series: strings.Repeat("\x00", 160), Unit: strings.Repeat("\x00", 40), TimestampMS: 9007199254740991, Value: -math.MaxFloat64}); err != nil || output.Len() > 4096 {
		t.Fatalf("valid boundaries failed: %v (%d bytes)", err, output.Len())
	}
}

type sampleFailWriter struct {
	err    error
	writes int
}

func (w *sampleFailWriter) Write(p []byte) (int, error) {
	w.writes++
	return len(p) / 2, w.err
}

func TestWriteSampleReturnsOutputFailureWithoutRetry(t *testing.T) {
	broken := errors.New("output closed")
	for _, want := range []error{io.ErrShortWrite, broken} {
		writer := &sampleFailWriter{}
		if want == broken {
			writer.err = broken
		}
		if err := WriteSample(writer, Sample{Name: "count", Value: 1}); !errors.Is(err, want) || writer.writes != 1 {
			t.Fatalf("write error %v; wanted %v after one attempt, got %d", err, want, writer.writes)
		}
	}
	if err := WriteSample(nil, Sample{Name: "count"}); err == nil {
		t.Fatal("nil writer accepted")
	}
}
