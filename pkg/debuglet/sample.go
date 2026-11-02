// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package debuglet

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"unicode/utf8"
)

// Sample is one observation for a live graph. Name and Unit identify the graph;
// Series distinguishes peers or directions within it. TimestampMS is the
// measurement's Unix time in milliseconds, not the dispatcher's receipt time.
// Run and executor identity come from the containing output stream.
type Sample struct {
	Name        string  `json:"name"`
	Series      string  `json:"series,omitempty"`
	Unit        string  `json:"unit"`
	TimestampMS int64   `json:"timestamp_ms"`
	Value       float64 `json:"value"`
}

// WriteSample writes one debuglet.timeseries.v1 JSON line to w. Pass os.Stdout
// in a guest. Names contain 1–160 UTF-8 bytes; series at most 160 and units at
// most 40. Timestamps must be nonnegative JavaScript-safe integers and values
// finite. Invalid samples write nothing. Each line is at most 4096 bytes.
//
// Output errors, including partial writes, are returned without retrying. A
// successful write does not confirm dispatcher storage. The executor's normal
// output and execution limits still apply; serialize calls sharing a writer.
func WriteSample(w io.Writer, sample Sample) error {
	for _, field := range []struct {
		name, value string
		min, max    int
	}{
		{"name", sample.Name, 1, 160},
		{"series", sample.Series, 0, 160},
		{"unit", sample.Unit, 0, 40},
	} {
		if !utf8.ValidString(field.value) || len(field.value) < field.min || len(field.value) > field.max {
			return fmt.Errorf("sample %s must contain %d–%d UTF-8 bytes", field.name, field.min, field.max)
		}
	}
	if sample.TimestampMS < 0 || sample.TimestampMS > 9007199254740991 {
		return fmt.Errorf("sample timestamp_ms must be an integer between 0 and 9007199254740991")
	}
	if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) {
		return fmt.Errorf("sample value must be finite")
	}
	record, err := json.Marshal(struct {
		Schema string `json:"schema"`
		Sample
	}{"debuglet.timeseries.v1", sample})
	if err != nil {
		return err
	}
	record = append(record, '\n')
	if len(record) > 4096 {
		return fmt.Errorf("sample line exceeds 4096 bytes")
	}
	if w == nil {
		return fmt.Errorf("sample writer is nil")
	}
	n, err := w.Write(record)
	if err == nil && n != len(record) {
		err = io.ErrShortWrite
	}
	return err
}
