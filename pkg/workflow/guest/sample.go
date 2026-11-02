// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"time"

	"github.com/netsec-ethz/debuglet/pkg/debuglet"
)

// PlotSample appends one observation to a live graph through the same writer
// and trace budget as ordinary workflow events. The timestamp is the guest's
// current clock, not a claim of synchronization with another executor.
func (r *Runtime) PlotSample(in map[string]any) (map[string]any, error) {
	if err := Check(in, map[string]string{"name": "string", "series": "string", "unit": "string", "value": "number"}); err != nil {
		return nil, err
	}
	err := debuglet.WriteSample(sampleWriter{r}, debuglet.Sample{
		Name: in["name"].(string), Series: in["series"].(string), Unit: in["unit"].(string),
		TimestampMS: time.Now().UnixMilli(), Value: in["value"].(float64),
	})
	return map[string]any{}, err
}

type sampleWriter struct{ runtime *Runtime }

func (w sampleWriter) Write(record []byte) (int, error) { return w.runtime.writeRecord(record) }
