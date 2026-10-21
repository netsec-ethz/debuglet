// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package guest

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	maxTimers               = 128
	maxCollections          = 32
	maxCollectionBytes      = 48 * 1024
	maxCollectionStateBytes = 256 * 1024
)

type collection struct {
	values []any
	bytes  int
}

// StartTimer retains the monotonic part of the local clock. A timer belongs to
// one workflow run and cannot be compared to another executor's clock.
func (r *Runtime) StartTimer() (map[string]any, error) {
	if len(r.timers) >= maxTimers {
		return nil, fmt.Errorf("a workflow may create at most %d timers", maxTimers)
	}
	id := fmt.Sprintf("timer:%d", len(r.timers)+1)
	r.timers[id] = time.Now()
	return map[string]any{"timer": id}, nil
}

func (r *Runtime) Elapsed(in map[string]any) (map[string]any, error) {
	id, _ := in["timer"].(string)
	started, ok := r.timers[id]
	if !ok {
		return nil, fmt.Errorf("timer is not from this workflow run")
	}
	return map[string]any{"duration_ms": float64(time.Since(started)) / float64(time.Millisecond)}, nil
}

// Collections retain explicitly collected samples when Repeat invalidates
// ordinary node outputs. Samples and returned lists are independent snapshots.
func (r *Runtime) CreateCollection() (map[string]any, error) {
	if len(r.collections) >= maxCollections {
		return nil, fmt.Errorf("a workflow may create at most %d collections", maxCollections)
	}
	id := fmt.Sprintf("collection:%d", len(r.collections)+1)
	r.collections[id] = &collection{values: []any{}}
	return map[string]any{"collection": id}, nil
}

func (r *Runtime) lookupCollection(in map[string]any) (*collection, error) {
	id, _ := in["collection"].(string)
	c, ok := r.collections[id]
	if !ok {
		return nil, fmt.Errorf("collection is not from this workflow run")
	}
	return c, nil
}

func (r *Runtime) Collect(in map[string]any) (map[string]any, error) {
	c, err := r.lookupCollection(in)
	if err != nil {
		return nil, err
	}
	value, ok := in["value"]
	if !ok {
		return nil, fmt.Errorf("missing value")
	}
	if err := checkValue(value, 2); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	// Include list separators in the bound; leave room for the trace envelope.
	size := len(encoded) + 1
	if len(c.values) >= 1024 || c.bytes+size > maxCollectionBytes || r.collectionBytes+size > maxCollectionStateBytes {
		return nil, fmt.Errorf("collection limit exceeded (1024 samples, 48 KiB per collection, 256 KiB per run)")
	}
	var copied any
	if err := json.Unmarshal(encoded, &copied); err != nil {
		return nil, err
	}
	c.values = append(c.values, copied)
	c.bytes += size
	r.collectionBytes += size
	return map[string]any{"count": float64(len(c.values))}, nil
}

func (r *Runtime) ReadCollection(in map[string]any) (map[string]any, error) {
	c, err := r.lookupCollection(in)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(c.values)
	if err != nil {
		return nil, err
	}
	var copied []any
	if err := json.Unmarshal(encoded, &copied); err != nil {
		return nil, err
	}
	return map[string]any{"values": copied, "count": float64(len(c.values))}, nil
}

func (r *Runtime) ResetCollection(in map[string]any) (map[string]any, error) {
	c, err := r.lookupCollection(in)
	if err != nil {
		return nil, err
	}
	r.collectionBytes -= c.bytes
	c.values, c.bytes = []any{}, 0
	return map[string]any{"count": float64(0)}, nil
}
