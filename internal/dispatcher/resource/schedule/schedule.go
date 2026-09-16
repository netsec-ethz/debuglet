// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package schedule

import (
	"debuglet/internal/dispatcher/resource"
	"debuglet/internal/dispatcher/resource/schedule/dyn"
	"sync"
	"time"
)

type Request struct {
	Executor    string
	Destination []string
	From, To    time.Time
	Use         resource.Bitrate
}

type SegTree interface {
	// Add increases the inclusive range [l, r] by adding adding use.
	Add(l, r, use int64)
	// Get returns the value of a specific position.
	Get(pos int64) int64
	// QueryMax returns the maximum usage in a specific range.
	QueryMax(l, r int64) int64
	// Total returns the total usage added to the tree.
	Total() int64
	ToDot() string
}

type JobScheduler struct {
	execTrees   map[string]SegTree
	destTrees   map[string]SegTree
	granularity time.Duration
	mu          sync.RWMutex
}

func New(granularity time.Duration) *JobScheduler {
	if granularity <= 0 {
		panic("granularity can't be <=0")
	}
	return &JobScheduler{
		execTrees:   make(map[string]SegTree),
		destTrees:   make(map[string]SegTree),
		granularity: granularity,
	}
}

func (j *JobScheduler) Submit(req Request) {
	from := req.From.UnixNano() / j.granularity.Nanoseconds()
	to := ceil(req.To.UnixNano(), j.granularity.Nanoseconds())
	if from < 0 || to < 0 {
		panic("negative from/to request values")
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	j.submitExec(req.Executor, from, to, req.Use)
	for _, d := range req.Destination {
		j.submitDest(d, from, to, req.Use)
	}
}

func (j *JobScheduler) submitExec(executor string, from, to int64, use resource.Bitrate) {
	t, ok := j.execTrees[executor]
	if !ok {
		t = dyn.New()
		j.execTrees[executor] = t
	}
	t.Add(from, to, int64(use))
	if t.Total() == 0 {
		delete(j.execTrees, executor)
	}
}

func (j *JobScheduler) submitDest(destination string, from, to int64, use resource.Bitrate) {
	t, ok := j.destTrees[destination]
	if !ok {
		t = dyn.New()
		j.destTrees[destination] = t
	}
	t.Add(from, to, int64(use))
	if t.Total() == 0 {
		delete(j.destTrees, destination)
	}
}

func ceil(a, b int64) int64 {
	if a == 0 {
		return 0
	}
	return 1 + (a-1)/b
}

func (j *JobScheduler) Remove(req Request) {
	req.Use = -req.Use
	j.Submit(req)
}

func (j *JobScheduler) QueryMaxDest(destination string, from, to time.Time) resource.Bitrate {
	return j.queryMax(j.destTrees, destination, from, to)
}

func (j *JobScheduler) QueryMaxExec(executor string, from, to time.Time) resource.Bitrate {
	return j.queryMax(j.execTrees, executor, from, to)
}

func (j *JobScheduler) queryMax(m map[string]SegTree, key string, from, to time.Time) resource.Bitrate {
	f := from.UnixNano() / j.granularity.Nanoseconds()
	t := ceil(to.UnixNano(), j.granularity.Nanoseconds())
	j.mu.RLock()
	defer j.mu.RUnlock()
	if tree, ok := m[key]; !ok {
		return 0
	} else {
		return resource.Bitrate(tree.QueryMax(f, t))
	}
}
