// Package demo owns the disposable installed local measurement.
package demo

import "github.com/netsec-ethz/debuglet/internal/artifact"

type Manifest = artifact.Manifest

type Assets struct {
	Root, CLI, Dispatcher, Executor, Guest string
	Manifest                               Manifest
}

type Result struct {
	Version    string `json:"version"`
	ExecutorID string `json:"executor_id"`
	RunID      string `json:"run_id"`
	Response   string `json:"response"`
	State      string `json:"state"`
	Cleanup    string `json:"cleanup"`
}
