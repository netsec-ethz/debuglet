// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "fmt"

// AccountLimits bounds work belonging to one authenticated account across all
// executors. ActiveJobs bounds overlapping reserved execution windows; QueuedJobs
// also includes active and unreconciled work until confirmed retirement.
type AccountLimits struct {
	RequestsPerMinute int   `toml:"requests_per_minute"`
	QueuedJobs        int64 `toml:"queued_jobs"`
	ActiveJobs        int64 `toml:"active_jobs"`
	QueuedBytes       int64 `toml:"queued_bytes"`
}

type AdmissionConfig struct {
	Account AccountLimits `toml:"account"`
	// Operator applies to authenticated operator accounts and the explicitly
	// enabled local-development bucket. Neither bypasses admission accounting.
	Operator AccountLimits `toml:"operator"`
}

func DefaultAdmissionConfig() AdmissionConfig {
	return AdmissionConfig{
		Account:  AccountLimits{RequestsPerMinute: 60, QueuedJobs: 128, ActiveJobs: 16, QueuedBytes: 256 << 20},
		Operator: AccountLimits{RequestsPerMinute: 240, QueuedJobs: 1024, ActiveJobs: 64, QueuedBytes: 1 << 30},
	}
}

func (cfg AdmissionConfig) Validate() error {
	for _, entry := range []struct {
		name   string
		limits AccountLimits
	}{
		{"account", cfg.Account}, {"operator", cfg.Operator},
	} {
		l := entry.limits
		if l.RequestsPerMinute < 1 || l.RequestsPerMinute > 100000 {
			return fmt.Errorf("admission.%s.requests_per_minute must be between 1 and 100000", entry.name)
		}
		if l.QueuedJobs < 1 || l.QueuedJobs > 100000 || l.ActiveJobs < 1 || l.ActiveJobs > l.QueuedJobs {
			return fmt.Errorf("admission.%s requires 1 <= active_jobs <= queued_jobs <= 100000", entry.name)
		}
		if l.QueuedBytes < 512 || l.QueuedBytes > 1<<50 {
			return fmt.Errorf("admission.%s.queued_bytes must be between 512 and 1125899906842624", entry.name)
		}
	}
	return nil
}
