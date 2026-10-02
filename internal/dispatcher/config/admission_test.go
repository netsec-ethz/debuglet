// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package config

import "testing"

func TestAdmissionLimitsAreFiniteForEveryProfile(t *testing.T) {
	cfg := DefaultAdmissionConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, limits := range []AccountLimits{cfg.Account, cfg.Operator} {
		if limits.RequestsPerMinute <= 0 || limits.QueuedJobs <= 0 || limits.ActiveJobs <= 0 || limits.QueuedBytes <= 0 {
			t.Fatalf("unbounded default: %#v", limits)
		}
	}
	for _, mutate := range []func(*AdmissionConfig){
		func(c *AdmissionConfig) { c.Account.RequestsPerMinute = 0 },
		func(c *AdmissionConfig) { c.Operator.QueuedBytes = 0 },
		func(c *AdmissionConfig) { c.Account.ActiveJobs = c.Account.QueuedJobs + 1 },
	} {
		invalid := cfg
		mutate(&invalid)
		if invalid.Validate() == nil {
			t.Fatalf("accepted invalid limit: %#v", invalid)
		}
	}
}

func TestPayloadRetentionRequiresOperatorChoice(t *testing.T) {
	var cfg RetentionConfig
	if cfg.Validate() != nil || cfg.PayloadMaxAge() != 0 {
		t.Fatal("zero retention must preserve payloads")
	}
	cfg.PayloadMaxAgeSeconds = -1
	if cfg.Validate() == nil {
		t.Fatal("negative retention accepted")
	}
	cfg.PayloadMaxAgeSeconds = 1<<63 - 1
	if cfg.Validate() == nil {
		t.Fatal("overflowing retention accepted")
	}
}
