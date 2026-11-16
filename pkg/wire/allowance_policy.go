// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package wire

import "time"

// AllowancePolicy describes the applied daily or one-time TEST refill.
// Integer amounts are decimal strings, as in Allowance.
type AllowancePolicy struct {
	Kind          string     `json:"kind"`
	Researcher    bool       `json:"researcher"`
	EligibleNodes int        `json:"eligible_nodes"`
	DailyCeiling  string     `json:"daily_ceiling"`
	HostingBonus  string     `json:"hosting_bonus"`
	Credited      string     `json:"credited"`
	NextReset     *time.Time `json:"next_reset,omitempty"`
}

// AllowanceEligibilityRequest replaces operator-approved researcher and owned
// executor eligibility. Existing grants and today's decision remain unchanged.
type AllowanceEligibilityRequest struct {
	Researcher          bool     `json:"researcher"`
	ApprovedExecutorIDs []string `json:"approved_executor_ids"`
}
