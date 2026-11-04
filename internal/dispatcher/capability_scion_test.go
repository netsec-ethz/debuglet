// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package dispatcher

import (
	"errors"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/dispatcher/models"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestSCIONListenerAdmissionUsesCurrentCapability(t *testing.T) {
	now := time.Now()
	spec := &models.DebugletSpec{Policy: models.DebugletPolicy{ListenSCION: true}}
	entry := &executorEntry{RegisteredExecutor: &RegisteredExecutor{}}
	// Existing legacy declarations remain compatible. The builder separately
	// requires the current optional host functions and protocol observation.
	if err := validateExecutorCapabilities(spec, entry, now); err != nil {
		t.Fatal(err)
	}
	entry.Capabilities = &wire.ExecutorCapabilities{Protocols: []string{"scion"}}
	entry.capabilityObserved = now
	if err := validateExecutorCapabilities(spec, entry, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		protocols []string
		observed  time.Time
		code      string
	}{
		{"daemon unavailable", []string{"tcp"}, now, "unsupported"},
		{"expired positive", []string{"scion"}, now.Add(-capabilityLifetime), "stale_observation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry.Capabilities.Protocols, entry.capabilityObserved = tc.protocols, tc.observed
			var refusal *CapabilityError
			if err := validateExecutorCapabilities(spec, entry, now); !errors.As(err, &refusal) || refusal.Field != "policy.listen_scion" || refusal.Code != tc.code {
				t.Fatalf("SCION listener admission: %v", err)
			}
		})
	}
}
