// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func TestExecutorSignsItsCurrentSchedule(t *testing.T) {
	f := newCredentialFixture(t)
	schedule, err := tesla.NewKeySchedule(tesla.Config{EpochLength: time.Second, DisclosureDelay: 3, ChainLength: 10})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := signSchedule("executor", schedule, f.client.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	var proof wire.AttributionScheduleProof
	if err := json.Unmarshal(raw, &proof); err != nil {
		t.Fatal(err)
	}
	// The same certificate used for authenticated control signs the exact
	// schedule; changing a later recovered origin cannot reuse this signature.
	c := schedule.Config()
	expected := wire.AttributionSchedule{K0: schedule.Anchor(), T0UnixNs: c.Epoch.UnixNano(), EpochSeconds: 1, DisclosureDelayEpochs: 3, ChainLength: 10, TagSpec: 1, OperatorProof: &proof}
	id := sha256.Sum256(schedule.Anchor())
	expected.ChainID = hex.EncodeToString(id[:16])
	if err := wire.VerifyAttributionSchedule("executor", expected, wire.AttributionCertificateID(f.client.Certificate.Certificate[0])); err != nil {
		t.Fatal(err)
	}
}
