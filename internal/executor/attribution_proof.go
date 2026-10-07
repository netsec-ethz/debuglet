// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package executor

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/netsec-ethz/debuglet/internal/executor/tagger/tesla"
	"github.com/netsec-ethz/debuglet/pkg/wire"
)

func signSchedule(executor string, schedule *tesla.KeySchedule, certificate tls.Certificate) ([]byte, error) {
	anchor := schedule.Anchor()
	id := sha256.Sum256(anchor)
	proof, err := wire.SignAttributionSchedule(executor, wire.AttributionSchedule{
		ChainID: hex.EncodeToString(id[:16]), K0: anchor, T0UnixNs: schedule.Config().Epoch.UnixNano(),
		EpochSeconds: int64(schedule.Config().EpochLength / time.Second), DisclosureDelayEpochs: schedule.DisclosureDelay(), ChainLength: schedule.ChainLength(), TagSpec: wire.TagSpecVersionV1,
	}, certificate)
	if err != nil {
		return nil, err
	}
	return json.Marshal(proof)
}
